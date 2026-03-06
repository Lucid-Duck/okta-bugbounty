# sftd (ScaleFT Server Agent) v1.100.2 -- Linux RE Security Analysis

## Binary Overview

- **Binary:** /usr/sbin/sftd (51MB)
- **Architecture:** Go 1.25.0, amd64, NOT STRIPPED, has debug_info
- **Runs as:** root (NT AUTHORITY\SYSTEM equivalent) via systemd, no hardening
- **Package:** github.com/atko-pam/device-tools
- **Bug Bounty Target:** Advanced Server Access -- $35,000 P1 ceiling
- **Date:** 2026-03-05
- **Researcher:** Lucid_Duck

---

## FINDING 1: Fchownat Without AT_SYMLINK_NOFOLLOW -- Symlink Following as Root (HIGH - LPE)

**Functions:** `createHomeDirectory.Execute` (create_home_directory_unix.go:20), `ensureDirectory.do` (ensure_directory_unix.go)
**Service:** Runs as root (PID 187058, no User= in systemd unit)

### Vulnerability

Both `createHomeDirectory.Execute` and `ensureDirectory.do` call `syscall.Fchownat()` with:
- `dirfd = AT_FDCWD` (-100, 0xffffff9c)
- `flags = 0` (no AT_SYMLINK_NOFOLLOW)

Disassembly proof:
```asm
; createHomeDirectory.Execute at 0xe9226a
syscall_linux.go:118  MOVQ $-0x64, AX    ; AT_FDCWD = -100
syscall_linux.go:118  XORL R8, R8        ; flags = 0 (FOLLOWS SYMLINKS)
syscall_linux.go:118  CALL syscall.Fchownat(SB)

; ensureDirectory.do at 0xe93141
syscall_linux.go:118  MOVQ $-0x64, AX    ; AT_FDCWD = -100
syscall_linux.go:118  XORL R8, R8        ; flags = 0 (FOLLOWS SYMLINKS)
syscall_linux.go:118  CALL syscall.Fchownat(SB)
```

With `flags=0`, `fchownat(AT_FDCWD, path, uid, gid, 0)` is equivalent to `chown(path, uid, gid)` -- it follows symlinks.

### Call Chain

```
createHomeDirectory.Execute:
  1. os.MkdirAll(homedir, perm)        ; Create home directory
  2. syscall.Fchownat(AT_FDCWD, path, uid, gid, 0)  ; Chown FOLLOWS SYMLINKS
  3. os.Stat(path)                     ; Verify

ensureDirectory.do:
  1. isDirPerfect()                    ; Check if dir exists with right perms
  2. os.removeAll(path)               ; Remove if exists with wrong perms
  3. os.MkdirAll(path, perm)          ; Recreate
  4. syscall.Fchownat(AT_FDCWD, path, uid, gid, 0)  ; Chown FOLLOWS SYMLINKS
```

### Attack Scenario

When sftd creates/manages a user's home directory:

1. An attacker (low-priv user or compromised sftd-managed user) creates a symlink at the expected home directory path pointing to a target (e.g., `/etc`, `/root`, or any sensitive directory)
2. `os.MkdirAll` on a symlink target may succeed (if the target already exists as a directory) or fail
3. `Fchownat` with `flags=0` follows the symlink and chowns the TARGET directory to the managed user's UID/GID
4. Result: arbitrary directory ownership change as root

### Exploitability Factors

- Requires sftd to be enrolled and managing users (needs enrollment token)
- Race window between MkdirAll and Fchownat is small but widens with I/O
- `ensureDirectory.do` also calls `os.removeAll` before MkdirAll -- potential for a different race where the attacker replaces the directory with a symlink between removeAll and MkdirAll
- The `UserHomedirOwnerLinux.Execute` function additionally uses `exec.CommandContext` with `chown` -- a separate chown path that may also follow symlinks

### Secure Fix

Use `AT_SYMLINK_NOFOLLOW` (0x100) in the flags parameter:
```go
syscall.Fchownat(unix.AT_FDCWD, path, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
```

Or better: open the directory with `O_NOFOLLOW`, get an fd, then `fchown(fd, uid, gid)`.

---

## FINDING 2: Shell-Out to useradd/userdel/groupadd/groupdel/usermod/groupmod (MEDIUM-HIGH)

**Functions:** All Linux user/group management functions
**Service:** Runs as root

### Vulnerability

All user and group management operations shell out to system binaries via `os/exec.CommandContext`:

| Function | Source File | Binary Called |
|----------|------------|---------------|
| `UserCreateUnix.Execute` | user_create_linux.go:46 | `useradd` |
| `deleteUserByUsernameLinux` | user_delete_linux.go:17 | `userdel` |
| `GroupCreateUnix.Execute` | group_create_linux.go:16 | `groupadd` |
| `GroupDeleteUnix.Execute` / `deleteGroupByNameLinux` | group_delete_linux.go | `groupdel` |
| `changeUserUnixName` | user_change_unix_name_linux.go:17 | `usermod` |
| `changeGroupUnixGid` | group_change_unix_gid_linux.go | `groupmod` |
| `changeGroupUnixGroupName` | group_change_unix_group_name_linux.go | `groupmod` |
| `GroupMemberAddUnix.Execute` | group_member_add_linux.go | `usermod` |
| `GroupMemberRemoveUnix.Execute` | group_member_rm_linux.go | `usermod` |
| `UserHomedirOwnerLinux.Execute` | user_homedir_owner.go:61 | `chown` |
| `ChangeUserPassword` | server_account_state_linux.go:66,77 | `chpasswd` (twice) |
| `optionalAttributes.Execute` | optional_attributes_linux.go | `usermod` |

### Risk

Arguments come from the ScaleFT platform API. The `UserCreateUnix` struct fields are:

```
Offset 8:   Name (string)          -> useradd username
Offset 24:  Uid (string)           -> useradd -u
Offset 40:  Gid (string)           -> useradd -g
Offset 56:  Comment (string)       -> useradd -c
Offset 72:  HomeDirectory (string) -> useradd -d
Offset 88:  Shell (string)         -> useradd -s
Offset 104: Groups ([]string)      -> useradd -G
```

Go's `os/exec.CommandContext` does NOT use a shell (it calls execve directly), so shell metacharacter injection is not directly possible. However:

1. **Path traversal in HomeDirectory:** If the home directory path contains `../` sequences, the user's home could be created at an arbitrary location (e.g., `/etc/sftd-managed/../../root`)
2. **`checkPath` validation:** A path validation function exists (`ensure_fs.go:9`) that checks against an allow list, but it uses `filepath.Clean` + string comparison -- if the allow list is misconfigured or bypassable, path traversal succeeds
3. **Shell field injection:** If the Shell field can be set to an arbitrary path, it creates a user with a login shell controlled by the attacker
4. **Comment field injection:** The `Comment` field is passed directly to useradd -c -- while exec.Command prevents shell injection, GECOS field special characters (`,`) could cause issues with some systems

### Confirmed: strings.Join Used for Args

`UserCreateUnix.Execute` at line 38 calls `strings.Join` -- this is used to join group names for the `-G` flag. The group names come from the API response.

---

## FINDING 3: Sudo Dropin File Writes to /etc/sudoers.d/ (MEDIUM-HIGH)

**Functions:** `NewSudoDropIn` (sudo_dropin.go), uses `NewEnsureFile` -> `safefile.WriteFile`
**Service:** Runs as root
**File:** `/etc/sudoers.d/95-scaleft`

### Vulnerability

sftd writes sudo configuration files to `/etc/sudoers.d/95-scaleft` with content:
```
<username> ALL=(ALL:ALL) NOPASSWD:ALL
```

The `safefile.WriteFile` uses a temp-then-rename pattern (good). However:

1. **Username validation:** The `disallowed value '%c'` error string is near `grant_user_based_sudo` in the binary, confirming character validation exists but the allowed character set needs investigation
2. **Sudoers injection:** If a username containing special sudoers syntax characters (e.g., `#`, `%`, `!`, `=`) passes validation, it could modify the intended sudoers rule semantics
3. **File path:** The target path `/etc/sudoers.d/95-scaleft` uses a fixed filename with priority 95 -- any existing 95-scaleft file gets atomically replaced

### Safe Pattern

The safefile package uses atomic writes (temp file + rename), which is correct. The risk is in the content written, not the write mechanism.

---

## FINDING 4: No Systemd Security Hardening (MEDIUM)

**File:** `/etc/systemd/system/sftd.service`

```ini
[Service]
ExecStart=/usr/sbin/sftd
Restart=always
RestartSec=10s
```

The service unit has ZERO security hardening:

| Missing Directive | Impact |
|-------------------|--------|
| `ProtectSystem=strict` | Service can write anywhere on filesystem |
| `ProtectHome=yes` | Service has unrestricted access to /home |
| `NoNewPrivileges=yes` | Spawned processes can gain privileges |
| `PrivateDevices=yes` | Service can access all devices |
| `PrivateTmp=yes` | Shared /tmp namespace enables symlink attacks |
| `CapabilityBoundingSet=` | Service has ALL Linux capabilities |
| `SeccompFilter=` | No syscall filtering |
| `ReadWritePaths=` | No filesystem access restrictions |

### Impact

Any vulnerability in sftd gives unrestricted root access. The service intentionally needs some root capabilities (user management, file ownership), but many could be restricted (network namespacing, device access, kernel module loading).

---

## FINDING 5: Runtime Directory Owned by Unprivileged sftd User (LOW-MEDIUM)

**Path:** `/run/sftd/` -- `drwxr-xr-x sftd:sftd`
**Service:** Runs as root (UID 0)

### Vulnerability

The runtime directory `/run/sftd/` is owned by the unprivileged `sftd` user (UID 963), but the service process runs as root. When the service creates Unix sockets or temporary files in this directory:

1. The `sftd` user (or any process that can impersonate it) can:
   - Pre-create files/symlinks in `/run/sftd/` before the service
   - Replace files in `/run/sftd/` between creation and use
   - Create hardlinks to sensitive files

2. The `broker.sock` Unix socket (used for broker communication) would be created in this directory with the directory owner's write access

### Note

This is only exploitable if an attacker can escalate to the `sftd` user (UID 963), which normally has `/sbin/nologin` as shell and no password.

---

## FINDING 6: Hooks System Executes Files from Configurable Directory (RESEARCH LEAD)

**Functions:** `hooks.Scan` (hooks.go), `hooks.Execute`, `hooks.runCommand`
**Source:** `osedit/hooks/hooks.go`

The hooks system:
1. `Scan()` -- uses `filepath.Glob` to find hook scripts in a configured directory
2. `Execute()` -- iterates and runs each hook
3. `runCommand()` -- calls `os/exec.CommandContext` with a timeout

Hook scripts are sorted numerically (`numericFileSorter`) and executed in order. The hook directory path and the hook execution context need investigation -- if the hook directory is writable by managed users, this is direct root code execution.

---

## FINDING 7: Password Change Uses chpasswd via Stdin (RESEARCH LEAD)

**Function:** `ChangeUserPassword` (server_account_state_linux.go)
**Calls:** `exec.CommandContext` at lines 66 and 77

The password change flow:
1. First exec call (line 66): likely generates a password hash
2. `fmt.Sprintf` (line 78): formats the password input
3. Second exec call (line 77): passes formatted password to `chpasswd` via CombinedOutput

The password arrives from the ScaleFT platform API. If the password contains newlines or other special characters, it could inject additional `username:password` pairs into chpasswd's stdin input (chpasswd processes one line per user).

---

## FINDING 8: UserHomedirOwnerLinux Calls chown via exec (RESEARCH LEAD)

**Function:** `UserHomedirOwnerLinux.Execute` (user_homedir_owner.go:58-61)
**Pattern:** `fmt.Sprintf` -> argument construction -> `exec.CommandContext` with `chown`

This function:
1. Uses `fmt.Sprintf` with 2 arguments (format `%s:%s` likely = `uid:gid`)
2. Builds a slice of arguments: the chown target and the `uid:gid` string
3. Calls `exec.CommandContext` to run `chown`

This is separate from the `Fchownat` call in `createHomeDirectory` -- it's a second chown path. If it uses `-R` (recursive), a symlink race could chown entire directory trees.

---

## Attack Chains

### Chain 1: Symlink Race in Home Directory Management (LPE)
**Prereq:** sftd must be enrolled and managing users

1. Create a symlink at the expected home directory path -> `/etc` or `/root`
2. When sftd runs `createHomeDirectory.Execute`, it calls:
   - `os.MkdirAll` (may fail on symlink, or succeed if target exists)
   - `Fchownat(AT_FDCWD, path, uid, gid, 0)` -- follows symlink, chowns target
3. Target directory is now owned by the managed user

### Chain 2: Enrollment Token Injection (Theoretical)
**Prereq:** Write access to `/var/lib/sftd/enrollment.token`

1. Directory is `0700 root:root` -- cannot directly write
2. BUT if combined with Chain 1 (chown /var/lib/sftd to a managed user)
3. Write a crafted enrollment token pointing to attacker-controlled server
4. sftd enrolls with attacker server, which then sends malicious user management instructions
5. Those instructions trigger useradd/usermod/chown with attacker-controlled parameters

### Chain 3: Hook Script Injection (If hook dir is writable)
1. Determine hook directory location
2. If writable, place a malicious script
3. sftd executes it as root during user management operations

---

## Service Details

| Property | Value |
|----------|-------|
| Binary | /usr/sbin/sftd |
| Version | 1.100.2 |
| Go Version | 1.25.0 |
| Identity | root (via systemd, no User= directive) |
| Data Dir | /var/lib/sftd/ (0700 root:root) |
| Runtime Dir | /run/sftd/ (0755 sftd:sftd) |
| Log Dir | /var/log/sftd/ |
| Config | /etc/sft/sftd.yaml (not yet created) |
| Lock File | /var/lib/sftd/sftd.lock |
| Database | /var/lib/sftd/internal.db (SQLite) |
| SSH CA Key | /var/lib/sftd/ssh_ca.pub |
| Enrollment | /var/lib/sftd/enrollment.token |
| Sudoers | /etc/sudoers.d/95-scaleft |
| Systemd | /etc/systemd/system/sftd.service |
| sftd User | uid=963(sftd), /sbin/nologin |

---

## Key Packages Analyzed

| Package | Purpose | Attack Surface |
|---------|---------|----------------|
| `osedit/actions` | User/group CRUD, home dirs, sudo | Shell-out to useradd/userdel as root |
| `osedit/hooks` | Post-operation hook execution | Arbitrary command execution as root |
| `osedit/sas` | Server account state, passwords | Password injection via chpasswd |
| `safefile` | Atomic file writes | Temp-then-rename (mostly safe) |
| `xsys/sandbox` | Privilege dropping | Drops to sftd user for some operations |
| `localft/peerchild` | Child process execution | exec.CommandContext as configurable user |
| `localft/enroll` | Enrollment protocol | Token-based enrollment, API trust |
| `localft/broker` | SSH broker service | Unix socket IPC |
| `clienttrustforwarding` | Trust token forwarding | gRPC over Unix socket |
| `keyring` | Secret storage (NaCl secretbox) | Key material in memory |

---

## Next Steps

1. **Enroll sftd** -- Create ScaleFT team, get enrollment token, observe runtime behavior
2. **Test symlink race end-to-end** -- Create a managed user, race the home directory creation
3. **Map hook directory** -- Determine where hooks are loaded from, check permissions
4. **Test password injection** -- Can newlines in password field inject additional chpasswd entries?
5. **Analyze internal.db** -- SQLite database may contain interesting state/credentials
6. **Review enrollment protocol** -- Is the enrollment token a simple bearer token? Can it be forged?
7. **Check broker.sock permissions** -- When enrolled, what permissions does the Unix socket get?
8. **Analyze the client (sft)** -- The SSH client replacement may have additional attack surface
