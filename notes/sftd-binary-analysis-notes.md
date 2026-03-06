# sftd Binary Analysis -- Technical Notes

**Date:** 2026-03-06
**Binary:** /usr/sbin/sftd v1.100.2
**Go Version:** 1.25.0
**Architecture:** amd64, NOT STRIPPED, has debug_info (full symbol names + source paths)
**Module:** github.com/atko-pam/device-tools

---

## RE Approach

Go binaries with debug symbols are best analyzed with `go tool objdump` rather than Ghidra. Ghidra doesn't handle Go calling conventions well. Key techniques used:

1. `go tool objdump -s 'pattern' /usr/sbin/sftd` -- disassemble specific functions
2. `grep 'CALL' | grep -v 'runtime\.'` -- trace non-runtime function calls
3. `strings` + `readelf --debug-dump=info` -- extract types, error messages, struct layouts
4. DWARF debug info for struct field names and offsets

## Key Package Map

### osedit/actions -- User/Group Management (PRIMARY ATTACK SURFACE)

All Linux operations shell out to system binaries via `os/exec.CommandContext`:

```
UserCreateUnix.Execute      -> useradd (user_create_linux.go:46)
deleteUserByUsernameLinux   -> userdel (user_delete_linux.go:17)
GroupCreateUnix.Execute     -> groupadd (group_create_linux.go:16)
GroupDeleteUnix.Execute     -> groupdel (group_delete_linux.go)
changeUserUnixName          -> usermod --login --new-name (user_change_unix_name_linux.go:17)
changeGroupUnixGid          -> groupmod (group_change_unix_gid_linux.go)
changeGroupUnixGroupName    -> groupmod (group_change_unix_group_name_linux.go)
GroupMemberAddUnix.Execute  -> usermod --groups (group_member_add_linux.go)
GroupMemberRemoveUnix.Execute -> usermod (group_member_rm_linux.go)
UserHomedirOwnerLinux.Execute -> chown via exec (user_homedir_owner.go:61)
optionalAttributes.Execute  -> usermod (optional_attributes_linux.go)
```

Arguments come from ScaleFT API responses. Go's exec.Command uses execve (no shell), so no metacharacter injection. But argument values (paths, usernames) are still controllable from the platform.

### osedit/actions -- File Operations

```
createHomeDirectory.Execute -> os.MkdirAll + syscall.Fchownat(AT_FDCWD, path, uid, gid, 0)
ensureDirectory.do          -> os.removeAll + os.MkdirAll + syscall.Fchownat(AT_FDCWD, path, uid, gid, 0)
ensureAuthorizedPrincipals  -> safefile.WriteFile (temp-then-rename, safe)
EnsureFile.Execute          -> safefile.CreateWithContext + Write + CommitIfChangedAndValid (safe)
```

Critical: Both Fchownat calls use flags=0 (follows symlinks).

### osedit/actions -- Path Validation

```
checkPath (ensure_fs.go:9)
  - Calls filepath.Clean on the target path
  - Iterates through an allow list
  - Calls filepath.Clean on each allow list entry
  - Uses runtime.memequal (string comparison) to check if cleaned path matches
  - Error: "ensure: cannot manage path, path is not in allow list" (53 chars)
```

### osedit/sas -- Password Management

```
CreatePasswordHash          -> server_account_state_linux.go
ChangeUserPassword          -> exec.CommandContext x2 (lines 66, 77)
                            -> fmt.Sprintf (line 78) formats password input
                            -> Likely: first call generates hash, second runs chpasswd
```

### osedit/hooks -- Hook Execution

```
Scan    -> filepath.Glob to find hook scripts
Execute -> iterates hooks in numeric order
runCommand -> exec.CommandContext with context.WithTimeout
```

### safefile -- Atomic File Writes (MOSTLY SAFE)

```
CreateWithContext -> makeTempName + create temp file
Commit          -> os.File.Sync + close + os.Stat + os.Rename (atomic)
WriteFile       -> CreateWithContext + Write + Commit
```

Uses temp-then-rename pattern. The authorized_principals and sudoers files use this.

### xsys/sandbox -- Privilege Dropping

```
NewSandbox  -> creates sandbox config
Setup       -> calls setUser
setUser     -> os/user.Lookup + strconv.ParseInt (uid/gid parsing)
```

### localft/peerchild -- Child Process Execution

```
NewWithExe -> configures child process
initCmd    -> exec.CommandContext (peerchild_nondebug.go:11)
Run        -> StdinPipe + StderrPipe + StdoutPipe + Cmd.Run
```

### clienttrustforwarding/server -- gRPC Trust Forwarding

```
RequestTrustForwardToken -> gets forwarding token from ScaleFT
RequestTeamInfo          -> returns team metadata
Ping                     -> health check
Run                      -> starts gRPC server (Unix socket)
SetSocketFile            -> configures socket path
```

### localft/enroll -- Enrollment

```
ExecToken   -> token-based enrollment
Enroll      -> interactive enrollment
EnrollToken -> programmatic enrollment
```

Enrollment token loaded from /var/lib/sftd/enrollment.token

## UserCreateUnix Struct Layout (from DWARF)

```
Offset   Field                    Type
0        userCreate               embedded struct
8        Name                     string
24       Uid                      string
40       Gid                      string
56       Comment                  string
72       HomeDirectory            string
88       Shell                    string
104      Groups                   []string
128      RespectPasswordPolicy    bool
129      CreateHomeDirectory      bool
Total: 136 bytes
```

## Fchownat Disassembly Proof

Both instances confirmed identical:

```asm
; AT_FDCWD = -100 = 0xffffff9c
MOVQ $-0x64, AX        ; dirfd = AT_FDCWD (-100)
XORL R8, R8            ; flags = 0 (NO AT_SYMLINK_NOFOLLOW)
CALL syscall.Fchownat  ; follows symlinks!
```

AT_SYMLINK_NOFOLLOW = 0x100 (256). Secure version would be:
```asm
MOVL $0x100, R8        ; flags = AT_SYMLINK_NOFOLLOW
```

## Interesting Strings Found

| String | Context |
|--------|---------|
| `/etc/sudoers.d/95-scaleft` | Sudo dropin file path |
| `/usr/local/etc/sudoers.d/` | macOS/BSD sudoers path |
| `ALL=(ALL:ALL) NOPASSWD:ALL` | Sudoers content template |
| `disallowed value '%c'` | Username character validation |
| `grant_user_based_sudo` | Sudo grant function |
| `chpasswd failed` | Password change error |
| `chown failed` | Ownership change error |
| `ensure-directory: chown failed` | Directory chown error |
| `ensure-directory: mkdir failed` | Directory creation error |
| `usermod modifying optional user attributes failed` | usermod error |
| `usermod (to change unix name) failed` | username change error |
| `groupmod (to change unix gid) failed` | group gid change error |
| `groupadd failed` | Group creation error |
| `groupdel failed` | Group deletion error |
| `broker.sock` | Broker Unix socket filename |
| `/var/lib/sftd/ssh_ca.pub` | SSH CA public key |
| `AuthorizedPrincipalsFile` | SSH authorized principals |
| `^[-._a-zA-Z][-._a-zA-Z0-9]*$` | Username validation regex |
| `^[a-z]([-a-z0-9]*[a-z0-9])?$` | Team name validation regex |

## Service Configuration

```ini
# /etc/systemd/system/sftd.service
[Unit]
Description=ScaleFT Daemon
After=syslog.target network-online.target

[Service]
ExecStart=/usr/sbin/sftd
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

No security hardening directives whatsoever.

## Filesystem State

```
/var/lib/sftd/           drwx------ root:root     (data directory)
/var/lib/sftd/internal.db  -rw------- root:root   (SQLite, 32KB)
/var/lib/sftd/sftd.lock   -rw------- root:root   (lock file)
/run/sftd/               drwxr-xr-x sftd:sftd    (runtime dir -- NOTE: owned by sftd user!)
/etc/sft/                does not exist yet       (config dir -- created on enrollment)
```

## System User

```
sftd:x:963:963:ScaleFT system service account:/var/lib/sftd:/sbin/nologin
```
