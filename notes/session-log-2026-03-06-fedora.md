# Session Log -- Fedora Claude -- 2026-03-06

## Session Summary

Pivoted from Optus to Okta bug bounty. Performed deep RE on the ScaleFT/ASA server daemon (sftd) binary, attempted PAM setup to prove findings end-to-end, hit provisioning wall.

---

## Work Completed

### 1. Optus ATO Timeline
- Scanned 39+ JSONL logs and ~/Documents text files
- Built complete timeline of the support@optusnet.com.au ATO and password change
- Published to `bugbounty-master-index/optus-009-ato-timeline.md`

### 2. Auth0 Scope Capture
- Captured full Auth0 by Okta Bugcrowd program scope
- 3 tenants, $50K P1 ceiling, Tier 1/2/SDK targets
- Saved to `auth0/SCOPE.md`

### 3. sftd Reverse Engineering (MAIN WORK)
- Installed sftd v1.100.2 and sft v1.100.2 on Fedora from ScaleFT RPMs
  - RPMs downloaded directly from `https://dist.scaleft.com/repos/rpm/stable/rhel/9/x86_64/1.100.2/`
  - dnf repo XML was broken, had to use direct download
- Identified binary as Go 1.25.0, NOT STRIPPED, with full debug_info
- Mapped complete attack surface using `go tool objdump` + DWARF analysis
- **8 findings documented** in `findings/sftd-re-security-findings.md`
- **Technical notes** in `notes/sftd-binary-analysis-notes.md`

### 4. PAM Setup Attempt (DEAD END)
- ScaleFT standalone signup is dead (redirects to "page not found")
- Created PAM app in Org 1 via API (app ID: 0oavvpaf5nqmwxJlY1d7)
- PAM subdomain is live but team backend not provisioned
- Provisioning is permanently disabled on preview orgs
- Documented in `notes/pam-setup-dead-end.md`

### 5. Okta API Verification
- Confirmed SSWS token works (initially missed it in CLAUDE.md, lesson learned)
- Verified org enumeration: 1 user, 2 groups, 11 OIDC apps, default auth server
- All consent IMPLICIT, device_sso scope available

---

## Key Findings

### sftd Fchownat Symlink Following (HIGH)
- `createHomeDirectory.Execute` and `ensureDirectory.do` both call `Fchownat` with `flags=0`
- Confirmed via disassembly: `XORL R8, R8` (flags=0) then `CALL syscall.Fchownat`
- Should use `AT_SYMLINK_NOFOLLOW` (0x100)
- Cannot prove runtime exploit without enrolled sftd

### sftd Shell-Out to useradd/userdel (MEDIUM-HIGH)
- All user/group management operations use `os/exec.CommandContext`
- Arguments come from ScaleFT API responses
- No shell metacharacter injection (Go exec uses execve), but arg values are platform-controlled

### sftd Zero Systemd Hardening (MEDIUM)
- No ProtectSystem, NoNewPrivileges, CapabilityBoundingSet, etc.
- Any vuln = unrestricted root

---

## Dead Ends

1. **VGW VM** -- Boots kernel but halts at "Starting device manager" without license. Dead without VGW license.
2. **ScaleFT standalone signup** -- Redirects to "page not found". ASA is sunset, folded into PAM.
3. **PAM provisioning** -- Disabled on preview orgs. Cannot be enabled via API. Cannot enroll sftd.

---

## Open Attack Surfaces (Ready to Test)

| Target | Access | Ceiling | Status |
|--------|--------|---------|--------|
| OIE API | SSWS Super Admin token | $75,000 | Ready -- full API access |
| OIE Web | Admin console access | $75,000 | Ready |
| Workflows | Via admin console | $35,000 | Ready |
| AtSpoke | Via admin console | $25,000 | Ready |
| Auth0 Tenant 1 | bugcrowd-1987 creds | $50,000 | Ready |
| Auth0 Tenant 2 | bugcrowd-1986 creds | $50,000 | Ready |
| Auth0 Tenant 3 | bugcrowd-1985 creds | $50,000 | Ready |
| Auth0 FGA | dashboard.fga.dev | $50,000 | Ready |
| Okta Verify Android | APK + preview orgs | $75,000 | Needs setup |
| Okta Verify Windows | Installed on Win11 | $75,000 | Windows Claude domain |
| sftd/sft | Installed, not enrolled | $35,000 | Blocked (no provisioning) |

---

## Tools Installed on Fedora

- `sftd` v1.100.2 at `/usr/sbin/sftd`
- `sft` v1.100.2 at `/usr/bin/sft`
- Go toolchain (for `go tool objdump`)
- Ghidra 11.3.1 at `/opt/ghidra_11.3.1_PUBLIC/`
- Standard Fedora dev tools (gcc, gdb, strace, etc.)
