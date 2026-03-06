# Linux + Android Attack Surface for Fedora Claude

**Date:** 2026-03-05
**Updated:** 2026-03-06
**Purpose:** Give Fedora Claude a target to work on

---

## Option 1: Advanced Server Access (ASA / ScaleFT) -- COMPLETED RE, BLOCKED ON ENROLLMENT

### Status: RE DONE, runtime PoC BLOCKED

**Findings:** 8 findings documented in `findings/sftd-re-security-findings.md`
**Technical notes:** `notes/sftd-binary-analysis-notes.md`
**Dead end details:** `notes/pam-setup-dead-end.md`

### What Was Done
- Installed sftd v1.100.2 and sft v1.100.2 from direct RPM download
  - dnf repo was broken (XML parsing failure), downloaded from `https://dist.scaleft.com/repos/rpm/stable/rhel/9/x86_64/1.100.2/`
- Complete RE of sftd using `go tool objdump` + DWARF debug info
- Binary is Go 1.25.0, NOT STRIPPED, full symbols + source paths
- Mapped all osedit/actions functions, confirmed shell-out pattern (useradd/userdel via exec.CommandContext)
- **Key finding: Fchownat called with flags=0 (follows symlinks) as root** -- confirmed in disassembly

### What's Blocked
- **ScaleFT standalone signup is DEAD** -- `app.scaleft.com/p/signup` redirects to 404
- **PAM provisioning is DISABLED** on preview orgs -- cannot be enabled via API or UI
- Without enrollment, cannot trigger user management operations to prove symlink race

### Install Notes (for reference)

```bash
# dnf repos are BROKEN. Download RPMs directly:
wget https://dist.scaleft.com/repos/rpm/stable/rhel/9/x86_64/1.100.2/scaleft-server-tools-1.100.2-1.x86_64.rpm
wget https://dist.scaleft.com/repos/rpm/stable/rhel/9/x86_64/1.100.2/scaleft-client-tools-1.100.2-1.x86_64.rpm
sudo rpm -i scaleft-server-tools-1.100.2-1.x86_64.rpm
sudo rpm -i scaleft-client-tools-1.100.2-1.x86_64.rpm
```

---

## Option 2: Okta Verify Android -- $75K P1 -- RECOMMENDED NEXT

### What It Is

The Android version of the same app we've been reversing on Windows. Handles FastPass authentication, push MFA, TOTP. Java/Android. This is the app family where we found the CORS reflection, named pipe LPE, DPAPI weakness, TOCTOU, etc. on Windows.

### Setup

- Download from Google Play Store on an emulator or device
- Enroll with one of the preview orgs:
  - Org 1: https://bugcrowd-pam-4593.oktapreview.com (user: bugbounty.okta@gmail.com)
  - Org 2: https://bugcrowd-pam-4594.oktapreview.com (user: bugbounty.okta@gmail.com)
- Can use Android Studio emulator on Fedora

### What to Look For

- **Loopback server** -- does the Android version have a local HTTP server like Windows (port 8769)?
- **IPC** -- Intents, Content Providers, Broadcast Receivers exposed to other apps
- **Key storage** -- Android Keystore usage, can keys be extracted on rooted device?
- **Certificate pinning** -- can it be bypassed with Frida?
- **Deep links / custom URI scheme** -- `com-okta-authenticator:/` hijacking on Android
- **WebView** -- any WebView usage for OAuth flows? JavaScript injection?
- **Local storage** -- SharedPreferences, SQLite databases, file permissions
- **Push notification handling** -- FCM token handling, can push auth be intercepted/replayed?

---

## Option 3: Okta Privileged Access (PAM) Server Agent -- BLOCKED (same as Option 1)

PAM uses the same sftd binary. Provisioning is disabled on preview orgs. Same dead end as Option 1. See `notes/pam-setup-dead-end.md`.

---

## Option 4: OIE API Testing -- $75K P1 -- READY NOW

No binary RE needed. We have a working Super Admin SSWS token and full API access.

### Focus Areas
- OAuth/OIDC/SAML protocol vulnerabilities
- Expression Language injection in user profile attributes
- Cross-org / multi-tenancy issues
- Privilege escalation (horizontal/vertical)
- Workflow sandbox escape (SSRF via Flo cards)

### What's Already Set Up
- SSWS token verified working
- API enumeration done (see `recon/api-enumeration-org1.md`)
- Test OIDC app created (0oavvphi56SbYPzXk1d7)
- PAM app created (0oavvpaf5nqmwxJlY1d7) -- useful for OIDC testing even if PAM backend is dead

---

## Option 5: Auth0 -- $50K P1 -- READY NOW

Separate Bugcrowd program, 3 tenants with credentials. Higher average payout ($3,808 vs $2,686).

See `auth0/SCOPE.md` for full details.

---

## Recommendation (Updated 2026-03-06)

~~Start with ASA (Option 1).~~ ASA RE is done but enrollment is blocked.

**Best next targets:**
1. **OIE API (Option 4)** -- highest ceiling ($75K), ready now, no setup needed
2. **Auth0 (Option 5)** -- highest avg payout, 3 tenants, FGA is interesting
3. **Okta Verify Android (Option 2)** -- $75K ceiling, same product family as Windows findings, needs emulator setup
