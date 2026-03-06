# Linux + Android Attack Surface for Fedora Claude

**Date:** 2026-03-05
**Purpose:** Give Fedora Claude a target to work on

---

## Option 1: Advanced Server Access (ASA / ScaleFT) -- Linux Native, $35K P1

### What It Is

Okta's SSH replacement. A root-level daemon (`sftd`) runs on Linux servers, handles certificate-based SSH auth, manages local user accounts, and audits logins. The client (`sft`) replaces the SSH command. Both are native Linux binaries -- perfect for RE on Fedora.

**Being sunset May 2026 but still in scope RIGHT NOW.**

### Account Setup

1. Go to `https://app.scaleft.com/p/signup`
2. Team name: use `bugcrowd-lucidduck` (or similar bugcrowd-username pattern)
3. Email: use `@bugcrowdninja.com` email
4. No credit card needed

### Install on Fedora

```bash
# Import GPG key
sudo rpm --import https://dist.scaleft.com/GPG-KEY-OktaPAM-2023

# Client (sft -- SSH replacement CLI, user-level)
sudo dnf install scaleft-client-tools

# Server agent (sftd -- root daemon, the main RE target)
sudo dnf install scaleft-server-tools
```

### RE Targets

| Binary | Runs As | Purpose | Notes |
|--------|---------|---------|-------|
| `sft` | User | SSH client replacement | Handles auth flows, certificate management |
| `sftd` | **root** | Server agent daemon | Creates local users, manages certs, audits logins |

### What to Look For

Same patterns that produced results on Windows Okta Verify:
- **IPC mechanisms** -- how do sft and sftd communicate? Unix sockets? Named pipes? D-Bus?
- **File operations as root** -- does sftd write to predictable paths? Symlink/junction attacks?
- **Certificate handling** -- key storage, validation, can certs be forged or replayed?
- **Local user management** -- sftd creates/removes local Linux accounts. Race conditions? Privilege issues?
- **Auth protocol** -- how does the challenge-response work? Can it be relayed?
- **Update mechanism** -- does it auto-update? As root? TOCTOU?
- **Config file permissions** -- who can read/write sftd config?
- **Enrollment token** -- how is the server enrolled? Can enrollment be hijacked?

### Docs

- Install client: https://help.okta.com/asa/en-us/content/topics/adv_server_access/docs/sft-redhat.htm
- Install agent: https://help.okta.com/asa/en-us/Content/Topics/Adv_Server_Access/docs/sftd-redhat.htm
- Getting started: https://help.okta.com/asa/en-us/content/topics/adv_server_access/docs/setup/getting-started.htm
- Client usage: https://help.okta.com/asa/en-us/content/topics/adv_server_access/docs/client.htm

---

## Option 2: Okta Verify Android -- $75K P1

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

## Option 3: Okta Privileged Access (PAM) Server Agent -- Linux Native, $35K P1

### What It Is

The successor to ASA. PAM server agents also run on Linux. Uses the existing preview orgs (bugcrowd-pam-4593/4594). This is the future-proof option since ASA is being sunset.

### Setup

- Access via Admin Dashboard > Applications > Browse App Catalog > "Okta Privileged Access"
- Team name: bugcrowd-pam-4593 (matches the org)
- Server agent install docs: https://help.okta.com/oie/en-us/content/topics/privileged-access/tool-setup/pam-sftd-redhat.htm

---

## Recommendation

**Start with ASA (Option 1).** It's the most straightforward -- standalone signup, no dependencies on the preview org config, native Linux binaries running as root. The attack surface is clear: reverse `sftd`, find the same class of bugs we found in the Windows auto-update service (IPC injection, file operation races, auth protocol flaws).

If ASA feels too small or dead-end, pivot to the Android Okta Verify app (Option 2) which has the $75K ceiling and is the same product family where we already have 13+ findings on Windows.
