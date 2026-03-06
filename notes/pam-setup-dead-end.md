# PAM Setup -- Dead End (Provisioning Disabled)

**Date:** 2026-03-06
**Researcher:** Lucid_Duck (Fedora Claude)

---

## What We Tried

### 1. ScaleFT Standalone Signup (DEAD)
- `https://app.scaleft.com/p/signup` redirects to "Okta Privileged Access -- page cannot be found"
- ASA has been sunset and folded into PAM
- No standalone team creation possible

### 2. PAM App Creation via API (SUCCESS -- but incomplete)
Created the PAM app in Org 1 via SSWS API:

```bash
POST /api/v1/apps
{
  "name": "okta_privileged_access_sso",
  "label": "Okta Privileged Access",
  "signOnMode": "OPENID_CONNECT",
  "settings": { "app": { "teamName": "bugcrowd-pam-4593" } }
}
```

- **App ID:** `0oavvpaf5nqmwxJlY1d7`
- **Client ID:** `0oavvpaf5nqmwxJlY1d7`
- **Client Secret:** `cVu7A32RB5admpr3VJzbaPIcMZwURMtvbxEK2aq3U5mDz1P7cHFbanod_vsc5q7R`
- **Status:** ACTIVE
- **User assigned:** Yes (00usk8d1s86Dr8Ltk1d7)
- **teamId:** **null** -- the PAM backend team was NOT provisioned

### 3. PAM Subdomain (LIVE but unprovisioned)
- `https://bugcrowd-pam-4593.pam.oktapreview.com` is live, serves the PAM dashboard HTML
- API at `/v1/teams` returns 404 with SSWS auth (accepted but no teams exist)
- POST to `/v1/teams` requires Bearer token (401 with SSWS)
- `/v1/internal/teamname-validate` returns: `"Infra APIs are not enabled"`

### 4. Provisioning Enablement via API (BLOCKED)
- PUT `/api/v1/apps/{id}/features/USER_PROVISIONING` returns: `"Provisioning is not supported."`
- The admin console shows "Provisioning and API integration are disabled"
- This is a hard restriction on the preview org -- not something we can toggle

### 5. sft Client Enrollment (BLOCKED)
```bash
sft enroll --url "https://bugcrowd-pam-4593.pam.oktapreview.com" --team "bugcrowd-pam-4593"
# error: You are not authorized to perform this operation
```

### 6. OAuth Bearer Token (BLOCKED)
- PAM app only supports `authorization_code` and `refresh_token` grant types
- `client_credentials` grant explicitly rejected
- Can't add it because the app is a first-party Okta app with locked-down configuration

## Why This Matters

Without PAM provisioning:
- Cannot create a server project
- Cannot generate an enrollment token
- Cannot enroll sftd
- Cannot trigger user management operations (useradd, home directory creation, etc.)
- Cannot prove the Fchownat symlink race end-to-end

## The sftd Findings Are Still Valid

The RE findings in `findings/sftd-re-security-findings.md` are code-level, confirmed via disassembly. But Okta scope says "Theoretical issues without complete PoC" are rejected. Without an enrolled sftd, we have:
- Disassembly proof of Fchownat(AT_FDCWD, path, uid, gid, 0) -- flags=0 follows symlinks
- Confirmed service runs as root with zero systemd hardening
- Confirmed shell-out to useradd/userdel/groupmod as root

Whether Bugcrowd accepts disassembly-only proof without runtime PoC is uncertain.

## PAM API Reference (for future use if provisioning gets enabled)

| Endpoint | Method | Auth | Status |
|----------|--------|------|--------|
| `/v1/teams` | GET | SSWS/Bearer | 404 (no teams) |
| `/v1/teams` | POST | Bearer only | 401 with SSWS |
| `/v1/teams/{name}/projects` | GET | Bearer only | 401 with SSWS |
| `/v1/internal/teamname-validate` | POST | Bearer | "Infra APIs not enabled" |
| App link | GET | Session | 404 |

## Credential Reference

| Item | Value |
|------|-------|
| PAM App ID | 0oavvpaf5nqmwxJlY1d7 |
| Client Secret | cVu7A32RB5admpr3VJzbaPIcMZwURMtvbxEK2aq3U5mDz1P7cHFbanod_vsc5q7R |
| PAM Dashboard | https://bugcrowd-pam-4593.pam.oktapreview.com |
| sftd binary | /usr/sbin/sftd v1.100.2 (Go 1.25.0, unstripped) |
| sft binary | /usr/bin/sft v1.100.2 |
