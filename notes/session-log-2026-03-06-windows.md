# Windows Claude Session Log - 2026-03-06

## Session Summary

This session continued from a previous crashed session. Primary work: testing the junction-based LPE on a Win10 Hyper-V VM, then pivoting to FastPass CORS attack chain research.

## Credentials & Access

### Okta Org 1 (Primary)
- **URL:** https://bugcrowd-pam-4593.oktapreview.com
- **API Token:** 00B_hG_7HZJaM145T6LL1QGBkLrDXDJoaqPLk4yQ53 (SSWS, Super Admin)
- **User:** bugbounty.okta@gmail.com
- **Password:** 6KkBNqBWrjvS
- **Authenticators:** Password + Okta Verify (FastPass) only

### Okta Org 2 (Dev)
- **URL:** https://dev-44786964.okta.com
- **Note:** API token for this org may be expired or was never created. Do NOT confuse with org 1.

### OIDC Test App (on Org 1)
- **App ID / Client ID:** 0oavvphi56SbYPzXk1d7
- **Name:** FastPass Test App
- **Type:** SPA (browser), PKCE, auth code
- **Redirect URI:** http://localhost:8080/callback
- **Grant Types:** authorization_code only (interaction_code NOT available)
- **Consent:** TRUSTED (no consent screen)

### Windows 10 VM (Hyper-V)
- **VM Name:** lucid-duck-win10-vm
- **User:** lucidduck / Password1
- **Admin:** lucidduck is local admin
- **Okta Verify:** Installed and enrolled with FastPass
- **PowerShell Direct:** Use hardcoded creds, NOT Get-Credential (it pops a GUI dialog)

## Key Findings

### 1. Junction LPE -- BLOCKED on Patched Systems
- The junction-based arbitrary directory deletion as SYSTEM works from admin context
- Previous session confirmed deletion in 0.5 seconds on Win11
- BUT: Win10 build 19045 with Feb 2026 updates uses C:\WINDOWS\SystemTemp, not C:\Windows\Temp
- KB5017308 (Aug 2022) introduced SystemTemp. Standard users cannot create junctions there.
- **Verdict:** Admin-to-SYSTEM only on modern systems. Standard-user-to-SYSTEM only on pre-2022 unpatched.

### 2. FastPass CORS Reflection -- CONFIRMED
Okta Verify's loopback server (127.0.0.1:8769) reflects ANY origin in CORS headers:

```
GET /probe -> 200, ACAO: https://evil.com
OPTIONS /challenge -> 204, ACAO: https://evil.com, Allow-Headers: content-type
POST /challenge (dummy) -> 400, ACAO: https://evil.com
GET /challenge -> 200, ACAO: https://evil.com
```

This means any website's JavaScript can:
- Detect Okta Verify presence (privacy/info disclosure)
- POST challenge requests with arbitrary JSON
- READ responses cross-origin

### 3. Legacy authn API Bypasses MFA
The `/api/v1/authn` endpoint returns `SUCCESS` with just username+password, even though the org has MFA configured. This is the classic vs OIE authentication pipeline difference -- could be a finding on its own.

### 4. IDX Pipeline Challenges
The OIE IDX pipeline (used by the sign-in widget) requires:
1. identify (username)
2. Password challenge
3. FastPass challenge

BUT the identify step returns error: "you'll need an additional security method" because the authentication policy requires 2 factors and the user only has password + OV FastPass. The IDX flow won't proceed past identify because FastPass is the ONLY second factor and it's device-bound.

The sign-in widget handles this differently -- it probes the loopback server first and sends a `launch-authenticator` or `challenge-authenticator` remediation. We need to figure out how the widget gets the challenge JWT.

## Dead Ends

### IDX API Attempts to Get Challenge JWT
1. **identify -> returns error** about needing additional security method
2. **identify with credentials** -> "Cannot use credentials with this request" (identify step doesn't accept password)
3. **Direct /idp/idx/challenge** -> "Invalid operation: Expected IDENTIFY, Attempted AUTHENTICATE"
4. **interact endpoint** -> "unauthorized_client" (needs interaction_code grant type, not available)
5. **identify on dev-44786964** -> wrong org entirely (OIDC app is on bugcrowd-pam-4593)

### Authenticators Available (Admin API)
| ID | Name | Key | Status |
|---|---|---|---|
| autsk8d1tfDZxHGWE1d7 | Email | okta_email | ACTIVE |
| autsk8d1tjzmPJtSn1d7 | Okta Verify | okta_verify | ACTIVE |
| autsk8d1tegD5stJx1d7 | Password | okta_password | ACTIVE |
| autsk8d1tgWpaDwAP1d7 | Phone | phone_number | INACTIVE |
| autsk8fl31umUU9g71d7 | Security Key/Biometric | webauthn | INACTIVE |
| autsk8d1ticZsxAqF1d7 | Security Question | security_question | INACTIVE |

### Okta Verify 1-Hour Cache
The auto-update service caches results for 1 hour. If you test the PoC and it times out, restart the service before retrying.

## Next Steps / Untried Approaches

### For FastPass Challenge JWT:
1. **Capture real widget traffic** -- Use browser devtools or mitmproxy to watch what the Okta sign-in widget actually sends when you log in with FastPass. The widget must get the challenge JWT somehow.
2. **Enable interaction_code grant** -- May need to modify app settings via admin API to add this grant type.
3. **Use the classic authn API** -- Since /api/v1/authn returns SUCCESS, maybe get a sessionToken and use it to get the challenge through a different path.
4. **Activate email or phone authenticator** -- Add a second factor type so the IDX flow can proceed past identify, then select FastPass as the second step.

### For Submission:
1. CORS reflection is confirmed and submittable as-is (info disclosure + detection)
2. If we can get a challenge JWT and complete the relay, it's a full auth bypass (P1, $75K)
3. The legacy authn API not enforcing MFA might be a separate finding
4. Named pipe injection + admin-to-SYSTEM is still valid

## Interesting Observations

- The loopback server uses `Microsoft-HTTPAPI/2.0` (Windows HTTP Server API), not a custom HTTP implementation
- CORS preflight returns `Access-Control-Allow-Methods: POST, GET, OPTIONS` -- all methods allowed
- The error for bad JWT is "Unexpected token type when deserializing payload" -- it tries to parse the JWT
- The org has 13 apps total, mostly built-in Okta admin/dashboard apps
- Email authenticator is ACTIVE but no email factor enrolled for the user -- could enroll one to unblock IDX flow
