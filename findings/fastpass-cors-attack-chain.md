# FastPass CORS Reflection -- Attack Chain Research

**Date:** 2026-03-06
**Status:** CORS reflection confirmed, challenge JWT acquisition in progress
**Updated:** 2026-03-06 (Windows Claude session -- IDX pipeline research)

---

## What's Confirmed

### 1. CORS Origin Reflection (CONFIRMED)
The loopback server at `http://127.0.0.1:8769` reflects ANY Origin into
`Access-Control-Allow-Origin` without validation:

```
GET /probe HTTP/1.1
Origin: https://evil.com
-> 200 OK
-> Access-Control-Allow-Origin: https://evil.com

OPTIONS /challenge HTTP/1.1
Origin: https://evil.com
-> 204 No Content
-> Access-Control-Allow-Origin: https://evil.com
-> Access-Control-Allow-Methods: POST, GET, OPTIONS
-> Access-Control-Allow-Headers: content-type

POST /challenge HTTP/1.1
Origin: https://evil.com
Content-Type: application/json
{"challengeRequest": "eyJhbGciOiJSUzI1NiJ9.eyJ0ZXN0IjoxfQ.fake"}
-> 400 Bad Request
-> Access-Control-Allow-Origin: https://evil.com
-> Body: {"error":"Unexpected token type  when deserializing payload."}

GET /challenge HTTP/1.1
Origin: https://evil.com
-> 200 OK
-> Access-Control-Allow-Origin: https://evil.com
```

This means any website's JavaScript can:
- GET /probe to detect Okta Verify (confirmed)
- POST /challenge with JSON body (confirmed -- CORS allows content-type header)
- READ the response (CORS allows the evil origin)

Server: `Microsoft-HTTPAPI/2.0` (Windows HTTP Server API)

### 2. FastPass Enrollment Active (CONFIRMED)
- Device: SKINNYD (Win11 host)
- Factor type: signed_nonce (FastPass)
- Key type: RSA (RS256)
- Status: ACTIVE
- Public key is registered with Okta backend
- Also enrolled on Win10 VM (lucid-duck-win10-vm)

### 3. Okta CSP Shows Design Intent
Okta's CSP on the authorize endpoint explicitly allows:
```
connect-src ... http://127.0.0.1:8769 http://localhost:8769 ...
```
This confirms the loopback server is used during normal auth flows.
But the CSP only restricts the Okta sign-in page's connections --
it does NOT prevent evil.com from connecting to 127.0.0.1:8769.

### 4. Test OIDC App Created
- App ID: 0oavvphi56SbYPzXk1d7
- Client ID: 0oavvphi56SbYPzXk1d7
- Type: SPA (browser), PKCE, auth code flow
- Redirect URI: http://localhost:8080/callback
- Grant Types: authorization_code only
- Consent: TRUSTED (no consent screen)
- User assigned and active

### 5. Legacy authn API Does NOT Enforce MFA
```
POST /api/v1/authn
{"username": "bugbounty.okta@gmail.com", "password": "6KkBNqBWrjvS"}
-> 200 OK, status: "SUCCESS"
```
This returns a session token WITHOUT requiring MFA, even though the org
has Okta Verify enrolled. The classic authn pipeline doesn't enforce the
OIE authentication policy. This may be a separate finding.

## IDX Pipeline Research (2026-03-06)

### What Works
- `/oauth2/v1/authorize` returns HTML with `modelDataBag` containing stateToken
- Extract stateToken via: `var modelDataBag = '...'` -> unicode_escape -> JSON parse
- `/idp/idx/introspect` with stateHandle returns `identify` remediation
- Identify form has: identifier (required), rememberMe (optional), stateHandle (required)

### What Doesn't Work (Dead Ends)

| Attempt | Result |
|---|---|
| identify with username only | 400: "need additional security method" |
| identify with credentials | 400: "Cannot use credentials with this request" |
| direct /idp/idx/challenge with okta_verify ID | 400: "Expected: IDENTIFY, Attempted: AUTHENTICATE" |
| /oauth2/v1/interact | 400: "unauthorized_client" (needs interaction_code grant) |
| /oauth2/default/v1/interact | 400: "Invalid client_id" (app not on default auth server) |

### Root Cause
The org's authentication policy requires 2 factors. The user only has:
1. Password (okta_password)
2. Okta Verify FastPass (okta_verify, signed_nonce)

The IDX API interprets this as: "user needs FastPass but FastPass is device-bound,
so they must be on the device OR set up another authenticator." The identify step
fails before we can get to the challenge step.

### How the Real Sign-in Widget Gets the Challenge
The sign-in widget likely:
1. Probes 127.0.0.1:8769/probe first
2. If Okta Verify is detected, uses a special IDX remediation path
3. This path may involve `launch-authenticator` or a client-side initiated challenge

We need to capture real browser traffic during a FastPass login to see the exact flow.

### Potential Unblocking Approaches
1. **Capture browser traffic** during real FastPass sign-in
2. **Enable interaction_code grant** on the OIDC app (admin API)
3. **Enroll email factor** for the user so IDX proceeds past identify
4. **Use sessionToken from authn** to access the challenge through another path
5. **Read Okta Sign-In Widget source** to find the FastPass challenge API calls

## The Attack Flow (Theoretical)
```
1. Victim visits evil.com
2. evil.com JavaScript:
   a. GET http://127.0.0.1:8769/probe -> 200 (detect Okta Verify)
   b. evil.com backend starts OAuth flow with attacker's Okta app
   c. Backend gets challenge JWT from Okta's IDX pipeline
   d. evil.com JavaScript POSTs challenge to http://127.0.0.1:8769/challenge
   e. Okta Verify signs challenge with victim's private key
   f. evil.com JavaScript reads signed response (CORS allows it!)
   g. Response relayed to evil.com backend
   h. Backend submits signed response to Okta to complete auth
```

## Phishing Resistance Question
Okta claims FastPass signs the origin header into the response. If the backend
checks that the origin matches the app's login URL, the attack would fail at
step h. But the CORS reflection still means:
- evil.com can detect if a user has Okta Verify (privacy leak)
- evil.com can trigger signing operations (resource consumption)
- If origin checking has any bypass or is optional, full auth hijack

## API Details

### Loopback Server
- Primary port: 8769
- Fallback ports: 65111, 65121, 65131, 65141, 65151
- Protocol: Plain HTTP (no TLS by default)
- Endpoints: /probe (GET), /challenge (GET/POST)

### Authenticators on Org (Admin API)
| ID | Name | Key | Status |
|---|---|---|---|
| autsk8d1tfDZxHGWE1d7 | Email | okta_email | ACTIVE |
| autsk8d1tjzmPJtSn1d7 | Okta Verify | okta_verify | ACTIVE |
| autsk8d1tegD5stJx1d7 | Password | okta_password | ACTIVE |
| autsk8d1tgWpaDwAP1d7 | Phone | phone_number | INACTIVE |
| autsk8fl31umUU9g71d7 | Security Key/Biometric | webauthn | INACTIVE |
| autsk8d1ticZsxAqF1d7 | Security Question | security_question | INACTIVE |

### Challenge Endpoint Request Format
```json
{"challengeRequest": "<base64-encoded-JWT>"}
```

### Challenge JWT Structure (from decompilation)
The JWT contains:
- iss: Okta org URL
- aud: device identifier
- sub: user identifier
- nonce: one-time value
- iat/exp: timestamps

### Signed Response
Okta Verify signs with the device's private key and includes:
- The original nonce
- Origin header from the HTTP request
- Device context signals (OS, hardware, etc.)
- Process caller information (if binary validation enabled)

## Next Steps

1. **PRIORITY:** Capture real browser traffic during FastPass login to see exact API calls
2. Try enabling interaction_code grant type via admin API
3. Try enrolling email factor to unblock IDX flow
4. Test if signed response includes the requesting origin (evil.com) and if Okta rejects it
5. If origin is checked -- submit as CORS info disclosure + detection bypass
6. If origin is NOT checked or bypassable -- submit as P1 auth bypass ($75K)
7. The legacy authn API not enforcing MFA may be a separate finding
