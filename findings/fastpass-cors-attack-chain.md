# FastPass CORS Reflection -- Attack Chain Research

**Date:** 2026-03-06
**Status:** CORS reflection confirmed, full chain in progress

---

## What's Confirmed

### 1. CORS Origin Reflection (CONFIRMED)
The loopback server at `http://127.0.0.1:8769` reflects ANY Origin into
`Access-Control-Allow-Origin` without validation:

```
OPTIONS /challenge HTTP/1.1
Origin: https://evil.com
-> Access-Control-Allow-Origin: https://evil.com

POST /challenge HTTP/1.1
Origin: https://evil.com
-> HTTP 401 (invalid challenge)
-> Access-Control-Allow-Origin: https://evil.com
```

This means any website's JavaScript can:
- GET /probe to detect Okta Verify (confirmed)
- POST /challenge with JSON body (confirmed -- CORS allows content-type header)
- READ the response (CORS allows the evil origin)

### 2. FastPass Enrollment Active (CONFIRMED)
- Device: SKINNYD (Win11 host)
- Factor type: signed_nonce (FastPass)
- Key type: RSA (RS256)
- Status: ACTIVE
- Public key is registered with Okta backend

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
- User assigned and active

## What's Needed to Complete the Chain

### The Attack Flow
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

### Missing Piece: Getting a Challenge JWT
The challenge JWT comes from Okta's Identity Engine (IDX) pipeline when FastPass
is selected as the authenticator. The flow is:

1. POST /idp/idx/identify (with username)
2. Response includes FastPass/signed_nonce as a remediation option
3. POST /idp/idx/challenge (selecting signed_nonce)
4. Response includes the challengeRequest JWT

The interaction_code grant type is not available on this preview org, so we
need to use the standard IDX API flow to get the challenge.

### Phishing Resistance Question
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

1. Use the IDX API to initiate a FastPass challenge flow
2. Extract the challengeRequest JWT
3. Relay it to 127.0.0.1:8769/challenge with Origin: https://evil.com
4. Check if the signed response includes the evil.com origin
5. Submit the signed response back to Okta and see if it's accepted or rejected
6. If rejected due to origin mismatch -- document as CORS weakness + info disclosure
7. If accepted -- this is a P1 remote authentication bypass ($75K)
