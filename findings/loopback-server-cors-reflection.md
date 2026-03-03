# Okta Verify 6.6.2.0 - Loopback FastPass Server CORS Origin Reflection

## Severity: TBD (depends on FastPass key state)

## Summary

Okta Verify for Windows runs a local HTTP server on `127.0.0.1:8769` (via http.sys)
that handles FastPass authentication challenges. This server **reflects any Origin header
directly into Access-Control-Allow-Origin**, allowing any website on the internet to
send cross-origin requests to the FastPass challenge endpoint.

## Current Status

CORS reflection is confirmed. Challenge JWT parsing is confirmed. Full chain
(cross-origin auth hijack) requires a device with FastPass keys enrolled --
our test device has Okta Verify enrolled but no FastPass keys configured
(cert store empty, challenge returns 500: "key" null). Need to complete
FastPass setup to prove or disprove full chain.

## Technical Details

### Server Configuration

- **URL**: `http://127.0.0.1:8769/` (registered via http.sys)
- **Process**: OktaVerify.exe (user-mode process)
- **Kernel driver**: http.sys (PID 4 - System)
- **Protocol**: Plain HTTP (no TLS on default config)
- **Endpoints**: `/probe` (GET), `/challenge` (GET/POST), both accept OPTIONS

### CORS Vulnerability

The server reflects the `Origin` request header directly into the
`Access-Control-Allow-Origin` response header without any validation:

```
REQUEST:
OPTIONS /challenge HTTP/1.1
Host: 127.0.0.1:8769
Origin: https://evil.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: content-type

RESPONSE:
HTTP/1.1 204 No Content
Access-Control-Allow-Methods: POST, GET, OPTIONS
Access-Control-Allow-Origin: https://evil.com       <-- REFLECTED
Access-Control-Allow-Headers: content-type           <-- JSON allowed
```

This was confirmed with multiple origins:
- `https://evil.com` -> reflected
- `https://bugcrowd-pam-4593.oktapreview.com` -> reflected
- Any origin tested -> reflected

### Challenge Processing

The `/challenge` endpoint accepts POST requests with JSON body:

```json
{"challengeRequest": "<base64-encoded-JWT>"}
```

The server parses the JWT, attempts to find the matching device key, and signs
the challenge response. Our test showed:

- Empty body -> 400: "challengeRequest could not be found"
- Empty string -> 400: "challengeRequest could not be found"
- Non-base64 -> 500: "not a valid Base-64 string"
- Valid base64 JWT -> 500: "Value cannot be null. Parameter name: key"
  (JWT parsed, org lookup attempted, failed because test org has no FastPass keys)
- If a matching key existed, the server would return the signed challenge response

### Security Configuration Defaults (from decompiled code)

From `SecureLoopbackBindingConfiguration.cs`:
- `RequireMutualAuthentication = false` (default)
- `FailOnUnsignedCallerBinaries = false` (default)
- `EnforceExactConnectionMapping = false` (HARDCODED)
- Binary validation cache: 30 seconds (race window)

From `WindowsBindingsManager.cs`:
- `enforceExactConnectionMapping: false` -- hardcoded, cannot change

### Attack Scenario

1. Attacker creates webpage at `https://evil.com/exploit.html`
2. Victim (with Okta Verify + FastPass) visits the page
3. JavaScript:
   a. GET `http://127.0.0.1:8769/probe` -> 200 confirms Okta Verify
   b. Attacker's server initiates Okta auth flow to target org
   c. Server obtains challenge JWT from Okta's authentication API
   d. Webpage POSTs challenge to `http://127.0.0.1:8769/challenge`
   e. Okta Verify signs challenge with device private key
   f. Webpage reads signed response (CORS allows it!)
   g. Signed response relayed to attacker's server
   h. Attacker completes authentication as victim

### Impact

- Remote authentication bypass for Okta FastPass
- Any Okta-protected application accessible to the victim is compromised
- Device trust attestation bypassed via relay
- No user interaction required beyond visiting a webpage
- Works from any website, email link, embedded iframe, etc.

### Affected Component

- Okta Verify for Windows 6.6.2.0
- FastPass loopback server (port 8769)
- Target: Okta Device Access / OIE

### Additional Loopback Security Weaknesses

1. **No TLS on current configuration** - Plain HTTP, no encryption
2. **No caller binary validation** - Any process can connect
3. **No session isolation** - Cross-session requests possible
4. **No CSRF protection** - No tokens, no origin whitelist
5. **Permissive CORS** - All origins reflected, content-type allowed

## Files

- Source: `sdk-core/Okta.Devices.SDK.Bindings/LoopbackChallengeEvent.cs`
- Source: `sdk-core-windows/Okta.Devices.SDK.Windows.Bindings/LoopbackConnectionValidator.cs`
- Source: `sdk-core-windows/Okta.Devices.SDK.Windows.Bindings/SecureLoopbackBindingConfiguration.cs`
- Source: `main-exe/Okta.Authenticator.NativeApp.Bindings/WindowsBindingsManager.cs`
- Ports: 8769, 65111, 65121, 65131, 65141, 65151 (sequential fallback)
- App GUID: 63c081db-1f13-5084-882f-e79e1e5e2da7

## Reproduction

```powershell
# 1. Confirm server is running
(New-Object System.Net.Sockets.TcpClient("127.0.0.1", 8769)).Connected

# 2. Test CORS reflection
$tcp = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 8769)
$stream = $tcp.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$reader = New-Object System.IO.StreamReader($stream)
$writer.Write("OPTIONS /challenge HTTP/1.1`r`nHost: 127.0.0.1:8769`r`nOrigin: https://evil.com`r`nAccess-Control-Request-Method: POST`r`nAccess-Control-Request-Headers: content-type`r`nConnection: close`r`n`r`n")
$writer.Flush()
# Response includes: Access-Control-Allow-Origin: https://evil.com
```
