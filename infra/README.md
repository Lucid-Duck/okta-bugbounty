# VPS Infrastructure - Okta MitM Proxy Setup

## Status: PARKED (not submittable as-is)

The CORS reflection on the FastPass loopback server is real but doesn't lead to account takeover.
The signed response goes directly from OV to the Okta backend (empty 200 OK to the browser).
No token exfiltration path exists via JavaScript/CORS. This infra is preserved in case a
future finding needs it.

## VPS: NJ (66.135.27.142)

SSH: `ssh -i ~/.ssh/id_ed25519 root@66.135.27.142`

### What's deployed

Two MitM reverse proxies targeting `bugcrowd-pam-4593.oktapreview.com`:

1. **evilginx2** - Phishing proxy with credential/cookie capture
   - Phishlet: `evilginx2/okta.yaml`
   - Lure URL: `https://66.135.27.142.sslip.io/cqXEQJJg`
   - Captures: sid, idx, DT, JSESSIONID cookies + username/password from JSON POST
   - Config: `evilginx2/config.json`
   - Start: `evilginx2/setup-okta.sh`

2. **Modlishka** - Transparent reverse proxy (patched for Okta)
   - Config: `modlishka/okta.json`
   - Domain: `66.135.27.142.sslip.io` with real Let's Encrypt cert
   - TLS: `modlishka/cert.pem` + `modlishka/key.pem`
   - Custom source patch: `modlishka/patch-modlishka.py`
   - Control panel: `https://66.135.27.142.sslip.io/SayHello2Modlishka`
   - Start: `cd /opt/Modlishka && screen -dmS modlishka bash -c './modlishka -config okta.json > /tmp/modlishka-live.log 2>&1'`

### Modlishka patch details

`patch-modlishka.py` modifies `/opt/Modlishka/core/proxy.go` to:
- Strip SRI `integrity` and `crossorigin` attributes (so rewritten CDN assets load)
- Replace Okta's JS hex-escaped domain (`bugcrowd\x2Dpam\x2D4593.oktapreview.com`) with proxy domain

Run `python3 patch-modlishka.py` then `go build -o modlishka` to rebuild.

### sslip.io

Both tools use `66.135.27.142.sslip.io` which auto-resolves to `66.135.27.142`.
No custom DNS needed. Let's Encrypt issues certs for it.

## IDX Scripts (PowerShell)

Local scripts used to walk the Okta IDX authentication pipeline step by step:

- `idx-scripts/okta-fastpass-11-proper-idx.ps1` - Full IDX flow: authorize -> stateToken -> introspect -> identify -> password -> select OV -> challenge JWT extraction
- `idx-scripts/okta-fp11-check-policy.ps1` - Dump authentication policies and rules
- `idx-scripts/okta-fp11-check-enrollments.ps1` - Check user authenticator enrollments
- `idx-scripts/okta-fp11-enroll-email.ps1` - Attempt email factor enrollment (classic API)
- `idx-scripts/okta-fp11-enroll-email2.ps1` - Email enrollment variant with file-based JSON body

## What was learned (dead ends)

1. **CORS reflection on loopback**: OV at 127.0.0.1:8769 reflects any Origin in ACAO. But the /challenge endpoint returns empty 200 OK - the signed token goes directly to Okta backend, never to the JS caller. No exfiltration path.

2. **Origin check in signed response**: OV includes `originHeader` in the signed nonce response. Okta backend validates it (`OktaServerError.OriginMismatch`). Even if you could relay the challenge, the origin wouldn't match.

3. **Legacy authn bypass**: `/api/v1/authn` returns SUCCESS with just password (no MFA), but the session can't get OAuth authorization codes (access_denied). Okta OIE enforces MFA at the OAuth layer.

4. **MitM proxy approach**: evilginx2/Modlishka can transparently proxy the login page and capture cookies/creds, but this is standard phishing - not a vulnerability in Okta itself. The FastPass loopback flow specifically checks if OV is on the same machine, so a remote proxy can't trigger it.

5. **Email factor enrollment**: Classic Factors API enrollment succeeds but OIE doesn't recognize classic enrollments for IDX authenticator selection.
