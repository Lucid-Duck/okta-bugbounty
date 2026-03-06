import requests, json, sys

ORG = "https://bugcrowd-pam-4593.oktapreview.com"
USR = "bugbounty.okta@gmail.com"
PWD = "6KkBNqBWrjvS"

print("[1] /api/v1/authn (primary auth)...", flush=True)
r = requests.post(f"{ORG}/api/v1/authn", json={
    "username": USR,
    "password": PWD
}, headers={"Content-Type": "application/json"}, timeout=15)
d = r.json()
print(f"    Status: {r.status_code}", flush=True)
print(f"    status field: {d.get('status')}", flush=True)
print(f"    stateToken: {str(d.get('stateToken',''))[:60]}", flush=True)

if d.get("status") == "MFA_REQUIRED":
    print("\n    MFA_REQUIRED!", flush=True)
    st = d.get("stateToken")
    factors = d.get("_embedded", {}).get("factors", [])
    for f in factors:
        print(f"    Factor: {f.get('factorType')} provider={f.get('provider')} id={f.get('id')}", flush=True)
        links = f.get("_links", {})
        if "verify" in links:
            print(f"      verify: {links['verify'].get('href')}", flush=True)
    
    # Look for signed_nonce or push or anything Okta Verify related
    for f in factors:
        if f.get("factorType") in ("signed_nonce", "token:software:totp", "push"):
            fid = f["id"]
            vhref = f.get("_links",{}).get("verify",{}).get("href","")
            print(f"\n    Verifying factor {f['factorType']} id={fid}...", flush=True)
            r2 = requests.post(vhref, json={"stateToken": st}, 
                             headers={"Content-Type": "application/json"}, timeout=15)
            d2 = r2.json()
            print(f"    Status: {r2.status_code}", flush=True)
            print(f"    status: {d2.get('status')}", flush=True)
            # Look for challenge
            challenge = d2.get("_embedded", {}).get("challenge", {})
            if challenge:
                print(f"    CHALLENGE: {json.dumps(challenge)[:500]}", flush=True)
            factor_result = d2.get("_embedded", {}).get("factor", {})
            if factor_result:
                profile = factor_result.get("profile", {})
                print(f"    factor profile: {json.dumps(profile)[:300]}", flush=True)
            print(json.dumps(d2, indent=2)[:3000], flush=True)

elif d.get("status") == "SUCCESS":
    print("    Logged in! (no MFA)", flush=True)
else:
    print(json.dumps(d, indent=2)[:2000], flush=True)
