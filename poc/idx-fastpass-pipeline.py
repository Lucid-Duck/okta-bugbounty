import requests, re, json, hashlib, base64, os, sys
print("ALIVE", flush=True)

ORG = "https://bugcrowd-pam-4593.oktapreview.com"
CID = "0oavvphi56SbYPzXk1d7"
RED = "http://localhost:8080/callback"
USR = "bugbounty.okta@gmail.com"
PWD = "6KkBNqBWrjvS"
CT = "application/ion+json; okta-version=1.0.0"
H = {"Content-Type": CT, "Accept": CT}
s = requests.Session()
cv = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
cc = base64.urlsafe_b64encode(hashlib.sha256(cv.encode()).digest()).rstrip(b"=").decode()

print("[1] authorize...", flush=True)
r = s.get(f"{ORG}/oauth2/v1/authorize", params={"client_id":CID,"response_type":"code","scope":"openid profile","redirect_uri":RED,"state":"t","code_challenge":cc,"code_challenge_method":"S256"}, allow_redirects=False, timeout=15)
m = re.search(r"var modelDataBag = '([^']+)'", r.text)
st = json.loads(m.group(1).encode().decode("unicode_escape"))["stateToken"]
print(f"    OK len={len(st)}", flush=True)

print("[2] identify...", flush=True)
r2 = s.post(f"{ORG}/idp/idx/identify", json={"stateHandle":st,"identifier":USR}, headers=H, timeout=15)
d2 = r2.json()
if d2.get("stateHandle"): st=d2["stateHandle"]
rems = d2.get("remediation",{}).get("value",[])
for rm in rems: print(f"    rem: {rm.get('name')}", flush=True)

# find password auth
pw_id=pw_href=None
for rm in rems:
    if rm.get("name") in ("select-authenticator-authenticate",):
        pw_href=rm.get("href")
        for f in rm.get("value",[]):
            if isinstance(f,dict) and f.get("name")=="authenticator":
                for o in f.get("options",[]):
                    v=o.get("value",{})
                    if isinstance(v,dict):
                        fm=v.get("form",{})
                        for fv in fm.get("value",[]):
                            if isinstance(fv,dict) and fv.get("name")=="methodType" and fv.get("value")=="password":
                                for fv2 in fm.get("value",[]):
                                    if isinstance(fv2,dict) and fv2.get("name")=="id": pw_id=fv2.get("value")
                        lbl=o.get("label","?")
                        print(f"      {lbl}: pw_id={pw_id}", flush=True)

if not pw_id:
    print("NO PASSWORD AUTH", flush=True)
    print(json.dumps(d2,indent=2)[:2000], flush=True)
    sys.exit(1)

print(f"[3] select password id={pw_id}...", flush=True)
r3 = s.post(pw_href, json={"stateHandle":st,"authenticator":{"id":pw_id,"methodType":"password"}}, headers=H, timeout=15)
d3=r3.json()
if d3.get("stateHandle"): st=d3["stateHandle"]
rems3=d3.get("remediation",{}).get("value",[])
for rm in rems3: print(f"    rem: {rm.get('name')}", flush=True)

ch_href=None
for rm in rems3:
    if rm.get("name")=="challenge-authenticator": ch_href=rm.get("href")

print(f"[4] answer password...", flush=True)
r4=s.post(ch_href, json={"stateHandle":st,"credentials":{"passcode":PWD}}, headers=H, timeout=15)
d4=r4.json()
if d4.get("stateHandle"): st=d4["stateHandle"]
print(f"    status={r4.status_code}", flush=True)
if "messages" in d4:
    for msg in d4["messages"].get("value",[]): print(f"    MSG: {msg.get('message')}", flush=True)
if "successWithInteractionCode" in d4:
    print("AUTH COMPLETE no 2FA", flush=True)
    sys.exit(0)

rems4=d4.get("remediation",{}).get("value",[])
for rm in rems4: print(f"    rem: {rm.get('name')}", flush=True)

# find signed_nonce
sn_id=sn_href=None
for rm in rems4:
    if rm.get("name") in ("select-authenticator-authenticate","challenge-authenticator"):
        sn_href=rm.get("href")
        for f in rm.get("value",[]):
            if isinstance(f,dict) and f.get("name")=="authenticator":
                for o in f.get("options",[]):
                    v=o.get("value",{})
                    if isinstance(v,dict):
                        fm=v.get("form",{})
                        for fv in fm.get("value",[]):
                            if isinstance(fv,dict) and fv.get("name")=="methodType":
                                mt=fv.get("value")
                                mtopts=[x.get("value") for x in fv.get("options",[])]
                                if mt=="signed_nonce" or "signed_nonce" in mtopts:
                                    for fv2 in fm.get("value",[]):
                                        if isinstance(fv2,dict) and fv2.get("name")=="id": sn_id=fv2.get("value")
                        lbl=o.get("label","?")
                        print(f"      {lbl}: sn_id={sn_id}", flush=True)

if not sn_id:
    print("NO SIGNED_NONCE", flush=True)
    print(json.dumps(d4,indent=2)[:3000], flush=True)
    sys.exit(1)

print(f"[5] challenge signed_nonce id={sn_id}...", flush=True)
r5=s.post(sn_href, json={"stateHandle":st,"authenticator":{"id":sn_id,"methodType":"signed_nonce"}}, headers=H, timeout=15)
d5=r5.json()
print(f"    status={r5.status_code}", flush=True)
for key in ("currentAuthenticator","currentAuthenticatorEnrollment"):
    if key in d5:
        cd=d5[key].get("value",{}).get("contextualData",{})
        if "challengeRequest" in cd:
            jwt=cd["challengeRequest"]
            print(f"\nCHALLENGE JWT! len={len(jwt)}", flush=True)
            print(jwt[:200], flush=True)
            open("/c/Users/uglyt/temp_ps/challenge_jwt.txt","w").write(jwt)
            print("SAVED!", flush=True)
            sys.exit(0)
print("No challengeRequest", flush=True)
print(json.dumps(d5,indent=2)[:3000], flush=True)
