import requests, json, sys

# Test the loopback server
BASE = "http://127.0.0.1:8769"

# Probe
print("[1] GET /probe...", flush=True)
try:
    r = requests.get(f"{BASE}/probe", headers={"Origin": "https://evil.com"}, timeout=5)
    print(f"    Status: {r.status_code}", flush=True)
    print(f"    CORS: {r.headers.get('Access-Control-Allow-Origin','N/A')}", flush=True)
    print(f"    Body: {r.text[:500]}", flush=True)
except Exception as e:
    print(f"    Error: {e}", flush=True)
    sys.exit(1)

# OPTIONS on /challenge
print("\n[2] OPTIONS /challenge...", flush=True)
r2 = requests.options(f"{BASE}/challenge", headers={
    "Origin": "https://evil.com",
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "content-type"
}, timeout=5)
print(f"    Status: {r2.status_code}", flush=True)
print(f"    CORS: {r2.headers.get('Access-Control-Allow-Origin','N/A')}", flush=True)
print(f"    Allow-Headers: {r2.headers.get('Access-Control-Allow-Headers','N/A')}", flush=True)
print(f"    All headers: {dict(r2.headers)}", flush=True)

# POST a dummy challenge to see error format
print("\n[3] POST /challenge (dummy)...", flush=True)
r3 = requests.post(f"{BASE}/challenge", json={"challengeRequest": "eyJhbGciOiJSUzI1NiJ9.eyJ0ZXN0IjoxfQ.fake"},
                    headers={"Origin": "https://evil.com", "Content-Type": "application/json"}, timeout=5)
print(f"    Status: {r3.status_code}", flush=True)
print(f"    CORS: {r3.headers.get('Access-Control-Allow-Origin','N/A')}", flush=True)
print(f"    Body: {r3.text[:500]}", flush=True)

# GET /challenge to see what it returns
print("\n[4] GET /challenge...", flush=True)
r4 = requests.get(f"{BASE}/challenge", headers={"Origin": "https://evil.com"}, timeout=5)
print(f"    Status: {r4.status_code}", flush=True)
print(f"    CORS: {r4.headers.get('Access-Control-Allow-Origin','N/A')}", flush=True)
print(f"    Body: {r4.text[:500]}", flush=True)
