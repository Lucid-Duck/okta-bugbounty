## MANDATORY: NO EM DASHES. EVER. ANYWHERE.

**NEVER use em dashes (the long dash character).** Use regular hyphens (-), double hyphens (--), commas, or rephrase instead. This applies to ALL output. No exceptions.

---

## RULE ZERO -- READ THIS BEFORE ANYTHING ELSE

**"Repo" = ONLINE GitHub. ALWAYS. NO EXCEPTIONS. EVER.**

When the user says "repo", "the repo", "read the repo", "save to repo", "update the repo", "commit it", "push it", or ANY variation -- they ALWAYS mean the ONLINE GitHub repository at github.com/Lucid-Duck/. NEVER local files. NEVER local clones.

- **Read from repos:** Use `gh api` or `WebFetch`. NEVER `Read`/`cat` on local clones.
- **Write to repos:** Always `git add + git commit + git push` or `gh api`. If it is not on GitHub, it does not exist.
- **Exception:** ONLY if user explicitly says "local only" or "do not push."

---

# Okta Bug Bounty -- Claude Code Context

## Quick Status
- **Phase:** Initial setup -- no credentials redeemed, no testing started
- **Program:** https://bugcrowd.com/engagements/okta
- **Platform:** Bugcrowd (Expedited triage)
- **Ceiling:** $75,000 (OIE / Device Access / Other In-Scope)
- **Average payout:** $2,685.71
- **Validation:** 75% within 3 business days

## Program Rules (Critical)
- **No automated scanning** -- no Burp, no scanners, no automation whatsoever
- **No DoS** -- instant disqualification
- **No automation against Workflows** -- instant removal from entire program
- **Production systems** -- do not affect load or customer data
- **If you gain server access:** STOP. Do not pivot. Report immediately.
- **Theoretical issues without complete PoC are OUT OF SCOPE**
- **Must demonstrate real impact, not potential impact**

## Credentials (NOT YET REDEEMED)
- Bugcrowd provides 2 sets of OIE org credentials
- Must use @bugcrowdninja.com email
- After redemption: change emails, create 2+ Super Admins, configure MFA

## Target Priority (by payout ceiling)

| Target | P1 Ceiling | RE Surface |
|--------|-----------|------------|
| Okta (OIE) | $75,000 | Web app, API, auth protocols |
| Okta Device Access | $75,000 | **Desktop MFA binaries (Win/Mac)** |
| Other In-Scope | $75,000 | **Okta Verify (mobile + desktop), On-Prem Agents, Browser Plugin** |
| Okta Personal | $75,000 | Mobile apps (iOS/Android), web |
| Okta Privileged Access | $35,000 | PAM web console, agents |
| Okta Workflows | $35,000 | Workflow engine, Flo cards, sandbox escape |
| Advanced Server Access | $35,000 | **ASA Client/Agents (native binaries, SSH replacement)** |
| AtSpoke | $25,000 | Access request system, integrations |
| Support Portal | $15,000 | support.okta.com |

## High-Value RE Targets
1. **Okta Verify (Windows/macOS)** -- native binary, handles Fastpass auth, $75K P1
2. **Desktop MFA (Windows)** -- system-level auth component, $75K P1
3. **ASA Client/Agents** -- SSH daemon replacement, runs as root/SYSTEM, $35K P1
4. **On-Prem Agents (AD, LDAP, RDP, IWA)** -- Java/.NET, runs in customer infrastructure, $75K P1
5. **Okta Agent Windows** -- system service, $75K P1

## Focus Areas (from Okta)
- **Auth protocol vulns:** SAML, OAuth, OIDC, Social Auth
- **Cross-org / multi-tenancy** -- this is the holy grail
- **Privilege escalation** (horizontal / vertical)
- **XXE** in XML processing
- **SSRF via Workflow Flo cards**
- **Workflow sandbox escape** via API Endpoint and Return Raw
- **Expression Language injection**
- **LDAP as a Service**

## For Claude Instances
- Read `SCOPE.md` for full program rules before testing anything
- NEVER suggest automated scanning or DoS testing
- All org/team names must follow bugcrowd-username convention
- Okta Classic is OUT OF SCOPE since May 2024
- Business logic READ issues are explicitly out of scope
- HTML injection must demonstrate real security risk (not just basic tags)
- Similar bugs may be combined into single award
