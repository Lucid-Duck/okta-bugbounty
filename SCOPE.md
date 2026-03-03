# Okta Bugcrowd Program Scope

**Program URL:** https://bugcrowd.com/engagements/okta
**Platform:** Bugcrowd (Expedited triage)
**Scope Rating:** 4 out of 4
**Started:** Nov 16, 2016
**Vulnerabilities Rewarded:** 448
**Validation:** 75% within 3 business days
**Average Payout:** $2,685.71
**Last Updated:** 10 Feb 2026

---

## In-Scope Targets

### Okta Personal

| Priority | Range |
|----------|-------|
| P1 | $5,000-$75,000 |
| P2 | $2,000-$5,000 |
| P3 | $500-$2,000 |
| P4 | $100-$500 |

**Setup:**
- Register at https://personal.trexcloud.com using @bugcrowdninja.com email
- iOS: Install from App Store, activate debug mode (tap "Okta Personal" 3x, shield 2x, long-press subtitle, select "Trex")
- Android: https://appdistribution.firebase.dev/i/4116040c826cc62f
- Save Recovery Key during mobile enrollment (needed for browser dashboard access)
- Push notifications NOT working with Trex env

**Targets:**
- `personal.trexcloud.com` (API Testing, Website Testing)

**Focus Areas:**
- Gaining access to Admin Dashboard or Identity Provider Dashboard (STOP TESTING AND REPORT if achieved)
- Breaking Okta Personal crypto and retrieving user data
- Sharing functionality
- Input validation issues
- Mobile intents
- Import + Export applications

---

### Okta Privileged Access (PAM)

| Priority | Range |
|----------|-------|
| P1 | $7,000-$35,000 |
| P2 | $3,000-$7,000 |
| P3 | $1,000-$3,000 |
| P4 | $100-$1,000 |

**Setup:**
- Redeem credentials at bottom of program brief (2 sets)
- Change email addresses for password reset capability
- Create 2+ Super Admins per org for account recovery
- Follow MFA configuration steps
- Access: Admin Dashboard > Applications > Browse App Catalog > "Okta Privileged Access" > team name: bugcrowd-pam-###
- Assign yourself, create groups with all team roles

**Targets:**
- `bugcrowd-pam-###.oktapreview.com`
- `bugcrowd-pam-###.pam.oktapreview.com`

**Focus Areas:**
- ASA Client / Agents
- Secrets
- Resource Administration
- Security Administration

---

### Okta Workflows

| Priority | Range |
|----------|-------|
| P1 | $7,000-$35,000 |
| P2 | $3,000-$7,000 |
| P3 | $1,000-$3,000 |
| P4 | $100-$1,000 |

**Access:** Admin Dashboard > Workflow > Workflows Console

**Targets:**
- `https://bugcrowd-pam-###.workflows.oktapreview.com` (API Testing, Website Testing)

**Focus Areas:**
- SSRF with Flo cards
- Provisioning/deprovisioning Workflow orgs
- Performing Flo actions across orgs
- Viewing sensitive information across orgs
- Escaping sandbox using API Endpoint and Return Raw
- Bypassing maximum 5 active flow limit

**CRITICAL:** DoS and automation testing STRICTLY out of scope for Workflows. Violation = removal from program.

---

### Okta Device Access

| Priority | Range |
|----------|-------|
| P1 | $10,000-$75,000 |
| P2 | $4,000-$10,000 |
| P3 | $1,000-$4,000 |
| P4 | $100-$1,000 |

**Targets:**
- Desktop MFA for Windows
- Desktop MFA for macOS
- Password Sync for macOS

**Downloads:** Admin Console > Settings > Downloads > Okta Verify for Windows (.exe) or macOS

---

### Okta Support Portal

| Priority | Range |
|----------|-------|
| P1 | $5,000-$15,000 |
| P2 | $2,000-$5,000 |
| P3 | $500-$2,000 |
| P4 | $100-$500 |

**Targets:**
- `support.okta.com`

**Notes:**
- Viewing basic data (first/last name, company, IDs) via Aura payloads NOT accepted
- Viewing credentials, emails, phone numbers reviewed on case-by-case basis
- Do NOT tamper with or delete customer data -- test against own account only

---

### AtSpoke (Okta Access Requests)

| Priority | Range |
|----------|-------|
| P1 | $5,000-$25,000 |
| P2 | $2,000-$5,000 |
| P3 | $500-$2,000 |
| P4 | $100-$500 |

**Targets:**
- `https://bugcrowd-pam-###.at.oktapreview.com` (API Testing, Website Testing)

**Focus Areas:**
- Configuration list bypass (resource restrictions)
- Modify critical fields of access requests (assignee, approver, resource)
- Injection attacks from integrations (Jira, ServiceNow, Slack, Teams)
- Export data from Access Requests
- File upload
- OIDC custom client implementation

**Privilege Model (Admin / Team Member / Regular User):**
- Private requests on another team: Admin NO, Team Member NO, Regular NO
- Edit invite-only teams: Admin YES, Team Member (own only), Regular NO
- Create request types: Admin YES (any), Team Member (own team), Regular NO

---

### Okta (OIE) In-Scope Targets

| Priority | Range |
|----------|-------|
| P1 | $10,000-$75,000 |
| P2 | $4,000-$10,000 |
| P3 | $1,000-$4,000 |
| P4 | $100-$1,000 |

**Setup:**
- Redeem 2 sets of credentials
- Change emails for password resets
- Create 2+ Super Admins per org
- Configure and enforce MFA (see MFA Configuration section)

**Targets:**
- `https://bugcrowd-pam-###.oktapreview.com` (API Testing, Website Testing)
- Okta Verify Fastpass
- `https://bugcrowd-pam-###-admin.oktapreview.com` (API Testing, Website Testing)

**Focus Areas:**
- Okta Expression Language
- LDAP as a Service
- Authentication Protocol Vulnerabilities (SAML, OAuth, OIDC, Social Auth)
- XXE within XML data
- Browser Plugin (IE / Firefox / Chrome)
- Cross-Org Access / Multi-Tenancy
- Horizontal / Vertical Privilege Escalation
- All on-premise Agents (LDAP / AD / OPP / Radius / RSA)
- Okta Verify (iOS / Android)
- XSS, Open Redirect, CSRF on sensitive actions

---

### Advanced Server Access (ASA / ScaleFT)

| Priority | Range |
|----------|-------|
| P1 | $7,000-$35,000 |
| P2 | $3,000-$7,000 |
| P3 | $1,000-$3,000 |
| P4 | $100-$1,000 |

**Setup:**
- Visit Advanced Server Access and create account as bugcrowd-username
- Use @bugcrowdninja.com email
- No credit card required

**Targets:**
- Advanced Server Access (ASA) / (ScaleFT)
- `http://app.scaleft.com/`
- Advanced Server Access Client / Agents

**Focus Areas:**
- ASA Client / Agents

---

### Other In-Scope Targets

| Priority | Range |
|----------|-------|
| P1 | $10,000-$75,000 |
| P2 | $4,000-$10,000 |
| P3 | $1,000-$4,000 |
| P4 | $100-$1,000 |

**Targets:**
- Okta Verify (iOS) -- Objective-C, SwiftUI, Swift
- Okta Verify (Android) -- Java, Android
- Okta Verify (macOS) -- Objective-C, Swift
- Okta Verify (Windows)
- Okta On-Prem Agents (AD, LDAP, RDP, IWA) -- Java, .NET
- Okta Agent Windows
- Okta Browser Plugin (IE / Firefox / Chrome)

---

## Out of Scope

### Domains
- `*.okta.com` (production)
- `*.trexcloud.com` (except personal.trexcloud.com)
- `login.okta.com`, `pages.okta.com`, `developer.okta.com`, `trust.okta.com`
- `www.okta.com` (static site)
- `https://scaleft.com`, `https://app.scaleft.com/p/signup`
- `https://github.com/oktadev`
- Backend Okta non-app infrastructure
- Network layer issues
- Okta Classic (out of scope since May 15, 2024)
- Anything not explicitly in scope

### Finding Types Excluded
- SOQL Injections
- Abandoned/unclaimed domains, domain squatting, link rot, social media hijacking
- All subdomain takeovers unless immediately critical
- EXIF Metadata, HTML Email Injection
- HTML Injection (must demonstrate real security risk beyond basic payloads)
- Host Header Redirect without user impact
- HTTP 404s / non-200 codes
- Fingerprinting / banner disclosure
- Known public files (robots.txt)
- Clickjacking
- CSRF on anonymous forms, Logout CSRF
- Autocomplete / save password
- Captcha issues
- Login / Forgot Password brute force
- HTTP methods (OPTIONS, PUT, GET, DELETE, INFO)
- WebServer type disclosures
- Social engineering, Physical attacks
- Requiring physical device access
- Non-sensitive error messages
- DoS / DDoS
- Missing cookie flags (HttpOnly, Secure, JSESSIONID)
- Username / email enumeration
- Missing HTTP security headers
- SPF / DMARC / DKIM, Email rate limiting, DNSSEC
- CSV issues, AV scanning
- SSL issues (BEAST, BREACH, weak ciphers)
- Service rate limiting, User or org enumeration
- Security image issues
- Business logic READ issues
- Session invalidation (must use "Sign me out of all other devices")
- Theoretical issues without complete PoC

---

## Rules of Engagement

1. **No automated scanning** -- no Burp scans, no scanners, no automation
2. **No DoS** -- Amazon prohibits it
3. **No automation against Workflows** -- instant removal from program
4. **Production systems** -- do not affect load or customer data
5. **Do NOT access customer instances**
6. **Limit AD/LDAP imports** to 1,000 users and groups
7. **Do NOT contact Okta support** -- use Bugcrowd support
8. **Zero-days:** not eligible until 30+ days after patch
9. **Server access:** stop, do not pivot, report immediately
10. **Okta Personal Admin/IdP Dashboard access:** stop immediately, report

---

## MFA Configuration (Required Before Testing)

### OIE Orgs
1. Security > Authenticators > Enrollment -- require enrollment
2. Security > Global Session Policy > Add Rule -- MFA REQUIRED
3. Security > Authentication Policies > Add policy with per-app rules

---

## Submission Format (Required by Okta)

1. **Description**
2. **Business Impact** (how does this affect Okta?)
3. **Working proof of concept**
4. **Discoverability** (how likely to be discovered)
5. **Exploitability** (how likely to be exploited)

---

## Key Program Notes

- Similar bugs from same researcher may be combined into single award
- Chaining bugs encouraged -- but do NOT pivot from compromised servers
- Payouts at Okta sole discretion based on risk AND impact
- Full MFA bypass requires MFA configured and enforced first
- Must provide complete PoC -- theoretical issues rejected

---

## Reference Links

- Okta Public API: https://developer.okta.com/docs/reference/
- Okta Help: https://help.okta.com
- SAML: https://developer.okta.com/docs/concepts/saml/
- OAuth/OIDC: https://developer.okta.com/docs/concepts/oauth-openid/
- Workflows Roles: https://help.okta.com/wf/en-us/content/topics/workflows/access-control/access-control-roles.htm
- Okta Personal Docs: https://help.okta.com/okta-personal/
- Device Access Docs: https://help.okta.com/en-us/content/topics/identity-engine/devices/oda-overview.htm
- PAM Setup: https://help.okta.com/en-us/content/topics/privileged-access/pam-setup.htm

---

*Scraped: 2026-03-02*
*Researcher: Lucid_Duck*
