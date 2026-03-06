# Auth0 by Okta -- Bugcrowd Program Scope

**Program URL:** https://bugcrowd.com/engagements/auth0-okta
**Platform:** Bugcrowd (Expedited triage)
**Scope Rating:** 4 out of 4
**Started:** Apr 29, 2024
**Vulnerabilities Rewarded:** 78
**Validation:** 75% within 11 days
**Average Payout:** $3,808.33
**Last Updated on Bugcrowd:** 26 Feb 2026
**Scope Captured:** 05 Mar 2026

---

## Researcher Environment

`https://manage.cic-bug-bounty.auth0app.com` -- created solely for researcher testing.

**Testing any other Auth0 environment is STRICTLY out of scope.** Submissions on `auth0.auth0.com` and `manage.auth0.com` will be immediately marked out of scope.

---

## Credentials (3 tenants, 3 users)

| Tenant | Username | Password |
|--------|----------|----------|
| bugcrowd-1987 | bugbounty.auth0+1987@gmail.com | maeBtucO |
| bugcrowd-1986 | bugbounty.auth0+1986@gmail.com | 7oZZR8cz |
| bugcrowd-1985 | bugbounty.auth0+1985@gmail.com | jlityWVP |

**Tenant Members:** You can invite User 2 and User 3 to Tenant 1 as members with configurable permissions. Each user accesses their own tenant plus any tenants they're invited to.

**Do NOT use tenants for personal use. Do NOT populate fields with personal information. Tenants may be deleted at any time.**

---

## In-Scope Targets

### Tier 1 -- $10,000-$50,000 P1

| P1 | P2 | P3 | P4 |
|----|----|----|-----|
| $10,000-$50,000 | $4,000-$10,000 | $1,000-$4,000 | $100-$1,000 |

| Location | Tags |
|----------|------|
| `config.cic-bug-bounty.auth0app.com` | Website Testing |
| `manage.cic-bug-bounty.auth0app.com` (Management Dashboard) | ReactJS, Website Testing |
| `*.cic-bug-bounty.auth0app.com` | Website Testing |
| Auth0 Guardian Android | Java, Kotlin, Mobile Application Testing |
| Auth0 Guardian iOS | Objective-C, SwiftUI, Swift |
| `marketplace.auth0.com` (Auth0 Marketplace) | Website Testing, HTTP |
| MFA Integrations | |
| `https://dashboard.fga.dev/` | .NET, Go, Website Testing |
| `https://api.us1.fga.dev/` | API Testing, .NET, HTTP |
| `https://customers.us1.fga.dev/` | API Testing, .NET, Go |
| `https://play.fga.dev/` | .NET, Go, Website Testing |

### SDK Targets -- $5,000-$15,000 P1

| P1 | P2 | P3 | P4 |
|----|----|----|-----|
| $5,000-$15,000 | $2,000-$5,000 | $500-$2,000 | $100-$500 |

| SDK | Notes |
|-----|-------|
| Auth0 SDK for Web (Auth0.js) | |
| Lock for Web (lock) | |
| Auth0 Single Page App SDK (auth0-spa-js) | |
| .NET SDK (Auth0.Net) | |
| Auth0 Next.js SDK (nextjs-auth0) | |
| Auth0 Java SDK (auth0-java) | |
| Auth0 React Native SDK (react-native-auth0) | |
| Auth0 PHP SDK (auth0-php) | |
| Auth0 passport-ws-fed | **New** |

**SDK rules:** Submissions must NOT rely on incorrect/unintended SDK implementations. Must demonstrate exploitation from an application built with the SDK, not individual function calls. User input assumed untrusted per SDK docs -- submissions relying on improperly validated input rejected.

### Tier 2 -- $5,000-$15,000 P1

| P1 | P2 | P3 | P4 |
|----|----|----|-----|
| $5,000-$15,000 | $2,000-$5,000 | $500-$2,000 | $100-$500 |

| Location | Tags |
|----------|------|
| `auth0.com` | ReactJS, Website Testing, NodeJS |
| `samltool.io` | Handlebars, jQuery, YUI |
| `webauthn.me` | jQuery, Website Testing, ExpressJS |
| `openidconnect.net` | ReactJS, jQuery, Lodash |
| `jwt.io` | jQuery, Lodash, Website Testing |
| `auth0.net` | Website Testing |

---

## Out-of-Scope Targets

| Target | Notes |
|--------|-------|
| `auth0.auth0.com` | Immediate OOS |
| `manage.auth0.com` | Immediate OOS |
| `accounts.auth0.com` | |
| `webtask.io` | |
| `phenix.rocks` | |
| Auth0 Docs (including quickstarts) | |
| `sharelock.io` | |
| `goextend.io` | |
| `https://support.auth0.com/tickets/new` | |
| `support.auth0.com` | |
| `community.auth0.com` | |

---

## Out-of-Scope Vulnerability Classes

- GitHub Actions vulnerabilities (token exfil = auto-duplicate)
- Double-dipping from Auth0 private program (permanent ban)
- Abandoned/unclaimed domains, domain squatting, link rot, social media hijacking
- Customize Login Page XSS
- Race conditions bypassing limits
- Invalidating session on password change/reset
- Incomplete/theoretical PoCs
- Host Header Redirect without user impact
- HTTP 404/non-200 codes
- Fingerprinting / banner disclosure
- Known public files (robots.txt)
- Clickjacking
- CSRF on anonymous forms, Logout CSRF
- Autocomplete / save password
- Captcha issues
- Login/Forgot Password brute force
- HTTP methods (OPTIONS, PUT, GET, DELETE, INFO)
- Web server type disclosures
- Social engineering, physical attacks
- Requiring physical device access
- Non-sensitive error messages
- DoS / DDoS
- Missing cookie flags (HttpOnly, Secure, JSESSIONID)
- Username/email enumeration
- Missing HTTP security headers (HSTS, X-Frame-Options, CSP, etc.)
- SPF/DMARC/DKIM, Email rate limiting, DNSSEC
- CSV issues, AV scanning
- SSL issues (BEAST, BREACH, weak ciphers)
- Service rate limiting, User/Org enumeration
- Security image issues
- Business logic issues

---

## Rules of Engagement

1. **No DoS** -- Amazon prohibits it
2. **No automated scanning tools** -- instant ban
3. **Burp Intruder allowed but max 5 req/sec**
4. **Production systems** -- do not affect load or customer data
5. **Customer instances/data must not be accessed or affected**
6. **If you gain server access: STOP. Do not pivot. Report immediately.**
7. **No social engineering, phishing, or physical testing**
8. **Do NOT contact Auth0 support** -- use Bugcrowd support only
9. **Public zero-days:** not eligible until 30+ days after patch availability
10. **Similar bugs from same researcher may be combined**
11. **Double-dipping from private program = permanent ban**

---

## Focus Areas

### Identity Protocol Vulnerabilities
- OAuth 2.0
- OpenID Connect
- SAML

### Core Focus
- Authentication or authorization bypass
- PII exfiltration
- Cross-tenant escalation of privilege

### Main Targets
- Mobile apps (Guardian)
- Authentication API and Management API
- Management Dashboard
- MFA offering
- SDKs
- Auth0-branded websites
- FGA (Fine-Grained Authorization)

---

## Submission Format (Required)

```
Description
Business Impact (how does this affect Auth0?)
Working proof of concept
Discoverability (how likely is this to be discovered)
Exploitability (how likely is this to be exploited)
```

---

## Documentation Index

| Target | Documentation |
|--------|---------------|
| Authentication API | https://auth0.com/docs/api/authentication |
| Management API | https://auth0.com/docs/api/management/v2 |
| Management Dashboard | https://auth0.com/docs/dashboard |
| Lock for Web | https://auth0.com/docs/libraries/lock/v11 |
| Auth0 SDK for Web | https://auth0.com/docs/libraries/auth0js/v9 |
| Auth0 SPA SDK | https://auth0.com/docs/libraries/auth0-spa-js |
| Express OpenID Connect | https://github.com/auth0/express-openid-connect |
| Auth0 React SPA SDK | https://github.com/auth0/auth0-react |
| MFA Overview | https://auth0.com/multifactor-authentication |
| MFA Docs | https://auth0.com/docs/multifactor-authentication |
| MFA Video | https://auth0.com/resources/videos/learn-about-guardian-mfa |
| FGA Documentation | https://docs.fga.dev/ |
| FGA Swagger | https://docs.fga.dev/api/service/ |

### Guardian Downloads
- Android: Google Play Store
- iOS: Apple App Store

---

## Key Differences from Okta Program

| Aspect | Okta | Auth0 |
|--------|------|-------|
| Max P1 | $75,000 | $50,000 |
| Avg payout | $2,686 | $3,808 |
| Validation | 3 days | 11 days |
| Automation | Zero tolerance | Burp Intruder OK at 5 req/sec |
| Environment | oktapreview.com orgs | cic-bug-bounty.auth0app.com |
| Credentials | 2 orgs | 3 tenants/users |

---

*Captured: 2026-03-05*
*Researcher: Lucid_Duck*
