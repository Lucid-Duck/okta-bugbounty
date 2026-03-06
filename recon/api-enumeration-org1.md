# Okta API Enumeration - Org 1 (bugcrowd-pam-4593)

**Date:** 2026-03-05
**Token:** SSWS API token (Super Admin)
**Org:** https://bugcrowd-pam-4593.oktapreview.com

---

## Current User (Token Owner)

- **ID:** 00usk8d1s86Dr8Ltk1d7
- **Login:** bugbounty.okta@gmail.com
- **Email:** lucid_duck@bugcrowdninja.com
- **Secondary Email:** bugcrowd.lucid.duck@gmail.com
- **Name:** Lucid Duck
- **Status:** ACTIVE
- **Last Login:** 2026-03-06T04:07:46.000Z
- **Password Changed:** 2026-03-03T04:23:49.000Z
- **Realm ID:** guosk8fl07ib1rlGS1d7
- **Type ID:** otysk8d1q1HpSL2wS1d7

## Users

Only 1 user in org -- the researcher account. No other users provisioned.

## Groups

| Group | Type | ID |
|-------|------|----|
| Everyone | BUILT_IN | 00gsk8d1prVUQqQhy1d7 |
| Okta Administrators | BUILT_IN | 00gsk8d1psxHaPzn01d7 |

No custom groups created.

## Applications (11 total)

All OIDC. All are Okta first-party apps -- no custom/third-party apps registered.

| App | Internal Name | ID | Sign-On |
|-----|---------------|----|---------|
| Okta Admin Console | saasure | 0oask8d1o76zyVufd1d7 | OPENID_CONNECT |
| Okta Dashboard | okta_enduser | 0oask8d1ozqJgTaHd1d7 | OPENID_CONNECT |
| Okta Browser Plugin | okta_browser_plugin | 0oask8d1q81rFSY2p1d7 | OPENID_CONNECT |
| Okta Access Certification Reviews | okta_iga_reviewer | 0oask8lsju8uzV29W1d7 | OPENID_CONNECT |
| Partner Admin Portal | partner_portal | 0oask8lsku6t3ZUu01d7 | OPENID_CONNECT |
| Okta Security Access Reviews | okta_iga_security_access_reviews | 0oask8lw9vgjIZOc61d7 | OPENID_CONNECT |
| Okta Identity Governance | okta_access_requests_resource_catalog | 0oask8m1ziFbik0E31d7 | OPENID_CONNECT |
| Okta Workflows | okta_flow_sso | 0oask8mr8op4Z4oao1d7 | OPENID_CONNECT |
| Okta Workflows OAuth | flow | 0oask8mrfvOMzWINN1d7 | OPENID_CONNECT |
| Okta Access Requests (AtSpoke) | okta_atspoke_sso | 0oask8xx0feKYF1BG1d7 | OPENID_CONNECT |
| Okta End User Settings | okta_account_settings | 0oatnqggosKiEblEY1d7 | OPENID_CONNECT |

## Authorization Servers

Only 1 -- the default:

- **ID:** aussk8fkvmzuj9HPH1d7
- **Name:** default
- **Audience:** api://default
- **Issuer:** https://bugcrowd-pam-4593.oktapreview.com/oauth2/default
- **Issuer Mode:** ORG_URL
- **Signing Key:** vDen3aGXJY9I4fKYOupitqtyxYk1uRk_3zVXDoGMmts
- **Key Rotation:** AUTO (next: 2026-03-10)
- **OIDC Discovery:** https://bugcrowd-pam-4593.oktapreview.com/oauth2/default/.well-known/openid-configuration

### Scopes (Default Auth Server)

| Scope | Consent | System |
|-------|---------|--------|
| openid | IMPLICIT | Yes |
| profile | IMPLICIT | Yes |
| email | IMPLICIT | Yes |
| address | IMPLICIT | Yes |
| phone | IMPLICIT | Yes |
| offline_access | IMPLICIT | Yes |
| device_sso | IMPLICIT | Yes |

All scopes use IMPLICIT consent (no user consent prompt required). `device_sso` is notable -- enables native SSO between apps on a device.

## Trusted Origins

**Empty.** No trusted origins configured.

## Identity Providers

**Empty.** No external IdPs (SAML, OIDC, Social) configured.

## Sign-On Policies

Only the default system policy:

- **ID:** 00psk8d1pt7jEM90U1d7
- **Name:** Default Policy
- **System:** Yes
- **Applies to:** Everyone group

## Access Policies

| Policy | ID | System | Notes |
|--------|----|--------|-------|
| Okta Admin Console | rstsk8d1t0oCh0QYj1d7 | No | APP resource |
| Okta Dashboard | rstsk8d1t7DzYqSaY1d7 | No | APP resource |
| Okta Browser Plugin | rstsk8d1taOSxGA7L1d7 | No | APP resource |
| Any two factors | rstsk8d1tk5kBKUP81d7 | Yes | Default 2FA policy |
| Okta Account Management | rstsk8d1ujFUjLJdF1d7 | No | Controls authenticator enrollment, password reset, unlock |
| Partner Admin Portal | rstsk8lsl2Wj6GHoq1d7 | No | APP resource |
| Okta End User Settings | rsttnqggpaTyHbJ4g1d7 | No | APP resource |

## User Schema

Standard Okta user schema. Key self-service permissions:
- **login:** READ_ONLY (user cannot change username)
- **firstName/lastName:** READ_WRITE (user can change)
- **email:** READ_WRITE (user can change via self-service)
- **middleName, honorificPrefix:** READ_ONLY

## Key Observations

1. **Pristine org** -- default config, single user, no custom apps, no IdPs, no trusted origins
2. **No MFA configured** -- required by program rules before testing MFA bypass
3. **All consent is IMPLICIT** -- no user consent prompts for any OIDC scope
4. **device_sso scope available** -- can request device secrets for native SSO
5. **No custom auth server** -- only default, standard scopes
6. **Workflows and Access Requests apps present** -- these are high-value targets per scope
7. **Partner Admin Portal** -- interesting, may have different access model
8. **Key rotation coming up** -- 2026-03-10 for the auth server signing key

## Next Steps

1. Create a custom OIDC app to test OAuth flows (redirect_uri handling, scope escalation)
2. Configure MFA (required by program before any MFA testing)
3. Create a second user for horizontal privilege escalation testing
4. Test the Workflows console (SSRF, sandbox escape)
5. Test the AtSpoke/Access Requests system
6. Enumerate the policy rules for each access policy
7. Check if the org-level authorization server (not custom) has different behavior
8. Test Expression Language in user profile attributes
9. Set up PAM (Privileged Access) per scope instructions
10. Probe the Partner Admin Portal for any exposed functionality
