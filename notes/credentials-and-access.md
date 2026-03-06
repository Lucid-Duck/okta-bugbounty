# Credentials and Access -- All Orgs

## Org 1: bugcrowd-pam-4593.oktapreview.com (PRIMARY)

### Admin API
- **Token:** 00B_hG_7HZJaM145T6LL1QGBkLrDXDJoaqPLk4yQ53
- **Type:** SSWS (Super Admin)
- **Usage:** `curl -H "Authorization: SSWS 00B_hG_7HZJaM145T6LL1QGBkLrDXDJoaqPLk4yQ53" "https://bugcrowd-pam-4593.oktapreview.com/api/v1/..."`

### User Account
- **Email:** bugbounty.okta@gmail.com
- **Password:** 6KkBNqBWrjvS
- **Enrolled Factors:** Password + Okta Verify (FastPass, signed_nonce)
- **MFA Note:** Legacy /api/v1/authn does NOT enforce MFA -- returns SUCCESS with just password

### OIDC Test App
- **App ID / Client ID:** 0oavvphi56SbYPzXk1d7
- **Name:** FastPass Test App
- **Redirect URI:** http://localhost:8080/callback
- **Grant Types:** authorization_code (PKCE)
- **Consent:** TRUSTED

### Authenticator IDs (Admin API)
| ID | Name | Key | Status |
|---|---|---|---|
| autsk8d1tfDZxHGWE1d7 | Email | okta_email | ACTIVE |
| autsk8d1tjzmPJtSn1d7 | Okta Verify | okta_verify | ACTIVE |
| autsk8d1tegD5stJx1d7 | Password | okta_password | ACTIVE |
| autsk8d1tgWpaDwAP1d7 | Phone | phone_number | INACTIVE |
| autsk8fl31umUU9g71d7 | Security Key/Biometric | webauthn | INACTIVE |
| autsk8d1ticZsxAqF1d7 | Security Question | security_question | INACTIVE |

### Apps on Org
13 total (mostly built-in). Key ones:
- 0oavvphi56SbYPzXk1d7: FastPass Test App (our test OIDC app)
- 0oavvpaf5nqmwxJlY1d7: Okta Privileged Access

## Org 2: dev-44786964.okta.com

### Status
- API token may be expired or never created
- Do NOT confuse with org 1
- The OIDC test app (0oavvphi56SbYPzXk1d7) is on ORG 1, not this one

## Windows 10 VM (Hyper-V)

- **VM Name:** lucid-duck-win10-vm
- **User:** lucidduck / Password1
- **Admin:** lucidduck is local admin
- **Build:** Windows 10 Pro 19045 (Feb 2026 updates)
- **Okta Verify:** Installed and enrolled with FastPass
- **SystemTemp:** Yes, this Win10 has C:\WINDOWS\SystemTemp (post-KB5017308)

### PowerShell Direct Access
```powershell
$pass = ConvertTo-SecureString "Password1" -AsPlainText -Force
$cred = New-Object PSCredential("lucidduck", $pass)
Invoke-Command -VMName "lucid-duck-win10-vm" -Credential $cred -ScriptBlock { whoami }
```
**WARNING:** Do NOT use Get-Credential -- it pops a GUI dialog on the host.
