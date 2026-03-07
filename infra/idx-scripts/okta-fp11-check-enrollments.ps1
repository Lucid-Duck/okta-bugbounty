# Check OIE authenticator enrollments (different from classic Factors API)
$org = "bugcrowd-pam-4593.oktapreview.com"
$apiToken = "00B_hG_7HZJaM145T6LL1QGBkLrDXDJoaqPLk4yQ53"
$userId = "00usk8d1s86Dr8Ltk1d7"

# OIE Authenticator enrollments
Write-Host "=== User Authenticator Enrollments (OIE) ===" -ForegroundColor Cyan
$enrollResult = & curl.exe -s -w "`n---HTTP_CODE:%{http_code}---" `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/users/$userId/authenticators" `
    --connect-timeout 10 --max-time 20

Write-Host $enrollResult

# Also try the idp/myaccount endpoint
Write-Host "`n=== Classic Factors ===" -ForegroundColor Cyan
$factorsResult = & curl.exe -s `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/users/$userId/factors" `
    --connect-timeout 10 --max-time 20

$factors = $factorsResult | ConvertFrom-Json
foreach ($f in $factors) {
    Write-Host "  $($f.factorType) / $($f.provider) / $($f.status) / ID: $($f.id)"
}

# Try modifying the authentication policy to add email as a constraint
# First, let's understand what the current "Any two factors" policy looks like
Write-Host "`n=== Any Two Factors Policy Details ===" -ForegroundColor Cyan
$policyId = "rstsk8d1tk5kBKUP81d7"
$ruleResult = & curl.exe -s `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/policies/$policyId/rules" `
    --connect-timeout 10 --max-time 20

Write-Host "Full rule JSON:"
Write-Host $ruleResult

# Check what our test app (FastPass Test App) is mapped to
Write-Host "`n=== FastPass Test App Policy ===" -ForegroundColor Cyan
$appResult = & curl.exe -s `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/apps/0oavvphi56SbYPzXk1d7" `
    --connect-timeout 10 --max-time 20

$app = $appResult | ConvertFrom-Json
Write-Host "App: $($app.label)"
if ($app._links -and $app._links.accessPolicy) {
    Write-Host "Access Policy: $($app._links.accessPolicy.href)"
} else {
    Write-Host "No explicit access policy -- using default"
}

# Map our test app to the "Any two factors" policy which might be more lenient
Write-Host "`n=== Mapping Test App to 'Any two factors' policy ===" -ForegroundColor Cyan
$mapResult = & curl.exe -s -w "`n---HTTP_CODE:%{http_code}---" `
    -X PUT "https://$org/api/v1/apps/0oavvphi56SbYPzXk1d7/policies/$policyId" `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    --connect-timeout 10 --max-time 20

Write-Host $mapResult
