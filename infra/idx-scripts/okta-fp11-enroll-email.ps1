# Enroll email factor for the test user via Admin API
# This should unblock the IDX flow which needs a second factor besides FastPass

$org = "bugcrowd-pam-4593.oktapreview.com"
$apiToken = "00B_hG_7HZJaM145T6LL1QGBkLrDXDJoaqPLk4yQ53"

# Get user ID
Write-Host "=== Getting user info ===" -ForegroundColor Cyan
$userResult = & curl.exe -s `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/users/bugbounty.okta@gmail.com" `
    --connect-timeout 10 --max-time 20

$user = $userResult | ConvertFrom-Json
$userId = $user.id
Write-Host "User ID: $userId"
Write-Host "Email: $($user.profile.email)"

# List current factor enrollments
Write-Host "`n=== Current Factor Enrollments ===" -ForegroundColor Cyan
$factorsResult = & curl.exe -s `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/users/$userId/factors" `
    --connect-timeout 10 --max-time 20

$factors = $factorsResult | ConvertFrom-Json
foreach ($f in $factors) {
    Write-Host "  $($f.factorType) / $($f.provider) - Status: $($f.status) - ID: $($f.id)"
}

# Enroll email factor
Write-Host "`n=== Enrolling Email Factor ===" -ForegroundColor Cyan
$enrollBody = '{"factorType":"email","provider":"OKTA","profile":{"email":"bugbounty.okta@gmail.com"}}'

$enrollResult = & curl.exe -s -w "`n---HTTP_CODE:%{http_code}---" `
    -X POST "https://$org/api/v1/users/$userId/factors?activate=true" `
    -H "Authorization: SSWS $apiToken" `
    -H "Content-Type: application/json" `
    -H "Accept: application/json" `
    -d $enrollBody `
    --connect-timeout 10 --max-time 20

Write-Host "Enroll result:"
Write-Host $enrollResult

# List factors again
Write-Host "`n=== Updated Factor Enrollments ===" -ForegroundColor Cyan
$factorsResult2 = & curl.exe -s `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/users/$userId/factors" `
    --connect-timeout 10 --max-time 20

$factors2 = $factorsResult2 | ConvertFrom-Json
foreach ($f in $factors2) {
    Write-Host "  $($f.factorType) / $($f.provider) - Status: $($f.status) - ID: $($f.id)"
}
