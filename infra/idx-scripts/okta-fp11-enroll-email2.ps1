# Enroll email factor for the test user via Admin API
$org = "bugcrowd-pam-4593.oktapreview.com"
$apiToken = "00B_hG_7HZJaM145T6LL1QGBkLrDXDJoaqPLk4yQ53"
$userId = "00usk8d1s86Dr8Ltk1d7"
$tempDir = "C:\Users\uglyt\temp_ps"

# Write JSON body to file to avoid escaping issues
$enrollJson = '{"factorType":"email","provider":"OKTA","profile":{"email":"lucid_duck@bugcrowdninja.com"}}'
[System.IO.File]::WriteAllText("$tempDir\okta-fp11-enroll-body.json", $enrollJson, [System.Text.Encoding]::UTF8)

Write-Host "=== Enrolling Email Factor ===" -ForegroundColor Cyan
$enrollResult = & curl.exe -s -w "`n---HTTP_CODE:%{http_code}---" `
    -X POST "https://$org/api/v1/users/$userId/factors?activate=true" `
    -H "Authorization: SSWS $apiToken" `
    -H "Content-Type: application/json" `
    -H "Accept: application/json" `
    -d "@$tempDir\okta-fp11-enroll-body.json" `
    --connect-timeout 10 --max-time 20

Write-Host $enrollResult

# If that fails, try without activate (needs separate activation)
if ($enrollResult -match "400|error") {
    Write-Host "`n=== Trying without activate ===" -ForegroundColor Yellow
    $enrollResult2 = & curl.exe -s -w "`n---HTTP_CODE:%{http_code}---" `
        -X POST "https://$org/api/v1/users/$userId/factors" `
        -H "Authorization: SSWS $apiToken" `
        -H "Content-Type: application/json" `
        -H "Accept: application/json" `
        -d "@$tempDir\okta-fp11-enroll-body.json" `
        --connect-timeout 10 --max-time 20

    Write-Host $enrollResult2
}

# List factors
Write-Host "`n=== Factors After ===" -ForegroundColor Cyan
$factorsResult = & curl.exe -s `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/users/$userId/factors" `
    --connect-timeout 10 --max-time 20

$factors = $factorsResult | ConvertFrom-Json
foreach ($f in $factors) {
    Write-Host "  $($f.factorType) / $($f.provider) - Status: $($f.status) - ID: $($f.id)"
    if ($f.profile) {
        Write-Host "    Profile: $($f.profile | ConvertTo-Json -Compress)"
    }
}
