# Check authentication policies to understand why email factor isn't offered
$org = "bugcrowd-pam-4593.oktapreview.com"
$apiToken = "00B_hG_7HZJaM145T6LL1QGBkLrDXDJoaqPLk4yQ53"
$tempDir = "C:\Users\uglyt\temp_ps"

# List all policies
Write-Host "=== Authentication Policies ===" -ForegroundColor Cyan
$policiesResult = & curl.exe -s `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/policies?type=ACCESS_POLICY" `
    --connect-timeout 10 --max-time 20

$policies = $policiesResult | ConvertFrom-Json
foreach ($p in $policies) {
    Write-Host "`n  Policy: $($p.name) (ID: $($p.id), Status: $($p.status))"
    Write-Host "  Description: $($p.description)"

    # Get rules for this policy
    $rulesResult = & curl.exe -s `
        -H "Authorization: SSWS $apiToken" `
        -H "Accept: application/json" `
        "https://$org/api/v1/policies/$($p.id)/rules" `
        --connect-timeout 10 --max-time 20

    $rules = $rulesResult | ConvertFrom-Json
    foreach ($r in $rules) {
        Write-Host "    Rule: $($r.name) (ID: $($r.id), Status: $($r.status))"
        if ($r.actions -and $r.actions.appSignOn) {
            $appSignOn = $r.actions.appSignOn
            Write-Host "      Access: $($appSignOn.access)"
            if ($appSignOn.verificationMethod) {
                Write-Host "      VerificationMethod:"
                Write-Host "        Type: $($appSignOn.verificationMethod.type)"
                Write-Host "        FactorMode: $($appSignOn.verificationMethod.factorMode)"
                Write-Host "        ReAuth: $($appSignOn.verificationMethod.reauthenticateIn)"
                if ($appSignOn.verificationMethod.constraints) {
                    Write-Host "        Constraints:" -ForegroundColor Yellow
                    Write-Host ($appSignOn.verificationMethod.constraints | ConvertTo-Json -Depth 10)
                }
            }
        }
    }
}

# Also check sign-on policies
Write-Host "`n=== Sign-On Policies ===" -ForegroundColor Cyan
$signOnResult = & curl.exe -s `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/policies?type=OKTA_SIGN_ON" `
    --connect-timeout 10 --max-time 20

$signOnPolicies = $signOnResult | ConvertFrom-Json
foreach ($p in $signOnPolicies) {
    Write-Host "`n  Policy: $($p.name) (ID: $($p.id))"

    $rulesResult = & curl.exe -s `
        -H "Authorization: SSWS $apiToken" `
        -H "Accept: application/json" `
        "https://$org/api/v1/policies/$($p.id)/rules" `
        --connect-timeout 10 --max-time 20

    $rules = $rulesResult | ConvertFrom-Json
    foreach ($r in $rules) {
        Write-Host "    Rule: $($r.name)"
        if ($r.actions -and $r.actions.signon) {
            Write-Host "      Access: $($r.actions.signon.access)"
            Write-Host "      RequireFactor: $($r.actions.signon.requireFactor)"
            Write-Host "      FactorPromptMode: $($r.actions.signon.factorPromptMode)"
            if ($r.actions.signon.primaryFactor) {
                Write-Host "      PrimaryFactor: $($r.actions.signon.primaryFactor)"
            }
        }
    }
}

# Check app-specific policy mapping for the Okta Dashboard app
Write-Host "`n=== App Policy Mapping (Okta Dashboard) ===" -ForegroundColor Cyan
$appResult = & curl.exe -s `
    -H "Authorization: SSWS $apiToken" `
    -H "Accept: application/json" `
    "https://$org/api/v1/apps/0oask8d1ozqJgTaHd1d7" `
    --connect-timeout 10 --max-time 20

$app = $appResult | ConvertFrom-Json
Write-Host "App: $($app.label)"
if ($app._links -and $app._links.accessPolicy) {
    Write-Host "Access Policy: $($app._links.accessPolicy.href)"

    # Fetch the access policy
    $apResult = & curl.exe -s `
        -H "Authorization: SSWS $apiToken" `
        -H "Accept: application/json" `
        "$($app._links.accessPolicy.href)" `
        --connect-timeout 10 --max-time 20

    $ap = $apResult | ConvertFrom-Json
    Write-Host "  Policy Name: $($ap.name)"
    Write-Host "  Policy ID: $($ap.id)"

    # Get rules
    $arResult = & curl.exe -s `
        -H "Authorization: SSWS $apiToken" `
        -H "Accept: application/json" `
        "$($app._links.accessPolicy.href)/rules" `
        --connect-timeout 10 --max-time 20

    $arRules = $arResult | ConvertFrom-Json
    foreach ($r in $arRules) {
        Write-Host "`n  Rule: $($r.name) (priority: $($r.priority))"
        if ($r.actions -and $r.actions.appSignOn) {
            $vm = $r.actions.appSignOn.verificationMethod
            Write-Host "    Type: $($vm.type)"
            Write-Host "    FactorMode: $($vm.factorMode)"
            Write-Host "    ReAuth: $($vm.reauthenticateIn)"
            if ($vm.constraints) {
                Write-Host "    Constraints:" -ForegroundColor Yellow
                Write-Host ($vm.constraints | ConvertTo-Json -Depth 10)
            }
        }
    }
}
