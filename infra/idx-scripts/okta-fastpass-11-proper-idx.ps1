# Proper IDX flow: identify (username ONLY) -> password challenge -> select OV -> get challenge JWT
# Previous scripts failed because they sent credentials with identify step

$org = "bugcrowd-pam-4593.oktapreview.com"
$tempDir = "C:\Users\uglyt\temp_ps"
$clientId = "okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26"
$codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

# ============================================================
# STEP 1: Get the login page and extract stateToken
# ============================================================
Write-Host "STEP 1: Getting login page..." -ForegroundColor Cyan

$authzPage = & curl.exe -s `
    "https://$org/oauth2/v1/authorize?client_id=$clientId&response_type=code&scope=openid+profile&redirect_uri=https://$org/enduser/callback&state=fp_test&nonce=fp_nonce&code_challenge=$codeChallenge&code_challenge_method=S256" `
    -c "$tempDir\okta-fp-cookies5.txt" `
    --connect-timeout 10 --max-time 20

# Extract stateToken from: var stateToken = 'eyJ...';
$stMatch = [regex]::Match($authzPage, "var stateToken = '([^']+)'")

if ($stMatch.Success) {
    $rawToken = $stMatch.Groups[1].Value
    $stateToken = $rawToken -replace '\\x2D', '-'
    Write-Host "stateToken extracted (length: $($stateToken.Length))"
} else {
    Write-Host "FATAL: Could not extract stateToken" -ForegroundColor Red
    $modelMatch = [regex]::Match($authzPage, 'stateToken.{0,100}')
    if ($modelMatch.Success) { Write-Host "Context: $($modelMatch.Value)" }
    exit 1
}

# ============================================================
# STEP 2: Introspect with stateToken
# ============================================================
Write-Host "`nSTEP 2: POST /idp/idx/introspect" -ForegroundColor Cyan

$introJson = '{"stateToken":"' + $stateToken + '"}'
[System.IO.File]::WriteAllText("$tempDir\okta-fp11-intro.json", $introJson, [System.Text.Encoding]::UTF8)

$introResult = & curl.exe -s `
    -X POST "https://$org/idp/idx/introspect" `
    -H "Content-Type: application/ion+json; okta-version=1.0.0" `
    -H "Accept: application/ion+json; okta-version=1.0.0" `
    -b "$tempDir\okta-fp-cookies5.txt" `
    -d "@$tempDir\okta-fp11-intro.json" `
    --connect-timeout 10 --max-time 20

$introObj = $introResult | ConvertFrom-Json
$stateHandle = $introObj.stateHandle

if (-not $stateHandle) {
    Write-Host "FATAL: No stateHandle from introspect" -ForegroundColor Red
    Write-Host $introResult.Substring(0, [Math]::Min(500, $introResult.Length))
    exit 1
}

Write-Host "stateHandle obtained"
if ($introObj.remediation -and $introObj.remediation.value) {
    Write-Host "Remediations:"
    foreach ($rem in $introObj.remediation.value) {
        Write-Host "  $($rem.name) -> $($rem.href)"
    }
}

# ============================================================
# STEP 3: Identify with username ONLY (no credentials!)
# ============================================================
Write-Host "`nSTEP 3: POST /idp/idx/identify (username only)" -ForegroundColor Cyan

$idJson = '{"stateHandle":"' + $stateHandle + '","identifier":"bugbounty.okta@gmail.com"}'
[System.IO.File]::WriteAllText("$tempDir\okta-fp11-identify.json", $idJson, [System.Text.Encoding]::UTF8)

$idResult = & curl.exe -s `
    -X POST "https://$org/idp/idx/identify" `
    -H "Content-Type: application/ion+json; okta-version=1.0.0" `
    -H "Accept: application/ion+json; okta-version=1.0.0" `
    -b "$tempDir\okta-fp-cookies5.txt" `
    -d "@$tempDir\okta-fp11-identify.json" `
    --connect-timeout 10 --max-time 20

[System.IO.File]::WriteAllText("$tempDir\okta-fp11-identify-result.json", $idResult, [System.Text.Encoding]::UTF8)
$idObj = $idResult | ConvertFrom-Json

# Check for errors
if ($idObj.messages) {
    Write-Host "Messages:" -ForegroundColor Yellow
    foreach ($msg in $idObj.messages.value) {
        Write-Host "  [$($msg.class)] $($msg.message)"
    }
}

$newSH = $idObj.stateHandle
if (-not $newSH) {
    Write-Host "No new stateHandle - flow may have errored" -ForegroundColor Red
    Write-Host $idResult.Substring(0, [Math]::Min(1000, $idResult.Length))
    exit 1
}

# Show remediations
if ($idObj.remediation -and $idObj.remediation.value) {
    Write-Host "Remediations after identify:" -ForegroundColor Green
    foreach ($rem in $idObj.remediation.value) {
        Write-Host "  $($rem.name) -> $($rem.href)"
    }
}

# Show authenticators
if ($idObj.authenticators -and $idObj.authenticators.value) {
    Write-Host "`nAvailable authenticators:"
    foreach ($a in $idObj.authenticators.value) {
        Write-Host "  [$($a.key)] $($a.displayName) (type=$($a.type), id=$($a.id))"
        if ($a.methods) {
            foreach ($m in $a.methods) { Write-Host "    method: $($m.type)" }
        }
    }
}

# Check what remediation we got
$selectAuth = $idObj.remediation.value | Where-Object { $_.name -eq "select-authenticator-authenticate" }
$challengeAuth = $idObj.remediation.value | Where-Object { $_.name -eq "challenge-authenticator" }
$challengePoll = $idObj.remediation.value | Where-Object { $_.name -eq "challenge-poll" }
$launchAuth = $idObj.remediation.value | Where-Object { $_.name -eq "launch-authenticator" }

# ============================================================
# STEP 4: Handle the next remediation
# ============================================================
if ($challengeAuth) {
    # We got a direct challenge - probably password
    Write-Host "`nSTEP 4: challenge-authenticator detected" -ForegroundColor Cyan
    $caKey = if ($idObj.currentAuthenticatorEnrollment -and $idObj.currentAuthenticatorEnrollment.value) { $idObj.currentAuthenticatorEnrollment.value.key } else { "unknown" }
    Write-Host "Current authenticator: $caKey"

    # If it's password, submit it
    if ($idObj.currentAuthenticatorEnrollment -and $idObj.currentAuthenticatorEnrollment.value.key -eq "okta_password") {
        Write-Host "  -> Password challenge. Submitting password..." -ForegroundColor Yellow

        $passJson = '{"stateHandle":"' + $newSH + '","credentials":{"passcode":"6KkBNqBWrjvS"}}'
        [System.IO.File]::WriteAllText("$tempDir\okta-fp11-password.json", $passJson, [System.Text.Encoding]::UTF8)

        $passResult = & curl.exe -s `
            -X POST $challengeAuth.href `
            -H "Content-Type: application/ion+json; okta-version=1.0.0" `
            -H "Accept: application/ion+json; okta-version=1.0.0" `
            -b "$tempDir\okta-fp-cookies5.txt" `
            -d "@$tempDir\okta-fp11-password.json" `
            --connect-timeout 10 --max-time 20

        [System.IO.File]::WriteAllText("$tempDir\okta-fp11-password-result.json", $passResult, [System.Text.Encoding]::UTF8)
        $passObj = $passResult | ConvertFrom-Json
        $newSH = $passObj.stateHandle

        if ($passObj.messages) {
            foreach ($msg in $passObj.messages.value) {
                Write-Host "  [$($msg.class)] $($msg.message)" -ForegroundColor Yellow
            }
        }

        if ($passObj.remediation) {
            Write-Host "`nRemediations after password:" -ForegroundColor Green
            foreach ($rem in $passObj.remediation.value) {
                Write-Host "  $($rem.name) -> $($rem.href)"
            }
        }

        # Now look for authenticator selection
        $selectAuth = $passObj.remediation.value | Where-Object { $_.name -eq "select-authenticator-authenticate" }
        $idObj = $passObj
    }
}

if ($selectAuth) {
    Write-Host "`nSTEP 4b: select-authenticator-authenticate" -ForegroundColor Cyan

    # Find authenticator options
    $authField = $selectAuth.value | Where-Object { $_.name -eq "authenticator" }
    if ($authField -and $authField.options) {
        Write-Host "Options:"
        foreach ($opt in $authField.options) {
            $optJson = $opt.value | ConvertTo-Json -Compress -Depth 5
            Write-Host "  [$($opt.label)] -> $optJson"
        }

        # Select Okta Verify
        $ovOpt = $authField.options | Where-Object { $_.label -match "Okta Verify" }
        if ($ovOpt) {
            Write-Host "`nSelecting Okta Verify..." -ForegroundColor Yellow

            $selBody = @{
                stateHandle = $newSH
                authenticator = $ovOpt.value
            } | ConvertTo-Json -Compress -Depth 5
            [System.IO.File]::WriteAllText("$tempDir\okta-fp11-select-ov.json", $selBody, [System.Text.Encoding]::UTF8)

            $selResult = & curl.exe -s `
                -X POST $selectAuth.href `
                -H "Content-Type: application/ion+json; okta-version=1.0.0" `
                -H "Accept: application/ion+json; okta-version=1.0.0" `
                -b "$tempDir\okta-fp-cookies5.txt" `
                -d "@$tempDir\okta-fp11-select-ov.json" `
                --connect-timeout 10 --max-time 20

            [System.IO.File]::WriteAllText("$tempDir\okta-fp11-select-ov-result.json", $selResult, [System.Text.Encoding]::UTF8)
            $selObj = $selResult | ConvertFrom-Json

            if ($selObj.messages) {
                foreach ($msg in $selObj.messages.value) {
                    Write-Host "  [$($msg.class)] $($msg.message)" -ForegroundColor Yellow
                }
            }

            if ($selObj.remediation) {
                Write-Host "`nRemediations after selecting OV:" -ForegroundColor Green
                foreach ($rem in $selObj.remediation.value) {
                    Write-Host "  $($rem.name) -> $($rem.href)"
                }
            }

            # THE KEY: currentAuthenticatorEnrollment.contextualData should have the challenge JWT
            if ($selObj.currentAuthenticatorEnrollment -and $selObj.currentAuthenticatorEnrollment.value) {
                $cae = $selObj.currentAuthenticatorEnrollment.value
                Write-Host "`n>>> AUTHENTICATOR ENROLLMENT:" -ForegroundColor Green
                Write-Host "  Key: $($cae.key)"
                Write-Host "  Type: $($cae.type)"
                Write-Host "  DisplayName: $($cae.displayName)"

                if ($cae.contextualData) {
                    Write-Host "`n!!! CONTEXTUAL DATA FOUND !!!" -ForegroundColor Red

                    if ($cae.contextualData.challengeContext) {
                        Write-Host "challengeContext:" -ForegroundColor Yellow
                        Write-Host ($cae.contextualData.challengeContext | ConvertTo-Json -Depth 10)
                    }

                    if ($cae.contextualData.challenge) {
                        Write-Host "`n!!! CHALLENGE JWT FOUND !!!" -ForegroundColor Red
                        Write-Host "Value: $($cae.contextualData.challenge.value)"

                        # Save the challenge JWT
                        $cae.contextualData.challenge.value | Out-File "$tempDir\okta-fp11-challenge-jwt.txt" -NoNewline -Encoding ascii
                        Write-Host "Saved to okta-fp11-challenge-jwt.txt"
                    }

                    # Full contextualData dump
                    Write-Host "`nFull contextualData:" -ForegroundColor Yellow
                    Write-Host ($cae.contextualData | ConvertTo-Json -Depth 10)
                }

                if ($cae.methods) {
                    Write-Host "`nMethods:"
                    foreach ($m in $cae.methods) {
                        Write-Host "  type=$($m.type)"
                    }
                }
            }

            # Check for challenge-poll or device-challenge-poll remediation
            $pollRem = $selObj.remediation.value | Where-Object { $_.name -match "poll|device-challenge|launch" }
            if ($pollRem) {
                Write-Host "`n>>> POLL/DEVICE-CHALLENGE REMEDIATION FOUND:" -ForegroundColor Red
                foreach ($pr in $pollRem) {
                    Write-Host "  $($pr.name) -> $($pr.href)"
                }

                # Try the first poll
                $firstPoll = $pollRem[0]
                Write-Host "`nCalling $($firstPoll.name)..."

                $pollBody = '{"stateHandle":"' + $selObj.stateHandle + '"}'
                [System.IO.File]::WriteAllText("$tempDir\okta-fp11-poll.json", $pollBody, [System.Text.Encoding]::UTF8)

                $pollResult = & curl.exe -s `
                    -X POST $firstPoll.href `
                    -H "Content-Type: application/ion+json; okta-version=1.0.0" `
                    -H "Accept: application/ion+json; okta-version=1.0.0" `
                    -b "$tempDir\okta-fp-cookies5.txt" `
                    -d "@$tempDir\okta-fp11-poll.json" `
                    --connect-timeout 10 --max-time 20

                [System.IO.File]::WriteAllText("$tempDir\okta-fp11-poll-result.json", $pollResult, [System.Text.Encoding]::UTF8)
                Write-Host "Poll response length: $($pollResult.Length)"

                $pollObj = $pollResult | ConvertFrom-Json
                if ($pollObj.currentAuthenticatorEnrollment -and $pollObj.currentAuthenticatorEnrollment.value.contextualData) {
                    Write-Host "`n>>> CONTEXTUAL DATA FROM POLL:" -ForegroundColor Red
                    Write-Host ($pollObj.currentAuthenticatorEnrollment.value.contextualData | ConvertTo-Json -Depth 10)

                    if ($pollObj.currentAuthenticatorEnrollment.value.contextualData.challenge) {
                        Write-Host "`n!!! CHALLENGE JWT FROM POLL !!!" -ForegroundColor Red
                        $jwt = $pollObj.currentAuthenticatorEnrollment.value.contextualData.challenge.value
                        Write-Host $jwt
                        $jwt | Out-File "$tempDir\okta-fp11-challenge-jwt.txt" -NoNewline -Encoding ascii
                    }
                }

                if ($pollObj.remediation) {
                    Write-Host "`nPoll remediations:"
                    foreach ($rem in $pollObj.remediation.value) {
                        Write-Host "  $($rem.name) -> $($rem.href)"
                    }
                }
            }

            # Full response dump for analysis
            Write-Host "`n>>> FULL SELECT-OV RESPONSE (first 3000 chars):" -ForegroundColor DarkGray
            $selResultTrunc = $selResult.Substring(0, [Math]::Min(3000, $selResult.Length))
            Write-Host $selResultTrunc
        } else {
            Write-Host "Okta Verify not in authenticator options!" -ForegroundColor Red
        }
    }
} elseif ($launchAuth) {
    Write-Host "`nSTEP 4: launch-authenticator detected!" -ForegroundColor Red
    Write-Host ($launchAuth | ConvertTo-Json -Depth 10)
} elseif ($challengePoll) {
    Write-Host "`nSTEP 4: challenge-poll detected!" -ForegroundColor Red
    Write-Host ($challengePoll | ConvertTo-Json -Depth 10)
} else {
    Write-Host "`nNo expected remediation found after identify." -ForegroundColor Red
    Write-Host "Full identify response (first 2000 chars):"
    Write-Host $idResult.Substring(0, [Math]::Min(2000, $idResult.Length))
}

Write-Host "`n================================================================"
Write-Host "DONE" -ForegroundColor Cyan
Write-Host "================================================================"
