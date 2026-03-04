# Okta Verify 6.6.2.0 - Unauthenticated Named Pipe Injection + SYSTEM Callback

## Status: END-TO-END CONFIRMED (2026-03-03)

## Summary

The Okta Auto Update Service (NT AUTHORITY\SYSTEM) accepts unauthenticated IPC
messages from any local user via `Okta.Coordinator.pipe`. The pipe grants
`BUILTIN\Users` FullControl with zero authentication. A standard user can:

1. Inject crafted IPCMessage to trigger update checks as SYSTEM
2. Force SYSTEM to connect to attacker-controlled named pipe via PipeName field
3. Force SYSTEM to make HTTPS requests to any Okta-domain URL (SSRF)
4. Receive internal configuration data from SYSTEM context
5. If a production org with artifacts API is used: trigger arbitrary directory
   deletion via junction at `C:\Windows\Temp\Okta-AutoUpdate`

## Live Test Results (2026-03-03)

### CONFIRMED: SYSTEM Callback to Attacker Pipe

Standard user (SKINNYD\uglyt, Is Admin: False) injected IPCMessage with PipeName
pointing to an attacker-created pipe. SYSTEM connected within ~1 second:

```
[20:56:37.244] Pipe closed. Server should now process the message.
[20:56:38.257] *** CONNECTION RECEIVED on callback pipe! ***
[20:56:38.257] Pipe connected: True
```

### CONFIRMED: Information Disclosure via SYSTEM Callback

SYSTEM sent internal configuration data through the attacker's pipe:

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
  "Exception": null,
  "NotificationType": 12
}
```

### NOT CONFIRMED: SYSTEM Token Impersonation

ImpersonateNamedPipeClient() failed with Win32 error 1368 (ERROR_CANT_OPEN_ANONYMOUS).
The Okta NamedPipeClient uses `TokenImpersonationLevel.None` (maps to
SECURITY_ANONYMOUS), which prevents the pipe server from impersonating the client.

```csharp
// NamedPipeClient.cs - default constructor uses None impersonation
new NamedPipeClientStream(".", pipeName, PipeDirection.InOut)
// Equivalent to TokenImpersonationLevel.None -> SECURITY_ANONYMOUS
```

### NOT CONFIRMED: Arbitrary Directory Deletion via Junction

CleanPreviousDownloads() only fires after GetUpdateAsync returns valid metadata
with a higher version number (ApplicationInstaller.cs line 184). The preview org
`bugcrowd-pam-4593.oktapreview.com` returns 404 for the artifacts API:

```
GET /api/v1/artifacts/OktaVerify/latest?releaseChannel=GA&bucketId=0
404: "Not found: Resource not found: OktaVerify (ArtifactVersionType)"
```

A production org with Okta Verify auto-update configured would return valid
metadata, allowing CleanPreviousDownloads to fire and follow the junction.

## Key Discovery: CurrentInstalledVersion is System.Version, Not String

The IPCMessage.CurrentInstalledVersion field is type `System.Version`, not string.
DataContractJsonSerializer expects `{"_Build":0,"_Major":1,"_Minor":0,"_Revision":0}`
format, not `"1.0.0.0"`. Using the wrong type causes silent deserialization failure
where the server never processes the message.

## Attack Chain Details

### Pipe Injection (No Auth Required)

Okta.Coordinator.pipe grants BUILTIN\Users FullControl:

```csharp
// NamedPipeServer.cs - pipe ACL
PipeAccessRule rule2 = new PipeAccessRule(
    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
    PipeAccessRights.FullControl,
    AccessControlType.Allow);
```

Messages are deserialized with DataContractJsonSerializer. No authentication,
no encryption, no caller identity validation.

### SYSTEM Callback Flow

```
Standard user                     SYSTEM Service
    |                                   |
    |---> Connect to coordinator pipe   |
    |---> Send IPCMessage with:         |
    |     - AutoUpdateUrl (Okta domain) |
    |     - PipeName (attacker pipe)    |
    |     - CurrentInstalledVersion     |
    |     (close pipe -> EOF)           |
    |                                   |
    |     [Deserializes message]        |
    |     [Validates URL is Okta domain]|
    |     [Makes HTTPS request as SYSTEM]
    |     [Gets metadata (or null)]     |
    |     [If metadata: CleanPreviousDownloads()]
    |                                   |
    |<--- Connects to attacker pipe ----|
    |<--- Sends UpgradeNotification ----|
    |     (OrgUrl, Channel, Version...) |
```

### CleanPreviousDownloads Junction Attack (Code-Provable)

```csharp
// Helper.cs - follows junctions, no symlink check
public static void CleanPreviousDownloads(ILogger logger)
{
    string text = Path.Combine(Path.GetTempPath(), "Okta-AutoUpdate");
    // For SYSTEM: C:\Windows\Temp\Okta-AutoUpdate
    if (Directory.Exists(text))
    {
        string[] directories = Directory.GetDirectories(text, "*", SearchOption.AllDirectories);
        for (int i = 0; i < directories.Length; i++)
        {
            Directory.Delete(directories[i], recursive: true);
            // Follows junction -> deletes attacker-chosen target
        }
    }
}
```

Standard user creates: `C:\Windows\Temp\Okta-AutoUpdate` -> `C:\target\dir`
(BUILTIN\Users has CreateFiles+AppendData on `C:\Windows\Temp`)

### Retry Cache (DoS Vector)

GetUpdateAsync uses an in-memory singleton cache (CacheData.Instance) with a
3600-second (1 hour) retry delay after failed checks. An attacker can trigger
a failed update check, then the service refuses to check again for 1 hour --
blocking legitimate Okta Verify updates for all users on the system.

## Impact Summary

| Finding | Severity | Status |
|---------|----------|--------|
| Unauthenticated pipe injection | Medium | CONFIRMED |
| SYSTEM callback to attacker pipe | Medium | CONFIRMED |
| Information disclosure via callback | Low-Medium | CONFIRMED |
| SSRF within Okta domains | Medium | CONFIRMED |
| Update check DoS (1hr cache poison) | Low | CONFIRMED |
| SYSTEM arbitrary directory deletion | High | Code-provable, needs prod org |
| SYSTEM token impersonation | Critical | BLOCKED (anonymous impersonation) |

## PoC Files

- `poc/okta-lpe-combined/Program.cs` - Combined PoC with both tests
- `poc/okta-lpe-combined/okta-lpe-combined.csproj` - .NET 8 project

### Build & Run

```bash
cd poc/okta-lpe-combined
dotnet publish -c Release -r win-x64 --self-contained false

# Run as standard user
runas /trustlevel:0x20000 "path\to\okta-lpe-combined.exe impersonation"
runas /trustlevel:0x20000 "path\to\okta-lpe-combined.exe deletion"
runas /trustlevel:0x20000 "path\to\okta-lpe-combined.exe both"
```

## Source Files (Decompiled from Okta.AutoUpdate.Executor.dll v0.8.7.0)

- `Okta.AutoUpdate.Executor/NamedPipeServer.cs` - Pipe creation with Users FullControl
- `Okta.AutoUpdate.Executor/ApplicationInstaller.cs` - Message handler + PipeName callback
- `Okta.AutoUpdate.Executor/NamedPipeClient.cs` - SYSTEM connects to arbitrary pipe
- `Okta.AutoUpdate.Executor/Helper.cs` - CleanPreviousDownloads follows junctions
- `Okta.AutoUpdate.Executor/AutoUpdateExecutor.cs` - Update fetch + retry cache
- `Okta.AutoUpdate.Executor/IPCMessage.cs` - CurrentInstalledVersion is Version type
- `Okta.AutoUpdate.Executor.Implementation/ClientConfiguration.cs` - SSL pinning config

## Remaining Avenues

1. **Find production org with artifacts API**: A real customer org with Okta Verify
   auto-update configured should return valid metadata, enabling the junction attack
2. **Bypass anonymous impersonation**: Research if there's a way to force the
   NamedPipeClientStream to connect with higher impersonation level (unlikely)
3. **Exploit SSRF within Okta domains**: The service connects to any `*.okta.com`,
   `*.oktapreview.com`, `*.oktacdn.com` etc. URL as SYSTEM -- potential for
   SSRF-based attacks against Okta infrastructure
4. **Alternative file operations**: Check if other code paths in the update flow
   perform file operations before the metadata check
