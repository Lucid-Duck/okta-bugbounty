# Okta Coordinator Service Named Pipe Impersonation - Local Privilege Escalation

## Summary

A standard (non-admin) Windows user can achieve NT AUTHORITY\SYSTEM code execution by exploiting a named pipe impersonation vulnerability in the Okta Coordinator Service. The service accepts a user-controlled `PipeName` field in IPC messages and connects back to that pipe as SYSTEM to send status notifications. An attacker creates a rogue pipe server, sends a trigger message, and impersonates the SYSTEM token when the service connects.

This is a **deterministic, instant** privilege escalation with no race condition, no file planting, and no prerequisites beyond Okta Verify being installed.

## Severity

**P1 - Local Privilege Escalation to SYSTEM (Deterministic)**

- Attack complexity: Very Low (single IPC message)
- Privileges required: Standard user account
- User interaction: None
- Impact: Full SYSTEM code execution, instant, repeatable
- No race condition, no timing dependency, no file system manipulation

## Affected Component

- **Product:** Okta Verify for Windows (OktaVerify-x64.msi)
- **Version tested:** 6.7.1.0 (Coordinator Service v0.8.7.0)
- **Specific components:**
  - `Okta.Coordinator.Service.exe` -- runs as NT AUTHORITY\SYSTEM (LocalSystem)
  - `Okta.AutoUpdate.Executor.dll` -- contains `ApplicationInstaller.PipeRequestHandler()`, `NamedPipeClient.SendMessage()`, `NamedPipeServer.StartNamedPipeServer()`
  - Named pipe: `Okta.Coordinator.pipe` -- ACL grants BUILTIN\Users FullControl

## Root Cause

### 1. User-controlled pipe callback

The `IPCMessage` data contract includes a `PipeName` field (line 1251 of `Okta.AutoUpdate.Executor.cs`):

```csharp
[DataMember]
public string PipeName { get; set; }
```

When `PipeName` is non-empty (line 219), the service creates a `NamedPipeClient` and uses it to send notifications back to the caller:

```csharp
if (!string.IsNullOrWhiteSpace(message.PipeName))
{
    namedPipeClient = new NamedPipeClient();
}
```

### 2. SYSTEM connects to attacker-controlled pipe

`SendNotification()` (line 347) calls `pipeClient.SendUpdateNotificationMessage(ipcMessage.PipeName, ...)` which calls `SendMessage()` (line 1213):

```csharp
private void SendMessage<T>(T message, string pipeName)
{
    using NamedPipeClientStream namedPipeClientStream =
        new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
    namedPipeClientStream.Connect(10000);
    // ... serializes and writes notification data ...
}
```

The `pipeName` parameter comes directly from the user-controlled `IPCMessage.PipeName` with **zero validation**. The SYSTEM service connects to whatever pipe name the attacker specified.

### 3. Coordinator pipe grants BUILTIN\Users FullControl

The `StartNamedPipeServer()` method (line 1266) defaults to `onlyAllowAdmins: false`:

```csharp
public NamedPipeServerStream StartNamedPipeServer(string pipeName)
{
    return StartNamedPipeServer(pipeName, onlyAllowAdmins: false);
}
```

When `onlyAllowAdmins` is false (line 1275), the ACL grants `BuiltinUsersSid` FullControl:

```csharp
PipeAccessRule rule2 = new PipeAccessRule(
    onlyAllowAdmins
        ? new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
        : new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
    PipeAccessRights.FullControl, AccessControlType.Allow);
```

Any standard user can connect and send messages.

### 4. No validation on PipeName

There is no check on the `PipeName` field -- no allowlist, no format validation, no restriction to known pipe names. The attacker can specify any pipe name and the SYSTEM service will connect to it.

## Attack Flow

### Prerequisites
- Standard user account on a Windows machine with Okta Verify installed
- Okta Coordinator Service running (it runs automatically as LocalSystem)

### Steps

1. **Create rogue pipe server:** Standard user creates a named pipe server (e.g., `\\.\pipe\Okta.LPE.random`) with permissive ACLs allowing SYSTEM to connect.

2. **Send trigger message:** Standard user connects to `\\.\pipe\Okta.Coordinator.pipe` and sends a JSON `IPCMessage` with:
   - `PipeName` set to the rogue pipe name
   - Valid `AutoUpdateUrl` (any `https://*.okta.com` URL)
   - Valid `ReleaseChannel` (`GA`, `EA`, or `BETA`)
   - Valid `ArtifactType` (e.g., `OktaVerify`)
   - Low `CurrentInstalledVersion` to trigger update logic

3. **SYSTEM connects back:** The Coordinator Service processes the message as SYSTEM. At multiple points (UpdateFound, DownloadCompleted, errors, etc.), it calls `SendNotification()` which connects to the attacker's rogue pipe.

4. **Impersonate SYSTEM:** The attacker's pipe server calls `ImpersonateNamedPipeClient()` on the connected handle, obtaining the SYSTEM token. The attacker can then:
   - Execute code as SYSTEM
   - Duplicate the token to a primary token via `DuplicateTokenEx()`
   - Launch processes as SYSTEM via `CreateProcessWithTokenW()`

## Evidence

### Exploit output (from standard user session):

```
=== Okta Pipe Impersonation LPE - EXPLOIT MODE ===

[*] Current user: SKINNYD\uglyt
[*] Creating rogue pipe server: Okta.LPE.9eb88c7a
[*] Rogue pipe server listening
[*] Sending trigger IPCMessage to Okta.Coordinator.pipe...
[*] PipeName field set to: Okta.LPE.9eb88c7a
[+] Trigger message sent successfully
[+] GOT CONNECTION on rogue pipe!
[+] Received 238 bytes from SYSTEM service
[+] Data: {"Databag":{"OrgUrl":"https:\/\/trial-3887003.okta.com","Channel":"GA",
    "ArtifactType":"OktaVerify","CurrentVersion":"1.0.0.0",...},"EndConnection":true,...
[+] IMPERSONATING: NT AUTHORITY\SYSTEM
[+] IsSystem: True

[!!!] ===== NT AUTHORITY\SYSTEM TOKEN OBTAINED ===== [!!!]

[+] Wrote SYSTEM proof marker: C:\ProgramData\Okta\PIPE-LPE-PROOF.txt
[+] Duplicated primary SYSTEM token (handle: 0x9EC)
[+] This token can be used with CreateProcessWithTokenW for SYSTEM shell

========================================
  EXPLOITATION SUCCESSFUL
  NT AUTHORITY\SYSTEM token obtained
  from standard user account
========================================
```

### Proof marker file (written as SYSTEM):

```
Okta Verify Pipe Impersonation LPE PoC
Timestamp: 2026-03-07T06:17:57.1198533Z
Impersonated Identity: NT AUTHORITY\SYSTEM
IsSystem: True
Exploit: Named pipe impersonation via Okta.Coordinator.pipe PipeName callback
Pipe: Okta.LPE.9eb88c7a
```

### Service confirmation:

```
Service: Okta Auto Update Service
Status: Running
Runs as: LocalSystem
Coordinator binary: C:\Program Files\Okta\UpdateService\Okta.Coordinator.Service.exe v0.8.7.0
Pipe: Okta.Coordinator.pipe -- BUILTIN\Users FullControl
```

## Comparison with MSI Config Injection LPE

| Attribute | Pipe Impersonation (this finding) | MSI Config Injection |
|-----------|----------------------------------|---------------------|
| Complexity | Very Low -- one IPC message | Medium -- junction + config + DLL + timing |
| Race condition | None -- deterministic | Yes -- TOCTOU between seq 1401-4001 |
| Prerequisites | Service running (always is) | WOV directory must not exist |
| Trigger | Instant -- attacker-initiated | Requires upgrade (auto or triggered) |
| Files planted | Zero | 3+ (junction, config, DLL) |
| Detection surface | Minimal -- just a pipe connection | Multiple file system artifacts |

## Decompiled Source References

From `Okta.AutoUpdate.Executor.dll` (extracted from Okta Verify 6.7.1.0):

- `IPCMessage.PipeName` -- line 1251 (user-controlled field)
- `PipeRequestHandler()` -- lines 181-331 (message processing)
- `PipeName check` -- line 219 (only checks for non-empty)
- `SendNotification()` -- lines 347-389 (triggers callback)
- `SendUpdateNotificationMessage()` -- line 1206-1210 (passes PipeName to SendMessage)
- `SendMessage()` -- lines 1213-1227 (SYSTEM connects to attacker pipe)
- `StartNamedPipeServer()` -- lines 1266-1279 (BUILTIN\Users FullControl ACL)

## Remediation Recommendations

1. **Remove or validate PipeName.** Either remove the callback pipe functionality entirely, or restrict `PipeName` to a hardcoded allowlist (e.g., only `Okta.Shim.pipe`).

2. **Restrict the Coordinator pipe ACL.** Change from `BUILTIN\Users FullControl` to `BUILTIN\Administrators FullControl` (like the Shim pipe already does at line 169 of `Okta.AutoUpdate.Shim.cs` with `onlyAllowAdmins: true`).

3. **Use impersonation on the callback.** When connecting back to the notification pipe, impersonate the original caller rather than connecting as SYSTEM.

4. **Authenticate IPC messages.** Add a shared secret or cryptographic authentication to the IPC protocol so only the legitimate OktaVerify.exe process can send messages.

## PoC Files

- `poc/okta-pipe-impersonation/okta-pipe-impersonation-poc.ps1` -- Full exploit script (Check, Exploit, Cleanup modes)
