# Okta Verify 6.6.2.0 - SYSTEM Service Connects to Attacker-Controlled Named Pipe

## Summary

The Okta Coordinator Service (NT AUTHORITY\SYSTEM) accepts IPC messages from any
local user via `Okta.Coordinator.pipe`. The IPCMessage contains a `PipeName` field.
After processing the update check, the SYSTEM service creates a NamedPipeClientStream
and connects to whatever pipe name the attacker specified -- with zero validation.

This means a standard user can:
1. Create a named pipe server
2. Send an IPCMessage to the SYSTEM service with PipeName pointing to their pipe
3. The SYSTEM service connects to the attacker's pipe as NT AUTHORITY\SYSTEM
4. Attacker calls ImpersonateNamedPipeClient() to get a SYSTEM token

## Code Flow

### Step 1: Attacker sends IPCMessage with controlled PipeName

IPCMessage.cs:
```csharp
[DataContract]
public class IPCMessage
{
    [DataMember] public string PipeName { get; set; }  // Attacker-controlled
    [DataMember] public string AutoUpdateUrl { get; set; }
    // ... other fields
}
```

### Step 2: SYSTEM service checks PipeName and creates client

ApplicationInstaller.cs lines 127-130:
```csharp
if (!string.IsNullOrWhiteSpace(message.PipeName))
{
    namedPipeClient = new NamedPipeClient();
}
```

### Step 3: SYSTEM service connects to attacker's pipe

ApplicationInstaller.cs line 274:
```csharp
pipeClient.SendUpdateNotificationMessage(ipcMessage.PipeName, upgradeNotificationIPCMessage);
```

NamedPipeClient.cs lines 30-44:
```csharp
private void SendMessage<T>(T message, string pipeName)
{
    using NamedPipeClientStream namedPipeClientStream =
        new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
    namedPipeClientStream.Connect(10000);  // CONNECTS TO ATTACKER PIPE AS SYSTEM
    // ... serializes and writes data
}
```

### No Validation Present

- No check that PipeName points to a legitimate Okta pipe
- No verification the pipe was created by a trusted process
- No ACL checking on the target pipe
- No origin validation linking the callback to the original requester

## Gating Condition

The callback only fires after the update flow progresses. The service needs
GetUpdateAsync to return metadata OR hit certain error paths. The callback sends
UpgradeNotificationIPCMessage which contains:

```csharp
[DataContract]
public class UpgradeNotificationIPCMessage
{
    [DataMember] public NotificationType NotificationType { get; set; }
    [DataMember] public Dictionary<string, string> Databag { get; set; }
    [DataMember] public bool EndConnection { get; set; }
    [DataMember] public Exception Exception { get; set; }
}
```

The Databag contains OrgUrl, Channel, ArtifactType, CurrentVersion, ProxyInUse,
NewVersion, and exception details from SYSTEM context.

## Confirmed Facts

- Okta.Coordinator.pipe is accessible to BUILTIN\Users with FullControl (CONFIRMED)
- IPCMessage is deserialized from attacker's JSON (CONFIRMED - PoC sent messages)
- Service runs as NT AUTHORITY\SYSTEM (CONFIRMED via WMI)
- PipeName field is not validated before use (CONFIRMED via code review)
- NamedPipeClient connects to arbitrary pipe name (CONFIRMED via code review)

## Outstanding

- Need to trigger the callback code path (requires update metadata OR error path)
- Need to verify ImpersonateNamedPipeClient works on the connection
- Full end-to-end PoC not yet built

## Files

- update-service-executor/Okta.AutoUpdate.Executor/IPCMessage.cs
- update-service-executor/Okta.AutoUpdate.Executor/ApplicationInstaller.cs (lines 127-130, 274)
- update-service-executor/Okta.AutoUpdate.Executor/NamedPipeClient.cs (lines 23-44)
- update-service-executor/Okta.AutoUpdate.Executor/UpgradeNotificationIPCMessage.cs
