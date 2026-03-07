# Okta Verify MSI Custom Action Config Injection - Local Privilege Escalation

## Summary

A standard (non-admin) Windows user can achieve NT AUTHORITY\SYSTEM code execution by hijacking the Okta Verify MSI installer's backup/restore custom actions. The installer backs up and restores the Okta Coordinator Service .NET config file through `C:\Windows\Temp\WOV\C\` -- a path writable by standard users. By pre-creating this path as an NTFS junction pointing to an attacker-controlled directory, the attacker can swap the config file between the backup and restore phases, injecting a malicious .NET `appDomainManagerAssembly` directive that loads attacker code when the SYSTEM service starts.

## Severity

**P1 - Local Privilege Escalation to SYSTEM**

- Attack complexity: Low (file plant + wait for auto-update)
- Privileges required: Standard user account
- User interaction: None (auto-update triggers the exploit)
- Impact: Full SYSTEM code execution on any Windows machine running Okta Verify

## Affected Component

- **Product:** Okta Verify for Windows (OktaVerify-x64.msi)
- **Version tested:** 6.7.1.0
- **Specific components:**
  - `OktaVerifyInstaller.CustomActions.dll` (embedded in MSI Binary table as `bin_customactions`)
  - `CustomActions.BackupData()` -- immediate CA, sequence 1401
  - `CustomActions.RestoreData()` -- deferred SYSTEM CA, sequence 4001
  - `BackupUtilities.BackupFile()` -- follows junctions, no integrity check
  - `RestoreConfiguration()` -- `File.Copy` with `overwrite: true`, no signature verification
  - Okta Coordinator Service (`Okta.Coordinator.Service.exe`) -- runs as LocalSystem

## Root Cause

Three independent issues combine into an exploitable chain:

### 1. Backup path in world-writable directory

`GetOktaVerifyProgramDataBackupInfo()` uses `EnvironmentVariableTarget.Machine` to resolve TEMP:

```csharp
ovConfigBackup = Path.Combine(
    Environment.GetEnvironmentVariable("TEMP", EnvironmentVariableTarget.Machine),
    "WOV\\C");
```

The machine-level TEMP registry value (`HKLM\...\Session Manager\Environment\TEMP`) is `%SystemRoot%\TEMP` = `C:\WINDOWS\TEMP`. This directory grants standard users `CreateFiles, AppendData` with `ContainerInherit` -- meaning users can create arbitrary directories and junctions here.

### 2. No junction/symlink protection on backup operations

`BackupFile()` and `RestoreConfiguration()` use `File.Copy` which transparently follows NTFS junctions. Neither method checks for reparse points on the backup directory:

```csharp
// BackupFile -- writes through junction to attacker's directory
File.Copy(fileInfo.FullName, Path.Combine(destination, fileInfo.Name), overwrite: true);

// RestoreConfiguration -- reads through junction from attacker's directory
File.Copy(text, text2, overwrite: true);  // text2 = Program Files target
```

### 3. No integrity verification on restored config

`RestoreConfiguration()` copies the backed-up config to `C:\Program Files\Okta\UpdateService\Okta.Coordinator.Service.exe.config` without verifying its integrity, hash, or signature. Whatever is in the backup location gets written to Program Files.

### 4. Wide TOCTOU window

BackupData runs at sequence 1401 (immediate, before InstallInitialize). RestoreData runs at sequence 4001 (deferred, after InstallFiles). Between them: RemoveExistingProducts, CloseOktaVerify, file operations, service removal -- several seconds to minutes of time for the attacker to swap the config file.

### 5. User-writable DLL hosting in ProgramData

`C:\ProgramData\Okta\` has `BUILTIN\Users: Write (ContainerInherit)`, allowing standard users to place DLLs there. Combined with .NET `codeBase` assembly binding in the injected config, this provides the code execution payload hosting.

## Attack Flow

### Prerequisites
- Standard user account on a Windows machine with Okta Verify installed
- `C:\Windows\Temp\WOV` does not yet exist (pre-first-upgrade, or after Temp cleanup)

### Steps

1. **Plant junction:** Standard user creates `C:\Windows\Temp\WOV\` directory, then `WOV\C` as an NTFS junction pointing to an attacker-owned directory (e.g., `%LOCALAPPDATA%\OktaLPE\staging\`). Sets `Everyone: FullControl` on the junction target so files written through the junction inherit permissive ACLs.

2. **Plant payload DLL:** Copy a strong-named .NET assembly (`OktaLPE.dll`) containing an `AppDomainManager` subclass to `C:\ProgramData\Okta\OktaLPE.dll`. The DLL's `InitializeNewDomain()` executes arbitrary code.

3. **Plant malicious config:** Place a crafted `Okta.Coordinator.Service.exe.config` in the junction target directory containing:
   ```xml
   <runtime>
     <appDomainManagerAssembly value="OktaLPE, Version=1.0.0.0, ..." />
     <appDomainManagerType value="OktaLPE.LPEManager" />
     <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
       <dependentAssembly>
         <assemblyIdentity name="OktaLPE" publicKeyToken="..." />
         <codeBase version="1.0.0.0" href="file:///C:/ProgramData/Okta/OktaLPE.dll" />
       </dependentAssembly>
     </assemblyBinding>
   </runtime>
   ```

4. **Wait for upgrade trigger:** Okta Verify auto-update checks periodically. When an upgrade MSI runs:

5. **BackupData (seq 1401, immediate):** Backs up the real `Okta.Coordinator.Service.exe.config` from Program Files through the junction into the attacker's directory. The file inherits `Everyone: FullControl` from the target directory ACLs.

6. **TOCTOU swap:** FileSystemWatcher detects the write. Attacker deletes the real config (possible because of inherited FullControl ACL) and replaces with the malicious config. Wide window between seq 1401 and 4001.

7. **RestoreData (seq 4001, deferred SYSTEM):** Reads from `C:\Windows\Temp\WOV\C\` (follows junction), gets the attacker's malicious config, copies it to `C:\Program Files\Okta\UpdateService\Okta.Coordinator.Service.exe.config` as SYSTEM.

8. **Service restart:** Okta Coordinator Service starts with the injected config. .NET runtime loads `OktaLPE.dll` from `C:\ProgramData\Okta\` via the `appDomainManagerAssembly` + `codeBase` directives. Attacker code executes as NT AUTHORITY\SYSTEM.

## Evidence

### 1. Backup path resolves to world-writable location (confirmed)

```
Machine TEMP: C:\WINDOWS\TEMP
BUILTIN\Users : CreateFiles, AppendData, ExecuteFile, Synchronize (Allow)
  Inherit=ContainerInherit
```

Standard user can create directories and junctions in `C:\Windows\Temp`:
```
SUCCESS: Created C:\Windows\Temp\WOV_test_6cc32a0b
SUCCESS: Junction created at C:\Windows\Temp\WOV_junc_2943adb1
```

### 2. File.Copy follows junctions transparently (confirmed)

Test: Created junction, wrote file through it, verified ACL inheritance:
```
File.Copy succeeded
Owner: SKINNYD\uglyt
  Everyone : FullControl (Allow)
```

File swap simulation:
```
Restored file contents:
<configuration>MALICIOUS - PWNED</configuration>
```

### 3. .NET AppDomainManager injection works (confirmed)

Test with strong-named DLL and codeBase pointing to `C:\ProgramData\Okta\OktaLPE.dll`:
```
DomainManager: OktaLPE.LPEManager     <-- loaded before Main()
Location: C:\ProgramData\Okta\OktaLPE.dll  <-- from user-writable dir

Marker file created:
Okta Verify LPE PoC - SYSTEM Code Execution
Running as: skinnyd\uglyt
Process: TestLoader2 (PID 75548)
```

### 4. ProgramData\Okta is user-writable (confirmed)

```
C:\ProgramData\Okta ACLs:
  BUILTIN\Users : Write (Allow) Inherit=ContainerInherit
```

### 5. MSI sequence confirms wide TOCTOU window (confirmed)

```
[1401] act_backup_data        <-- Immediate CA (writes backup)
[1402] RemoveExistingProducts
[1500] InstallInitialize
[1502] CloseOktaVerify
  ... (file operations, service removal, etc.) ...
[4000] InstallFiles
[4001] act_restore_data        <-- Deferred SYSTEM CA (reads backup)
```

Both CAs have condition: `WIX_UPGRADE_DETECTED OR INSTALLMATEVERSIONINSTALLED` (upgrade only).

### 6. Existing WOV backup on test machine (confirms CAs execute)

```
C:\Windows\Temp\WOV\C\Okta.Coordinator.Service.exe.config
Owner: NT AUTHORITY\SYSTEM
Contents: (legitimate config -- from previous upgrade)
```

## Decompiled Source References

Extracted from `bin_customactions` Binary table entry in `OktaVerify-x64.msi` v6.7.1.0. The WiX DTF DLL embeds a CAB at offset 237056 containing the .NET assemblies.

- `OktaVerifyInstaller.CustomActions.dll` -> `CustomActions.cs`
  - `GetOktaVerifyProgramDataBackupInfo()` -- line 119-124
  - `BackupData()` -- line 127-159
  - `RestoreData()` -- line 162-181
  - `RestoreConfiguration()` -- line 463-484
  - `BackupUtilities.BackupFile()` -- line 747-761
  - `BackupUtilities.CopyFolder()` -- line 677-726

## Remediation Recommendations

1. **Use a secure backup location:** Don't use `C:\Windows\Temp` for privileged backup operations. Use a SYSTEM-only directory like `C:\Windows\SystemTemp\` or a randomly-named subdirectory with restrictive ACLs.

2. **Validate backup integrity:** Hash or sign the backed-up config before writing. Verify integrity before restoring.

3. **Check for reparse points:** Before any privileged file operation, check whether the path or any component contains junction/symlink reparse points using `FileAttributes.ReparsePoint`.

4. **Restrict ProgramData ACLs:** `C:\ProgramData\Okta\` should not be writable by BUILTIN\Users. Use specific ACLs for the Okta service account only.

5. **Use impersonation for backup:** BackupData should impersonate the calling user when creating backup directories, preventing standard users from pre-creating the path.

## PoC Files

- `poc/okta-msi-config-lpe/okta-lpe-poc.ps1` -- Full exploit script (Plant, Monitor, Check, Cleanup)
- `poc/okta-msi-config-lpe/okta-lpe-payload.cs` -- Payload DLL source (AppDomainManager)
- `poc/okta-msi-config-lpe/OktaLPE.csproj` -- Build project for strong-named DLL
- `poc/okta-msi-config-lpe/key.snk` -- Strong name key
