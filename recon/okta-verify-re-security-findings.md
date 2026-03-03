# Okta Verify 6.6.2.0 Windows -- Complete RE Security Analysis

## Binary Overview

- **Architecture:** .NET 4.7.2 WPF application (decompilable with ILSpy)
- **Total decompiled files:** 1,348 .cs files across 16 assemblies
- **Key components:** Auto-update SYSTEM service, OIDC auth, Device Access, SDK crypto
- **Native DLLs:** OktaVerify.Native.dll, Okta.Devices.SDK.Windows.Native.dll (C/C++, need Ghidra)
- **Obfuscation:** String obfuscation throughout (runtime decode functions), method name obfuscation in tamper protection
- **Tamper protection:** DigitalAI integrity checking with checksums
- **Service:** `Okta Auto Update Service` runs as `NT AUTHORITY\SYSTEM` (`Okta.Coordinator.Service.exe`)

---

## FINDING 1: SYSTEM Service Arbitrary Directory Deletion via Junction (HIGH - LPE PRIMITIVE)

**Files:** `Okta.AutoUpdate.Executor/Helper.cs` (lines 79-101), `ApplicationInstaller.cs` (line 184)
**Service:** Runs as NT AUTHORITY\SYSTEM (CONFIRMED)
**Target path:** `C:\Windows\Temp\Okta-AutoUpdate\`

### Vulnerability

The SYSTEM-level auto-update service calls `CleanPreviousDownloads()` which recursively enumerates and deletes subdirectories under `C:\Windows\Temp\Okta-AutoUpdate\`:

```csharp
public static void CleanPreviousDownloads(ILogger logger)
{
    string text = Path.Combine(Path.GetTempPath(), "Okta-AutoUpdate");
    // For SYSTEM service, GetTempPath() = C:\Windows\Temp
    if (Directory.Exists(text))
    {
        string[] directories = Directory.GetDirectories(text, "*", SearchOption.AllDirectories);
        for (int i = 0; i < directories.Length; i++)
        {
            Directory.Delete(directories[i], recursive: true);
        }
    }
}
```

### Confirmed Preconditions

1. **Service identity:** SYSTEM (confirmed via WMI: `StartName = LocalSystem`)
2. **Directory does NOT exist:** On fresh install, `C:\Windows\Temp\Okta-AutoUpdate` does not exist (CONFIRMED)
3. **Standard users CAN create junctions:** `C:\Windows\Temp` ACL grants `BUILTIN\Users` CreateFiles+AppendData with ContainerInherit (CONFIRMED)
4. **Junction creation test:** Successfully created and removed a test junction in `C:\Windows\Temp` as standard user (CONFIRMED)

### Attack Flow

1. Standard user creates `C:\Windows\Temp\Okta-AutoUpdate` as a **directory junction** pointing to an arbitrary target (e.g., `C:\Program Files\SomeApp\`)
2. SYSTEM service calls `CleanPreviousDownloads()` during next update cycle (every 3600 seconds)
3. `Directory.Exists()` returns TRUE (follows junction)
4. `Directory.GetDirectories()` with `SearchOption.AllDirectories` enumerates subdirectories of the TARGET through the junction
5. `Directory.Delete()` calls resolve through the junction and delete ACTUAL target subdirectories AS SYSTEM
6. Result: arbitrary directory contents deleted with SYSTEM privileges

### Trigger

The deletion is triggered whenever `CleanPreviousDownloads` is called, which happens at the start of every update check (line 184 of ApplicationInstaller.cs). This can be triggered on-demand by injecting a message via the named pipe (Finding 2).

### Impact

Arbitrary directory deletion as SYSTEM is a well-documented LPE primitive. It can be chained with:
- DLL planting (delete a directory, recreate with a malicious DLL)
- Service config modification
- Windows Installer rollback exploitation

### PoC

See `poc/okta-junction-deletion-poc.cs`

---

## FINDING 2: Named Pipe Accessible to All Local Users (HIGH)

**File:** `Okta.AutoUpdate.Executor/NamedPipeServer.cs`
**Pipe:** `\\.\pipe\Okta.Coordinator.pipe` (CONFIRMED LIVE)
**Service:** Runs as NT AUTHORITY\SYSTEM

The `Okta.Coordinator.pipe` named pipe is created with `onlyAllowAdmins: false` (the default), granting `BuiltinUsersSid` (all local users) `FullControl`:

```csharp
// Called with onlyAllowAdmins: false by default
PipeAccessRule rule2 = new PipeAccessRule(
    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
    PipeAccessRights.FullControl,
    AccessControlType.Allow);
```

### IPC Message Format (DataContractJsonSerializer)

```json
{
  "CurrentInstalledVersion": "1.0.0.0",
  "AutoUpdateUrl": "https://org.okta.com",
  "EventLogName": "Okta Verify",
  "EventSourceName": "OktaVerify",
  "ReleaseChannel": "GA",
  "ArtifactType": "OktaVerify",
  "PipeName": "response.pipe",
  "BucketId": "0",
  "UserId": null
}
```

### Validation

- `AutoUpdateUrl` must be HTTPS with host ending in an Okta domain (.okta.com, .oktapreview.com, .oktacdn.com, .trexcloud.com, etc.)
- `ReleaseChannel` must be BETA, EA, or GA
- Messages are plaintext JSON (no encryption, no authentication)
- No caller validation on pipe connection

### Impact

Any local user can:
1. Trigger SYSTEM-level update checks on demand
2. Control the release channel (BETA/EA/GA) and bucket ID
3. Force the SYSTEM service to make outbound HTTPS connections to any Okta-domain URL
4. Receive update status notifications via a response pipe
5. **Trigger `CleanPreviousDownloads()` which enables Finding 1 on demand**

### Contrast

Device Access pipes (`OktaDeviceAccessPipe`, `OktaLogonOfflineFactorManagementPipe`) DO use DPAPI encryption on messages -- showing Okta knows pipe messages should be encrypted, but the coordinator pipe was skipped.

### PoC

See `poc/okta-coordinator-pipe-poc.cs`

---

## FINDING 3: TOCTOU Race in Update Execution (HIGH - SYSTEM RCE)

**Files:** `ApplicationInstaller.cs` (lines 184-193), `AutoUpdateExecutor.cs` (lines 316-330), `ProcessLauncher.cs`

### Execution Sequence

```
Line 184: Helper.CleanPreviousDownloads(logger)
Line 185: tempFolder = Helper.GetTempFolder(metadata.Version)
           -> C:\Windows\Temp\Okta-AutoUpdate\{version}_{GUID}\
Line 187: DownloadAndValidateArtifactsAsync()
           -> FileStream(path, Create, ReadWrite, FileShare.None) [HANDLE #1]
           -> Compute hash (FileStream, Open) [HANDLE #2]
           -> BOTH HANDLES CLOSED
Line 190: fileVerifier.ValidateFileSignature(text, logger)
           -> WinVerifyTrust() [HANDLE #3, then CLOSED]
Line 191: SendNotificationWithElapsedTime() [I/O to response pipe]
Line 192: LogMessage() [I/O to event log]
Line 193: processLauncher.LaunchProcess(text, commandLineArgument)
           -> Process.Start() [HANDLE #4 - EXECUTES AS SYSTEM]
```

### Race Window

Between line 190 (Authenticode verification CLOSES its handle) and line 193 (Process.Start), there are:
- A notification sent via named pipe (I/O operation)
- An event log write (I/O operation)
- Process startup preparation

**During this window, the file is unlocked and can be replaced.**

### ProcessLauncher Details

```csharp
process.StartInfo.FileName = path;              // File path from download
process.StartInfo.Arguments = commandLineArgument; // From server metadata!
process.StartInfo.CreateNoWindow = true;
process.StartInfo.UseShellExecute = false;
process.Start();                                 // NO RE-VERIFICATION
```

The `commandLineArgument` comes from the server's `commandArgs` JSON field -- meaning a MITM attacker (with pinning disabled) can pass arbitrary arguments to a legitimately signed Okta installer.

### Exploitation

An attacker who can:
1. Monitor `C:\Windows\Temp\Okta-AutoUpdate\` for new GUID-named directories
2. Detect when the file is unlocked (after Authenticode check)
3. Atomically replace the verified file with a malicious binary

Achieves arbitrary code execution as SYSTEM.

### Difficulty

- GUID makes folder name unpredictable, but observable via `ReadDirectoryChangesW`
- Race window is small (milliseconds) but widened by I/O operations
- Advanced technique: use oplocks to pause file operations and extend the window

---

## FINDING 4: DPAPI LocalMachine with No Entropy (MEDIUM-HIGH)

**File:** `Okta.DeviceAccess.Core.DPAPIHelper/DpapiHelper.cs`

```csharp
public byte[] Decrypt(byte[] dataToDecrypt, byte[] entropy)
{
    return ProtectedData.Unprotect(dataToDecrypt, entropy, DataProtectionScope.LocalMachine);
}
```

The Device Access IPC uses DPAPI encryption but with:
- `DataProtectionScope.LocalMachine` (not CurrentUser)
- `entropy: null` (no additional entropy)

**Called as:** `dpApiHelper.Encrypt(array, null)` / `dpApiHelper.Decrypt(memoryStream2.ToArray(), null)`

**Impact:** ANY process running on the same machine can call `ProtectedData.Unprotect()` with the same parameters and decrypt the pipe messages. The DPAPI protection is effectively decorative -- it prevents network interception but not local process interception.

### PoC

See `poc/okta-dpapi-decrypt-poc.cs`

---

## FINDING 5: SSL Pinning Disabled via Registry Key (MEDIUM-HIGH)

**File:** `Okta.AutoUpdate.Executor.Implementation/ClientConfiguration.cs`
**Also:** `Okta.DeviceAccess.Core.Configuration/OktaDeviceAccessConfiguration.cs`

```csharp
// CertificatePinningValidator.cs
if (clientConfiguration.IsSslPinningDisabled(logger))
{
    logger.WriteInfo("SslPinningDisabled", "Ssl pinning is disabled, bypassing validation.");
    return true;
}
```

Registry key: `HKLM\SOFTWARE\Okta\Okta Verify\DisableSslPinning` (DWORD, non-zero = disabled)

**Current ACL:** BUILTIN\Users = ReadKey only, Administrators = FullControl. Requires admin to write.

**Impact:** A local admin can disable certificate pinning for the auto-update system AND Device Access. Combined with MITM, the attacker controls update metadata including `commandArgs` passed to `Process.Start()`.

---

## FINDING 6: Security-Disabling Registry Keys (MEDIUM)

**File:** `Okta.OktaVerify.Foundations/Constants.cs`

| Key | Effect |
|-----|--------|
| `DisableSslPinning` | Disables ALL certificate pinning |
| `DisableSandbox` | Disables credential sandbox isolation |
| `ForceDebugger` | Forces debugger attachment |
| `SandboxLocationOverride` | Allows custom sandbox directory |
| `CallerBinaryValidationMode` | Can weaken caller validation (enum value 0 = Unknown) |
| `AutoUpdateClientVersionOverride` | Override version check for auto-updates |
| `AutoUpdateBucketIdOverride` | Override update bucket ID |
| `OIDCUseIntegratedBrowser` | Force legacy IE WebBrowser for OAuth (currently set to 0) |

All require admin-level HKLM write access.

---

## FINDING 7: Legacy IE WebBrowser for OIDC (MEDIUM)

**File:** `Okta.Oidc.Wpf/DefaultIntegratedBrowser.cs`

The integrated browser uses `System.Windows.Controls.WebBrowser` (MSHTML/Trident engine -- Internet Explorer), not WebView2. Controlled by registry key `OIDCUseIntegratedBrowser` (currently 0 = disabled).

The system browser flow uses an HTTP loopback listener (`http://127.0.0.1`) -- plain HTTP, per RFC 8252. Auth codes pass in cleartext on loopback.

---

## FINDING 8: `.oktacdn.com` Exempt from Certificate Pinning (MEDIUM)

**File:** `Okta.AutoUpdate.Executor.CertificatePinning/OktaPublicKeyList.cs`

All Okta domains have 12+ pinned public keys EXCEPT `.oktacdn.com`, which is completely exempt from pinning validation. This CDN domain is also in the trusted URL whitelist for update downloads.

---

## FINDING 9: Proxy Credentials Recoverable by Any Local Process (MEDIUM)

**File:** `Okta.AutoUpdate.Executor/ApplicationInstaller.cs` (lines 382-398)

```csharp
webProxy.Credentials = new NetworkCredential(text2,
    NativeEncryptionDecryptionInterop.Decrypt(
        Convert.FromBase64String(text3),  // encrypted password from app.config
        Encoding.Unicode.GetBytes(s)));    // entropy ALSO from app.config
```

- `CRYPTPROTECT_LOCAL_MACHINE` flag means any process can decrypt
- Entropy stored alongside ciphertext in same config file
- Username stored in plaintext in app.config

---

## FINDING 10: AES-CBC Without Authentication Tag (MEDIUM)

**File:** `Okta.Devices.SDK.Cryptography/AesCbcEncryptionProvider.cs`

Credential storage at rest uses AES-CBC without an HMAC or GCM authentication tag. This is vulnerable to:
- Padding oracle attacks (if decryption errors are observable)
- Ciphertext malleability (attacker can flip bits in known-position plaintext)

---

## FINDING 11: App Secret Managed by Native DLL (RESEARCH LEAD)

**File:** `Okta.Authenticator.NativeApp.AppSecret/WindowsAppSecretManager.cs`

All app secret operations delegate to `NativeLibrary` (P/Invoke into `OktaVerify.Native.dll`):

```csharp
public byte[] GetLegacyAppSecret() => NativeLibrary.GetAppSecret(logger);
public bool InitializeAppSecret(string name, uint size, bool allowRoaming) => NativeLibrary.InitializeAppSecret(...);
```

Key functions: `GetAppSecret`, `InitializeAppSecret`, `LoadAppSecret`, `EncryptData`, `DecryptData`, `CreateKeyPair`, `GenerateECDHKeyPair`, `GenerateECDHSharedSecret`, `GetHardwareKeyHash`

**Next step:** Reverse native DLLs with Ghidra for key derivation and memory corruption.

---

## FINDING 12: Custom URI Scheme Hijacking (LOW)

**File:** `Okta.OktaVerify.Foundations/Constants.cs`

```csharp
public const string AUTHENTICATOR_CUSTOM_URI_SCHEME = "com-okta-authenticator:/";
public const string AUTHENTICATOR_CUSTOM_URI_SCHEME_OAUTH = "com-okta-authenticator:/oauth/callback";
```

Another application could register the same scheme with higher priority and intercept OAuth callbacks.

---

## FINDING 13: Symmetric Key Material Never Zeroed (LOW-MEDIUM)

**File:** `Okta.Devices.SDK.Cryptography/` multiple files

AES keys and ECDH shared secrets remain in managed memory after use. No `SecureString`, no `Array.Clear()`, no `CryptographicOperations.ZeroMemory()`. Memory dumps or cold boot attacks can recover key material.

**Exception:** `ClientStorageManagerV2.cs` DOES call `Array.Clear(encryptionKey, 0, encryptionKey.Length)` after passing the key to SQLite -- showing the pattern IS known but inconsistently applied.

---

## Attack Chains

### Chain 1: Standard User to SYSTEM (Junction + Pipe)
1. Create junction: `C:\Windows\Temp\Okta-AutoUpdate` -> target directory
2. Inject IPC message via `Okta.Coordinator.pipe` to trigger update check
3. `CleanPreviousDownloads()` runs, deleting target directory contents as SYSTEM
4. Chain with DLL planting for code execution

### Chain 2: Admin to SYSTEM Code Execution (Registry + MITM + TOCTOU)
1. Set `DisableSslPinning = 1` in HKLM registry
2. MITM the update check, provide crafted metadata with `commandArgs`
3. Legitimate signed Okta binary downloads and passes Authenticode
4. During TOCTOU window, replace with malicious binary
5. SYSTEM executes replacement binary

### Chain 3: Credential Theft (DPAPI + Pipe Interception)
1. Create competing named pipe server (race service restart)
2. Intercept DPAPI-encrypted Device Access messages
3. Decrypt with `ProtectedData.Unprotect(data, null, LocalMachine)`
4. Recover offline MFA factors, device credentials

---

## Registry Values (Current State)

### HKLM\SOFTWARE\Okta\Okta Verify
| Value | Data |
|-------|------|
| AutoUpdatePollingInSecond | 3600 |
| IsFreshInstall | True |
| JustInTimeEnrollmentConfiguration | Default |
| LogLevel | Warning |
| OIDCUseIntegratedBrowser | 0 |
| ReportToAppCenter | Default |
| StaticUserVerificationType | WindowsHello |

---

## Service Details

| Property | Value |
|----------|-------|
| Name | Okta Auto Update Service |
| Identity | NT AUTHORITY\SYSTEM (LocalSystem) |
| Binary | C:\Program Files\Okta\UpdateService\Okta.Coordinator.Service.exe |
| Start | Automatic |
| Pipe | Okta.Coordinator.pipe |
| Temp path | C:\Windows\Temp (via GetTempPath()) |

---

## PoC Tools

| File | Purpose |
|------|---------|
| `poc/okta-coordinator-pipe-poc.cs` | Named pipe message injection |
| `poc/okta-dpapi-decrypt-poc.cs` | DPAPI LocalMachine decryption demo |
| `poc/okta-junction-deletion-poc.cs` | Junction-based directory deletion |

---

## Next Steps

1. **Ghidra RE of native DLLs** -- key derivation, memory corruption in OktaVerify.Native.dll
2. **Test junction deletion end-to-end** -- trigger via pipe injection, verify target deletion
3. **OIDC loopback interception** -- race condition on auth code capture
4. **SQLCipher database key extraction** -- if key derivation is weak in native DLL
5. **Process Monitor** -- observe full IPC patterns during enrollment/authentication
