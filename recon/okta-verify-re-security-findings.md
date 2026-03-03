# Okta Verify 6.6.2.0 Windows -- Complete RE Security Analysis

## Binary Overview

- **Architecture:** .NET 4.7.2 WPF application (decompilable with ILSpy)
- **Total decompiled files:** 1,348 .cs files across 16 assemblies
- **Key components:** Auto-update SYSTEM service, OIDC auth, Device Access, SDK crypto
- **Native DLLs:** OktaVerify.Native.dll, Okta.Devices.SDK.Windows.Native.dll (C/C++, need Ghidra)
- **Obfuscation:** String obfuscation throughout (runtime decode functions), method name obfuscation in tamper protection
- **Tamper protection:** DigitalAI integrity checking with checksums

---

## FINDING 1: Named Pipe Accessible to All Local Users (HIGH)

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

IPC messages are plain JSON (no encryption) and include:
- `AutoUpdateUrl` -- base URL for update checks (validated against Okta domains)
- `ReleaseChannel` -- controls which update channel is used
- `ArtifactType` -- controls artifact selection
- `PipeName` -- controls response pipe name
- `BucketId` -- controls update bucket
- `CurrentInstalledVersion` -- triggers update if server version is higher

**Impact:** Any local user can trigger update checks, control the release channel/bucket, and receive update status notifications. Combined with other findings, this expands the attack surface for LPE.

**Contrast:** Device Access pipes (`OktaDeviceAccessPipe`, `OktaLogonOfflineFactorManagementPipe`) DO use DPAPI encryption on messages -- showing Okta knows pipe messages should be encrypted, but the coordinator pipe was skipped.

---

## FINDING 2: DPAPI LocalMachine with No Entropy (MEDIUM-HIGH)

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

**Impact:** ANY process running on the same machine can call `ProtectedData.Unprotect()` with the same parameters and decrypt the pipe messages. The DPAPI protection is effectively decorative -- it prevents network interception but not local process interception.

---

## FINDING 3: SSL Pinning Disabled via Registry Key (MEDIUM-HIGH)

**File:** `Okta.AutoUpdate.Executor.Implementation/ClientConfiguration.cs`
**Also:** `Okta.DeviceAccess.Core.Configuration/OktaDeviceAccessConfiguration.cs`

```csharp
// Update service
public bool IsSslPinningDisabled(ILogger logger)
{
    return IsRegistryFlagEnabled("DisableSslPinning", logger, ...);
}

// CertificatePinningValidator.cs
if (clientConfiguration.IsSslPinningDisabled(logger))
{
    logger.WriteInfo("SslPinningDisabled", "Ssl pinning is disabled, bypassing validation.");
    return true;
}
```

Registry key: `HKLM\SOFTWARE\Okta\Okta Verify\DisableSslPinning` (DWORD, non-zero = disabled)

**Current ACL:** BUILTIN\Users = ReadKey only, Administrators = FullControl. Requires admin to write.

**Impact:** A local admin (or any process running elevated) can set this single registry value to completely disable certificate pinning for the auto-update system AND Device Access communications. Combined with a network MITM position, the attacker controls update metadata (download URLs, command-line arguments, release channels).

The Authenticode signature check (WinVerifyTrust + hardcoded Okta public keys) still applies independently -- so the downloaded binary must be Okta-signed. However, the `commandArgs` field in the JSON metadata is passed directly to `Process.Start()`, so an attacker could supply custom arguments to a legitimate Okta installer.

---

## FINDING 4: Security-Disabling Registry Keys (MEDIUM)

**File:** `Okta.OktaVerify.Foundations/Constants.cs`

Multiple registry values under `Software\Okta\Okta Verify` control security features:

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

All require admin-level HKLM write access. However, any single compromised admin process could set these to weaken the entire application's security posture.

---

## FINDING 5: TOCTOU Race in Update Execution (MEDIUM)

**File:** `Okta.AutoUpdate.Executor/ApplicationInstaller.cs`, `Helper.cs`

The auto-update flow:
1. Clean previous downloads (`Helper.CleanPreviousDownloads`)
2. Generate temp folder with GUID: `C:\Windows\Temp\Okta-AutoUpdate\{version}_{guid}\`
3. Download file (handle opened with `FileShare.None`, then CLOSED)
4. Compute hash (NEW handle opened)
5. Validate Authenticode signature (ANOTHER new handle)
6. Execute as SYSTEM via `processLauncher.LaunchProcess()` (FINAL handle)

**Three TOCTOU windows exist** between handle close/open cycles. If an attacker can:
- Predict or observe the GUID folder name
- Replace the file between verification and execution

They achieve arbitrary code execution as SYSTEM.

**Mitigations:** GUID makes folder name unpredictable; SYSTEM temp directory has restricted permissions; Authenticode check is robust (WinVerifyTrust + hardcoded Okta public keys + dual-signature rejection).

---

## FINDING 6: Legacy IE WebBrowser for OIDC (MEDIUM)

**File:** `Okta.Oidc.Wpf/DefaultIntegratedBrowser.cs`

The integrated browser uses `System.Windows.Controls.WebBrowser` (MSHTML/Trident engine -- Internet Explorer), not WebView2:

```csharp
WebBrowser webBrowser = new WebBrowser();
webBrowser.Source = new Uri(options.StartUrl);
```

Controlled by registry key `OIDCUseIntegratedBrowser` (currently set to 0 = disabled, meaning system browser is used by default). But a local attacker could set this to 1 to force all OAuth flows through the IE engine.

The system browser flow uses an HTTP loopback listener (`http://127.0.0.1` or `http://localhost`) -- plain HTTP, per RFC 8252. Auth codes pass in cleartext on loopback.

---

## FINDING 7: `.oktacdn.com` Exempt from Certificate Pinning (MEDIUM)

**File:** `Okta.AutoUpdate.Executor.CertificatePinning/OktaPublicKeyList.cs`

All Okta domains have 12+ pinned public keys EXCEPT `.oktacdn.com`, which is completely exempt from pinning validation. If this CDN domain's CA is compromised or a mis-issued certificate exists, it provides a pinning bypass path for update downloads.

---

## FINDING 8: Proxy Credentials Recoverable by Any Local Process (MEDIUM)

**File:** `Okta.AutoUpdate.Executor/ApplicationInstaller.cs`

Proxy credentials stored in app.config, encrypted with DPAPI using `CRYPTPROTECT_LOCAL_MACHINE` flag and entropy from the same config file:

```csharp
webProxy.Credentials = new NetworkCredential(text2,
    NativeEncryptionDecryptionInterop.Decrypt(
        Convert.FromBase64String(text3),  // encrypted password from config
        Encoding.Unicode.GetBytes(s)));    // entropy from config
```

The `CRYPTPROTECT_LOCAL_MACHINE` flag means any process on the machine can decrypt. The entropy is stored alongside the ciphertext.

---

## FINDING 9: StorageEncryptionKey in Protected Registry (LOW-MEDIUM)

**File:** `Okta.DeviceAccess.Core.Configuration/OktaDeviceAccessConfiguration.cs`

```csharp
public string GetStorageEncryptionKey()
{
    return protectedConfigurationStorage.ReadStringValueOrDefault("StorageEncryptionKey", string.Empty);
}
```

The encryption key for the Device Access local database is stored in `HKLM\SOFTWARE\Okta\Okta Device Access\Local Storage\StorageEncryptionKey`.

The `Local Storage` subkey is created with ACL restricted to `LocalSystemSid` only -- so only SYSTEM can read it. This is properly protected.

---

## FINDING 10: App Secret Managed by Native DLL (RESEARCH LEAD)

**File:** `Okta.Authenticator.NativeApp.AppSecret/WindowsAppSecretManager.cs`

All app secret operations delegate to `NativeLibrary` (P/Invoke into `OktaVerify.Native.dll`):

```csharp
public byte[] GetLegacyAppSecret() => NativeLibrary.GetAppSecret(logger);
public bool InitializeAppSecret(string name, uint size, bool allowRoaming) => NativeLibrary.InitializeAppSecret(...);
public (bool, byte[]) LoadAppSecret(string name, ...) => NativeLibrary.LoadAppSecret(...);
public SecureString LoadClientAssociation(string clientName, byte[] identifier) => NativeLibrary.LoadClientAssociation(...);
```

The native DLL handles all cryptographic secret management. Key functions from strings analysis:
- `GetAppSecret`, `InitializeAppSecret`, `LoadAppSecret`
- `EncryptData`, `DecryptData`, `CreateKeyPair`
- `ConfigureLoopbackCertificates`
- `GenerateECDHKeyPair`, `GenerateECDHSharedSecret`
- `GetHardwareKeyHash` -- hardware binding
- `EnsureCertificatesMatch` -- cert validation

**Next step:** Reverse the native DLLs with Ghidra to understand the actual key derivation and storage mechanism. The SQLCipher database key likely comes from this path.

---

## FINDING 11: Custom URI Scheme Hijacking Potential (LOW)

**File:** `Okta.OktaVerify.Foundations/Constants.cs`

```csharp
public const string AUTHENTICATOR_CUSTOM_URI_SCHEME = "com-okta-authenticator:/";
public const string AUTHENTICATOR_CUSTOM_URI_SCHEME_OAUTH = "com-okta-authenticator:/oauth/callback";
```

Custom URI scheme registered for OAuth callbacks. On Windows, another application could register the same scheme with higher priority and intercept authentication callbacks.

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

### HKCU\SOFTWARE\Okta
| Value | Data |
|-------|------|
| DeviceTraceId | debdfa38-e783-477c-b476-e7431aca12e8 |
| installed | 1 |
| DiagnosticsUserSettings | Default |
| StaticAuthenticatorOperationMode | Normal |

---

## Named Pipes (Live)
- `\\.\pipe\Okta.Coordinator.pipe` -- SYSTEM service, all users full control, plaintext JSON

## Attack Priority
1. **Named pipe message injection** -- most practical, write PoC tool
2. **Ghidra RE of native DLLs** -- understand key derivation, find memory corruption
3. **OIDC loopback interception** -- race condition on auth code capture
4. **Registry key manipulation** (requires admin, but demonstrates defense-in-depth failure)
5. **Update TOCTOU race** (difficult but SYSTEM execution)

## Tools Needed
- Ghidra for native DLL analysis (OktaVerify.Native.dll, Okta.Devices.SDK.Windows.Native.dll)
- Named pipe PoC tool (C# or Python) to send crafted IPC messages
- Process Monitor to observe pipe communication patterns
- Wireshark for loopback OIDC traffic capture
