# Okta Verify Windows -- Install Recon

**Version:** 6.6.2.0-4997fa8
**Installer:** OktaVerifySetup-6.6.2.0-4997fa8.exe (36MB, WiX Burn bootstrapper)
**Installed:** 2026-03-02
**Method:** Pre/post snapshot diffing (services, tasks, drivers, processes, filesystem, registry)

---

## Install Footprint

### New Service
- **Name:** Okta Auto Update Service
- **Binary:** `C:\Program Files\Okta\UpdateService\Okta.Coordinator.Service.exe`
- **Status:** Running
- **Start Type:** Automatic
- **Runs as:** SYSTEM (service account)

### New Scheduled Task
- **Name:** Okta Verify Activation Task
- **Path:** `\`
- **State:** Running

### New Processes
| Process | PID | Path |
|---------|-----|------|
| OktaVerify | -- | `C:\Program Files\Okta\Okta Verify\OktaVerify.exe` |
| Okta.Coordinator.Service | -- | `C:\Program Files\Okta\UpdateService\Okta.Coordinator.Service.exe` |

### New Drivers
None. Entirely userland.

### Filesystem
- `C:\Program Files\Okta\` -- 133 files
- `C:\ProgramData\Okta\OktaVerify\Plugins\com.okta.windowsSecurityCenter.json`
- `C:\Users\uglyt\AppData\Local\Okta\OktaVerify\DataStore.db` (encrypted, SQLCipher)

---

## Binary Inventory

### App Type
.NET WPF application. All `Okta.*.dll` files are managed .NET assemblies -- decompilable with dnSpy/ILSpy to near-source-code quality.

### Okta-Authored Binaries (RE targets)

| Binary | Type | Notes |
|--------|------|-------|
| `OktaVerify.exe` | .NET WPF | Main application entry point |
| `Okta.OktaVerify.Windows.Core.dll` | .NET | Core app logic |
| `Okta.OktaVerify.Foundations.dll` | .NET | Foundation layer |
| `Okta.Application.Foundations.dll` | .NET | Application framework |
| `Okta.DeviceAccess.Core.dll` | .NET | Device Access -- Desktop MFA core ($75K target) |
| `Okta.DeviceAccess.Windows.dll` | .NET | Device Access -- Windows-specific implementation |
| `Okta.Devices.SDK.Core.dll` | .NET | Device SDK core |
| `Okta.Devices.SDK.Core.Foundation.dll` | .NET | Device SDK foundation |
| `Okta.Devices.SDK.Core.Windows.dll` | .NET | Device SDK Windows impl |
| `Okta.Devices.SDK.Base.Windows.dll` | .NET | Device SDK base |
| `Okta.Devices.SDK.Win32.dll` | .NET | Win32 API interop |
| `Okta.Devices.SDK.Windows.Native.dll` | **Native** | **Ghidra target** -- native code |
| `OktaVerify.Native.dll` | **Native** | **Ghidra target** -- native code |
| `OktaVerify.Bridge.dll` | .NET | Managed-to-native bridge (IPC boundary) |
| `Okta.Oidc.Abstractions.dll` | .NET | OIDC abstractions |
| `Okta.Oidc.Wpf.dll` | .NET | OIDC client -- auth protocol implementation |
| `Okta.FeatureFlag.Client.dll` | .NET | Feature flag client (LaunchDarkly?) |
| `Okta.AutoUpdate.Executor.dll` | .NET | Auto-update execution logic |
| `Okta.AutoUpdate.Shim.dll` | .NET | Auto-update shim |
| `Okta.Application.Resources.dll` | .NET | UI resources + localization |
| `Okta.Coordinator.Service.exe` | .NET | SYSTEM-level auto-update service |

### Third-Party Libraries

| Library | Purpose | Security Relevance |
|---------|---------|-------------------|
| `Azure.Security.KeyVault.Secrets.dll` | Azure Key Vault | Secrets management -- where are keys stored? |
| `Azure.Data.AppConfiguration.dll` | Azure App Config | Remote configuration -- what gets fetched? |
| `Azure.Messaging.EventGrid.dll` | Azure Event Grid | Telemetry/events |
| `IdentityModel.dll` | OAuth/OIDC | Auth protocol handling |
| `IdentityModel.OidcClient.dll` | OIDC Client | Auth flow implementation |
| `Microsoft.IdentityModel.JsonWebTokens.dll` | JWT handling | Token validation |
| `Microsoft.IdentityModel.Tokens.dll` | Token crypto | Key management |
| `System.IdentityModel.Tokens.Jwt.dll` | JWT | Token parsing |
| `Microsoft.FeatureManagement.dll` | Feature flags | Remote feature toggle |
| `Microsoft.ApplicationInsights.dll` | App Insights | Telemetry -- what data is sent? |
| `e_sqlcipher.dll` (x64 + x86) | SQLCipher | Encrypted SQLite -- DataStore.db |
| `e_sqlite3.dll` (x64 + x86) | SQLite | Unencrypted SQLite fallback? |
| `Newtonsoft.Json.dll` | JSON | Deserialization (type confusion?) |
| `Sentry.dll` | Error reporting | Crash reports -- what data is leaked? |
| `Serilog.dll` + `Serilog.Sinks.File.dll` | Logging | Log files -- sensitive data in logs? |
| `SimpleInjector.dll` | DI container | Dependency injection |
| `Prism.dll` | MVVM framework | WPF architecture |
| `QRCoder.dll` + `QRCoder.Xaml.dll` | QR codes | Enrollment QR generation |
| `DnsClient.dll` | DNS | Custom DNS resolution |
| `OpenTelemetry.dll` | Telemetry | Observability |
| `System.Formats.Cbor.dll` | CBOR | Binary serialization (FIDO2/WebAuthn?) |

### Update Service (SYSTEM-level)

Only 4 files -- minimal attack surface:
```
C:\Program Files\Okta\UpdateService\
    Okta.Coordinator.Service.exe        # Main service binary
    Okta.Coordinator.Service.exe.config  # Configuration
    Okta.AutoUpdate.Executor.dll         # Update execution
    Okta.AutoUpdate.Shim.dll             # Update shim
```

---

## Initial Attack Surface Assessment

### Priority 1: Auto-Update Service (LPE)
- Runs as SYSTEM with Automatic start
- Only 4 files -- small, auditable
- Questions: How does it download updates? Does it validate signatures? Can the update path be hijacked (DLL sideload, symlink, TOCTOU)? Where does it write temporary files?

### Priority 2: OIDC Implementation
- `Okta.Oidc.Wpf.dll` handles auth flows
- OIDC redirect URI handling, token validation, state parameter
- WPF embedded browser for auth -- is it using WebView2 or legacy IE control?

### Priority 3: SQLCipher Key Management
- `DataStore.db` is encrypted with SQLCipher
- Key must be stored somewhere accessible to the app process
- If key is recoverable, all stored credentials/tokens are exposed
- Check: Is the key derived from DPAPI, hardcoded, or fetched from Azure Key Vault?

### Priority 4: Native DLLs
- `Okta.Devices.SDK.Windows.Native.dll` -- Ghidra target
- `OktaVerify.Native.dll` -- Ghidra target
- These handle the managed-to-native boundary via `OktaVerify.Bridge.dll`
- Memory corruption, type confusion at the interop boundary

### Priority 5: Feature Flags
- `Okta.FeatureFlag.Client.dll` + `Microsoft.FeatureManagement.dll`
- Can feature flags be manipulated to enable debug/test functionality?
- What flags exist and what do they control?

### Priority 6: Newtonsoft.Json Deserialization
- Known attack surface for .NET type confusion / RCE
- Check if TypeNameHandling is set to anything other than None

### Priority 7: Sentry / App Insights Telemetry
- What data is sent in crash reports and telemetry?
- Can telemetry endpoints be intercepted for data leakage?

---

## Tools for Analysis

- **dnSpy / ILSpy** -- decompile all .NET assemblies (primary tool)
- **Ghidra** -- `OktaVerify.Native.dll` and `Okta.Devices.SDK.Windows.Native.dll` only
- **Process Monitor (Sysinternals)** -- trace file/registry/network activity
- **Wireshark / Fiddler** -- intercept network traffic (OIDC flows, update checks, telemetry)
- **DB Browser for SQLite** -- if SQLCipher key is recovered

---

*Recon date: 2026-03-02*
*Researcher: Lucid_Duck*
