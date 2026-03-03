# Okta Verify 6.6.2.0 - Loopback Server Complete Security Analysis

## Architecture

Okta Verify runs a local HTTP server for FastPass authentication.
The server uses http.sys (kernel-level URL reservation) and HttpListener.

### Port Configuration
Hardcoded port list with sequential fallback:
- 8769 (primary)
- 65111, 65121, 65131, 65141, 65151 (fallbacks)

### Endpoints Discovered

| Path | Methods | Response | Purpose |
|------|---------|----------|---------|
| /probe | GET, OPTIONS | 200 (empty body) | Detect Okta Verify presence |
| /challenge | GET, OPTIONS, POST | 200/400/401/500 | FastPass challenge-response |
| /* | Any | 400 JSON error | Rejected |

### HTTP.sys Registration
```
URL: HTTP://127.0.0.1:8769:127.0.0.1/
Process: OktaVerify.exe (PID varies)
Request queue: Unnamed, active
Max requests: 1000
```

### Native DLL Exports (Okta.Devices.SDK.Windows.Native.dll)

78 exported functions including:
- ConfigureLoopbackCertificates
- ConfigureWebServer
- IsWebServerConfigured
- ResetWebServer
- GetConnectionInfo (TCP connection mapping)
- ValidateBinarySignature
- EncryptData / DecryptData (AES-256-GCM/CBC)
- GenerateECDHKeyPair / GenerateECDHSharedSecret
- StartImpersonatingAccount / StopImpersonatingAccount
- CheckSandboxIntegrity
- CreateBiometricKeyPair / CreateSilentKeyPair
- HashAndSignData / SignHash / VerifySignature

### Security Layers (Decompiled Analysis)

1. **IP Validation**: Hardcoded 127.0.0.1 check (cannot be bypassed remotely)
2. **TCP Connection Mapping**: Maps HTTP request to calling process via native API
3. **Session Validation**: Checks Windows session ID
4. **Binary Signature**: Validates Authenticode signature of calling process
5. **mTLS**: Client certificate validation (when enabled)

### Configuration Defaults (WEAK)

From `SecureLoopbackBindingConfiguration`:
- `EnableTransportLayerSecurity = true` (configurable)
- `RequireMutualAuthentication = false` (DEFAULT - WEAK)
- `FailOnUnsignedCallerBinaries = false` (DEFAULT - WEAK)
- `EnforceExactConnectionMapping = false` (HARDCODED - CANNOT CHANGE)
- `BinaryValidationCacheDuration = 30 seconds` (race window)

### Certificate PKI Chain

Store: "Okta FastPass Certificates" (LocalMachine)
- Root: CN=Okta FastPass + [MachineName] + "-Root"
- Issuer: CN=Okta FastPass + [MachineName] + "-Issuer"
- Server: CN=Okta FastPass + [MachineName] + "-Server"
- Client: CN=Okta FastPass + [UserName]

### String Obfuscation

Two XOR cipher classes found:
- `gy5lotsq.lih(string, int)` - XOR each char with int
- `b_a9hjj.f0y(string, int)` - Same pattern, different class

Algorithm (trivially reversible):
```csharp
public static string lih(string input, int key) {
    char[] array = input.ToCharArray();
    for (int i = 0; i < array.Length; i++)
        array[i] = (char)(array[i] ^ key);
    return new string(array);
}
```

### Sandbox Account System

Okta Verify creates real Windows local accounts for credential isolation:
- `AddAuthenticatorSandboxAccount` - Creates Windows user
- `StartImpersonatingAccount(name, password)` - Impersonates
- `CheckSandboxIntegrity` - Validates account state
- Password stored as SecureString, persisted somewhere recoverable
- Profile directory under `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

### Encryption

- Default: AES-256-GCM (12-byte IV, 16-byte tag)
- Alternative: AES-256-CBC
- Key derivation: `DeriveStrings` in native DLL (combines two SecureStrings)
- App secrets: `NCryptProtectSecret` / `NCryptUnprotectSecret` (DPAPI-NG)
- Windows Credential Manager used for some secrets (`CredReadW/CredWriteW`)
