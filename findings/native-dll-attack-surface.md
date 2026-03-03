# Okta Verify 6.6.2.0 - Native DLL Attack Surface Map

## DLLs Analyzed

### OktaVerify.Native.dll (480,080 bytes)
Build: C:\Program Files\CircleCI\Workdir\bin\Release\x64\OktaVerify.Native.pdb
Compiled with: MSVC 14.44.35207, Visual Studio 2022 Enterprise

13 Exports:
1. CreateClientInstanceIdentifier
2. CreateRandomInstanceIdentifier
3. GetAppSecret - retrieves app secret from Windows credential storage
4. GetExpectedCodeSigningCertPublicKey - hardcoded Okta signing cert public key
5. GetMachineJoinStatus - Azure AD / domain join detection
6. GetMachinePerformanceInfo - RAM, CPU info
7. GetUsersInfo - enumerates Win32_UserProfile via WMI
8. GetWindowState - window positioning
9. InitializeAppSecret - creates new secret with name and size
10. LoadAppSecret - loads named secret from protected storage
11. LoadClientIdentifier - loads client ID
12. OverlayApplicationWindows - window management
13. RemoveAppSecret - deletes named secret

Key APIs Used:
- BCrypt* (CNG hashing): BCryptOpenAlgorithmProvider, BCryptCreateHash, BCryptHashData, BCryptFinishHash
- NCrypt* (DPAPI-NG): NCryptCreateProtectionDescriptor, NCryptProtectSecret, NCryptUnprotectSecret
- Credential Manager: CredReadW, CredWriteW, CredDeleteW, CredFree
- WMI: CoCreateInstance, IWbemLocator, "SELECT * FROM Win32_UserProfile where Special='False'"
- Code signing: WinVerifyTrust, WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain

Internal function: EnsureIsAuthenticatedCaller - checks caller identity (needs RE)

### Okta.Devices.SDK.Windows.Native.dll (628,048 bytes)

78 Exports (key ones):

Crypto:
- EncryptData / DecryptData (AES-256, supports CBC and GCM modes)
- GenerateECDHKeyPair / GenerateECDHSharedSecret
- GenerateRandomBytes
- HashAndSignData / HashData / SignHash / VerifySignature
- DeriveStrings (KDF combining two SecureStrings)

Key Management:
- CreateBiometricKeyPair / CreatePinProtectedKeyPair / CreateSilentKeyPair
- CreateSilentKeyPairInSandbox
- OpenPinProtectedKey / OpenSilentKey / OpenUserVerificationKey
- DeletePrivateKey / DeletePrivateKeyFromSandbox / UnloadKey
- CheckIsKeyProviderSupported / CheckIsPrivateKeyAccessible
- GetRsaPublicKeyExponent / GetRsaPublicKeyModulus
- GetHardwareKeyHash

Sandbox/Impersonation:
- AddAuthenticatorSandboxAccount - creates real Windows local account
- CheckSandboxIntegrity - validates sandbox state
- StartImpersonatingAccount / StopImpersonatingAccount
- CheckAccountExists / RemoveAccount
- GetAccountSid / GetAccountSidString / GetMachineSidString
- MoveAccountProfileLocation / RemoveProfileBySid

Loopback Web Server:
- ConfigureLoopbackCertificates
- ConfigureWebServer / ResetWebServer / IsWebServerConfigured
- GetConnectionInfo (TCP connection mapping)

Biometrics:
- CheckBiometricsConfigured / CheckBiometricsEnabled
- EnumerateBiometricUnits / GetSupportedSensorTypes
- WinBio* (8 functions for Windows Hello)

Security:
- ValidateBinarySignature
- CreateSecurityDescriptorStringForWellKnownGroup
- CreateSecurityDescriptorStringFromSid
- IsRunningElevated
- CurrentUserHasNonEmptyPassword
- CheckWindowSecurityCenterStatus / GetAntiVirusProductsInfo / GetBitLockerStatus

Other:
- AreSecureStringsEqual / SecureStringIsPattern
- BinaryToString
- FreeProcessHeapMemory / FreeProcessHeapMemoryWithLog / FreeSignerCertificates
- GetEnrolledFactors / GetProviderImplementationType
- CheckCredentialState / UpdateAccountPassword

## String Obfuscation

Two XOR cipher classes (trivially reversible):
- gy5lotsq.lih(string, int) -- XOR each char with int16
- b_a9hjj.f0y(string, int) -- same pattern

## Encryption Defaults

- AES-256-GCM: 12-byte IV, 16-byte auth tag (default for secure channel)
- AES-256-CBC: alternative mode
- ECDH key exchange for shared secrets
- NCrypt protection descriptors for at-rest secrets (descriptor string in native DLL)
- App secrets stored via Windows Credential Manager (CredReadW/CredWriteW)

## Not Yet Reversed

The native DLLs need Ghidra/IDA analysis for:
1. NCrypt protection descriptor strings (what's the actual DPAPI-NG descriptor?)
2. EnsureIsAuthenticatedCaller implementation (can it be bypassed?)
3. Key derivation details in DeriveStrings
4. ECDH implementation specifics (curve, parameters)
5. Buffer handling in all exported functions (overflow potential)
6. The actual hardware key hash computation (GetHardwareKeyHash)
