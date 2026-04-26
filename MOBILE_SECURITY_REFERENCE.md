# Mobile Security Reference

> Comprehensive reference for mobile application security, platform architecture, malware analysis, MDM, mobile network threats, and enterprise mobile defense.

---

## Table of Contents

1. [Mobile Security Landscape](#1-mobile-security-landscape)
2. [Android Security Architecture](#2-android-security-architecture)
3. [iOS Security Architecture](#3-ios-security-architecture)
4. [Mobile Application Security Testing (MAST)](#4-mobile-application-security-testing-mast)
5. [Common Mobile Vulnerabilities](#5-common-mobile-vulnerabilities)
6. [Mobile Malware Analysis](#6-mobile-malware-analysis)
7. [Mobile Device Management (MDM) Security](#7-mobile-device-management-mdm-security)
8. [Mobile Network Security](#8-mobile-network-security)
9. [Enterprise Mobile Security](#9-enterprise-mobile-security)
10. [Mobile CTF and Bug Bounty](#10-mobile-ctf-and-bug-bounty)

---

## 1. Mobile Security Landscape

### Android vs. iOS Security Architecture Comparison

| Feature | Android | iOS |
|---|---|---|
| **Kernel** | Linux (monolithic) | XNU hybrid (Mach + BSD) |
| **Sandbox model** | UID-based, SELinux mandatory access control | App sandbox + entitlements enforced by kernel |
| **Code signing** | APK signing (v1-v4 schemes); Google Play signing | Enforced at all times; no unsigned code runs |
| **App distribution** | Google Play + sideloading (APK) | App Store only; TestFlight/ADP for testing |
| **Sideloading risk** | High; USB debugging and unknown sources common | Low; requires developer cert or enterprise profile |
| **Root/Jailbreak** | Root via Magisk, KernelSU; varies by OEM | Jailbreak (checkra1n, unc0ver, Dopamine); kernel exploits |
| **Permissions model** | Manifest + runtime dangerous permissions | TCC (Transparency, Consent, Control) per-resource |
| **Encryption** | File-Based Encryption (FBE) default since Android 7 | Data Protection classes (hardware-backed) |
| **Secure hardware** | Trusted Execution Environment (TEE); StrongBox (optional) | Secure Enclave (dedicated ARM processor, every device since A7) |
| **Bootchain security** | Verified Boot / AVB 2.0; dm-verity | Secure Boot ROM to LLB to iBoot to XNU kernel |
| **Update model** | OEM-dependent; Project Treble separates vendor/framework | OTA via Apple; fast adoption rate |
| **Exploit mitigations** | ASLR, PIE, stack canaries, CFI, ShadowCallStack | PAC (Pointer Authentication Codes), ASLR, stack canaries, LLVM CFI |
| **Browser engine** | Chromium (V8) | WebKit enforced for all browsers by policy |
| **USB attack surface** | ADB enabled on developer devices; fastboot mode | Limited; lockdown mode disables USB accessories |
| **Forensic acquisition** | Varies widely by OEM/version; ADB backup (deprecated) | GrayKey/Cellebrite physical; iCloud logical |

---

### OWASP Mobile Top 10 (2024 Edition)

| Rank | Category | Description | CVE Examples |
|---|---|---|---|
| M1 | Improper Credential Usage | Hardcoded credentials, insecure credential transmission, weak credential storage | CVE-2023-27363 (Foxit PDF hardcoded API key) |
| M2 | Inadequate Supply Chain Security | Third-party SDKs with vulnerabilities, malicious dependencies, unsigned libraries | CVE-2022-20452 (Android framework supply chain) |
| M3 | Insecure Authentication/Authorization | Insecure biometric auth, client-side access control, improper session management | CVE-2021-30860 (FORCEDENTRY - auth bypass) |
| M4 | Insufficient Input/Output Validation | XSS in WebViews, SQL injection in local DBs, path traversal in content providers | CVE-2023-0266 (Android kernel use-after-free via ALSA) |
| M5 | Insecure Communication | Cleartext HTTP, improper certificate validation, weak TLS configuration | CVE-2022-26766 (Apple certificate chain bypass) |
| M6 | Inadequate Privacy Controls | PII in logs, unnecessary permission requests, third-party analytics data leakage | CVE-2021-39624 (Android SystemUI PII exposure) |
| M7 | Insufficient Binary Protections | Lack of obfuscation, debug symbols in release builds, anti-tampering absent | CVE-2022-42856 (iOS type confusion in JavaScriptCore) |
| M8 | Security Misconfiguration | ADB debug left on, NetworkSecurityConfig misconfig, exported components | CVE-2022-20007 (Android exported activity escalation) |
| M9 | Insecure Data Storage | Plaintext SQLite, world-readable SharedPreferences, external storage PII | CVE-2021-25394 (Samsung MagicInfo content provider path traversal) |
| M10 | Insufficient Cryptography | ECB mode encryption, hardcoded IVs/keys, deprecated algorithms (MD5/SHA1/DES) | CVE-2023-21282 (Android Bluetooth crypto weakness) |

---

### Mobile Threat Categories

**Malware**
- Trojans disguised as legitimate apps (banking trojans, RATs, adware droppers)
- Drive-by downloads via malicious web pages targeting mobile browsers
- Repackaged apps with embedded malicious code uploaded to third-party stores

**Spyware**
- Commercial spyware (Pegasus, Predator, FinFisher) targeting activists, journalists, government officials
- Consumer-grade monitoring apps marketed as parental controls
- Keyloggers, screenshot capturers, and mic/camera access without consent

**Stalkerware**
- Apps designed to covertly monitor a victim; often requires physical device access to install
- Hide from launcher/app list; blend in as system apps
- Indicators: increased battery/data drain, new unknown contacts/apps, device behaving unexpectedly

**Potentially Harmful Apps (PHA)**
- Google classification: apps that can harm users, data, or devices
- Subcategories: backdoors, fraud, hostile downloaders, privilege escalation, ransomware, rooting, spam, spyware, trojans
- Detected by Google Play Protect on-device scanner

---

### Attack Surface Dimensions

| Surface | Examples |
|---|---|
| **Application** | Insecure storage, WebView XSS, exported components, hardcoded secrets, broken crypto |
| **Operating System** | Kernel vulnerabilities, privilege escalation, bootchain attacks, OEM customization flaws |
| **Network** | MITM via rogue APs, SS7 attacks, IMSI catchers, Bluetooth/NFC attacks, cleartext protocols |
| **Hardware** | Secure Enclave/TEE attacks, side-channel (power analysis), JTAG debug access, physical extraction |
| **Supply Chain** | Malicious SDKs, compromised build environments, counterfeit devices with pre-installed malware |

---

## 2. Android Security Architecture

### Linux Kernel Security

**SELinux (Security-Enhanced Linux)**
- Mandatory Access Control (MAC) enforced since Android 5.0 (Lollipop)
- Every process and file is labeled; policy rules define allowed interactions
- Enforcing mode default; `getenforce` shows current mode
- Policy audit logs: `adb logcat | grep avc`
- Android-specific domains: `untrusted_app`, `platform_app`, `system_server`, `zygote`
- Sepolicy source: `external/sepolicy/` in AOSP; device-specific in `device/<oem>/<board>/sepolicy/`

**Linux Namespaces**
- Mount namespace: isolates filesystem view per process
- PID namespace: isolates process ID space (used by Work Profile containers)
- Network namespace: each Android user can have isolated network stack
- User namespace: supports UID remapping for rootless containers

**seccomp-bpf**
- System call filtering via Berkeley Packet Filter (BPF) programs attached to processes
- Renderer/GPU processes use strict seccomp profiles
- Chrome on Android restricts renderer to approximately 70 system calls
- Custom policy example:

```c
struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};
```

---

### Application Sandbox

**UID Isolation**
- Each installed app receives a unique Linux UID (10000-19999 range)
- Shared UID possible via `android:sharedUserId` manifest attribute (deprecated API 29+)
- App data directories (`/data/data/<package>/`) owned by app UID; other apps cannot read

**Zygote**
- Pre-forked process containing initialized Dalvik/ART runtime
- Every new app forks from Zygote via `fork()` + `exec()` pattern
- COW (copy-on-write) memory sharing of pre-loaded classes
- Security implication: zygote compromise means all subsequent app processes are compromised

**Binder IPC**
- Primary inter-process communication mechanism in Android
- Kernel driver at `/dev/binder`; provides reference counting, thread pooling, death notifications
- Security enforced via UID/GID checks at the driver level
- `checkCallingPermission()` / `enforceCallingPermission()` in service implementations
- Binder transaction data can be inspected with `binder-trace` or Frida hooks
- Attack surface: Binder transaction fuzzing, use-after-free in binder driver (CVE-2019-2215)

---

### Permission Model

| Permission Type | Description | Examples |
|---|---|---|
| **Normal** | Granted automatically at install; no user prompt | `INTERNET`, `ACCESS_NETWORK_STATE`, `VIBRATE` |
| **Dangerous** | Runtime prompt required since Android 6.0 | `READ_CONTACTS`, `CAMERA`, `ACCESS_FINE_LOCATION` |
| **Signature** | Granted only to apps signed with same certificate | `INTERACT_ACROSS_USERS`, `READ_FRAME_BUFFER` |
| **Privileged** | System apps on `/system/priv-app/` whitelist | `INSTALL_PACKAGES`, `CHANGE_COMPONENT_ENABLED_STATE` |
| **Development** | Granted via `pm grant` (debugging only) | `READ_LOGS`, `WRITE_SECURE_SETTINGS` |

**Dangerous Permissions by Group (Android 14)**

```
CALENDAR: READ_CALENDAR, WRITE_CALENDAR
CAMERA: CAMERA
CONTACTS: READ_CONTACTS, WRITE_CONTACTS, GET_ACCOUNTS
LOCATION: ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION, ACCESS_BACKGROUND_LOCATION
MICROPHONE: RECORD_AUDIO
PHONE: READ_PHONE_STATE, CALL_PHONE, READ_CALL_LOG, WRITE_CALL_LOG, ADD_VOICEMAIL
SENSORS: BODY_SENSORS, ACTIVITY_RECOGNITION
SMS: SEND_SMS, RECEIVE_SMS, READ_SMS, RECEIVE_WAP_PUSH
STORAGE: READ_MEDIA_IMAGES, READ_MEDIA_VIDEO, READ_MEDIA_AUDIO
```

---

### APK Structure

```
app.apk (ZIP archive)
  AndroidManifest.xml        -- Binary XML; app metadata, permissions, components
  classes.dex                -- Dalvik bytecode (DEX format)
  classes2.dex               -- Multi-dex (>65K method limit)
  res/                       -- Compiled resources
    layout/
    drawable/
    values/
  resources.arsc             -- Compiled resource table
  assets/                    -- Raw assets (accessed via AssetManager)
  lib/                       -- Native shared libraries
    arm64-v8a/
    armeabi-v7a/
    x86_64/
  META-INF/                  -- Signing block
    MANIFEST.MF
    CERT.SF
    CERT.RSA
```

**AndroidManifest.xml key security fields:**

```xml
<uses-permission android:name="android.permission.CAMERA" />
<application android:debuggable="false"
             android:allowBackup="false"
             android:networkSecurityConfig="@xml/network_security_config">
  <activity android:name=".MainActivity"
            android:exported="true">
    <intent-filter>
      <action android:name="android.intent.action.MAIN" />
    </intent-filter>
  </activity>
  <provider android:name=".FileProvider"
            android:exported="false"
            android:grantUriPermissions="true"
            android:authorities="${applicationId}.fileprovider" />
</application>
```

---

### Android Security Features

**Verified Boot / AVB 2.0**
- Android Verified Boot (AVB) ensures all code executed at boot is signed
- Boot states: GREEN (fully verified), YELLOW (custom key), ORANGE (unlocked), RED (failed verification)
- `dm-verity` provides block-level integrity checking of the system partition
- Vbmeta chain: `vbmeta.img` signs `boot.img`, `system.img`, `vendor.img`
- Hash tree stored at end of each partition; root hash in vbmeta

**SafetyNet / Play Integrity API**

SafetyNet (deprecated; replaced by Play Integrity API):
```
Attestation result fields:
- basicIntegrity: device not tampered
- ctsProfileMatch: device passes CTS
- evaluationType: BASIC | HARDWARE_BACKED
- apkCertificateDigestSha256: caller app cert
```

Play Integrity API (2022+):
```
Verdict fields:
- appRecognitionVerdict: PLAY_RECOGNIZED | UNRECOGNIZED | UNEVALUATED
- deviceRecognitionVerdict: MEETS_DEVICE_INTEGRITY | MEETS_BASIC_INTEGRITY | MEETS_STRONG_INTEGRITY
- accountDetails: LICENSED | UNLICENSED | UNEVALUATED
```

---

### Android Keystore

- Hardware-backed key storage since Android 6.0 (Marshmallow)
- Keys never leave secure hardware (TEE or StrongBox)
- StrongBox: dedicated secure element (Titan M2 on Pixel devices)

```java
// Key generation with hardware backing
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
keyPairGenerator.initialize(
    new KeyGenParameterSpec.Builder(KEY_ALIAS,
        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        .setIsStrongBoxBacked(true)
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationValidityDurationSeconds(-1)
        .build());
KeyPair keyPair = keyPairGenerator.generateKeyPair();
```

Key attestation allows remote verification that a key lives in hardware. The leaf certificate contains attestation extension OID 1.3.6.1.4.1.11129.2.1.17 with fields: securityLevel (SOFTWARE/TRUSTED_ENVIRONMENT/STRONG_BOX), challenge (nonce to prevent replay), and authorizationList.

---

### App Signing Schemes

| Scheme | Android Version | Description | Security Notes |
|---|---|---|---|
| **v1** (JAR signing) | All versions | Signs individual files in ZIP; MANIFEST.MF + .SF + .RSA | Vulnerable to Janus attack (CVE-2017-13156) |
| **v2** (APK signing) | 7.0+ | Signs entire APK as byte stream; block in ZIP central directory | Resistant to Janus; faster verification |
| **v3** (Rotation) | 9.0+ | Adds signing certificate rotation; proof-of-rotation struct | Allows key rotation without app reinstall |
| **v4** (Streaming) | 11+ | Merkle hash tree over APK; required for incremental install | Enables fast ADB incremental push |

Google Play requires v2 or higher. Use `apksigner verify --verbose app.apk` to inspect.

---

### Intent Security

**Exported Activities Attack**

```bash
# Find exported activities with no permission protection
grep -r 'android:exported="true"' AndroidManifest.xml
# Launch exported activity from adb
adb shell am start -n com.example.app/.SecretActivity
# Pass extras to exported activity
adb shell am start -n com.example.app/.LoginActivity --es "username" "admin" --es "bypass" "true"
```

**Intent Sniffing**
- Implicit intents broadcast to all apps with matching intent filters
- Sensitive data in implicit intent extras can be read by any app
- Sticky broadcasts (deprecated) remain in system; any app can retrieve last value
- Fix: use explicit intents; avoid sticky broadcasts

**Pending Intent Security**

```java
// Insecure: mutable PendingIntent with implicit base intent
PendingIntent pi = PendingIntent.getActivity(ctx, 0,
    new Intent(),
    PendingIntent.FLAG_MUTABLE);  // Can be filled and modified by attacker

// Secure: immutable with explicit intent
PendingIntent pi = PendingIntent.getActivity(ctx, 0,
    new Intent(ctx, TargetActivity.class),
    PendingIntent.FLAG_IMMUTABLE);
```

---

### Content Provider Security

**SQL Injection via URI**

```java
// Vulnerable provider implementation
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    SQLiteDatabase db = dbHelper.getReadableDatabase();
    // VULNERABLE: direct concatenation
    return db.rawQuery("SELECT * FROM users WHERE " + selection, null);
}
// Attacker passes UNION SELECT payload via selection parameter
```

**Path Traversal in FileProvider**

A malicious URI such as `content://com.example.app.fileprovider/../../../data/data/com.example.app/shared_prefs/creds.xml` can escape the FileProvider root. Always validate the canonicalized path stays within the authorized root directory.

---

## 3. iOS Security Architecture

### Secure Enclave

- Dedicated ARM processor integrated into Apple SoC (A7+, all devices since iPhone 5s)
- Runs its own microkernel (L4-based); isolated from application processor
- Unique Device ID (UID) key fused in hardware; never exposed to software
- Stores: biometric templates (Face ID, Touch ID), device passcode key material, Apple Pay keys, Health data encryption key
- Key operations: AES-256 encryption/decryption, ECDH, ECDSA using keys that never leave Secure Enclave
- Anti-replay counter storage (prevents rollback attacks)
- Communication: mailbox interface to application processor only

---

### Secure Boot Chain

```
Boot ROM (immutable, Apple root CA burned in silicon)
  |-- verifies signature of:
  LLB (Low-Level Bootloader) -- stored in NOR flash
    |-- verifies signature of:
    iBoot (main bootloader)
      |-- verifies kernel, device tree, trust cache signatures
      XNU Kernel
        |
        User space (launchd -> system daemons -> SpringBoard -> apps)
```

- Every link verified with RSA-4096 or ECDSA-384 against Apple root key
- Failure at any stage: device enters recovery mode (DFU)
- SEPROM: Secure Enclave Boot ROM; equivalent chain for Secure Enclave firmware
- Chain of trust prevents cold boot attacks and persistent kernel implants

---

### Code Signing Enforcement

- All code must be signed; kernel enforces at mmap/mprotect level
- `CS_ENFORCEMENT` flag; `CS_VALID` required on all pages mapped executable
- W^X (write XOR execute) enforced; JIT requires special entitlement (`dynamic-codesigning`)
- Provisioning profiles bind app ID, device UDIDs, entitlements, and certificate
- Trust cache: OS-level cache of known-good CDHashes; speeds up verification

**Key entitlements:**

```xml
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.developer.associated-domains</key>
<array><string>applinks:example.com</string></array>
<key>com.apple.developer.healthkit</key><true/>
<key>com.apple.security.network.client</key><true/>
<key>platform-application</key><true/>
<key>get-task-allow</key><true/>  <!-- debuggable; removed in App Store builds -->
```

---

### App Sandbox and Entitlements

- Each app confined to container directory: `/var/mobile/Containers/Data/Application/<UUID>/`
- Can only access own container + system frameworks + explicitly granted resources
- App extensions share data via App Groups: `group.<bundle-id>`
- XPC services: lightweight IPC between app and extension; audited connections enforce security attributes
- No access to other apps' containers; no access to raw filesystem outside container

---

### TCC Framework (Transparency, Consent, Control)

| Resource | TCC Key | Notes |
|---|---|---|
| Location | `kTCCServiceLocation` | Fine/coarse/background distinction |
| Contacts | `kTCCServiceAddressBook` | |
| Microphone | `kTCCServiceMicrophone` | iOS 14+: mic indicator light |
| Camera | `kTCCServiceCamera` | iOS 14+: camera indicator light |
| Photos | `kTCCServicePhotos` | Read-only vs. read-write |
| Health | `kTCCServiceHealth` | Requires HealthKit entitlement |
| HomeKit | `kTCCServiceHomeKit` | |
| Bluetooth | `kTCCServiceBluetooth` | iOS 13+ |
| Tracking (IDFA) | `kTCCServiceUserTracking` | App Tracking Transparency (ATT) |
| Pasteboard | `kTCCServicePasteboard` | iOS 16+: implicit paste prompts |
| Focus Status | `kTCCServiceFocusStatus` | iOS 15+ |

TCC database: `/private/var/mobile/Library/TCC/TCC.db` (protected; requires root/jailbreak to read)

---

### Data Protection Classes

| Class | Constant | Availability | Use Case |
|---|---|---|---|
| Complete | `NSFileProtectionComplete` | Locked after first unlock | Most sensitive files; encrypted key in Secure Enclave |
| Complete Unless Open | `NSFileProtectionCompleteUnlessOpen` | Locked after close when device locked | Files that may need to be written when locked |
| Complete Until First Auth | `NSFileProtectionCompleteUntilFirstUserAuthentication` | After first unlock post-reboot | Background-accessible data; most app files default |
| None | `NSFileProtectionNone` | Always available | Not recommended; accessible even before first unlock |

```swift
// Setting file protection
let attributes = [FileAttributeKey.protectionKey: FileProtectionType.complete]
try FileManager.default.setAttributes(attributes, ofItemAtPath: filePath)

// CoreData persistent store options
let options = [NSPersistentStoreFileProtectionKey: FileProtectionType.complete]
```

---

### Keychain Services

```swift
// Store secret with strong access control
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    [.biometryCurrentSet, .privateKeyUsage],
    nil
)!

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.example.MyApp",
    kSecAttrAccount as String: "userToken",
    kSecValueData as String: secretData,
    kSecAttrAccessControl as String: access,
    kSecUseAuthenticationContext as String: laContext
]
SecItemAdd(query as CFDictionary, nil)
```

**kSecAttrAccessible values (ordered most to least secure):**
1. `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` - requires device passcode; not backed up
2. `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` - only when unlocked; not backed up
3. `kSecAttrAccessibleWhenUnlocked` - only when unlocked; backed up to iCloud
4. `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` - after first unlock; not backed up
5. `kSecAttrAccessibleAfterFirstUnlock` - after first unlock; backed up
6. `kSecAttrAccessibleAlways` (deprecated) - always accessible; backed up

Keychain access groups allow sharing between apps with same team ID via the `keychain-access-groups` entitlement.

---

### App Transport Security (ATS)

ATS enforces HTTPS-only connections with strong TLS requirements by default (iOS 9+):
- TLS 1.2 minimum
- Forward secrecy required
- No SHA-1 certificates
- Certificate validity 825 days maximum

**Risky NSAllowsArbitraryLoads exceptions:**

```xml
<!-- DANGEROUS: disables ATS globally -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key><true/>
</dict>

<!-- Better: domain-specific exception -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
            <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.1</string>
        </dict>
    </dict>
</dict>
```

App Store review scrutinizes `NSAllowsArbitraryLoads`; must provide justification.

---

### iOS Lockdown Mode

Introduced iOS 16 for high-risk users (activists, journalists, government officials):

| Feature | Lockdown Mode Behavior |
|---|---|
| Messages | Blocks most message attachment types; disables link previews |
| Web browsing | Disables JIT JavaScript compilation; blocks some web fonts and link previews |
| FaceTime/calls | Blocks calls from unknown numbers |
| Wired connections | Blocks USB accessories/computers when locked |
| Configuration profiles | Blocks installation of MDM profiles |
| Shared albums | Disabled |
| Network connections | Blocks 2G connections; disables IPv6 CLAT |

Hardening rationale: removes most complex parsers (JIT, font rendering, image decoding) that have historically been used in zero-click exploit chains.

---

## 4. Mobile Application Security Testing (MAST)

### OWASP MASTG Methodology

The Mobile Application Security Testing Guide (MASTG) defines a repeatable testing methodology aligned with MASVS.

**Engagement phases:**
1. **Reconnaissance**: app metadata, permissions, SDK inventory, backend URLs
2. **Static analysis**: decompile and review source/bytecode
3. **Dynamic analysis**: runtime instrumentation, network interception, API fuzzing
4. **Reporting**: MASVS level compliance, CVSSv3 scoring, PoC evidence

---

### Static Analysis - Android

```bash
# Decompile APK to Java source + resources
jadx -d output_dir/ target.apk

# Decompile with debug info and deobfuscation
jadx --show-bad-code --deobf -d output_dir/ target.apk

# Extract and decode APK with apktool (Smali level)
apktool d target.apk -o decoded/

# Rebuild after modification
apktool b decoded/ -o patched.apk
jarsigner -keystore ~/.android/debug.keystore patched.apk androiddebugkey

# Secrets hunt in decompiled source
grep -r "api_key\|apikey\|secret\|password\|token\|AWS\|firebase" output_dir/
grep -rE "AKIA[A-Z0-9]{16}" output_dir/        # AWS Access Key ID
grep -rE "AIza[0-9A-Za-z\-_]{35}" output_dir/ # Google API Key

# Check for dangerous permissions
aapt dump permissions target.apk

# MobSF static analysis (Docker)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# Upload via REST API:
curl -F "file=@target.apk" http://localhost:8000/api/v1/upload -H "Authorization: <mobsf_api_key>"
```

**Key files to review in decoded APK:**
- `AndroidManifest.xml` - exported components, permissions, debuggable flag
- `res/xml/network_security_config.xml` - cleartext traffic exceptions, certificate pinning
- `assets/` - hardcoded configs, JS bundles, SQLite databases
- `shared_prefs/` (runtime artifact) - check for sensitive data in XML preferences

---

### Static Analysis - iOS

```bash
# Extract IPA (rename .ipa to .zip)
unzip app.ipa -d extracted/
# Binary is at extracted/Payload/App.app/AppBinary

# Dump Objective-C headers
class-dump -H --arch arm64 extracted/Payload/App.app/AppBinary -o headers/

# jtool2 for entitlements, load commands
jtool2 --ent extracted/Payload/App.app/AppBinary
jtool2 -l extracted/Payload/App.app/AppBinary

# Check for PIE/stack canaries/ARC
otool -hv AppBinary | grep PIE
otool -Iv AppBinary | grep stack_chk
otool -Iv AppBinary | grep _objc_release

# Disassemble with radare2
r2 -A -a arm -b 64 AppBinary
# In r2 console: pdf @ sym.functionName

# Search for sensitive strings
strings AppBinary | grep -iE "password|apikey|secret|token|http://"
```

---

### Dynamic Analysis - Frida

```bash
# Install Frida
pip install frida-tools
# On device: frida-server must be running as root
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# List running processes
frida-ps -U

# Attach to process by name
frida -U -n "com.example.app"
```

**Frida Android instrumentation:**

```javascript
// Hook Activity lifecycle
Java.perform(function() {
    var Activity = Java.use('android.app.Activity');
    Activity.onCreate.overload('android.os.Bundle').implementation = function(b) {
        console.log('[*] Activity.onCreate called: ' + this.getClass().getName());
        this.onCreate(b);
    };
});

// Hook SharedPreferences to capture stored values
Java.perform(function() {
    var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    Editor.putString.implementation = function(key, value) {
        console.log('[SharedPrefs] putString: ' + key + ' = ' + value);
        return this.putString(key, value);
    };
});

// Bypass root detection
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        console.log('[*] isRooted() hooked -- returning false');
        return false;
    };
});

// Dump SQLite queries
Java.perform(function() {
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation =
        function(sql, selectionArgs) {
            console.log('[SQLite] query: ' + sql);
            return this.rawQuery(sql, selectionArgs);
        };
});
```

**Frida iOS instrumentation:**

```javascript
// Hook iOS Objective-C method
if (ObjC.available) {
    Interceptor.attach(
        ObjC.classes.NSURLRequest['- URL'].implementation,
        {
            onEnter: function(args) {
                var request = new ObjC.Object(args[0]);
                console.log('[*] NSURLRequest URL: ' + request.URL().toString());
            }
        }
    );
}
```

---

### SSL Pinning Bypass

**Method 1: Objection (automated)**

```bash
objection -g com.example.app explore
# In objection REPL:
android sslpinning disable
ios sslpinning disable
```

**Method 2: apk-mitm (patch APK)**

```bash
npm install -g apk-mitm
apk-mitm app.apk
# Installs patched APK with pinning removed and Burp CA trusted
```

**Method 3: Frida script (manual OkHttp3)**

```javascript
Java.perform(function() {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation =
        function(hostname, peerCertificates) {
            console.log('[*] CertificatePinner.check bypassed for: ' + hostname);
        };
    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation =
        function(hostname, certs) {
            console.log('[*] CertificatePinner.check bypassed');
        };
});
```

---

### Burp Suite Mobile Proxy Setup

**Android:**

```bash
# Export Burp CA certificate as DER
# Settings > Proxy > Options > Import/Export CA Certificate > DER format

# Android 7+ requires system cert (user certs not trusted by apps)
# On rooted device:
adb push burp.der /system/etc/security/cacerts/9a5ba575.0
adb shell "chmod 644 /system/etc/security/cacerts/9a5ba575.0"

# Without root: use apk-mitm or patch network_security_config.xml to add:
# <certificates src="user" />
```

**iOS:**

```
1. Export Burp CA as DER: Proxy > Options > CA Certificate
2. AirDrop or serve via HTTP to iPhone
3. Settings > General > VPN & Device Management > Install certificate
4. Settings > General > About > Certificate Trust Settings > enable Burp CA
5. Configure Wi-Fi proxy: Burp listener IP:port
```

---

### MASVS Levels

| Level | Name | Description |
|---|---|---|
| L1 | Standard Security | Basic security hygiene; baseline for all apps |
| L2 | Defense in Depth | Additional controls for high-value apps (banking, health) |
| R | Resilience | Anti-tampering, obfuscation, anti-debugging for DRM/payment apps |

**Key MASVS-STORAGE requirements:**
- MSTG-STORAGE-1: No sensitive data in system logs
- MSTG-STORAGE-2: No sensitive data in app container unless necessary and encrypted
- MSTG-STORAGE-3: No sensitive data in auto-generated screenshots
- MSTG-STORAGE-4: No sensitive data shared with third-party keyboards
- MSTG-STORAGE-9: No sensitive data leaked via IPC mechanisms

---

## 5. Common Mobile Vulnerabilities

### Insecure Data Storage

**Android SharedPreferences (insecure):**

```xml
<!-- Stored in /data/data/<package>/shared_prefs/<filename>.xml -->
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="auth_token">eyJhbGciOiJIUzI1NiJ9...</string>
    <string name="user_password">P@ssw0rd123</string>
</map>
```

**SQLite on Android:**

```java
// Unencrypted DB in app directory -- readable via ADB backup or root
SQLiteDatabase db = openOrCreateDatabase("users.db", MODE_PRIVATE, null);
// Located at: /data/data/<pkg>/databases/users.db

// Secure: use SQLCipher for encrypted SQLite
SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase(dbFile, "passphrase", null);
```

**External Storage:**

```java
// BAD: sensitive data on external storage
// Readable by any app with READ_EXTERNAL_STORAGE permission (before Android 10)
File file = new File(Environment.getExternalStorageDirectory(), "sensitive.txt");
// Use internal storage or MediaStore API instead
```

**iOS Insecure Storage:**

```swift
// BAD: NSUserDefaults for sensitive data
// Stored in plist under Library/Preferences/ -- not encrypted at rest
UserDefaults.standard.set(authToken, forKey: "auth_token")

// GOOD: Use Keychain for secrets
SecItemAdd([kSecClass: kSecClassGenericPassword, ...] as CFDictionary, nil)
```

---

### Hardcoded Credentials and API Keys

**Detection techniques:**

```bash
# Search decompiled APK
grep -r "api_key\|apiKey\|api_secret\|client_secret\|password\|token" output/
grep -rE "AKIA[A-Z0-9]{16}" output/          # AWS Access Key
grep -rE "AIza[0-9A-Za-z\-_]{35}" output/   # Google API Key

# Use truffleHog on APK contents
trufflehog filesystem --directory output/ --json
```

**Common locations in APKs:**
- `res/values/strings.xml` - API keys, base URLs
- `assets/config.json` / `assets/google-services.json`
- `classes.dex` - constants in code
- Native `.so` files - hardcoded in binary (use `strings` command)

---

### Improper Authentication

**Biometric Bypass (Android):**

```java
// Insecure: biometric result not tied to crypto operation
BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
    public void onAuthenticationSucceeded(AuthenticationResult result) {
        isAuthenticated = true;   // BAD: just sets a boolean flag
        loadSensitiveData();
    }
};

// Secure: tie biometric to Keystore-backed crypto object
// cipher initialized with Keystore key requiring user authentication
// onAuthenticationSucceeded receives cryptoObject -- key used only if biometric accepted
CryptoObject cryptoObject = new CryptoObject(cipher);
```

---

### Client-Side Injection

**WebView XSS / JavaScript Injection:**

```java
// VULNERABLE: JavaScript enabled + addJavascriptInterface exposed
WebView wv = (WebView) findViewById(R.id.webview);
wv.getSettings().setJavaScriptEnabled(true);
wv.addJavascriptInterface(new WebAppInterface(this), "Android");
// If attacker controls URL loaded, can call Android.getToken() etc.

// SECURE:
wv.getSettings().setAllowFileAccessFromFileURLs(false);
wv.getSettings().setAllowUniversalAccessFromFileURLs(false);
// Use shouldOverrideUrlLoading to validate URLs before loading
```

**iOS UIWebView / WKWebView:**

```swift
// VULNERABLE: UIWebView (deprecated) evaluates JavaScript on load
let webView = UIWebView()
webView.loadHTMLString(userControlledContent, baseURL: nil)  // XSS risk

// SECURE: WKWebView with message handler + origin validation
let config = WKWebViewConfiguration()
config.userContentController.add(self, name: "appBridge")
// In userContentController(_:didReceive:): validate message.frameInfo.securityOrigin
```

---

### Broken Cryptography

| Anti-Pattern | Risk | Fix |
|---|---|---|
| ECB mode | Identical plaintext blocks produce identical ciphertext; pattern leakage | Use AES-GCM or AES-CBC with random IV |
| Hardcoded IV | Predictable IV allows chosen-plaintext attacks | Generate random IV per encryption; prepend to ciphertext |
| MD5/SHA1 for HMAC | Collision vulnerabilities | Use HMAC-SHA256 minimum |
| DES/3DES | Deprecated; SWEET32 attack on 3DES-CBC | Use AES-256 |
| Hardcoded AES key | Key extraction from binary | Use Android Keystore / iOS Secure Enclave |
| Weak PBKDF | MD5-based KDF, low iteration count | PBKDF2-HMAC-SHA256 at least 310,000 iterations (NIST 2023) |

---

### Tapjacking and Overlay Attacks

```java
// Attacker app overlays transparent view over victim app button
WindowManager.LayoutParams params = new WindowManager.LayoutParams(
    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
    PixelFormat.TRANSLUCENT
);
// Victim taps what appears to be a button but actually taps attacker overlay

// Defense in victim app:
getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                     WindowManager.LayoutParams.FLAG_SECURE);
// Or in view XML: android:filterTouchesWhenObscured="true"
```

---

### Deep Link Hijacking and Intent Redirection

```xml
<!-- Attacker registers same custom URI scheme -->
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="myapp" android:host="callback"/>
</intent-filter>
<!-- Both victim and attacker can receive myapp://callback?token=xxx OAuth redirect -->
```

**Defense:** Use App Links (HTTPS + `assetlinks.json`) instead of custom schemes:

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.app",
    "sha256_cert_fingerprints": ["AA:BB:CC:..."]
  }
}]
```

---

### Broadcast Receiver Attacks

- Exported broadcast receivers without permission restrictions receive any intent from any app
- Sticky broadcasts remain in system memory; any app can call `registerReceiver()` to receive last sticky broadcast
- Ordered broadcasts allow malicious app registered at high priority to intercept and abort

```java
// VULNERABLE: exported receiver with no permission
// <receiver android:name=".SmsReceiver" android:exported="true">

// SECURE: restrict with permission
// <receiver android:name=".SmsReceiver"
//           android:exported="true"
//           android:permission="android.permission.RECEIVE_SMS">
```

---

### Fragment Injection in PreferenceActivity

```java
// Vulnerable: PreferenceActivity prior to Android 4.4
// isValidFragment() not overridden -- attacker can load arbitrary Fragment class via:
// adb shell am start -n com.example/.SettingsActivity
//   --es ":android:show_fragment" "com.example.SensitiveFragment"

// Fix: override isValidFragment()
@Override
protected boolean isValidFragment(String fragmentName) {
    return MyPreferenceFragment.class.getName().equals(fragmentName);
}
```

---

## 6. Mobile Malware Analysis

### Android Malware Families

| Family | Type | Key Behaviors | C2 / Persistence |
|---|---|---|---|
| **BankBot** | Banking trojan | Overlay attacks on banking apps; SMS interception for OTP; keylogging | Firebase C2 |
| **Cerberus** | Banking RAT | Screen capture, keylogging, overlay, 2FA bypass, Google Authenticator stealing | HTTP C2 |
| **FluBot** | SMS worm | Spreads via smishing; installs via APK link; banking overlay; contact harvesting | DGA-based C2 |
| **Joker** | Fleeceware/spyware | Subscribes to premium SMS without user consent; repeatedly found on Google Play | Embedded payload dropper |
| **SpyNote** | RAT | Remote access, camera/mic access, keylogging, location tracking | TCP reverse shell |
| **Anubis** | Banking trojan | Screen reader abuse; motion sensor anti-sandbox; overlay; ransomware module | Telegram/Twitter as C2 |
| **Ginp** | Banking trojan | Injects fake cards in banking apps; SMS intercept; contact stealer | HTTP |
| **Sharkbot** | Banking RAT | Keylogging, overlay, ATS (Automatic Transfer System), Google Play dropper | HTTP |

---

### iOS Malware: Pegasus (NSO Group) Technical Analysis

**Infection Vectors:**
- Zero-click: no user interaction required
  - FORCEDENTRY (CVE-2021-30860): Integer overflow in CoreGraphics PDF parser; sent via iMessage
  - BlastDoor sandbox bypass (iOS 14 iMessage protection circumvented)
  - Pre-2021 zero-click chain: `IMTranscoderAgent` exploitation
- One-click: malicious link triggers Safari/WebKit exploit chain

**Persistence:**
- Kernel exploit for unsandboxing and persistence across reboots
- Hides as system process; modifies kernel data structures to remove from process list
- Survives iTunes backup/restore at kernel level

**Capabilities:**
- Encrypted message extraction (Signal, WhatsApp, iMessage) by reading plaintext in memory after decryption
- Microphone and camera capture without activation indicator (pre-iOS 14)
- Real-time GPS tracking
- Keylogging, call recording
- Email and contact extraction

**Indicators (Amnesty International / MVT methodology):**

```bash
pip install mvt
mvt-ios check-icloud --iocs indicators.stix2 --output report/ backup_path/
mvt-android check-adb --iocs indicators.stix2 --output report/
# Look for: anomalous process names, DataUsage.sqlite anomalies, C2 domains in net.plist
```

---

### Dynamic Analysis Sandbox

**Android:**

```bash
# Create AVD for analysis
avdmanager create avd -n malware_sandbox -k "system-images;android-29;google_apis;x86_64"
emulator -avd malware_sandbox -no-snapshot -writable-system

# Capture network traffic
adb shell tcpdump -i any -w /sdcard/capture.pcap &
adb install malware_sample.apk
adb shell monkey -p com.malware.sample 500

# Monitor syscalls
adb shell strace -p <pid> -e trace=network,file

# Frida for runtime behavior
frida-trace -U -n com.malware.sample -i "open" -i "connect" -i "send"
```

**Joe Sandbox Mobile:**
- Commercial cloud sandbox for Android and iOS
- Behavioral report: network connections, file operations, SMS/calls, permissions used
- API: submit APK/IPA and receive JSON report with IOCs

---

### Indicators of Compromise (Mobile Malware)

| Category | Indicator |
|---|---|
| **Network** | Connections to DGA-generated domains, unusual ports (4444, 5555, 8888), periodic beacon intervals |
| **Process** | Unfamiliar processes with root privileges, processes mimicking system app names |
| **File system** | New files in `/data/local/tmp/`, modified `/system/` files, hidden `.` prefix files |
| **Battery/Data** | Unexplained battery drain, high background data usage by unknown apps |
| **SMS/Calls** | Outgoing SMS to premium numbers, calls to unknown numbers |
| **Permissions** | Apps with RECEIVE_SMS, READ_CALL_LOG, BIND_ACCESSIBILITY_SERVICE without explanation |
| **Android-specific** | Unrecognized device admin apps, accessibility services enabled without consent |
| **iOS-specific** | Unexpected enterprise profiles, TCC database modifications, unsigned processes |

---

### APK Obfuscation and Deobfuscation

**Obfuscation techniques:**

```
ProGuard:     Renames classes/methods to a, b, c; removes dead code
DexGuard:     Commercial; string encryption, class encryption, native conversion
String encryption: XOR/AES-encrypted strings decoded at runtime
Reflection:   Dynamic method invocation hides call graph from static analysis
Native packing: DEX loaded from native .so; defeats DEX-level analysis
Multi-stage loading: dropper downloads main payload in stages
```

**Deobfuscation techniques:**

```bash
# jadx with deobfuscation
jadx --deobf --deobf-min 3 --deobf-max 64 -d output/ obfuscated.apk

# Frida: hook ClassLoader to capture loaded classes
Java.perform(function() {
    var ClassLoader = Java.use('java.lang.ClassLoader');
    ClassLoader.loadClass.overload('java.lang.String').implementation = function(name) {
        console.log('[ClassLoader] Loading: ' + name);
        return this.loadClass(name);
    };
});

# Simplify for control flow deobfuscation
java -jar simplify.jar obfuscated.dex -o simplified.dex

# DEX dump from memory (after runtime unpacking)
adb shell "dd if=/proc/<pid>/mem bs=4096 skip=<offset> count=<size>" > dumped.dex
```

---

## 7. Mobile Device Management (MDM) Security

### MDM Architecture

```
Enrollment:   Device registers with MDM server (certificate + MDM profile)
Policy Push:  MDM server pushes config payloads (Wi-Fi, VPN, restrictions, apps)
Compliance:   MDM queries device compliance state (OS version, encryption, passcode)
Action:       Wipe, lock, revoke certificates, remove managed apps
```

**MDM Profile contents (mobileconfig):**

```xml
<dict>
    <key>PayloadType</key><string>com.apple.mdm</string>
    <key>ServerURL</key><string>https://mdm.company.com/checkin</string>
    <key>CheckInURL</key><string>https://mdm.company.com/checkin</string>
    <key>CheckOutWhenRemoved</key><true/>
    <key>AccessRights</key><integer>8191</integer>
    <key>IdentityCertificateUUID</key><string>...</string>
</dict>
```

---

### Apple MDM Protocol (APNS-based)

```
MDM Server --> APNS --> iPhone (silent push notification)
iPhone --> MDM Server: PUT /mdm/checkin (check-in request)
MDM Server --> iPhone: CommandResponse (JSON payload with command)
iPhone --> MDM Server: PUT /mdm/checkin (command result)
```

MDM commands include: `DeviceLock`, `EraseDevice`, `InstallApplication`, `RemoveApplication`, `ProfileList`, `SecurityInfo`, `DeviceInformation`, `ScheduleOSUpdateScan`, `InstallProfile`, `RemoveProfile`

**Supervision (Apple Configurator 2 / DEP):**
- Supervised devices allow: silent app installation/removal, restrictions not dismissible by user, deeper MDM controls
- DEP (Device Enrollment Program / ADE): device automatically enrolls in MDM on activation; user cannot remove MDM

---

### Android Enterprise (EMM API)

**Work Profile (BYOD):** Separate container with work apps/data; personal apps in primary profile; cross-profile restrictions configurable.

**Fully Managed Device (corporate-owned):** DPC (Device Policy Controller) installed as device owner; full control of device.

**Dedicated Device:** Locked to single purpose; kiosk mode; no user accounts.

```kotlin
// Setting device-wide policy (requires DEVICE_OWNER or PROFILE_OWNER)
val dpm = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager
val admin = ComponentName(this, AdminReceiver::class.java)

dpm.setPasswordQuality(admin, DevicePolicyManager.PASSWORD_QUALITY_COMPLEX)
dpm.setPasswordMinimumLength(admin, 8)
dpm.setCameraDisabled(admin, true)
dpm.wipeData(0)  // Remote wipe
```

---

### MAM vs. MDM vs. UEM

| Solution | Control Scope | Data Separation | User Privacy | Best For |
|---|---|---|---|---|
| **MAM** (Mobile Application Management) | Per-app policies only | App-level containers | High (personal data untouched) | BYOD with specific app control |
| **MDM** (Mobile Device Management) | Full device | OS-level enforcement | Lower (sees device info) | Corporate-owned devices |
| **UEM** (Unified Endpoint Management) | MDM + PC + IoT in single console | Cross-platform | Varies by policy | Enterprise with diverse device fleet |

---

### MDM Bypass Techniques

| Technique | Description | Defense |
|---|---|---|
| Profile removal | User removes MDM profile (unsupervised iOS, non-DPC Android) | Supervision (iOS), Device Owner (Android) |
| Factory reset | Resets device; removes MDM enrollment | DEP/Zero-touch enrollment re-enrolls on activation |
| Jailbreak/Root | Bypasses MDM restrictions; can fake compliance | MDM compliance check + jailbreak detection; MTD integration |
| Certificate spoofing | Fake MDM certificate to intercept commands | mTLS; certificate pinning in MDM client |
| Enrollment bypass | Intercept DEP enrollment; enroll under attacker MDM | Signed DEP tokens; validate server URL |

---

### Zero-Touch Enrollment Security

- Android: managed Google Play accounts; QR code or NFC bump enrollment; zero-touch portal
- Apple DEP: device tied to org at purchase via Apple Reseller; activation server redirects to org MDM
- Security concern: if MDM server URL is taken over (domain expiry, DNS hijack), devices could auto-enroll to attacker MDM
- Defense: monitor MDM server URL registration; use pinned DEP server URLs

---

### Conditional Access Integration with MDM Compliance

```
Device State (MDM compliance: encrypted, OS patched, no jailbreak)
     |
MDM compliance signal --> Azure AD / Okta / Google Workspace
     |
Conditional Access Policy: Block access if device not compliant
     |
App (Office 365 / GSuite) blocks until device enrolled and compliant
```

Tools: Microsoft Intune + Azure AD Conditional Access, Jamf Pro + Okta, Google Workspace MDM + BeyondCorp

---

## 8. Mobile Network Security

### SS7/Diameter Attacks

SS7 (Signaling System 7) is the protocol suite for telephone network signaling, designed in 1975 with no authentication.

| Attack | Description | Impact |
|---|---|---|
| **Location tracking** | Send SRI-SM to get HLR/VLR/IMSI; then ProvideSubscriberInfo for precise location | Real-time tracking without victim awareness |
| **Call interception** | Register attacker as roaming partner; redirect calls to attacker switch | Full call recording |
| **SMS redirection** | Update HLR with rogue VLR; SMS OTPs delivered to attacker | 2FA bypass; account takeover |
| **IMSI harvesting** | SendIdentification requests across interconnect | Building subscriber database for targeted attacks |
| **DoS** | CancelLocation removes subscriber from HLR | Service disruption |

**Diameter (4G/LTE equivalent):**
- Same conceptual attacks but over Diameter protocol
- Better potential for access control but still widely misconfigured
- Operators must implement Diameter Edge Agents (DEA) with firewall rules

**Defense:** GSMA FS.11/FS.19 recommendations; SS7 firewall deployment; SMS home routing; monitoring for anomalous roaming queries

---

### IMSI Catchers (Stingray)

- Active GSM/LTE base station emulators; force nearby devices to connect
- Capture IMSI, IMEI, location; may intercept calls/SMS (2G downgrade attacks)
- Downgrade attack: force 2G (no encryption or A5/0 null cipher) for interception

**Detection techniques:**
- AIMSICD (Android IMSI-Catcher Detector): anomalous base station parameters
- SnoopSnitch: analyze baseband AT commands for IMSI catcher indicators
- CryptoPhone (GSMK): baseband traffic monitoring for cipher downgrades

**Indicators:**
- Sudden drop to 2G/EDGE in area with strong 4G coverage
- Tower with unusually strong signal not in carrier published database
- Network rejects encryption (A5/0 cipher selected)
- Sudden battery drain (continuous high-power transmission)

---

### 5G NR Security Improvements over LTE

| Feature | LTE | 5G NR |
|---|---|---|
| SUPI/SUCI | IMSI sent in cleartext; IMSI catcher exploitable | SUCI: IMSI encrypted with home network public key (ECIES) |
| Mutual auth | AKA protocol; some vectors allow fake base station | 5G-AKA with home control; SEAF/AUSF architecture |
| Ciphering mandatory | Optional downgrade to null cipher | Null cipher blocked in 5G SA; downgrade detection |
| Integrity protection | User plane optional | User plane integrity mandatory in 5G |
| Subscriber privacy | Long-term tracking via IMSI | Pseudonymization via SUCI rotation |
| Network slicing | N/A | Slice-specific security policies; isolation between slices |

---

### Wi-Fi Attacks on Mobile

**KARMA / MANA Attack:**

```bash
# hostapd-mana: responds to all Wi-Fi probe requests with matching SSID
hostapd-mana mana.conf
# Devices with preferred network lists auto-connect to known SSIDs
# Capture WPA2 handshakes; serve evil twin with captive portal
```

**Deauthentication Attack:**

```bash
# Aireplay-ng: send deauth frames to disconnect victim from legitimate AP
aireplay-ng --deauth 10 -a <AP_BSSID> -c <victim_MAC> wlan0mon
# Victim reconnects to strongest AP -- evil twin
```

**Protection:** WPA3 with PMF (Protected Management Frames); 802.11w; always-on VPN; avoid auto-connect to open networks.

---

### Bluetooth Security

**BLE Pairing Modes:**

| Mode | Security | Attack Surface |
|---|---|---|
| Just Works | No auth; passive MITM | Eavesdropping, MITM |
| Passkey Entry | PIN displayed/entered | Brute force (6-digit PIN) |
| Numeric Comparison | User confirms 6-digit number on both | User confusion attacks |
| Out of Band (OOB) | NFC/QR pre-shared key | Depends on OOB channel |
| LE Secure Connections | ECDH + numeric comparison | Secure; attack is protocol downgrade |

**BlueBorne (CVE-2017-0781, CVE-2017-0782, CVE-2017-0785, CVE-2017-0786):**
- Critical Bluetooth stack vulnerabilities in Android, Linux, iOS, Windows (2017)
- Remote code execution without pairing or user interaction over Bluetooth
- Android: SDP overflow in `android.hardware.bluetooth@1.0`; remote heap overflow
- Mitigation: patched in September 2017 security patch level; disable Bluetooth when not needed

---

### NFC Security

**Relay Attack (NFC):**

```
Victim card --> Reader Proxy (attacker near victim)
             --> Internet/Bluetooth -->
                 Emulator (attacker near POS terminal)
```

- Allows payment fraud using victim contactless card
- Defense: EMV transaction counters; distance bounding protocols; NFC shielding wallets

**NDEF Injection:**
- Malicious NFC tag triggers URL, phone call, or app launch when scanned
- Auto-open NDEF could trigger drive-by download or phishing page
- Android NFC Beam (deprecated) vulnerabilities: auto-accept files in older Android versions
- Defense: disable NFC when not in use; Android 10+ prompts before opening NDEF URLs

---

## 9. Enterprise Mobile Security

### Samsung Knox Security Architecture

**Hardware Security:**
- Arm TrustZone-based Trusted Execution Environment (TEE)
- Samsung eSE (embedded Secure Element) on flagship devices
- Hardware-backed keystore with Knox attestation

**Software Security Layers:**

```
Application Layer: Knox Workspace (isolated container)
                   TIMA (TrustZone-based Integrity Measurement Architecture)
Framework Layer:   SE for Android (enhanced SELinux policy)
                   Real-time Kernel Protection (RKP) - hypervisor-level
Kernel Layer:      Verified Boot + dm-verity
                   DEFEX (Defect Execution prevention)
TrustZone Layer:   Secure World OS
```

**Knox Attestation:** Hardware-backed certificate chain verifiable by MDM; detects Knox compromised status if device is rooted or modified.

---

### Apple Business Manager (ABM) and DEP

- ABM: web portal for volume app purchases, device enrollment, MDM server assignment
- Automated Device Enrollment (ADE, formerly DEP): devices auto-enroll in MDM on activation
- Security implication: device ties to organization before user ever touches it
- User Enrollment (iOS 13+): for BYOD; creates separate managed Apple ID; separate cryptographic volume; MDM has limited visibility

---

### Android Enterprise Work Profile Isolation

```
Primary Profile (Personal)         Work Profile (Managed)
--------------------------         ----------------------
Personal apps                      Work apps (badged with briefcase icon)
Personal data                      Work data
Personal Google account            Managed Google account
User controls                      DPC + IT admin controls

Cross-profile policies (IT-configurable):
- Block copy/paste between profiles
- Block screenshots in work apps
- Block work contact lookup from personal dialer
- Restrict which work apps can open personal content
```

---

### Microsoft Intune + Conditional Access

**Compliance policy example (Intune):**

```json
{
  "displayName": "iOS Compliance Policy",
  "osMinimumVersion": "16.0",
  "passcodeRequired": true,
  "passcodeMinimumLength": 6,
  "passcodeRequireExpiry": true,
  "jailBroken": "Block",
  "deviceThreatProtectionEnabled": true,
  "deviceThreatProtectionRequiredSecurityLevel": "Low",
  "storageRequireEncryption": true
}
```

**Conditional Access policy flow:**

```
User authenticates --> Azure AD checks:
  1. Is device enrolled in Intune?
  2. Is device compliant with policy?
  3. Is user in allowed group?
  4. Is device platform allowed?
  --> Grant / Block / Require MFA
```

---

### Mobile Threat Defense (MTD) Solutions

| Vendor | Product | Key Capabilities |
|---|---|---|
| **Zimperium** | zIPS, z3A | On-device ML detection; network, app, OS, phishing threat detection; no-cloud option |
| **Lookout** | Mobile Endpoint Security | App risk analysis; network protection; cloud-based detection; Intune integration |
| **CrowdStrike** | Falcon for Mobile | EDR for iOS/Android; unified with Falcon console; IOA-based detection |
| **Microsoft** | Defender for Endpoint Mobile | Android + iOS; web protection, jailbreak/root detection, MTD integration with Intune |
| **Check Point** | Harmony Mobile | Network threat prevention; anti-phishing; app risk; sandbox |
| **Jamf** | Jamf Protect (iOS) | Native iOS security; zero-trust network access; behavioral analytics |

**MTD integration with MDM:**

```
MTD agent on device --> risk assessment --> signal to MDM
MDM conditional access policy checks MTD risk level
If high risk --> block corporate email/apps until resolved
```

---

### Enterprise App Vetting Process

```
Step 1: Source verification (official store, signed binary, known developer)
Step 2: Static analysis (MobSF scan, permission audit, binary analysis)
Step 3: Dynamic analysis (sandbox execution, network traffic review)
Step 4: Privacy analysis (PII collection, third-party SDK inventory)
Step 5: Vendor risk assessment (SOC 2, privacy policy, data residency)
Step 6: Ongoing monitoring (app updates re-vetted; CVE monitoring for included libraries)
```

Tools: AppDome, NowSecure Platform, Veracode Mobile, NTT Application Security

---

## 10. Mobile CTF and Bug Bounty

### Android Bug Bounty Programs

| Program | Scope | Payout Range |
|---|---|---|
| **Android VRP** (Google) | Android OS, AOSP, Pixel firmware, Android apps | $1K to $1M+ (critical Pixel exploits) |
| **Google Play Security Rewards** | Apps on Google Play with 100M+ installs | $1K to $30K |
| **Samsung Mobile** | Samsung Galaxy firmware, Knox, One UI | $200 to $1M (Samsung Mobile Security Rewards) |
| **Meta** | Messenger, WhatsApp, Instagram on Android/iOS | $500 to $500K+ |
| **HackerOne / Bugcrowd** | Various mobile apps in scope | Program-dependent |

**Android VRP high-value categories:**
- Remote code execution in Android OS/Pixel (no interaction): up to $1M
- TEE/Secure Element compromise: $500K+
- Bootloader/TrustZone: $250K+
- Lock screen bypass: $100K+
- Data exfiltration from locked device: $50K+

---

### Apple Security Research Device Program (SRDP)

- Provides specialized iPhone hardware with relaxed security model for security research
- Allows: SSH access, custom entitlements, custom kernel caching, crash logging
- Eligible researchers: security community members with track record
- Terms: findings must be reported to Apple before publication

**Apple Security Bounty payouts:**
- iCloud account compromise (no interaction): up to $1M
- Network attack without user interaction (kernel RCE): $500K
- Lock screen bypass: $100K
- App sandbox escape: $25K
- Access to sensitive user data: $100K-$250K

---

### Common High-Severity Mobile Findings

| Finding | Impact | Example |
|---|---|---|
| RCE via WebView | Full app compromise; potential device compromise | loadUrl() with attacker-controlled URL + JavaScript bridge exposed |
| Auth bypass (biometric) | Unauthorized access to app data | Boolean-flag-only biometric check; no crypto key binding |
| Deeplink token theft | Account takeover via OAuth redirect interception | Custom scheme OAuth callback + no PKCE |
| Exported content provider | Arbitrary file read/write; SQL injection | ContentProvider with android:exported="true", no permission |
| Insecure direct object reference | Data of other users accessible via mobile API | IDOR in REST API called by mobile app |
| Cleartext credential transmission | Credential theft via MITM | HTTP login endpoint; missing ATS exception |
| Hardcoded API key | Backend compromise | AWS key in strings.xml; Firebase key without restrictions |
| Universal XSS in WebView | Cross-origin data theft | setAllowUniversalAccessFromFileURLs(true) + file:// load |

---

### CTF Platforms: Mobile Challenges

| Platform | Challenge Types | Notes |
|---|---|---|
| **HackTheBox** | Android APK reversing, Frida challenges, iOS binary analysis | Mobile category in main challenge section |
| **MOBISEC CTF** | Mobile-specific CTF; Android + iOS | Dedicated mobile security CTF archive |
| **OWASP UnCrackable Apps** | Android: 3 levels of reverse engineering; iOS: 2 levels | Deliberately insecure apps for practice |
| **DIVA (Damn Insecure Vulnerable App)** | Android app with 13 insecure scenarios | Local practice |
| **iGoat** | iOS vulnerable app | OWASP sponsored |
| **InsecureShop** | Android e-commerce app with intentional vulnerabilities | Covers OWASP Mobile Top 10 |

```bash
# OWASP UnCrackable Level 1 approach
jadx -d output/ UnCrackable-Level1.apk
grep -r "verify\|checkRoot\|secret" output/
frida -U -f owasp.mstg.uncrackable1 --no-pause -l uncrackable1_solve.js
```

---

### MITRE ATT&CK Mobile Technique Mapping

| Tactic | Technique ID | Technique Name | Example |
|---|---|---|---|
| Initial Access | T1475 | Deliver Malicious App via Authorized App Store | Joker malware on Google Play |
| Initial Access | T1476 | Deliver Malicious App via Other Means | Smishing link to APK; enterprise profile abuse |
| Initial Access | T1458 | Repackaged Application | Trojanized APK with RAT embedded |
| Execution | T1603 | Scheduled Task/Job | AlarmManager / JobScheduler for persistence |
| Persistence | T1577 | Compromise Application Executable | Modify APK; reflash device firmware |
| Persistence | T1402 | Broadcast Receivers | BOOT_COMPLETED receiver for auto-start |
| Privilege Escalation | T1404 | Exploitation for Privilege Escalation | CVE-2019-2215 (Binder use-after-free) |
| Defense Evasion | T1407 | Download New Code at Runtime | Reflective DEX loading; dynamic dexClassLoader |
| Defense Evasion | T1418 | Software Discovery | Enumerate installed apps; detect sandbox/AV |
| Credential Access | T1417 | Input Capture | Keylogger; overlay attack capturing credentials |
| Credential Access | T1414 | Clipboard Data | READ_CLIPBOARD to steal OTPs |
| Discovery | T1420 | File and Directory Discovery | Enumerate /sdcard/; find documents |
| Discovery | T1421 | System Network Connections Discovery | List active connections; find listening services |
| Collection | T1412 | Capture SMS Messages | READ_SMS; SMS worm for banking 2FA |
| Collection | T1429 | Capture Audio | RECORD_AUDIO without activation indicator |
| Collection | T1512 | Video Capture | CAMERA access; background recording |
| Collection | T1430 | Location Tracking | ACCESS_FINE_LOCATION; GPS polling |
| Exfiltration | T1437 | Application Layer Protocol | HTTPS C2; XMPP; Firebase; Telegram API |
| Impact | T1448 | Carrier Billing Fraud | SEND_SMS to premium numbers without consent |
| Impact | T1471 | Data Encrypted for Impact | Android ransomware; file encryption |

---

## Quick Reference: Mobile Security Tools

| Tool | Platform | Category | Usage |
|---|---|---|---|
| **jadx** | Android | Static analysis | Decompile APK to Java |
| **apktool** | Android | Static analysis | Decode/rebuild APK; Smali analysis |
| **MobSF** | Android + iOS | Static + Dynamic | Automated scan suite |
| **Frida** | Android + iOS | Dynamic analysis | Runtime instrumentation |
| **Objection** | Android + iOS | Dynamic analysis | Automated Frida-based exploration |
| **apk-mitm** | Android | Network | Patch APK for MITM proxy |
| **Drozer** | Android | Attack surface | Module-based app attack framework |
| **Burp Suite** | Android + iOS | Network | HTTP/S proxy interception |
| **class-dump** | iOS | Static analysis | Dump Objective-C headers |
| **jtool2** | iOS | Static analysis | Binary analysis, entitlements |
| **Hopper Disassembler** | iOS + Android | RE | GUI disassembler/decompiler |
| **Ghidra** | Android + iOS | RE | NSA-developed; ARM/ARM64 support |
| **r2frida** | Android + iOS | RE + Dynamic | radare2 + Frida combined |
| **MVT** | Android + iOS | Forensics | Pegasus/spyware detection |
| **Cellebrite UFED** | All | Forensics | Physical/logical acquisition |
| **ADB** | Android | All | Android Debug Bridge; core tool |
| **iMazing** | iOS | Forensics | iOS backup and analysis |
| **checkra1n** | iOS | Jailbreak | Hardware exploit (A5-A11) |
| **Magisk** | Android | Root | Systemless root; hide from attestation |
| **SnoopSnitch** | Android | Network | SS7 / IMSI catcher detection |

---

## Further Reading and Resources

- [OWASP Mobile Application Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/)
- [OWASP Mobile Application Security Verification Standard (MASVS)](https://mas.owasp.org/MASVS/)
- [Google Android Security Bulletins](https://source.android.com/docs/security/bulletin)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
- [MITRE ATT&CK for Mobile](https://attack.mitre.org/matrices/mobile/)
- [GSMA Mobile Security Guidelines](https://www.gsma.com/security/)
- [NSO Group Pegasus - Amnesty International Technical Analysis](https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/)
- [Android Source Security](https://source.android.com/docs/security)
- [Project Zero Blog - iOS exploits](https://googleprojectzero.blogspot.com/)
- [NowSecure Mobile Security Research](https://www.nowsecure.com/blog/)

---

*Last updated: 2026-04-26 | Part of the [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) cybersecurity reference library*
