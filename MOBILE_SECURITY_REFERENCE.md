# Mobile Security Reference

> OWASP MASVS v2, Android/iOS security architecture, APK/IPA static and dynamic analysis, Frida/objection tooling, MDM/MAM policy baselines, and mobile threat defense.

---

## Table of Contents

1. [OWASP MASVS v2](#owasp-masvs-v2)
2. [Android Security](#android-security)
3. [iOS Security](#ios-security)
4. [Mobile Device Management (MDM)](#mobile-device-management-mdm)
5. [Mobile Threat Defense (MTD)](#mobile-threat-defense-mtd)
6. [Mobile Attack Vectors](#mobile-attack-vectors)
7. [ATT&CK for Mobile Mapping](#attck-for-mobile-mapping)

---

## OWASP MASVS v2

The Mobile Application Security Verification Standard (MASVS) v2 defines seven security control categories. Each category maps directly to MASTG (Mobile Application Security Testing Guide) test cases.

### MASVS-STORAGE — Secure Data Storage

Sensitive data must never be stored in unprotected locations. Applies to both Android and iOS.

**Key Requirements**
- No sensitive data in SharedPreferences (Android) or NSUserDefaults (iOS) without encryption
- SQLite databases containing PII must use SQLCipher or equivalent
- No credentials, tokens, or keys written to application logs
- Backups excluded from containing sensitive data (`android:allowBackup="false"`, `NSApplicationSupport` exclusions)
- No sensitive data exposed via screenshot cache (FLAG_SECURE / ignoresScreenCapture)

**Testing Commands**
```bash
# Android — pull shared preferences and inspect
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml

# Android — check SQLite databases
adb pull /data/data/com.target.app/databases/
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users;"

# Android — check logcat for sensitive data leakage
adb logcat | grep -iE "password|token|key|secret|credential"

# Android — check backup flag in manifest
apktool d target.apk -o decoded/
grep "allowBackup" decoded/AndroidManifest.xml

# iOS — dump NSUserDefaults via objection
objection --gadget TargetApp explore
# ios nsuserdefaults get

# iOS — check keychain entries
# ios keychain dump

# iOS — check for plaintext data in app container
find /private/var/mobile/Containers/Data/Application/<UUID>/ -name "*.plist" -exec plutil -p {} \;
```

---

### MASVS-CRYPTO — Cryptography

Cryptographic operations must use current, secure algorithms with proper key management.

**Key Requirements**
- No hardcoded cryptographic keys, IVs, or salts in source code or resources
- No deprecated algorithms: MD5, SHA-1, DES, RC4, ECB mode
- AES-GCM or AES-CBC with HMAC preferred; minimum 256-bit key length
- Key derivation via PBKDF2 (100,000+ iterations), bcrypt, or Argon2
- Keys stored in Android Keystore / iOS Secure Enclave, not in app files
- RNG must use `SecureRandom` (Android) or `SecRandomCopyBytes` (iOS)

**Testing Commands**
```bash
# Grep decompiled source for hardcoded secrets
jadx -d output/ target.apk
grep -rE "AES/ECB|DES|RC4|MD5|SHA-?1|\"password\"|\"secret\"|\"key\"" output/sources/

# Search binary for embedded keys
strings decoded/classes.dex | grep -E "[A-Za-z0-9+/]{32,}={0,2}"
strings decoded/classes.dex | grep -iE "BEGIN (RSA|PRIVATE|CERTIFICATE)"

# Check for ECB mode usage
grep -r "AES/ECB" output/

# iOS — check for hardcoded keys in binary
strings TargetApp | grep -iE "password|secret|key|token|apikey"
rabin2 -z TargetApp | grep -iE "key|secret|password"

# Check for deprecated hash usage
grep -rE "MessageDigest\.getInstance\(\"MD5\"\|\"SHA-1\"\)" output/
```

---

### MASVS-AUTH — Authentication and Session Management

Authentication must be implemented server-side with strong credential requirements and token management.

**Key Requirements**
- Biometric authentication must require a cryptographic operation tied to the Secure Enclave/Keystore
- Biometric fallback to device PIN (not app-level PIN only)
- Session tokens must expire: short-lived access tokens (15–60 min), refresh token rotation
- No session tokens persisted to disk in plaintext
- Password/PIN policies enforced server-side, not client-only
- Re-authentication required for sensitive operations (payment, account changes)

**Testing Commands**
```bash
# Android — check biometric implementation
grep -r "BiometricPrompt\|FingerprintManager" output/
grep -r "setUserAuthenticationRequired\|setUserAuthenticationValidityDurationSeconds" output/

# Check for insecure token storage
adb shell run-as com.target.app find . -name "*.xml" -exec cat {} \; | grep -iE "token|session|auth"

# iOS — check keychain accessibility attribute
grep -r "kSecAttrAccessibleAlways\|kSecAttrAccessibleAfterFirstUnlock" headers/

# Intercept session token expiry via Burp
# Set system proxy, install Burp CA, replay captured requests after timeout

# objection — check authentication state
android intent launch_activity com.target.app/.MainActivity
android hooking watch class_method com.target.app.auth.SessionManager.isTokenExpired
```

---

### MASVS-NETWORK — Network Communication

All network communication must be encrypted and server identity must be verified.

**Key Requirements**
- TLS 1.2 minimum; TLS 1.3 preferred
- Certificate validation must not be disabled (`ALLOW_ALL_HOSTNAME_VERIFIER`, custom TrustManagers that accept all)
- Certificate pinning implemented and tested against bypass
- No sensitive data in HTTP (cleartext) traffic
- Android Network Security Config (NSC) properly configured
- ATS (App Transport Security) not globally disabled on iOS

**Testing Commands**
```bash
# Static — check for disabled TLS validation
grep -r "ALLOW_ALL_HOSTNAME_VERIFIER\|onReceivedSslError\|proceed()\|NullHostnameVerifier" output/
grep -r "setHostnameVerifier\|SSLSocketFactory\|TrustManager" output/

# Check Android NSC
cat decoded/res/xml/network_security_config.xml

# Check iOS ATS
plutil -p TargetApp.app/Info.plist | grep -A5 "NSAppTransportSecurity"

# Dynamic — route through Burp Suite
adb shell settings put global http_proxy BURP_IP:8080
# Install Burp CA: adb push burp_ca.crt /sdcard/ then install via Settings

# SSL pinning bypass with Frida
frida -U -l ssl_bypass.js com.target.app
# ssl_bypass.js — universal pinning bypass (from apk-mitm or frida-codeshare)

# SSL pinning bypass with objection
objection -g com.target.app explore
android sslpinning disable

# iOS SSL kill switch
# ios sslpinning disable

# MobSF dynamic — start HTTPS proxy
# MobSF auto-routes traffic through its embedded proxy

# Verify cleartext traffic
adb logcat | grep -i "http://"
```

---

### MASVS-PLATFORM — Platform Interaction

Apps must use platform features securely and not expose sensitive functionality to other apps.

**Key Requirements**
- No exported Activities, Services, or ContentProviders without proper permission controls
- WebViews must not enable `setJavaScriptEnabled` with untrusted content
- WebViews must not enable `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs`
- Deep link handling validates and sanitizes all input
- No sensitive data passed in Intent extras to exported components
- Broadcast receivers for sensitive actions use `LocalBroadcastManager` or signature-level permissions
- iOS URL scheme handlers validate caller context

**Testing Commands**
```bash
# Enumerate exported components
apktool d target.apk -o decoded/
grep -E "exported=\"true\"|android:exported" decoded/AndroidManifest.xml

# Test exported Activity
adb shell am start -n com.target.app/.ExportedActivity --es extra_data "payload"

# Test ContentProvider
adb shell content query --uri content://com.target.app.provider/data

# Check WebView security settings
grep -r "setJavaScriptEnabled\|setAllowFileAccess\|addJavascriptInterface" output/

# Check deep link handling
grep -r "intent-filter\|scheme\|host\|pathPrefix" decoded/AndroidManifest.xml

# iOS — check URL scheme handlers
plutil -p TargetApp.app/Info.plist | grep -A3 "CFBundleURLSchemes"

# Check for IPC vulnerabilities with Drozer
drozer console connect
run app.package.attacksurface com.target.app
run app.activity.start --component com.target.app com.target.app.ExportedActivity
run scanner.provider.injection -a com.target.app
```

---

### MASVS-CODE — Code Quality

Apps must not expose debug functionality and must protect against known vulnerabilities.

**Key Requirements**
- `debuggable` flag must be `false` in release builds
- `android:testOnly` must be `false`
- No logging of sensitive data in production builds (`Log.d`, `NSLog` stripped)
- ProGuard/R8 obfuscation enabled for release
- No hardcoded URLs pointing to development/staging endpoints
- Dependencies must be current; no known-vulnerable third-party libraries
- Stack canaries, PIE, NX enabled in native libraries

**Testing Commands**
```bash
# Check debuggable flag
grep "debuggable" decoded/AndroidManifest.xml
# Should NOT be: android:debuggable="true"

# iOS — check PIE and stack canaries
otool -hv TargetApp | grep PIE
checksec TargetApp

# Check for debug log statements
grep -rE "Log\.(d|v|i)\(|System\.out\.print|printStackTrace" output/sources/

# Check obfuscation (look for meaningful class/method names)
jadx -d output/ target.apk
ls output/sources/  # Obfuscated: should see a/, b/, c/ etc.

# Check for hardcoded dev endpoints
grep -rE "http://|staging\.|dev\.|localhost|127\.0\.0\.1|192\.168\." output/sources/

# Dependency vulnerability check
# Extract dependencies from decompiled source or build files
# Cross-reference with OSV/NVD

# Check native library security
find decoded/lib/ -name "*.so" -exec checksec {} \;
```

---

### MASVS-RESILIENCE — Resilience Against Reverse Engineering

High-security apps (banking, mHealth, enterprise) should implement additional protections.

**Key Requirements**
- Root/jailbreak detection with multiple check vectors
- Anti-tampering: signature verification, checksum of critical code
- Anti-debugging: detect ptrace, debugger presence checks
- Emulator detection for production builds
- Code obfuscation beyond basic ProGuard/R8 (string encryption, control flow obfuscation)
- Runtime Application Self-Protection (RASP) integration for Tier 1 apps

**Testing Commands**
```bash
# Bypass root detection with objection
objection -g com.target.app explore
android root disable

# Bypass root detection with Frida
frida -U -l root_bypass.js com.target.app

# Typical root detection methods to hook:
# - RootBeer checks
# - su binary existence checks
# - Build.TAGS contains "test-keys"
# - Magisk detection

# Check anti-debugging implementation
grep -r "Debug.isDebuggerConnected\|android.os.Debug" output/
grep -r "ptrace\|PTRACE_TRACEME" decoded/lib/

# iOS — jailbreak bypass Frida snippet
# frida -U -l jb_bypass.js TargetApp

# Emulator detection checks
grep -r "Build.FINGERPRINT\|Build.MODEL\|isEmulator\|QEMU" output/

# App integrity check
# Verify APK signature
apksigner verify --verbose target.apk
jarsigner -verify -verbose target.apk
```

---

## Android Security

### Architecture Overview

Android is built on a Linux kernel with multiple security layers:

| Layer | Component | Security Function |
|---|---|---|
| Hardware | TrustZone / StrongBox | Secure key storage, attestation |
| Kernel | Linux + SELinux | Process isolation, MAC policy |
| Runtime | ART + Bionic libc | ASLR, stack canaries, CFI |
| Framework | Binder IPC | Enforced permission checks |
| App Layer | APK Sandbox | UID-per-app isolation |

**APK Structure**
```
target.apk
├── AndroidManifest.xml    # Permissions, components, exported status
├── classes.dex            # Dalvik bytecode (primary)
├── classes2.dex           # Multidex overflow
├── res/                   # Resources, layouts, strings
├── assets/                # Raw bundled files
├── lib/                   # Native .so libraries (armeabi-v7a, arm64-v8a)
├── META-INF/             # Signature files (CERT.RSA, MANIFEST.MF)
└── resources.arsc         # Compiled resource table
```

**Permission Model**

| Level | Description | Example |
|---|---|---|
| Normal | Auto-granted, low-risk | INTERNET, VIBRATE |
| Dangerous | Requires user approval | CAMERA, CONTACTS, LOCATION |
| Signature | Granted only to apps signed with same cert | BIND_DEVICE_ADMIN |
| Privileged | System apps only | INSTALL_PACKAGES |

---

### Android Static Analysis

```bash
# Step 1 — Decompile APK
apktool d target.apk -o decoded/          # Resources + manifest
jadx -d output/ target.apk               # Java source decompilation
jadx-gui target.apk                       # GUI decompiler

# Step 2 — Extract strings
strings decoded/classes.dex | grep -iE "password|key|secret|token|api"
strings decoded/classes.dex | grep -E "[A-Za-z0-9]{32,}"  # Potential keys

# Step 3 — Search for security anti-patterns
grep -r "MODE_WORLD_READABLE\|MODE_WORLD_WRITEABLE" output/
grep -r "ALLOW_ALL_HOSTNAME_VERIFIER\|NullHostnameVerifier" output/
grep -r "AES/ECB\|DES/\|RC4\|MD5\|SHA-1" output/
grep -r "setJavaScriptEnabled(true)" output/
grep -r "setAllowFileAccess\|setAllowUniversalAccess" output/
grep -r "android:debuggable=\"true\"" decoded/
grep -r "allowBackup=\"true\"" decoded/AndroidManifest.xml

# Step 4 — Certificate pinning review
grep -r "CertificatePinner\|TrustManagerFactory\|X509TrustManager\|pinCertificate" output/

# Step 5 — MobSF automated analysis (Docker)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# Upload APK at http://localhost:8000 for automated static + dynamic analysis

# Step 6 — Native library analysis
for lib in decoded/lib/arm64-v8a/*.so; do
    echo "=== $lib ==="
    nm -D "$lib" 2>/dev/null | grep " T "  # Exported symbols
    strings "$lib" | grep -iE "password|key|http"
done
```

---

### Android Dynamic Analysis

**ADB Essentials**
```bash
# Device enumeration and shell access
adb devices
adb shell
adb -s <device_id> shell           # Target specific device

# App installation and management
adb install target.apk
adb install -r target.apk          # Reinstall (keep data)
adb uninstall com.target.app

# Runtime log monitoring
adb logcat | grep com.target.app
adb logcat -s com.target.app:V     # Filter by app tag, Verbose+
adb logcat *:E                     # Errors only

# File system access (rooted or debug build)
adb pull /data/data/com.target.app/shared_prefs/
adb pull /data/data/com.target.app/databases/
adb pull /sdcard/Android/data/com.target.app/

# Proxy configuration for Burp Suite
adb shell settings put global http_proxy BURP_IP:8080
adb shell settings put global http_proxy :0            # Remove proxy

# Screen capture
adb exec-out screencap -p > screen.png
adb screenrecord /sdcard/capture.mp4
```

**Frida Instrumentation**
```bash
# List running processes
frida-ps -U                          # USB device
frida-ps -H DEVICE_IP:27042         # Network

# Attach and run a script
frida -U -l script.js com.target.app
frida -U -f com.target.app -l script.js --no-pause   # Spawn mode

# SSL pinning bypass
frida -U -l ssl_bypass.js com.target.app
# Recommended: https://github.com/httptoolkit/frida-android-unpinning

# Example Frida SSL pinning bypass snippet
# ssl_bypass.js:
# Java.perform(function() {
#   var OkHttpClient = Java.use("okhttp3.OkHttpClient");
#   var CertificatePinner = Java.use("okhttp3.CertificatePinner");
#   CertificatePinner.check.overload("java.lang.String","java.util.List").implementation = function(a,b) {
#     console.log("[*] SSL Pinning Bypassed for: " + a);
#   };
# });

# Hook method for monitoring
frida-trace -U -j "*!*login*" com.target.app        # Trace login methods
frida-trace -U -j "com.target.app.AuthManager!*" com.target.app
```

**objection — Runtime Exploration**
```bash
# Attach to running app
objection -g com.target.app explore

# Inside objection REPL:
android info libraries                    # Loaded libraries
android hooking list classes              # All loaded classes
android hooking list class_methods com.target.app.auth.TokenManager
android hooking watch class_method com.target.app.auth.TokenManager.getToken

android root disable                      # Bypass root detection
android sslpinning disable               # Bypass SSL pinning
android clipboard monitor               # Monitor clipboard

android intent launch_activity com.target.app.DebugActivity  # Launch exported Activity
android keystore list                    # List Android Keystore entries

memory dump all /tmp/memory.bin          # Dump app memory
memory search "password" --string        # Search memory for strings
```

---

### Dangerous Permissions Audit

| Permission | Risk Level | Legitimate Use | Red Flags |
|---|---|---|---|
| `READ_CONTACTS` | High | Dialer, messaging apps | Flashlight, game, utility apps |
| `ACCESS_FINE_LOCATION` | High | Navigation, delivery, weather | Apps with no location feature |
| `CAMERA` | High | Video call, QR scanner, photo | Apps that only need file selection |
| `READ_SMS` | Critical | 2FA apps, SMS backup | Any app not needing SMS OTP |
| `RECORD_AUDIO` | High | Voice call, voice memo | Calculator, note apps |
| `SYSTEM_ALERT_WINDOW` | High | Screen overlay, assistive tech | Requested by unknown sideloaded apps |
| `BIND_DEVICE_ADMIN` | Critical | MDM agents, enterprise management | Consumer apps, games |
| `READ_CALL_LOG` | Critical | Call manager, caller ID | Any app that should not see call history |
| `PACKAGE_USAGE_STATS` | High | Parental control, productivity | Apps without explicit tracking purpose |
| `REQUEST_INSTALL_PACKAGES` | Critical | App stores, MDM | Any app with no legitimate reason |
| `WRITE_SETTINGS` | Medium | VPN client, accessibility | Unknown third-party utilities |

---

## iOS Security

### Architecture Overview

iOS provides defense-in-depth through hardware and OS-level controls:

| Layer | Component | Security Function |
|---|---|---|
| Hardware | Secure Enclave Processor (SEP) | Biometric templates, key operations, Touch/Face ID |
| Kernel | XNU + PAC | Pointer authentication, code signing enforcement |
| OS | Mandatory code signing | Only Apple-signed or provisioned code executes |
| Runtime | ASLR + sandboxing | App containers isolated at `/private/var/mobile/Containers/` |
| Data | Data Protection API | Per-file encryption keys tied to device + passcode |

**Data Protection Classes**

| Class | iOS Constant | Access Policy |
|---|---|---|
| Complete | `NSFileProtectionComplete` | Only while device unlocked |
| Complete Unless Open | `NSFileProtectionCompleteUnlessOpen` | File opened before lock remains accessible |
| Complete Until First Auth | `NSFileProtectionCompleteUntilFirstUserAuthentication` | Available after first unlock after boot (default) |
| None | `NSFileProtectionNone` | Always accessible (avoid for sensitive data) |

**App Container Structure**
```
/private/var/mobile/Containers/Bundle/Application/<UUID>/  (App binary + bundle)
/private/var/mobile/Containers/Data/Application/<UUID>/    (App data)
├── Documents/      # User-visible documents, included in iTunes backup
├── Library/        # Preferences, caches, support files
│   ├── Preferences/  # NSUserDefaults plist files
│   └── Caches/       # Rebuildable data, excluded from backup
└── tmp/            # Temporary files, excluded from backup
```

---

### iOS Static Analysis

```bash
# Step 1 — Extract IPA
unzip TargetApp.ipa -d extracted/
cd extracted/Payload/TargetApp.app/

# Step 2 — Binary analysis
otool -L TargetApp                         # Linked libraries
otool -hv TargetApp | grep PIE            # PIE (ASLR) check
nm TargetApp | grep " T "                 # Exported symbols
strings TargetApp | grep -iE "password|key|secret|token"

# Step 3 — Security flags
checksec TargetApp                         # Stack canary, PIE, ARC, NX

# Step 4 — Class dump
class-dump -H TargetApp -o headers/       # Objective-C headers
# For Swift: use swift-demangle or Ghidra

# Step 5 — Info.plist review
plutil -p TargetApp.app/Info.plist
plutil -p TargetApp.app/Info.plist | grep NSAllowsArbitraryLoads  # ATS check
plutil -p TargetApp.app/Info.plist | grep -A5 "NSAppTransportSecurity"
plutil -p TargetApp.app/Info.plist | grep -E "CFBundleURLSchemes|NSFaceIDUsageDescription"

# Step 6 — MobSF IPA upload
# Launch MobSF, upload .ipa file, review automated findings:
# - Binary protections, ATS config, permissions, hardcoded secrets, URL schemes

# Step 7 — Hardcoded secrets
grep -r "password\|api_key\|secret\|token" extracted/Payload/TargetApp.app/
# Check embedded plist, .js, .html files inside bundle
find extracted/ -name "*.plist" -exec plutil -p {} \; | grep -iE "key|secret|password"
```

---

### iOS Dynamic Analysis

**Frida on iOS**
```bash
# List processes
frida-ps -U

# Trace Objective-C method calls
frida-trace -U -m "-[NSURLConnection sendSynchronousRequest:returningResponse:error:]" TargetApp
frida-trace -U -m "-[NSURLSession dataTask*]" TargetApp
frida-trace -U -m "-[*ViewController *]" TargetApp  # All ViewController methods

# Attach and instrument
frida -U -l ios_script.js TargetApp

# Jailbreak detection bypass (Frida)
# ios_jb_bypass.js:
# ObjC.classes.DTXDocumentViewController  # enumerate classes
# var SSLContext = ObjC.classes.DTXSSLContext;
# Common jailbreak checks to hook:
# - fileExistsAtPath for /Applications/Cydia.app
# - canOpenURL for cydia:// scheme
# - access() syscall for /bin/su, /usr/sbin/sshd

frida -U -l jb_bypass.js TargetApp
```

**objection on iOS**
```bash
# Attach
objection --gadget TargetApp explore

# Keychain inspection
ios keychain dump                     # Dump all keychain entries
ios keychain dump --json             # JSON output

# NSUserDefaults
ios nsuserdefaults get               # All NSUserDefaults keys/values

# SSL pinning bypass
ios sslpinning disable               # Patch pinning at runtime

# Pasteboard monitoring
ios pasteboard monitor

# Touch/Face ID bypass
ios ui biometric_bypass

# Filesystem
ios bundles list_bundles             # All installed app bundles
env                                  # App's environment variables and paths

# Cookie inspection
ios cookies get

# Memory
memory dump all /tmp/ios_memory.bin
memory search "token" --string
```

---

## Mobile Device Management (MDM)

### Microsoft Intune — Policy Baseline

**Device Compliance Policies**

| Platform | Setting | Required Value |
|---|---|---|
| iOS | Minimum OS version | 16.0 |
| iOS | Passcode required | Yes |
| iOS | Minimum passcode length | 6 |
| iOS | Jailbroken devices | Block |
| iOS | Max minutes of inactivity before lock | 5 |
| Android | Minimum OS version | 12 |
| Android | Device encryption | Required |
| Android | SafetyNet attestation | Basic integrity + certified |
| Android | Rooted devices | Block |
| Android | Threat level (MTD integration) | Secured |
| Windows | BitLocker | Required |
| Windows | Secure Boot | Required |
| Windows | Code integrity | Required |
| macOS | Minimum OS version | 13.0 (Ventura) |
| macOS | FileVault | Required |
| macOS | Firewall | Enabled |

**App Protection Policies (MAM — Without Enrollment)**

| Control | iOS Setting | Android Setting |
|---|---|---|
| Prevent backup | Prevent iCloud backup | Prevent Google Drive backup |
| Data transfer | Managed apps only | Managed apps only |
| Cut/copy/paste | Managed apps only | Managed apps only |
| App data encryption | Require (OS-level) | Require (Intune AES-256) |
| PIN required | After 5 min inactivity | After 5 min inactivity |
| Biometric override | Allowed | Allowed |
| Offline grace period | 720 hours (access) | 720 hours (access) |
| Wipe threshold | 10 failed PIN attempts | 10 failed PIN attempts |
| Screen capture | Block | Block |
| Managed browser required | Microsoft Edge | Microsoft Edge |
| Min OS version | 16.0 | 12.0 |
| Min app version | Per-app policy | Per-app policy |

**Conditional Access Integration**
```
Non-compliant device detected
    → Block access to Microsoft 365 (Exchange, SharePoint, Teams)
    → Push notification: "Your device does not meet security requirements"
    → Redirect to Company Portal for enrollment/remediation

Non-enrolled BYOD
    → MAM-only policy applied to managed apps
    → Personal apps and data untouched
    → Work data isolated in managed app container
```

---

### BYOD vs Corporate-Managed Matrix

| Scenario | MDM Approach | Device Control | Privacy Impact | Wipe Scope |
|---|---|---|---|---|
| Corporate-owned (dedicated) | Full MDM enrollment | Full device policy control | Low privacy expectation | Full device wipe |
| Corporate-owned (COPE) | Full MDM + work profile | Full device + work profile | Moderate | Full or work profile |
| BYOD — MAM only | App-level protection, no MDM | App data only | High privacy protection | Selective app wipe only |
| BYOD — Android work profile | Work profile enrollment | Work profile isolated | Personal profile untouched | Work profile wipe only |
| Contractor / External | MAM + Conditional Access | App-level only | Maximum privacy | Selective wipe |

---

### MDM Vendor Reference

| Vendor | Primary Strength | Platform Support | Key Capabilities |
|---|---|---|---|
| Microsoft Intune | M365 integration, MAM without enrollment | iOS, Android, Windows, macOS | Conditional Access, MAM, RBAC, Autopilot, co-management |
| Jamf Pro | Apple-native depth | iOS, macOS, tvOS | Zero-touch deployment, PPPC, DEP/ABM, compliance policies |
| VMware Workspace ONE | Unified endpoint + VDI | iOS, Android, Windows, macOS, ChromeOS | Intelligent Hub, Workspace ONE Tunnel, Access (ZTNA) |
| IBM MaaS360 | AI-driven insights | iOS, Android, Windows, macOS | Watson AI risk scoring, MaaS360 Advisor, Wandera MTD |
| SOTI MobiControl | Rugged + kiosk devices | iOS, Android, Windows CE, WinMo | Kiosk lockdown, remote control, IoT endpoint management |

---

## Mobile Threat Defense (MTD)

MTD platforms provide on-device and cloud-based threat detection beyond MDM compliance checks.

### MTD Platforms

| Platform | Detection Engine | Key Detections | MDM Integration |
|---|---|---|---|
| Lookout | Machine learning, cloud graph | Malware, network MITM, phishing URLs, OS exploits | Intune, MobileIron, Jamf |
| Zimperium (z9) | On-device ML (no cloud lookups) | Zero-day exploits, MITM, sideloaded apps, device anomaly | Intune, Workspace ONE, Jamf |
| Microsoft Defender for Endpoint (Mobile) | Cloud + on-device | Web protection, network inspection, jailbreak/root | Native Intune Conditional Access |
| CrowdStrike Falcon Mobile | Falcon Intelligence | Malicious apps, network threats, OS vulnerability | Intune, Workspace ONE |
| SentinelOne Mobile | Singularity platform | Behavioral AI, phishing, MITM, app reputation | Intune, Jamf, Workspace ONE |

### MTD Detection Categories

| Category | Examples | Response |
|---|---|---|
| Malware / Malicious Apps | Trojanized APKs, spyware, stalkerware | Block access, alert SOC, quarantine |
| Network MITM | Rogue WiFi, SSL stripping, ARP poisoning | Block corporate access, alert |
| OS/Device Vulnerability | Unpatched CVEs, outdated OS | Flag non-compliant, notify user |
| Phishing | SMS phishing (smishing), malicious URLs in browsers | Block URL, alert user |
| Malicious Profiles (iOS) | Unauthorized MDM profiles, CA injection | Alert, prompt removal |
| Physical Attack | Fake charging stations (juice jacking) | Alert |
| App Behavior Anomaly | Unexpected data exfiltration, permission abuse | Isolate, investigate |

### MTD + Intune Conditional Access Integration

```
Device enrolls in Intune
    → MTD agent (Lookout/Zimperium/Defender) installed via Intune app policy
    → MTD agent reports device risk score to MTD cloud
    → MTD cloud sends risk signal to Intune via Graph API
    → Intune compliance policy evaluates: MTD threat level <= Medium
    → High risk device → marked non-compliant → Conditional Access blocks M365
    → SOC alert triggered via SIEM connector
```

---

## Mobile Attack Vectors

| Attack | Platform | Description | Defense |
|---|---|---|---|
| Malicious APK Sideloading | Android | Trojanized apps delivered via phishing, third-party stores, or social engineering | Disable "Install unknown apps", MTD, app reputation |
| Pegasus Spyware (Zero-Click) | iOS / Android | NSO Group exploit leveraging zero-click iMessage/WhatsApp vulns; full device compromise with no user interaction | Keep OS/apps updated, Lockdown Mode (iOS), MTD |
| SIM Swapping | Both | Social engineering of carrier to transfer victim's number; enables MFA bypass | Use authenticator apps or hardware keys instead of SMS MFA |
| AitM on Public WiFi | Both | Adversary-in-the-Middle on open networks; SSL stripping, session hijack | VPN enforcement, HSTS, certificate pinning |
| QR Code Phishing (Quishing) | Both | Malicious QR codes redirect to credential harvesting sites | User awareness, MTD web protection, MDM managed browser |
| MDM Exploit / Profile Injection | iOS / Android | Malicious MDM enrollment or profile pushes malicious CA or VPN config | Restrict MDM enrollment to trusted sources, monitor profiles |
| App Store Malware | Both | Malicious apps that pass review via delayed payload activation or update-based delivery | App reputation, MTD, enterprise app allowlisting |
| Juice Jacking | Both | Malicious USB charging stations exfiltrate data or install malware | USB Restricted Mode (iOS), use AC adapters, charge-only cables |
| Stalkerware / Spouseware | Both | Commercially available monitoring apps installed by abuser with physical access | MDM app inventory, MTD app analysis |
| Evil Twin / Rogue AP | Both | Attacker clones SSID of trusted network to capture traffic | Certificate pinning, VPN always-on, 802.1X for enterprise WiFi |
| Insecure Deep Link Hijacking | Android | Malicious app registers competing intent filter for deep link; intercepts sensitive data | Use HTTPS deep links with Digital Asset Links verification |
| iOS Enterprise Cert Abuse | iOS | Abusing enterprise developer certificates to distribute malicious apps outside App Store | Certificate revocation monitoring, MDM enrollment restrictions |

---

## ATT&CK for Mobile Mapping

MITRE ATT&CK for Mobile covers iOS and Android threat techniques across 14 tactics.

| Technique ID | Name | Description | Relevant Attack Above |
|---|---|---|---|
| T1407 | Download New Code at Runtime | Malicious apps download and execute payload after store review | App Store Malware |
| T1411 | Input Prompt | Overlay attacks steal credentials via fake UI | AitM, Phishing |
| T1417 | Input Capture | Keyloggers, accessibility service abuse for credential theft | Stalkerware, Malicious APK |
| T1430 | Location Tracking | Apps exfiltrate precise location without user knowledge | Pegasus, Stalkerware |
| T1516 | Input Injection | Malicious app injects input into other apps via accessibility | Malicious APK |
| T1521 | Encrypted Channel | C2 communication over encrypted channels to evade detection | Pegasus, RATs |
| T1406 | Obfuscated Files or Information | APK packing, string encryption to evade static analysis | Malicious APK Sideloading |
| T1409 | Stored Application Data | Access sensitive data from app storage | Insecure Storage attacks |
| T1412 | Capture SMS Messages | Exfiltrate SMS for MFA interception | SIM Swap, READ_SMS abuse |
| T1422 | System Network Configuration Discovery | Identify network configuration for lateral movement | Reconnaissance |
| T1426 | System Information Discovery | Collect device metadata for targeting | Spyware |
| T1432 | Access Contact List | Exfiltrate contacts for spearphishing | Stalkerware, Spyware |
| T1456 | Drive-by Compromise | Exploit mobile browser to install malware without user action | Zero-Click, Quishing |
| T1458 | Replication Through Removable Media | Spread via USB/SD card | Juice Jacking |

**MITRE ATT&CK for Mobile Navigator**: https://attack.mitre.org/matrices/mobile/

---

## Quick Reference — Tool Summary

| Tool | Platform | Purpose | Install |
|---|---|---|---|
| apktool | Android | Decompile/recompile APK | `apt install apktool` |
| jadx / jadx-gui | Android | Java source decompilation | `apt install jadx` |
| MobSF | Both | Automated static + dynamic analysis | Docker |
| Frida | Both | Dynamic instrumentation framework | `pip install frida-tools` |
| objection | Both | Runtime exploration built on Frida | `pip install objection` |
| Drozer | Android | Android attack surface analysis | `pip install drozer` |
| adb | Android | Device communication | Android SDK Platform Tools |
| Burp Suite | Both | HTTP/S proxy and testing | PortSwigger |
| class-dump | iOS | Objective-C header extraction | Homebrew / package |
| otool | iOS | Binary analysis (linked libs, arch) | Xcode CLI tools |
| checksec | Both | Binary security flags | `apt install checksec` |
| apksigner | Android | APK signature verification | Android SDK Build Tools |
| rabin2 | Both | Binary analysis (radare2) | `apt install radare2` |
