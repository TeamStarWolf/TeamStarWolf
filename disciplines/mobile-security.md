# Mobile Security

> Securing iOS and Android devices, mobile applications, and enterprise mobility management — from app vulnerability assessment to MDM/EMM deployment, mobile threat defense, and offensive exploitation techniques.

Mobile security encompasses the protection of smartphones, tablets, and the applications running on them across iOS and Android platforms. The discipline bridges application security (static/dynamic analysis of APKs and IPAs), network security (certificate pinning, TLS inspection), endpoint management (MDM/EMM policy enforcement), and threat intelligence (mobile malware, zero-click exploits, stalkerware). Practitioners analyze apps for MASVS compliance, conduct runtime hooking with Frida to bypass security controls, investigate spyware campaigns, and configure mobile threat defense (MTD) platforms. Understanding both the offensive perspective — how attackers abuse exported Android components, bypass jailbreak detection on iOS, or deliver zero-click exploits — and the defensive controls is essential for comprehensive mobile security programs.

---

## Where to Start

| Level | Description | Free Resource |
|---|---|---|
| Beginner | Understand Android APK and iOS IPA structures, the OWASP Mobile Top 10 (2024), and how to use ADB for basic Android analysis. Set up MobSF for automated static scanning. | [OWASP MASTG (Mobile Application Security Testing Guide)](https://mas.owasp.org/MASTG/) |
| Intermediate | Perform dynamic analysis with Frida and Objection: hook methods, bypass certificate pinning, and enumerate exported Android components. Analyze iOS keychain and plist files. Intercept traffic with Burp Suite configured for mobile. | [Frida Documentation](https://frida.re/docs/) |
| Advanced | Research zero-click exploit methodology, develop custom Frida scripts for obfuscated targets, bypass advanced jailbreak/root detection, exploit deep link abuse and intent hijacking, and analyze mobile spyware (Pegasus methodology). | [Azeria Labs ARM Exploitation](https://azeria-labs.com/) |

---

## Free Training

| Platform | URL | What You Learn |
|---|---|---|
| OWASP MASTG | https://mas.owasp.org/MASTG/ | Definitive mobile app security testing guide — iOS and Android, static and dynamic |
| OWASP MASVS | https://mas.owasp.org/MASVS/ | Security verification standard for mobile apps — requirements and control mapping |
| Frida Documentation | https://frida.re/docs/ | Dynamic instrumentation: method hooking, class enumeration, native tracing |
| TryHackMe — Android rooms | https://tryhackme.com/ | Guided Android static/dynamic analysis labs |
| HackTricks Mobile | https://book.hacktricks.xyz/mobile-pentesting/ | Mobile pentesting techniques reference |
| TCM Security (free resources) | https://academy.tcm-sec.com/ | Practical mobile security fundamentals (free tier available) |

---

## Tools & Repositories

### Static Analysis

| Tool | Purpose | Platform | Link |
|---|---|---|---|
| MobSF | Automated static and dynamic analysis of APKs and IPAs | iOS + Android | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| apktool | Decode APK resources, decompile smali bytecode, rebuild APKs | Android | https://apktool.org/ |
| jadx | Decompile APK/DEX to readable Java source | Android | https://github.com/skylot/jadx |
| class-dump | Extract Objective-C class and method headers from iOS binaries | iOS | https://github.com/nygard/class-dump |
| jtool2 | iOS binary analysis: entitlements, dylibs, Mach-O parsing | iOS | http://www.newosxbook.com/tools/jtool.html |
| strings / jtool2 | Extract hardcoded secrets, URLs, and keys from binaries | iOS + Android | Built-in / https://newosxbook.com/ |

### Dynamic Analysis & Runtime Hooking

| Tool | Purpose | Platform | Link |
|---|---|---|---|
| Frida | Dynamic instrumentation framework — hook methods, bypass controls at runtime | iOS + Android | https://frida.re/ |
| Objection | Frida-based exploration toolkit — certificate pinning bypass, keychain dump, root detection bypass | iOS + Android | https://github.com/sensepost/objection |
| Shadow | iOS jailbreak detection bypass — works without jailbreak on some scenarios | iOS | https://github.com/jjolano/shadow |
| SSL Kill Switch 2 | Disable iOS NSURLSession certificate validation (requires jailbreak) | iOS | https://github.com/nabla-c0d3/ssl-kill-switch2 |
| apk-mitm | Automatically patches APKs to trust user-installed CA certificates | Android | https://github.com/shroudedcode/apk-mitm |
| drozer | Android attack surface analysis — exported components, content providers, IPC | Android | https://github.com/WithSecureLabs/drozer |
| ADB (Android Debug Bridge) | Shell access, app install/uninstall, logcat, screenshot, file transfer | Android | https://developer.android.com/studio/command-line/adb |

### Traffic Interception

| Tool | Purpose | Link |
|---|---|---|
| Burp Suite | HTTP/HTTPS proxy with mobile certificate installation support | https://portswigger.net/burp |
| mitmproxy | Open-source scriptable HTTPS proxy | https://mitmproxy.org/ |
| ProxyDroid | Android proxy configuration helper (root required) | https://github.com/madeye/proxydroid |

---

## Commercial Platforms

### MDM / EMM

| Vendor | Capability | Notes |
|---|---|---|
| [Microsoft Intune](https://www.microsoft.com/en-us/security/business/endpoint-management/microsoft-intune) | MDM/EMM | BYOD + COPE; Conditional Access integration; widely deployed |
| [Jamf Pro](https://www.jamf.com/products/jamf-pro/) | Apple device management | MDM for iOS, macOS, tvOS; zero-touch deployment |
| [VMware Workspace ONE](https://www.vmware.com/products/workspace-one.html) | EMM + UEM | AirWatch heritage; unified endpoint management |
| [Ivanti MobileIron](https://www.ivanti.com/products/ivanti-neurons-for-mdm) | MDM + MTD | Enterprise mobility management with integrated threat defense |

### Mobile Threat Defense (MTD)

| Vendor | Capability | Notes |
|---|---|---|
| [Lookout](https://www.lookout.com/) | Mobile Threat Defense | iOS + Android MTD; phishing and network threat protection |
| [Zimperium](https://www.zimperium.com/) | MTD + MAPS (Mobile App Protection Suite) | zIPS for device MTD; zScan for app security testing |
| [SentinelOne Mobile](https://www.sentinelone.com/platform/mobile/) | Mobile EDR | Behavioral detection for iOS and Android |
| [CrowdStrike Falcon Go](https://www.crowdstrike.com/products/endpoint-security/falcon-go/) | Mobile endpoint protection | Lightweight mobile protection for iOS and Android |

---

## OWASP Mobile Top 10 (2024)

| Rank | Category | Description | Key Attack Example |
|---|---|---|---|
| M1 | Improper Credential Usage | Hardcoded credentials, insecure storage of tokens/passwords | Static analysis finds AWS keys in APK resources |
| M2 | Inadequate Supply Chain Security | Malicious SDKs, compromised third-party libraries | Malicious ad SDK exfiltrates device data |
| M3 | Insecure Authentication/Authorization | Weak auth, missing server-side authorization checks | Client-side authorization bypass with Frida |
| M4 | Insufficient Input/Output Validation | Injection via WebViews, SQL injection in content providers | JavaScript injection in WebView via deep link |
| M5 | Insecure Communication | HTTP, improper TLS, no certificate pinning | Burp Suite intercepts cleartext credentials |
| M6 | Inadequate Privacy Controls | PII collection/transmission without user consent | Health app sending location to third parties |
| M7 | Insufficient Binary Protections | No obfuscation, root/jailbreak detection absent, easy RE | jadx recovers full source code from unobfuscated APK |
| M8 | Security Misconfiguration | Exported components, debug flags in production, open deep links | Drozer exploits exported Activity to bypass auth |
| M9 | Insecure Data Storage | SQLite plaintext, SharedPreferences, external storage abuse | ADB pull retrieves unencrypted database with tokens |
| M10 | Insufficient Cryptography | Weak algorithms, ECB mode, hardcoded encryption keys | Hardcoded AES key in app resources decrypts local data |

---

## Android Security Deep Dive

Android applications are distributed as APKs (ZIP archives containing DEX bytecode, resources, native libraries). The `AndroidManifest.xml` declares components — Activities, Services, Broadcast Receivers, and Content Providers — and their exported status. Exported components accessible without permissions are a common attack surface.

Key attack techniques:
- **Intent hijacking**: Malicious apps intercept implicit intents from exported components
- **Exported content providers**: Unprotected content providers expose data without authentication
- **Broadcast receiver abuse**: Exported receivers can be triggered by any app to invoke functionality
- **Deep link abuse**: Malformed deep links trigger unintended application behavior (M4/M8)
- **Frida for hooking**: Attach to running app, hook Java methods, bypass root detection, dump decrypted traffic

---

## iOS Security Deep Dive

iOS applications are distributed as IPAs (ZIP archives with Mach-O binaries, plists, and assets). Key security mechanisms include the keychain for credential storage, code signing (App Store + enterprise profiles), and the Secure Enclave for biometric key storage.

Key attack techniques:
- **Jailbreak detection bypass**: Objection and Shadow automate bypass of common detection checks
- **SSL Kill Switch**: Disable NSURLSession certificate validation to intercept pinned traffic
- **Keychain extraction**: On jailbroken devices, dump keychain items with Objection or Frida
- **class-dump analysis**: Extract Objective-C class headers from stripped binaries
- **Plist analysis**: `Info.plist`, `Entitlements.plist`, and app data plists often contain sensitive configuration

---

## Offensive Perspective — Mobile Attack Techniques

| Technique | Description | Target |
|---|---|---|
| Smishing (SMS phishing) | SMS messages delivering malicious links or rogue app installs | All mobile users |
| Rogue MDM profiles | Malicious configuration profiles install CA certificates or enforce policy | iOS device enrollment |
| SIM swapping | Social engineering carrier to transfer victim SIM; bypass SMS 2FA | SMS-based MFA |
| Stalkerware | Covertly installed monitoring apps track location, messages, calls | Domestic abuse, corporate espionage |
| Zero-click exploits | No user interaction required; exploit parsing libraries (image, SMS, iMessage) | High-value targets (NSO Pegasus methodology) |
| Deep link abuse | Malformed deep links trigger unintended app behavior or content provider access | Android and iOS |
| Malicious app impersonation | Clone of legitimate app distributed via phishing or third-party stores | Device users without app store restrictions |

---

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---|---|---|
| SC-28 | System & Communications Protection | Encryption of data at rest — device encryption, encrypted app storage |
| IA-2 | Identification & Authentication | Multi-factor authentication — biometric + PIN enforcement via MDM |
| IA-5 | Identification & Authentication | Authenticator management — prevent hardcoded credentials (M1) |
| CM-7 | Configuration Management | Least functionality — MDM policy restricting app installs, camera, USB |
| SC-7 | System & Communications Protection | Boundary protection — MDM VPN enforcement, split tunneling controls |
| AC-19 | Access Control | Access control for mobile devices — BYOD policy, device registration |
| SC-12 | System & Communications Protection | Cryptographic key management — keychain security, certificate pinning |
| SI-3 | System & Information Integrity | Malicious code protection — MTD deployment on managed devices |
| AC-17 | Access Control | Remote access — MDM-enforced VPN, conditional access for mobile |

---

## ATT&CK Coverage (Mobile Matrix)

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| [T1437](https://attack.mitre.org/techniques/T1437/) | Standard Application Layer Protocol | Command and Control | Malware using HTTPS/HTTP for C2; MTD network inspection detects anomalies |
| [T1444](https://attack.mitre.org/techniques/T1444/) | Masquerade as Legitimate Application | Defense Evasion | Trojanized apps in third-party stores; enterprise app store controls |
| [T1446](https://attack.mitre.org/techniques/T1446/) | Device Lockout | Impact | Ransomware locks device; MDM remote wipe as recovery |
| [T1447](https://attack.mitre.org/techniques/T1447/) | Delete Device Data | Impact | Destructive apps wipe device data; MDM selective wipe limits blast radius |
| [T1448](https://attack.mitre.org/techniques/T1448/) | Carrier Billing Fraud | Impact | Malware silently charges premium SMS; MTD anomaly detection |
| [T1517](https://attack.mitre.org/techniques/T1517/) | Access Notifications | Collection | Spyware reads notification content; permission model enforcement |
| [T1532](https://attack.mitre.org/techniques/T1532/) | Archive Collected Data | Collection | Staging exfiltrated data before transmission; MTD detects large outbound transfers |
| [T1533](https://attack.mitre.org/techniques/T1533/) | Data from Local System | Collection | Reading contacts, SMS, files, keychain data; Frida-based spyware |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [GMOB](https://www.giac.org/certifications/mobile-device-security-analyst-gmob/) | GIAC | Mobile Device Security Analyst — device management and mobile threat defense |
| [eMAPT](https://elearnsecurity.com/product/emapt-certification/) | eLearnSecurity | Mobile Application Penetration Tester — practical iOS and Android testing |
| [OSCP](https://www.offensive-security.com/pwk-oscp/) | OffSec | Penetration testing — foundational skills applicable to mobile exploitation |
| [eWPTXv2](https://elearnsecurity.com/product/ewptxv2-certification/) | eLearnSecurity | Web + mobile pentesting, API security |
| [MAPT (TCM Security)](https://www.tcm-sec.com/mapt/) | TCM Security | Practical mobile application pentesting (Android + iOS) |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [OWASP MASTG](https://mas.owasp.org/MASTG/) | Free guide | Definitive mobile application security testing guide — iOS and Android |
| [Android Security Internals (Elenkov)](https://nostarch.com/androidsecurity) | Book | Deep Android security architecture: permissions, cryptography, secure storage |
| [iOS App Security (Charlie Miller)](https://www.amazon.com/iOS-App-Security-Charlie-Miller/dp/0470639520) | Book | iOS security internals and vulnerability research |
| [HackTricks — Mobile Pentesting](https://book.hacktricks.xyz/mobile-pentesting/) | Reference | Extensive mobile pentesting techniques for Android and iOS |
| [TCM Security Mobile Course](https://academy.tcm-sec.com/p/mobile-application-penetration-testing) | Course | Practical Android + iOS pentesting from scratch |
| [Frida Handbook / Snippets](https://github.com/iddoeldor/frida-snippets) | Reference | Frida snippet collection for common mobile hooking scenarios |
| [NSO Group Pegasus Technical Analysis (Amnesty Tech)](https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/) | Research | Forensic methodology for detecting mobile spyware; zero-click exploit indicators |

---

## Related Disciplines

- [Application Security](application-security.md) — Mobile API and backend security, OWASP alignment
- [Malware Analysis](malware-analysis.md) — Mobile malware analysis — APK/IPA reverse engineering
- [Penetration Testing / Offensive Security](offensive-security.md) — Mobile pentesting methodology, red team techniques
- [DevSecOps](devsecops.md) — Mobile SAST/DAST integration in CI/CD pipelines
- [Privacy Engineering](privacy-engineering.md) — Mobile data collection, consent, and GDPR/CCPA compliance
- [Identity & Access Management](identity-access-management.md) — MDM conditional access, mobile certificate-based auth
