# Mobile Security

> Securing iOS and Android devices, mobile applications, and enterprise mobility management — from app vulnerability assessment to MDM/EMM deployment and mobile threat defense.

## What Mobile Security Engineers Do

- Conduct mobile application penetration testing (iOS and Android)
- Perform static and dynamic analysis of mobile apps: decompilation, traffic interception, runtime hooking
- Implement and operate Mobile Device Management (MDM) and Enterprise Mobility Management (EMM)
- Deploy and tune Mobile Threat Defense (MTD) solutions
- Define and enforce mobile security policies: app vetting, BYOD vs. COPE frameworks
- Analyze mobile malware: APK/IPA analysis, C2 communication, privilege abuse
- Assess mobile API security and certificate pinning implementations
- Implement secure mobile development practices (MASVS compliance)

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [OWASP Mobile Application Security Verification Standard (MASVS)](https://mas.owasp.org/MASVS/) | Security requirements for mobile apps |
| [OWASP Mobile Application Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/) | Comprehensive mobile pentesting guide |
| [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | Top 10 mobile application risks |
| [NIST SP 800-124r2](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final) | Guidelines for Managing Mobile Device Security |
| [CIS Benchmarks — Android/iOS](https://www.cisecurity.org/cis-benchmarks) | Mobile OS hardening benchmarks |
| [NIAP Mobile Device Protection Profile](https://www.niap-ccevs.org/) | Government mobile device requirements |

---

## Free & Open-Source Tools

### Mobile App Analysis

| Tool | Purpose | Platform | Notes |
|---|---|---|---|
| [MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Automated static + dynamic analysis | iOS + Android | Decompiles APK/IPA; finds vulnerabilities |
| [apktool](https://apktool.org/) | APK decompilation | Android | Decode resources, rebuild APKs |
| [jadx](https://github.com/skylot/jadx) | APK/DEX decompiler | Android | Decompile to readable Java |
| [Frida](https://frida.re/) | Dynamic instrumentation | iOS + Android | Hook methods, bypass certificate pinning |
| [Objection](https://github.com/sensepost/objection) | Runtime mobile exploration | iOS + Android | Frida-based; certificate pinning bypass |
| [drozer](https://github.com/WithSecureLabs/drozer) | Android security assessment | Android | Attack surface analysis; IPC testing |
| [r2frida](https://github.com/nowsecure/r2frida) | Radare2 + Frida integration | iOS + Android | Deep binary analysis + hooking |
| [Ghidra](https://ghidra-sre.org/) | Binary reverse engineering | iOS + Android | Analyze native libraries (.so, .dylib) |

### Traffic Interception

| Tool | Purpose | Notes |
|---|---|---|
| [Burp Suite](https://portswigger.net/burp) | HTTP/HTTPS proxy | Install CA cert on device; intercept app traffic |
| [mitmproxy](https://mitmproxy.org/) | Open-source HTTPS proxy | scriptable; SSL stripping; certificate pinning bypass |
| [Charles Proxy](https://www.charlesproxy.com/) | HTTP proxy | macOS-friendly; SSL proxying for mobile |
| [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2) | iOS cert pinning bypass | Requires jailbreak; disables NSURLSession validation |

### iOS-Specific

| Tool | Purpose | Notes |
|---|---|---|
| [iMazing](https://imazing.com/) | iOS app extraction | Extract IPAs from device |
| [Checkra1n](https://checkra.in/) | iOS jailbreak | Research tool; hardware-based jailbreak |
| [Needle](https://github.com/WithSecureLabs/needle) | iOS security testing | Automates iOS app assessment |
| [passionfruit](https://github.com/chaitin/passionfruit) | iOS app analysis GUI | Frida-based app explorer |

### Android-Specific

| Tool | Purpose | Notes |
|---|---|---|
| [ADB (Android Debug Bridge)](https://developer.android.com/studio/command-line/adb) | Android device interface | Shell access, app install, logcat |
| [Android Emulator / AVD](https://developer.android.com/studio/run/emulator) | Rooted test environment | AVD Manager; Google APIs image |
| [RootAVD](https://github.com/newbit1/rootAVD) | Root Android emulator | Magisk-based emulator rooting |
| [dex2jar](https://github.com/pxb1988/dex2jar) | DEX to JAR conversion | Convert for JD-GUI decompilation |
| [Dexcalibur](https://github.com/FrenchYeti/dexcalibur) | Android RE + Frida | Dynamic instrumentation IDE |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [Microsoft Intune](https://www.microsoft.com/en-us/security/business/endpoint-management/microsoft-intune) | MDM/EMM | Widely deployed; BYOD + COPE; Conditional Access |
| [VMware Workspace ONE](https://www.vmware.com/products/workspace-one.html) | EMM + UEM | AirWatch heritage; enterprise mobility |
| [Jamf Pro](https://www.jamf.com/products/jamf-pro/) | Apple device management | MDM for iOS, macOS, tvOS |
| [Lookout](https://www.lookout.com/) | Mobile Threat Defense | iOS + Android MTD; phishing protection |
| [Zimperium](https://www.zimperium.com/) | MTD + MAPS | zIPS MTD; zScan mobile app security |
| [NowSecure](https://www.nowsecure.com/) | Mobile app security testing | Automated MASVS testing; CI/CD integration |
| [MobileIron (Ivanti)](https://www.ivanti.com/products/ivanti-neurons-for-mdm) | MDM + MTD | Enterprise mobility management |
| [Corellium](https://corellium.com/) | iOS/Android virtualization | Virtual iOS devices for security research |

---

## Mobile Threat Categories

### OWASP Mobile Top 10 (2024)

| Rank | Category | Description |
|---|---|---|
| M1 | Improper Credential Usage | Hardcoded credentials, insecure storage |
| M2 | Inadequate Supply Chain Security | Malicious SDKs, compromised dependencies |
| M3 | Insecure Authentication/Authorization | Weak auth, missing authorization checks |
| M4 | Insufficient Input/Output Validation | Injection, XSS via WebViews |
| M5 | Insecure Communication | HTTP, improper TLS, no cert pinning |
| M6 | Inadequate Privacy Controls | PII collection/transmission without consent |
| M7 | Insufficient Binary Protections | No obfuscation, easy reverse engineering |
| M8 | Security Misconfiguration | Exported components, debug flags in production |
| M9 | Insecure Data Storage | SQLite, SharedPreferences, external storage |
| M10 | Insufficient Cryptography | Weak algorithms, ECB mode, hardcoded keys |

---

## ATT&CK Coverage (Mobile)

MITRE ATT&CK has a dedicated [Mobile matrix](https://attack.mitre.org/matrices/mobile/). Key techniques:

| Technique | Description | Control |
|---|---|---|
| [T1407](https://attack.mitre.org/techniques/T1407/) | Download New Code at Runtime | App vetting, MDM app control |
| [T1411](https://attack.mitre.org/techniques/T1411/) | Input Prompt (phishing) | MTD, user awareness |
| [T1430](https://attack.mitre.org/techniques/T1430/) | Location Tracking | MDM privacy controls |
| [T1432](https://attack.mitre.org/techniques/T1432/) | Access Contact List | App permission management |
| [T1437](https://attack.mitre.org/techniques/T1437/) | Standard App Layer Protocol (C2) | MTD network inspection |
| [T1444](https://attack.mitre.org/techniques/T1444/) | Masquerade as Legitimate App | App signing, enterprise app store |
| [T1516](https://attack.mitre.org/techniques/T1516/) | Input Injection | Accessibility service abuse controls |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [GMOB](https://www.giac.org/certifications/mobile-device-security-analyst-gmob/) | GIAC | Mobile Device Security Analyst |
| [eWPTXv2](https://elearnsecurity.com/product/ewptxv2-certification/) | eLearnSecurity | Web + mobile pentesting |
| [MAPT (Mobile Application Penetration Testing)](https://www.tcm-sec.com/mapt/) | TCM Security | Practical mobile app pentesting |
| [Android Bug Bounty](https://bughunters.google.com/about/rules/6171833274204160) | Google | Android vulnerability research |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [OWASP MASTG](https://mas.owasp.org/MASTG/) | Free guide | The definitive mobile app security testing guide |
| [Hacking Android (Packt)](https://www.packtpub.com/product/hacking-android/9781785883149) | Book | Android pentesting techniques |
| [iOS App Reverse Engineering](https://github.com/iosre/iOSAppReverseEngineering) | Free book | iOS RE techniques |
| [TCM Security Mobile Course](https://academy.tcm-sec.com/p/mobile-application-penetration-testing) | Course | Practical Android + iOS pentesting |
| [Frida Handbook](https://github.com/iddoeldor/frida-snippets) | Reference | Frida snippet collection |
| [Android Security Internals (Elenkov)](https://nostarch.com/androidsecurity) | Book | Deep Android security architecture |
| [HackTricks - Mobile](https://book.hacktricks.xyz/mobile-pentesting/) | Reference | Mobile pentesting techniques |

---

## Related Disciplines

- [Application Security](application-security.md) — Mobile API and backend security
- [Malware Analysis](malware-analysis.md) — Mobile malware analysis (APK analysis)
- [Penetration Testing / Offensive Security](offensive-security.md) — Mobile pentesting methodology
- [DevSecOps](devsecops.md) — Mobile SAST/DAST in CI/CD pipelines
- [Privacy Engineering](privacy-engineering.md) — Mobile data collection and consent
