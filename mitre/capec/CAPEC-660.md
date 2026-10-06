# CAPEC-660: Root/Jailbreak Detection Evasion via Hooking

<a id="capec-660"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: Medium  
Status: Stable  

An adversary forces a non-restricted mobile application to load arbitrary code or code files, via Hooking, with the goal of evading Root/Jailbreak detection. Mobile device users often Root/Jailbreak their devices in order to gain administrative control over the mobile operating system and/or to install third-party mobile applications that are not provided by authorized application stores (e.g. Google Play Store and Apple App Store). Adversaries may further leverage these capabilities to escalate privileges or bypass access control on legitimate applications. Although many mobile applications check if a mobile device is Rooted/Jailbroken prior to authorized use of the application, adversaries may be able to "hook" code in order to circumvent these checks. Successfully evading Root/Jailbreak detection allows an adversary to execute administrative commands, obtain confidential data, impersonate legitimate users of the application, and more.

## Mapped ATT&CK techniques (1)

- [T1055: Process Injection](/mitre/techniques/T1055.md): Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.

## Related CWE (1)

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html): The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- The targeted application must be non-restricted to allow code hooking.

## Skills required

- [High] Knowledge about Root/Jailbreak detection and evasion techniques.
- [Medium] Knowledge about code hooking.

## Consequences

- Integrity, Authorization / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Access Control / Read Data

## Mitigations

- Ensure mobile applications are signed appropriately to avoid code inclusion via hooking.
- Inspect the application's memory for suspicious artifacts, such as shared objects/JARs or dylibs, after other Root/Jailbreak detection methods.
- Inspect the application's stack trace for suspicious method calls.
- Allow legitimate native methods, and check for non-allowed native methods during Root/Jailbreak detection methods.
- For iOS applications, ensure application methods do not originate from outside of Apple's SDK.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
