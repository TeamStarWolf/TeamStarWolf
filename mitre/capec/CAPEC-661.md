# CAPEC-661 — Root/Jailbreak Detection Evasion via Debugging

<a id="capec-661"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary inserts a debugger into the program entry point of a mobile application to modify the application binary, with the goal of evading Root/Jailbreak detection. Mobile device users often Root/Jailbreak their devices in order to gain administrative control over the mobile operating system and/or to install third-party mobile applications that are not provided by authorized application stores (e.g. Google Play Store and Apple App Store). Rooting/Jailbreaking a mobile device also provides users with access to system debuggers and disassemblers, which can be leveraged to exploit applications by dumping the application's memory at runtime in order to remove or bypass signature verification methods. This further allows the adversary to evade Root/Jailbreak detection mechanisms, which can result in execution of administrative commands, obtaining confidential data, impersonating legitimate users of the application, and more.

## Related CWE (1)

- [CWE-489 — Active Debug Code](https://cwe.mitre.org/data/definitions/489.html) — The product is released with debugging code still enabled or active.

## Prerequisites

- A debugger must be able to be inserted into the targeted application.

## Skills required

- [High] Knowledge about Root/Jailbreak detection and evasion techniques.
- [Medium] Knowledge about runtime debugging.

## Consequences

- Integrity, Authorization / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Access Control / Read Data

## Mitigations

- Instantiate checks within the application code that ensures debuggers are not attached.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
