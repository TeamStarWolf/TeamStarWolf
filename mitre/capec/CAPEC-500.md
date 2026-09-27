# CAPEC-500 — WebView Injection

<a id="capec-500"></a>

**Abstraction:** Detailed  
**Status:** Draft  

An adversary, through a previously installed malicious application, injects code into the context of a web page displayed by a WebView component. Through the injected code, an adversary is able to manipulate the DOM tree and cookies of the page, expose sensitive information, and can launch attacks against the web application from within the web page.

## Related CWE (2)

- [CWE-749 — Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)
- [CWE-940 — Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

## Prerequisites

- An adversary must be able install a purpose built malicious application onto the device and convince the user to execute it. The malicious application is designed to target a specific web applicatio

## Mitigations

- The only known mitigation to this type of attack is to keep the malicious application off the system. There is nothing that can be done to the target application to protect itself from a malicious application that has been installed and executed.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
