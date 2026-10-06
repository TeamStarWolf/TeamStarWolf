# CAPEC-698: Install Malicious Extension

<a id="capec-698"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Stable  

An adversary directly installs or tricks a user into installing a malicious extension into existing trusted software, with the goal of achieving a variety of negative technical impacts.

## Mapped ATT&CK techniques (2)

- [T1176: Software Extensions](/mitre/techniques/T1176.md): Adversaries may abuse software extensions to establish persistent access to victim systems.
- [T1505.004: IIS Components](/mitre/techniques/T1505-004.md): Adversaries may install malicious components that run on Internet Information Services (IIS) web servers to establish persistence.

## Related CWE (2)

- [CWE-507: Trojan Horse](https://cwe.mitre.org/data/definitions/507.html): The product appears to contain benign or useful functionality, but it also contains code that is hidden from normal operation that violates the intended security policy of the user or the system administrator.
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html): The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- The adversary must craft malware based on the type of software and system(s) they intend to exploit.
- If the adversary intends to install the malicious extension themself, they must first compromise the target machine via some other means.

## Skills required

- [Medium] Ability to create malicious extensions that can exploit specific software applications and systems.
- [Medium] Optional: Ability to exploit target system(s) via other means in order to gain entry.

## Consequences

- Confidentiality, Access Control / Read Data
- Integrity, Access Control / Modify Data
- Authorization, Access Control / Execute Unauthorized Commands, Alter Execution Logic, Gain Privileges

## Mitigations

- Only install extensions/plugins from official/verifiable sources.
- Confirm extensions/plugins are legitimate and not malware masquerading as a legitimate extension/plugin.
- Ensure the underlying software leveraging the extension/plugin (including operating systems) is up-to-date.
- Implement an extension/plugin allow list, based on the given security policy.
- If applicable, confirm extensions/plugins are properly signed by the official developers.
- For web browsers, close sessions when finished to prevent malicious extensions/plugins from executing the the background.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
