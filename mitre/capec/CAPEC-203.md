# CAPEC-203: Manipulate Registry Information

<a id="capec-203"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Stable  

An adversary exploits a weakness in authorization in order to modify content within a registry (e.g., Windows Registry, Mac plist, application registry). Editing registry information can permit the adversary to hide configuration information or remove indicators of compromise to cover up activity. Many applications utilize registries to store configuration and service information. As such, modification of registry information can affect individual services (affecting billing, authorization, or even allowing for identity spoofing) or the overall configuration of a targeted application. For example, both Java RMI and SOAP use registries to track available services. Changing registry values is sometimes a preliminary step towards completing another attack pattern, but given the long term usage of many registry values, manipulation of registry information could be its own end.

## Mapped ATT&CK techniques (2)

- [T1112: Modify Registry](/mitre/techniques/T1112.md): Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution.
- [T1647: Plist File Modification](/mitre/techniques/T1647.md): Adversaries may modify property list files (plist files) to enable other malicious activity, while also potentially evading and bypassing system defenses.

## Related CWE (1)

- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html): One or more system settings or configuration elements can be externally controlled by a user.

## Prerequisites

- The targeted application must rely on values stored in a registry.
- The adversary must have a means of elevating permissions in order to access and modify registry content through either administrator privileges (e.g., credentialed access), or a remote access tool capable of editing a registry through an API.

## Skills required

- [High] The adversary requires privileged credentials or the development/acquiring of a tailored remote access tool.

## Mitigations

- Ensure proper permissions are set for Registry hives to prevent users from modifying keys.
- Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.
- Employ robust identification and audit/blocking using an allowlist of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

## Related pages

- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-15
- [CAPEC-69: Target Programs with Elevated Privileges](/mitre/capec/CAPEC-69.md), also related to CWE-15
- [CAPEC-76: Manipulating Web Input to File System Calls](/mitre/capec/CAPEC-76.md), also related to CWE-15
- [CAPEC-77: Manipulating User-Controlled Variables](/mitre/capec/CAPEC-77.md), also related to CWE-15
- [CAPEC-146: XML Schema Poisoning](/mitre/capec/CAPEC-146.md), also related to CWE-15
- [CAPEC-176: Configuration/Environment Manipulation](/mitre/capec/CAPEC-176.md), also related to CWE-15
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
