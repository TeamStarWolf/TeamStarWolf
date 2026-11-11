# CAPEC-169: Footprinting

<a id="capec-169"></a>

Abstraction: Meta  
Typical severity: Very Low  
Likelihood: High  
Status: Stable  

An adversary engages in probing and exploration activities to identify constituents and properties of the target.

## Mapped ATT&CK techniques (3)

- [T1217: Browser Information Discovery](/mitre/techniques/T1217.md): Adversaries may enumerate information about browsers to learn more about compromised environments.
- [T1592: Gather Victim Host Information](/mitre/techniques/T1592.md): Adversaries may gather information about the victim's hosts that can be used during targeting.
- [T1595: Active Scanning](/mitre/techniques/T1595.md): Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- An application must publicize identifiable information about the system or application through voluntary or involuntary means. Certain identification details of information systems are visible on communication networks (e.g., if an adversary uses a sniffer to inspect the traffic) due to their inherent structure and protocol standards. Any system or network that can be detected can be footprinted. However, some configuration choices may limit the useful information that can be collected during a footprinting attack.

## Skills required

- [Low] The adversary knows how to send HTTP request, run the scan tool.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Keep patches up to date by installing weekly or daily if possible.
- Shut down unnecessary services/ports.
- Change default passwords by choosing strong passwords.
- Curtail unexpected input.
- Encrypt and password-protect sensitive data.
- Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

## Related pages

- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-200
- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-200
- [CAPEC-59: Session Credential Falsification through Prediction](/mitre/capec/CAPEC-59.md), also related to CWE-200
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-200
- [CAPEC-79: Using Slashes in Alternate Encoding](/mitre/capec/CAPEC-79.md), also related to CWE-200
- [CAPEC-116: Excavation](/mitre/capec/CAPEC-116.md), also related to CWE-200
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Cyber Operations as Statecraft: The Cases in The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
