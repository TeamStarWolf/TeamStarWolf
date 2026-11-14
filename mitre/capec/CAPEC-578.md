# CAPEC-578: Disable Security Software

<a id="capec-578"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: Medium  
Status: Usable  

An adversary exploits a weakness in access control to disable security tools so that detection does not occur. This can take the form of killing processes, deleting registry keys so that tools do not start at run time, deleting log files, or other methods.

## Mapped ATT&CK techniques (7)

- [T1556.006: Multi-Factor Authentication](/mitre/techniques/T1556-006.md): Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts.
- [T1562.001: Disable or Modify Tools](/mitre/techniques/T1562-001.md): Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.
- [T1562.002: Disable Windows Event Logging](/mitre/techniques/T1562-002.md): Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits.
- [T1562.004: Disable or Modify System Firewall](/mitre/techniques/T1562-004.md): Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage.
- [T1562.007: Disable or Modify Cloud Firewall](/mitre/techniques/T1562-007.md): Adversaries may disable or modify a firewall within a cloud environment to bypass controls that limit access to cloud resources.
- [T1562.008: Disable or Modify Cloud Logs](/mitre/techniques/T1562-008.md): An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection.
- [T1562.009: Safe Mode Boot](/mitre/techniques/T1562-009.md): Adversaries may abuse Windows safe mode to disable endpoint defenses.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Prerequisites

- The adversary must have the capability to interact with the configuration of the targeted system.

## Consequences

- Availability / Hide Activities

## Mitigations

- Ensure proper permissions are in place to prevent adversaries from altering the execution status of security tools.

## Related pages

- [T1685: Disable or Modify Tools](/mitre/techniques/T1685.md), whose ATT&CK profile lists this pattern
- [T1685.001: Disable or Modify Windows Event Log](/mitre/techniques/T1685-001.md), whose ATT&CK profile lists this pattern
- [T1685.002: Disable or Modify Cloud Log](/mitre/techniques/T1685-002.md), whose ATT&CK profile lists this pattern
- [T1686: Disable or Modify System Firewall](/mitre/techniques/T1686.md), whose ATT&CK profile lists this pattern
- [T1686.001: Cloud Firewall](/mitre/techniques/T1686-001.md), whose ATT&CK profile lists this pattern
- [T1688: Safe Mode Boot](/mitre/techniques/T1688.md), whose ATT&CK profile lists this pattern
- [CAPEC-19: Embedding Scripts within Scripts](/mitre/capec/CAPEC-19.md), also related to CWE-284
- [CAPEC-441: Malicious Logic Insertion](/mitre/capec/CAPEC-441.md), also related to CWE-284
- [CAPEC-478: Modification of Windows Service Configuration](/mitre/capec/CAPEC-478.md), also related to CWE-284
- [CAPEC-479: Malicious Root Certificate](/mitre/capec/CAPEC-479.md), also related to CWE-284
- [CAPEC-502: Intent Spoof](/mitre/capec/CAPEC-502.md), also related to CWE-284
- [CAPEC-503: WebView Exposure](/mitre/capec/CAPEC-503.md), also related to CWE-284
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- [The Year 2004 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2004.md)
- [The Year 2005 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2005.md)
- [The Year 2006 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2006.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
