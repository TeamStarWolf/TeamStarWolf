# D3FEND: Service Binary Verification

<a id="service-binary-verification"></a>

D3FEND tactic: Detect  
Digital artifacts: Service Application  

Analyzing changes in service binary files by comparing to a source of truth.

## ATT&CK techniques countered (12)

- [T0843: Program Download](https://attack.mitre.org/techniques/T0843): verifies
- [T0845: Program Upload](https://attack.mitre.org/techniques/T0845): verifies
- [T0873: Project File Infection](https://attack.mitre.org/techniques/T0873): verifies
- [T0889: Modify Program](https://attack.mitre.org/techniques/T0889): verifies
- [T1056.003: Web Portal Capture](/mitre/techniques/T1056-003.md): verifies. Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service.
- [T1072: Software Deployment Tools](/mitre/techniques/T1072.md): verifies. Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network.
- [T1212: Exploitation for Credential Access](/mitre/techniques/T1212.md): verifies. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.
- [T1489: Service Stop](/mitre/techniques/T1489.md): verifies. Adversaries may stop or disable services on a system to render those services unavailable to legitimate users.
- [T1564.006: Run Virtual Instance](/mitre/techniques/T1564-006.md): verifies. Adversaries may carry out malicious operations using a virtual instance to avoid detection.
- [T1574.005: Executable Installer File Permissions Weakness](/mitre/techniques/T1574-005.md): verifies. Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer.
- [T1574.010: Services File Permissions Weakness](/mitre/techniques/T1574-010.md): verifies. Adversaries may execute their own malicious payloads by hijacking the binaries used by services.
- [T1649: Steal or Forge Authentication Certificates](/mitre/techniques/T1649.md): verifies. Adversaries may steal or forge certificates used for authentication to access remote systems or resources.

## Related pages

- [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md), which also counters 12 of these techniques
- [Restore Software](/mitre/d3fend/restore-software.md), which also counters 12 of these techniques
- [Software Inventory](/mitre/d3fend/software-inventory.md), which also counters 12 of these techniques
- [Software Update](/mitre/d3fend/software-update.md), which also counters 12 of these techniques
- [Message Authentication](/mitre/d3fend/message-authentication.md), which also counters 4 of these techniques
- [Message Encryption](/mitre/d3fend/message-encryption.md), which also counters 4 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Stuxnet: The Case Study](/case-studies/STUXNET.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
