# CAPEC-233: Privilege Escalation

<a id="capec-233"></a>

Abstraction: Meta  
Status: Draft  

An adversary exploits a weakness enabling them to elevate their privilege and perform an action that they are not supposed to be authorized to perform.

## Mapped ATT&CK techniques (1)

- [T1548: Abuse Elevation Control Mechanism](/mitre/techniques/T1548.md): Adversaries may circumvent mechanisms designed to control privilege elevation to gain higher-level permissions.

## Related CWE (3)

- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html): The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.
- [CWE-1264: Hardware Logic with Insecure De-Synchronization between Control and Data Channels](https://cwe.mitre.org/data/definitions/1264.html): The hardware logic for error handling and security checks can incorrectly forward data before the security check is complete.
- [CWE-1311: Improper Translation of Security Attributes by Fabric Bridge](https://cwe.mitre.org/data/definitions/1311.html): The bridge incorrectly translates security attributes from either trusted to untrusted or from untrusted to trusted when converting from one fabric protocol to another.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
