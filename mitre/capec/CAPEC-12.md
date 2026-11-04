# CAPEC-12: Choosing Message Identifier

<a id="capec-12"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Draft  

This pattern of attack is defined by the selection of messages distributed via multicast or public information channels that are intended for another client by determining the parameter value assigned to that client. This attack allows the adversary to gain access to potentially privileged information, and to possibly perpetrate other attacks through the distribution means by impersonation. If the channel/message being manipulated is an input rather than output mechanism for the system, (such as a command bus), this style of attack could be used to change the adversary's identifier to more a privileged one.

## Related CWE (2)

- [CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html): The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.
- [CWE-306: Missing Authentication for Critical Functionality](https://cwe.mitre.org/data/definitions/306.html): The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.

## Prerequisites

- Information and client-sensitive (and client-specific) data must be present through a distribution channel available to all users.
- Distribution means must code (through channel, message identifiers, or convention) message destination in a manner visible within the distribution means itself (such as a control channel) or in the messages themselves.

## Skills required

- [Low] All the adversary needs to discover is the format of the messages on the channel/distribution means and the particular identifier used within the messages.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Associate some ACL (in the form of a token) with an authenticated user which they provide middleware. The middleware uses this token as part of its channel/message selection for that client, or part of a discerning authorization decision for privileged channels/messages. The purpose is to architect the system in a way that associates proper authentication/authorization with each channel/message.
- Re-architect system input/output channels as appropriate to distribute self-protecting data. That is, encrypt (or otherwise protect) channels/messages so that only authorized readers can see them.

## Related pages

- [CAPEC-36: Using Unpublished Interfaces or Functionality](/mitre/capec/CAPEC-36.md), also related to CWE-306
- [CAPEC-62: Cross Site Request Forgery](/mitre/capec/CAPEC-62.md), also related to CWE-306
- [CAPEC-166: Force the System to Reset Values](/mitre/capec/CAPEC-166.md), also related to CWE-306
- [CAPEC-216: Communication Channel Manipulation](/mitre/capec/CAPEC-216.md), also related to CWE-306
- [CAPEC-217: Exploiting Incorrectly Configured SSL/TLS](/mitre/capec/CAPEC-217.md), also related to CWE-201
- [CAPEC-612: WiFi MAC Address Tracking](/mitre/capec/CAPEC-612.md), also related to CWE-201
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
