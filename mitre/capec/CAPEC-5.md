# CAPEC-5: Blue Boxing

<a id="capec-5"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: Medium  
Status: Obsolete  

This type of attack against older telephone switches and trunks has been around for decades. A tone is sent by an adversary to impersonate a supervisor signal which has the effect of rerouting or usurping command of the line. While the US infrastructure proper may not contain widespread vulnerabilities to this type of attack, many companies are connected globally through call centers and business process outsourcing. These international systems may be operated in countries which have not upgraded Telco infrastructure and so are vulnerable to Blue boxing. Blue boxing is a result of failure on the part of the system to enforce strong authorization for administrative functions. While the infrastructure is different than standard current applications like web applications, there are historical lessons to be learned to upgrade the access control for administrative functions. This attack pattern is included in CAPEC for historical purposes.

## Related CWE (1)

- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html): The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.

## Prerequisites

- System must use weak authentication mechanisms for administrative functions.

## Skills required

- [Low] Given a vulnerable phone system, the attackers' technical vector relies on attacks that are well documented in cracker 'zines and have been around for decades.

## Consequences

- Availability / Resource Consumption
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Implementation: Upgrade phone lines. Note this may be prohibitively expensive
- Use strong access control such as two factor access control for administrative access to the switch

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
