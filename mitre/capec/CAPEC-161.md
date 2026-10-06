# CAPEC-161: Infrastructure Manipulation

<a id="capec-161"></a>

Abstraction: Meta  
Typical severity: High  
Status: Draft  

An attacker exploits characteristics of the infrastructure of a network entity in order to perpetrate attacks or information gathering on network objects or effect a change in the ordinary information flow between network objects. Most often, this involves manipulation of the routing of network messages so, instead of arriving at their proper destination, they are directed towards an entity of the attackers' choosing, usually a server controlled by the attacker. The victim is often unaware that their messages are not being processed correctly. For example, a targeted client may believe they are connecting to their own bank but, in fact, be connecting to a Pharming site controlled by the attacker which then collects the user's login information in order to hijack the actual bank account.

## Related CWE (1)

- [CWE-923: Improper Restriction of Communication Channel to Intended Endpoints](https://cwe.mitre.org/data/definitions/923.html): The product establishes a communication channel to (or from) an endpoint for privileged or protected operations, but it does not properly ensure that it is communicating with the correct endpoint.

## Prerequisites

- The targeted client must access the site via infrastructure that the attacker has co-opted and must fail to adequately verify that the communication channel is operating correctly (e.g. by verifying that they are, in fact, connected to the site they intended.)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
