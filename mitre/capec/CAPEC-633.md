# CAPEC-633: Token Impersonation

<a id="capec-633"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Stable  

An adversary exploits a weakness in authentication to create an access token (or equivalent) that impersonates a different entity, and then associates a process/thread to that that impersonated token. This action causes a downstream user to make a decision or take action that is based on the assumed identity, and not the response that blocks the adversary.

## Mapped ATT&CK techniques (1)

- [T1134: Access Token Manipulation](/mitre/techniques/T1134.md): Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls.

## Related CWE (2)

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html): When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.
- [CWE-1270: Generation of Incorrect Security Tokens](https://cwe.mitre.org/data/definitions/1270.html): The product implements a Security Token mechanism to differentiate what actions are allowed or disallowed when a transaction originates from an entity.

## Prerequisites

- This pattern of attack is only applicable when a downstream user leverages tokens to verify identity, and then takes action based on that identity.

## Consequences

- Integrity / Alter Execution Logic
- Integrity / Gain Privileges
- Integrity / Hide Activities

## Related pages

- [CAPEC-121: Exploit Non-Production Interfaces](/mitre/capec/CAPEC-121.md), also related to CWE-1270
- [CAPEC-681: Exploitation of Improperly Controlled Hardware Security Identifiers](/mitre/capec/CAPEC-681.md), also related to CWE-1270
- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-287
- [CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data](/mitre/capec/CAPEC-57.md), also related to CWE-287
- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-287
- [CAPEC-114: Authentication Abuse](/mitre/capec/CAPEC-114.md), also related to CWE-287
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
