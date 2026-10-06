# CAPEC-212: Functionality Misuse

<a id="capec-212"></a>

Abstraction: Meta  
Typical severity: Medium  
Likelihood: Medium  
Status: Stable  

An adversary leverages a legitimate capability of an application in such a way as to achieve a negative technical impact. The system functionality is not altered or modified but used in a way that was not intended. This is often accomplished through the overuse of a specific functionality or by leveraging functionality with design flaws that enables the adversary to gain access to unauthorized, sensitive data.

## Related CWE (3)

- [CWE-1242: Inclusion of Undocumented Features or Chicken Bits](https://cwe.mitre.org/data/definitions/1242.html): The device includes chicken bits or undocumented features that can create entry points for unauthorized actors.
- [CWE-1246: Improper Write Handling in Limited-write Non-Volatile Memories](https://cwe.mitre.org/data/definitions/1246.html): The product does not implement or incorrectly implements wear leveling operations in limited-write non-volatile memories.
- [CWE-1281: Sequence of Processor Instructions Leads to Unexpected Behavior](https://cwe.mitre.org/data/definitions/1281.html): Specific combinations of processor instructions lead to undesirable behavior such as locking the processor until a hard reset performed.

## Prerequisites

- The adversary has the capability to interact with the application directly.The target system does not adequately implement safeguards to prevent misuse of authorized actions/processes.

## Skills required

- [Low] General computer knowledge about how applications are launched, how they interact with input/output, and how they are configured.

## Consequences

- Confidentiality / Gain Privileges
- Confidentiality, Integrity, Availability / Other

## Mitigations

- Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.
- When implementing security features, consider how they can be misused and compromised.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
