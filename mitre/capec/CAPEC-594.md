# CAPEC-594: Traffic Injection

<a id="capec-594"></a>

Abstraction: Meta  
Status: Stable  

An adversary injects traffic into the target's network connection. The adversary is therefore able to degrade or disrupt the connection, and potentially modify the content. This is not a flooding attack, as the adversary is not focusing on exhausting resources. Instead, the adversary is crafting a specific input to affect the system in a particular way.

## Related CWE (1)

- [CWE-940: Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html): The product establishes a communication channel to handle an incoming request that has been initiated by an actor, but it does not properly verify that the request is coming from the expected origin.

## Prerequisites

- The target application must leverage an open communications channel.
- The channel on which the target communicates must be vulnerable to interception (e.g., adversary in the middle attack - CAPEC-94).

## Consequences

- Availability / Unreliable Execution
- Integrity / Other

## Related pages

- [CAPEC-500: WebView Injection](/mitre/capec/CAPEC-500.md), also related to CWE-940
- [CAPEC-595: Connection Reset](/mitre/capec/CAPEC-595.md), also related to CWE-940
- [CAPEC-596: TCP RST Injection](/mitre/capec/CAPEC-596.md), also related to CWE-940
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
