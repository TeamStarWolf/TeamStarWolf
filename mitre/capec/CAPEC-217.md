# CAPEC-217: Exploiting Incorrectly Configured SSL/TLS

<a id="capec-217"></a>

Abstraction: Standard  
Likelihood: Low  
Status: Draft  

An adversary takes advantage of incorrectly configured SSL/TLS communications that enables access to data intended to be encrypted. The adversary may also use this type of attack to inject commands or other traffic into the encrypted stream to cause compromise of either the client or server.

## Related CWE (1)

- [CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html): The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

## Prerequisites

- Access to the client/server stream.

## Skills required

- [High] The adversary needs real-time access to network traffic in such a manner that the adversary can grab needed information from the SSL stream, possibly influence the decided-upon encryption method and options, and perform automated analysis to decipher encrypted material recovered. Tools exist to automate part of the tasks, but to successfully use these tools in an attack scenario requires detailed understanding of the underlying principles.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Do not use SSL, as all SSL versions have been broken and should not be used. If TLS is not an option for the client or server, consider setting timeouts on SSL sessions to extremely low values to lessen the potential impact.
- Only use TLS version 1.2+, as versions 1.0 and 1.1 are insecure.
- Configure TLS to use secure algorithms. The current recommendation is to use ECDH, ECDSA, AES256-GCM, and SHA384 for the most security.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
