# CAPEC-59: Session Credential Falsification through Prediction

<a id="capec-59"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

This attack targets predictable session ID in order to gain privileges. The attacker can predict the session ID used during a transaction to perform spoofing and session hijacking.

## Related CWE (11)

- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html): This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html): The product uses insufficiently random numbers or values in a security context that depends on unpredictable numbers.
- [CWE-331: Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html): The product uses an algorithm or scheme that produces insufficient entropy, leaving patterns or clusters of values that are more likely to occur than others.
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html): The product does not properly verify that the source of data or communication is valid.
- [CWE-488: Exposure of Data Element to Wrong Session](https://cwe.mitre.org/data/definitions/488.html): The product does not sufficiently enforce boundaries between the states of different sessions, causing data to be provided to, or used by, the wrong session.
- [CWE-539: Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html): The web application uses persistent cookies, but the cookies contain sensitive information.
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
- [CWE-6: J2EE Misconfiguration: Insufficient Session-ID Length](https://cwe.mitre.org/data/definitions/6.html): The J2EE application is configured to use an insufficient session ID length.
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html): The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html): Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html): The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Prerequisites

- The target host uses session IDs to keep track of the users.
- Session IDs are used to control access to resources.
- The session IDs used by the target host are predictable. For example, the session IDs are generated using predictable information (e.g., time).

## Skills required

- [Low] There are tools to brute force session ID. Those tools require a low level of knowledge.
- [Medium] Predicting Session ID may require more computation work which uses advanced analysis such as statistical analysis.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Use a strong source of randomness to generate a session ID.
- Use adequate length session IDs
- Do not use information available to the user in order to generate session ID (e.g., time).
- Ideas for creating random numbers are offered by Eastlake [RFC1750]
- Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
