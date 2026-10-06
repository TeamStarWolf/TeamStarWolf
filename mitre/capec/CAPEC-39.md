# CAPEC-39: Manipulating Opaque Client-based Data Tokens

<a id="capec-39"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: High  
Status: Draft  

In circumstances where an application holds important data client-side in tokens (cookies, URLs, data files, and so forth) that data can be manipulated. If client or server-side application components reinterpret that data as authentication tokens or data (such as store item pricing or wallet information) then even opaquely manipulating that data may bear fruit for an Attacker. In this pattern an attacker undermines the assumption that client side tokens have been adequately protected from tampering through use of encryption or obfuscation.

## Related CWE (9)

- [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html): The product uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission, such as a checksum.
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html): The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-302: Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html): The authentication scheme or implementation uses key data elements that are assumed to be immutable, but can be controlled or modified by the attacker.
- [CWE-472: External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html): The web application does not sufficiently verify inputs that are assumed to be immutable but are actually externally controllable, such as hidden form fields.
- [CWE-565: Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html): The product relies on the existence or values of cookies when performing security-critical operations, but it does not properly ensure that the setting is valid for the associated user.
- [CWE-315: Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html): The product stores sensitive information in cleartext in a cookie.
- [CWE-539: Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html): The web application uses persistent cookies, but the cookies contain sensitive information.
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html): Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.
- [CWE-233: Improper Handling of Parameters](https://cwe.mitre.org/data/definitions/233.html): The product does not properly handle when the expected number of parameters, fields, or arguments is not provided in input, or if those parameters are undefined.

## Prerequisites

- An attacker already has some access to the system or can steal the client based data tokens from another user who has access to the system.
- For an Attacker to viably execute this attack, some data (later interpreted by the application) must be held client-side in a way that can be manipulated without detection. This means that the data or tokens are not CRCd as part of their value or through a separate meta-data store elsewhere.

## Skills required

- [Medium] If the client site token is obfuscated.
- [High] If the client site token is encrypted.

## Consequences

- Integrity / Modify Data
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- One solution to this problem is to protect encrypted data with a CRC of some sort. If knowing who last manipulated the data is important, then using a cryptographic "message authentication code" (or hMAC) is prescribed. However, this guidance is not a panacea. In particular, any value created by (and therefore encrypted by) the client, which itself is a "malicious" value, all the protective cryptography in the world can't make the value 'correct' again. Put simply, if the client has control over the whole process of generating and encoding the value, then simply protecting its integrity doesn't help.
- Make sure to protect client side authentication tokens for confidentiality (encryption) and integrity (signed hash)
- Make sure that all session tokens use a good source of randomness
- Perform validation on the server side to make sure that client side data tokens are consistent with what is expected.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
