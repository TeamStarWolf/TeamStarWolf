# CAPEC-73 — User-Controlled Filename

<a id="capec-73"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attack of this type involves an adversary inserting malicious characters (such as a XSS redirection) into a filename, directly or indirectly that is then used by the target software to generate HTML text or other potentially executable content. Many websites rely on user-generated content and dynamically build resources like files, filenames, and URL links directly from user supplied data. In this attack pattern, the attacker uploads code that can execute in the client browser and/or redirect the client browser to a site that the attacker owns. All XSS attack payload variants can be used to pass and exploit these vulnerabilities.

## Related CWE (8)

- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-184 — Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html) — The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are not allowed by policy or otherwise require other action to neutralize before additional processing takes…
- [CWE-96 — Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html) — The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before inserting the input into an executable resource, such as a library, configuration file, or…
- [CWE-348 — Use of Less Trusted Source](https://cwe.mitre.org/data/definitions/348.html) — The product has two different sources of the same data or information, but it uses the source that has less support for verification, is less trusted, or is less resistant to attack.
- [CWE-116 — Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html) — The product prepares a structured message for communication with another component, but encoding or escaping of the data is either missing or done incorrectly.
- [CWE-350 — Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html) — The product performs reverse DNS resolution on an IP address to obtain the hostname and make a security decision, but it does not properly ensure that the IP address is truly associated with the hostname.
- [CWE-86 — Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html) — The product does not neutralize or incorrectly neutralizes invalid characters or byte sequences in the middle of tag names, URI schemes, and other identifiers.
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html) — The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- The victim must trust the name and locale of user controlled filenames.

## Skills required

- [Low] To achieve a redirection and use of less trusted source, an attacker can simply edit data that the host uses to build the filename
- [Medium] Deploying a malicious "look-a-like" site (such as a site masquerading as a bank or online auction site) that the user enters their authentication data into.
- [High] Exploiting a client side vulnerability to inject malicious scripts into the browser's executable process.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Availability / Alter Execution Logic
- Confidentiality / Read Data

## Mitigations

- Design: Use browser technologies that do not allow client side scripting.
- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Perform input validation for all remote content.
- Implementation: Perform output validation for all remote content.
- Implementation: Disable scripting languages such as JavaScript in browser
- Implementation: Scan dynamically generated content against validation specification

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
