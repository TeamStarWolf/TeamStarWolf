# CAPEC-48: Passing Local Filenames to Functions That Expect a URL

<a id="capec-48"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Draft  

This attack relies on client side code to access local files and resources instead of URLs. When the client browser is expecting a URL string, but instead receives a request for a local file, that execution is likely to occur in the browser process space with the browser's authority to local files. The attacker can send the results of this request to the local files out to a site that they control. This attack may be used to steal sensitive authentication data (either local or remote), or to gain system profile information to launch further attacks.

## Related CWE (2)

- [CWE-241: Improper Handling of Unexpected Data Type](https://cwe.mitre.org/data/definitions/241.html): The product does not handle or incorrectly handles when a particular element is not the expected type, e.g. it expects a digit (0-9) but is provided with a letter (A-Z).
- [CWE-706: Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html): The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Prerequisites

- The victim's software must not differentiate between the location and type of reference passed the client software, e.g. browser

## Skills required

- [Medium] Attacker identifies known local files to exploit

## Consequences

- Confidentiality / Read Data
- Integrity / Modify Data

## Mitigations

- Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Implementation: Ensure all configuration files and resource are either removed or protected when promoting code into production.
- Design: Use browser technologies that do not allow client side scripting.
- Implementation: Perform input validation for all remote content.
- Implementation: Perform output validation for all remote content.
- Implementation: Disable scripting languages such as JavaScript in browser

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
