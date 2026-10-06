# CAPEC-207: Removing Important Client Functionality

<a id="capec-207"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An adversary removes or disables functionality on the client that the server assumes to be present and trustworthy.

## Related CWE (1)

- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html): The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.

## Prerequisites

- The targeted server must assume the client performs important actions to protect the server or the server functionality. For example, the server may assume the client filters outbound traffic or that the client performs all price calculations correctly. Moreover, the server must fail to detect when these assumptions are violated by a client.

## Skills required

- [High] To reverse engineer the client-side code to disable/remove the functionality on the client that the server relies on.
- [Low] The adversary installs a web tool that allows scripts or the DOM model of web-based applications to be modified before they are executed in a browser. GreaseMonkey and Firebug are two examples of such tools.

## Consequences

- Confidentiality / Other
- Integrity / Modify Data
- Confidentiality / Read Data
- Accountability, Authentication, Authorization, Non-Repudiation / Gain Privileges
- Access Control, Authorization / Bypass Protection Mechanism

## Mitigations

- Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.
- Design: Ship client-side application with integrity checks (code signing) when possible.
- Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
