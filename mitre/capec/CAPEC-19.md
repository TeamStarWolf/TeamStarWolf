# CAPEC-19: Embedding Scripts within Scripts

<a id="capec-19"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Stable  

An adversary leverages the capability to execute their own script by embedding it within other scripts that the target software is likely to execute due to programs' vulnerabilities that are brought on by allowing remote hosts to execute scripts.

## Mapped ATT&CK techniques (3)

- [T1027.009: Embedded Payloads](/mitre/techniques/T1027-009.md): Adversaries may embed payloads within other files to conceal malicious content from defenses.
- [T1546.004: Unix Shell Configuration Modification](/mitre/techniques/T1546-004.md): Adversaries may establish persistence through executing malicious commands triggered by a user’s shell.
- [T1546.016: Installer Packages](/mitre/techniques/T1546-016.md): Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Prerequisites

- Target software must be able to execute scripts, and also grant the adversary privilege to write/upload scripts.

## Skills required

- [Low] To load malicious script into open, e.g. world writable directory
- [Medium] Executing remote scripts on host and collecting output

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Use browser technologies that do not allow client side scripting.
- Utilize strict type, character, and encoding enforcement.
- Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.
- Ensure all content that is delivered to client is sanitized against an acceptable content specification.
- Perform input validation for all remote content.
- Perform output validation for all remote content.
- Disable scripting languages such as JavaScript in browser
- Session tokens for specific host
- Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.
- Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
