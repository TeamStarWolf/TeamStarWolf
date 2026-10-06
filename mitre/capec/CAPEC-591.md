# CAPEC-591: Reflected XSS

<a id="capec-591"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: High  
Status: Stable  

This type of attack is a form of Cross-Site Scripting (XSS) where a malicious script is "reflected" off a vulnerable web application and then executed by a victim's browser. The process starts with an adversary delivering a malicious script to a victim and convincing the victim to send the script to the vulnerable web application.

## Related CWE (1)

- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html): The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

## Prerequisites

- An application that leverages a client-side web browser with scripting enabled.
- An application that fail to adequately sanitize or encode untrusted input.

## Skills required

- [Medium] Requires the ability to write malicious scripts and embed them into HTTP requests.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Authorization, Access Control / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Integrity / Modify Data

## Mitigations

- Use browser technologies that do not allow client-side scripting.
- Utilize strict type, character, and encoding enforcement.
- Ensure that all user-supplied input is validated before use.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
