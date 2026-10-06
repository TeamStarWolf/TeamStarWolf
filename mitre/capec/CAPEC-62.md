# CAPEC-62: Cross Site Request Forgery

<a id="capec-62"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

An attacker crafts malicious web links and distributes them (via web pages, email, etc.), typically in a targeted manner, hoping to induce users to click on the link and execute the malicious action against some third-party application. If successful, the action embedded in the malicious link will be processed and accepted by the targeted application with the users' privilege level. This type of attack leverages the persistence and implicit trust placed in user session cookies by many web applications today. In such an architecture, once the user authenticates to an application and a session cookie is created on the user's system, all following transactions for that session are authenticated using that cookie including potential actions initiated by an attacker and simply "riding" the existing session cookie.

## Related CWE (5)

- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html): The web application does not, or cannot, sufficiently verify whether a request was intentionally provided by the user who sent the request, which could have originated from an unauthorized actor.
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html): The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.
- [CWE-664: Improper Control of a Resource Through its Lifetime](https://cwe.mitre.org/data/definitions/664.html): The product does not maintain or incorrectly maintains control over a resource throughout its lifetime of creation, use, and release.
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html): The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.
- [CWE-1275: Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html): The SameSite attribute for sensitive cookies is not set, or an insecure value is used.

## Skills required

- [Medium] The attacker needs to figure out the exact invocation of the targeted malicious action and then craft a link that performs the said action. Having the user click on such a link is often accomplished by sending an email or posting such a link to a bulletin board or the likes.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality / Read Data
- Integrity / Modify Data

## Mitigations

- Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.
- Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.
- Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.
- In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
