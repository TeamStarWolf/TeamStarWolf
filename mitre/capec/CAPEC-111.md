# CAPEC-111 — JSON Hijacking (aka JavaScript Hijacking)

<a id="capec-111"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attacker targets a system that uses JavaScript Object Notation (JSON) as a transport mechanism between the client and the server (common in Web 2.0 systems using AJAX) to steal possibly confidential information transmitted from the server back to the client inside the JSON object by taking advantage of the loophole in the browser's Same Origin Policy that does not prohibit JavaScript from one website to be included and executed in the context of another website.

## Related CWE (3)

- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) — The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html) — The product does not properly verify that the source of data or communication is valid.
- [CWE-352 — Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html) — The web application does not, or cannot, sufficiently verify whether a request was intentionally provided by the user who sent the request, which could have originated from an unauthorized actor.

## Prerequisites

- JSON is used as a transport mechanism between the client and the server
- The target server cannot differentiate real requests from forged requests
- The JSON object returned from the server can be accessed by the attackers' malicious code via a script tag

## Skills required

- [Medium] Once this attack pattern is developed and understood, creating an exploit is not very complex.The attacker needs to have knowledge of the URLs that need to be accessed on the target system to request the JSON objects.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Ensure that server side code can differentiate between legitimate requests and forged requests. The solution is similar to protection against Cross Site Request Forger (CSRF), which is to use a hard to guess random nonce (that is unique to the victim's session with the server) that the attacker has no way of knowing (at least in the absence of other weaknesses). Each request from the client to the server should contain this nonce and the server should reject all requests that do not contain the nonce.
- On the client side, the system's design could make it difficult to get access to the JSON object content via the script tag. Since the JSON object is never assigned locally to a variable, it cannot be readily modified by the attacker before being used by a script tag. For instance, if while(1) was added to the beginning of the JavaScript returned by the server, trying to access it with a script tag would result in an infinite loop. On the other hand, legitimate client side code can remove the while(1) statement after which the JavaScript can be evaluated. A similar result can be achieved by surrounding the returned JavaScript with comment tags, or using other similar techniques (e.g. wrapping the JavaScript with HTML tags).
- Make the URLs in the system used to retrieve JSON objects unpredictable and unique for each user session.
- Ensure that to the extent possible, no sensitive data is passed from the server to the client via JSON objects. JavaScript was never intended to play that role, hence the same origin policy does not adequate address this scenario.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
