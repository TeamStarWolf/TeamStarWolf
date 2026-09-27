# CAPEC-173 — Action Spoofing

<a id="capec-173"></a>

**Abstraction:** Meta  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

An adversary is able to disguise one action for another and therefore trick a user into initiating one type of action when they intend to initiate a different action. For example, a user might be led to believe that clicking a button will submit a query, but in fact it downloads software. Adversaries may perform this attack through social means, such as by simply convincing a victim to perform the

## Related CWE (1)

- [CWE-451 — User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html) — The user interface (UI) does not properly represent critical information to the user, allowing the information - or its source - to be obscured or spoofed.

## Prerequisites

- The adversary must convince the victim into performing the decoy action.
- The adversary must have the means to control a user's interface to present them with a decoy action as well as the actual ma

## Mitigations

- Avoid interacting with suspicious sites or clicking suspicious links.
- An organization should provide regular, robust cybersecurity training to its employees.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
