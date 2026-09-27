# CAPEC-662 — Adversary in the Browser (AiTB)

<a id="capec-662"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Stable  

An adversary exploits security vulnerabilities or inherent functionalities of a web browser, in order to manipulate traffic between two endpoints.

## Mapped ATT&CK techniques (1)

- [T1185 — Browser Session Hijacking](/mitre/techniques/T1185.md) — Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking…

## Related CWE (2)

- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html) — The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or…
- [CWE-494 — Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) — The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.

## Prerequisites

- The adversary must install or convince a user to install a Trojan.
- There are two components communicating with each other.
- An attacker is able to identify the nature and mechanism of communication between the two target components.
- Strong mutual authentication is not used between the two target components yielding opportunity for adversarial interposition.
- For browser pivoting, the SeDebugPrivilege and a high-integrity process must both exist to execute this attack.

## Skills required

- [Medium] Tricking the victim into installing the Trojan is often the most difficult aspect of this attack. Afterwards, the remainder of this attack is fairly trivial.

## Consequences

- Integrity / Modify Data
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality / Read Data

## Mitigations

- Ensure software and applications are only downloaded from legitimate and reputable sources, in addition to conducting integrity checks on the downloaded component.
- Leverage anti-malware tools, which can detect Trojan Horse malware.
- Use strong, out-of-band mutual authentication to always fully authenticate both ends of any communications channel.
- Limit user permissions to prevent browser pivoting.
- Ensure browser sessions are regularly terminated and when their effective lifetime ends.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
