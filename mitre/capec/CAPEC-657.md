# CAPEC-657 — Malicious Automated Software Update via Spoofing

<a id="capec-657"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attackers uses identify or content spoofing to trick a client into performing an automated software update from a malicious source. A malicious automated software update that leverages spoofing can include content or identity spoofing as well as protocol spoofing. Content or identity spoofing attacks can trigger updates in software by embedding scripted mechanisms within a malicious web page, w

## Mapped ATT&CK techniques (1)

- [T1072 — Software Deployment Tools](/mitre/techniques/T1072.md) — Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network.

## Related CWE (1)

- [CWE-494 — Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) — The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
