# CAPEC-187 — Malicious Automated Software Update via Redirection

<a id="capec-187"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attacker exploits two layers of weaknesses in server or client software for automated update mechanisms to undermine the integrity of the target code-base. The first weakness involves a failure to properly authenticate a server as a source of update or patch content. This type of weakness typically results from authentication mechanisms which can be defeated, allowing a hostile server to satisfy the criteria that establish a trust relationship. The second weakness is a systemic failure to validate the identity and integrity of code downloaded from a remote location, hence the inability to distinguish malicious code from a legitimate update.

## Mapped ATT&CK techniques (1)

- [T1072 — Software Deployment Tools](/mitre/techniques/T1072.md) — Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network.

## Related CWE (1)

- [CWE-494 — Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) — The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.

## Consequences

- Access Control, Availability, Confidentiality / Execute Unauthorized Commands

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
