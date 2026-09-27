# CAPEC-680 — Exploitation of Improperly Controlled Registers

<a id="capec-680"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary exploits missing or incorrectly configured access control within registers to read/write data that is not meant to be obtained or modified by a user.

## Related CWE (5)

- [CWE-1224 — Improper Restriction of Write-Once Bit Fields](https://cwe.mitre.org/data/definitions/1224.html) — The hardware design control register sticky bits or write-once bit fields are improperly implemented, such that they can be reprogrammed by software.
- [CWE-1231 — Improper Prevention of Lock Bit Modification](https://cwe.mitre.org/data/definitions/1231.html) — The product uses a trusted lock bit for restricting access to registers, address regions, or other resources, but the product does not prevent the value of the lock bit from being modified after it has been set.
- [CWE-1233 — Security-Sensitive Hardware Controls with Missing Lock Bit Protection](https://cwe.mitre.org/data/definitions/1233.html) — The product uses a register lock bit protection mechanism, but it does not ensure that the lock bit prevents modification of system registers or controls that perform changes to important hardware system configuration.
- [CWE-1262 — Improper Access Control for Register Interface](https://cwe.mitre.org/data/definitions/1262.html) — The product uses memory-mapped I/O registers that act as an interface to hardware functionality from software, but there is improper access control to those registers.
- [CWE-1283 — Mutable Attestation or Measurement Reporting Data](https://cwe.mitre.org/data/definitions/1283.html) — The register contents used for attestation or measurement reporting data to verify boot flow are modifiable by an adversary.

## Prerequisites

- Awareness of the hardware being leveraged.
- Access to the hardware being leveraged.

## Skills required

- [High] Intricate knowledge of registers.

## Consequences

- Integrity / Modify Data
- Confidentiality / Read Data

## Mitigations

- Design proper access control policies for hardware register access from software and ensure these policies are implemented in accordance with the specified design.
- Ensure security lock bit protections are reviewed for design inconsistencies and common weaknesses.
- Test security lock programming flow in both pre-silicon and post-silicon environments.
- Leverage automated tools to test that values are not reprogrammable and that write-once fields lock on writing zeros.
- Ensure that measurement data is stored in registers that are read-only or otherwise have access controls that prevent modification by an untrusted agent.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
