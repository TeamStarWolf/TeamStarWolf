# CAPEC-674 — Design for FPGA Maliciously Altered

<a id="capec-674"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Stable  

An adversary alters the functionality of a field-programmable gate array (FPGA) by causing an FPGA configuration memory chip reload in order to introduce a malicious function that could result in the FPGA performing or enabling malicious functions on a host system. Prior to the memory chip reload, the adversary alters the program for the FPGA by adding a function to impact system operation.

## Mapped ATT&CK techniques (1)

- [T1195.003 — Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md)

## Prerequisites

- An adversary would need to have access to FPGA programming/configuration-related systems in a chip maker’s development environment where FPGAs can be initially configured prior to delivery to a cust

## Skills required

- An adversary would need to be skilled in FPGA programming in order to create/manipulate configurations in such a way that when loaded into an

## Mitigations

- Utilize DMEA’s (Defense Microelectronics Activity) Trusted Foundry Program members for acquisition of microelectronic components.
- Ensure that each supplier performing hardware development implements comprehensive, security-focused configuration ma

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
