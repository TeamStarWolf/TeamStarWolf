# CAPEC-671 — Requirements for ASIC Functionality Maliciously Altered

<a id="capec-671"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

An adversary with access to functional requirements for an application specific integrated circuit (ASIC), a chip designed/customized for a singular particular use, maliciously alters requirements derived from originating capability needs. In the chip manufacturing process, requirements drive the chip design which, when the chip is fully manufactured, could result in an ASIC which may not meet the

## Mapped ATT&CK techniques (1)

- [T1195.003](/mitre/techniques/T1195-003.md)

**Prerequisites:** ::An adversary would need to have access to a foundry’s or chip maker’s requirements management system that stores customer requirements for ASICs, requirements upon which the design of the ASIC is ba

**Skills required:** ::SKILL:An adversary would need experience in designing chips based on functional requirements in order to manipulate requirements in such a way that 

**Mitigations:** ::Utilize DMEA’s (Defense Microelectronics Activity) Trusted Foundry Program members for acquisition of microelectronic components.::Ensure that each supplier performing hardware development implements comprehensive, security-focused configuration ma


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
