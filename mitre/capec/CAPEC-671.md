# CAPEC-671: Requirements for ASIC Functionality Maliciously Altered

<a id="capec-671"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  

An adversary with access to functional requirements for an application specific integrated circuit (ASIC), a chip designed/customized for a singular particular use, maliciously alters requirements derived from originating capability needs. In the chip manufacturing process, requirements drive the chip design which, when the chip is fully manufactured, could result in an ASIC which may not meet the user’s needs, contain malicious functionality, or exhibit other anomalous behaviors thereby affecting the intended use of the ASIC.

## Mapped ATT&CK techniques (1)

- [T1195.003: Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md): Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- An adversary would need to have access to a foundry’s or chip maker’s requirements management system that stores customer requirements for ASICs, requirements upon which the design of the ASIC is based.

## Skills required

- [High] An adversary would need experience in designing chips based on functional requirements in order to manipulate requirements in such a way that deviations would not be detected in subsequent stages of ASIC manufacture and where intended malicious functionality would be available to the adversary once integrated into a system and fielded.

## Consequences

- Integrity / Alter Execution Logic

## Mitigations

- Utilize DMEA’s (Defense Microelectronics Activity) Trusted Foundry Program members for acquisition of microelectronic components.
- Ensure that each supplier performing hardware development implements comprehensive, security-focused configuration management including for hardware requirements and design.
- Require that provenance of COTS microelectronic components be known whenever procured.
- Conduct detailed vendor assessment before acquiring COTS hardware.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
