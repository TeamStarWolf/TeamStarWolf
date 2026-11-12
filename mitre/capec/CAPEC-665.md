# CAPEC-665: Exploitation of Thunderbolt Protection Flaws

<a id="capec-665"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: Low  
Status: Stable  

An adversary leverages a firmware weakness within the Thunderbolt protocol, on a computing device to manipulate Thunderbolt controller firmware in order to exploit vulnerabilities in the implementation of authorization and verification schemes within Thunderbolt protection mechanisms. Upon gaining physical access to a target device, the adversary conducts high-level firmware manipulation of the victim Thunderbolt controller SPI (Serial Peripheral Interface) flash, through the use of a SPI Programing device and an external Thunderbolt device, typically as the target device is booting up. If successful, this allows the adversary to modify memory, subvert authentication mechanisms, spoof identities and content, and extract data and memory from the target device. Currently 7 major vulnerabilities exist within Thunderbolt protocol with 9 attack vectors as noted in the Execution Flow.

## Mapped ATT&CK techniques (3)

- [T1211: Exploitation for Stealth](/mitre/techniques/T1211.md): Adversaries may exploit vulnerabilities to evade detection by hiding activity, suppressing logging, or operating within trusted or unmonitored components.
- [T1542.002: Component Firmware](/mitre/techniques/T1542-002.md): Adversaries may modify component firmware to persist on systems.
- [T1556: Modify Authentication Process](/mitre/techniques/T1556.md): Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.

## Related CWE (5)

- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html): The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.
- [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html): The product uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission, such as a checksum.
- [CWE-288: Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html): The product requires authentication, but the product has an alternate path or channel that does not require authentication.
- [CWE-1188: Initialization of a Resource with an Insecure Default](https://cwe.mitre.org/data/definitions/1188.html): The product initializes or sets a resource with a default that is intended to be changed by the product's installer, administrator, or maintainer, but the default is not secure.
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html): The product does not perform an authorization check when an actor attempts to access a resource or perform an action.

## Prerequisites

- The adversary needs at least a few minutes of physical access to a system with an open Thunderbolt port, version 3 or lower, and an external thunderbolt device controlled by the adversary with maliciously crafted software and firmware, via an SPI Programming device, to exploit weaknesses in security protections.

## Skills required

- [High] Detailed knowledge on various system motherboards, PCI Express Domain, SPI, and Thunderbolt Protocol in order to interface with internal system components via external devices.
- [High] Detailed knowledge on OS/Kernel memory address space, Direct Memory Access (DMA) mapping, Input-Output Memory Management Units (IOMMUs), and vendor memory protections for data leakage.
- [High] Detailed knowledge on scripting and SPI programming in order to configure and modify Thunderbolt controller firmware and software configurations.

## Consequences

- Access Control / Bypass Protection Mechanism
- Confidentiality / Read Data
- Integrity / Modify Data
- Authorization / Execute Unauthorized Commands

## Mitigations

- Implementation: Kernel Direct Memory Access Protection
- Configuration: Enable UEFI option USB Passthrough mode - Thunderbolt 3 system port operates as USB 3.1 Type C interface
- Configuration: Enable UEFI option DisplayPort mode - Thunderbolt 3 system port operates as video-only DP interface
- Configuration: Enable UEFI option Mixed USB/DisplayPort mode - Thunderbolt 3 system port operates as USB 3.1 Type C interface with support for DP mode
- Configuration: Set Security Level to SL3 for Thunderbolt 2 system port
- Configuration: Disable PCIe tunneling to set Security Level to SL3
- Configuration: Disable Boot Camp upon MacOS systems

## Related pages

- [CAPEC-127: Directory Indexing](/mitre/capec/CAPEC-127.md), also related to CWE-288
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-353
- [CAPEC-14: Client-side Injection-induced Buffer Overflow](/mitre/capec/CAPEC-14.md), also related to CWE-353
- [CAPEC-39: Manipulating Opaque Client-based Data Tokens](/mitre/capec/CAPEC-39.md), also related to CWE-353
- [CAPEC-74: Manipulating State](/mitre/capec/CAPEC-74.md), also related to CWE-353
- [CAPEC-75: Manipulating Writeable Configuration Files](/mitre/capec/CAPEC-75.md), also related to CWE-353
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
