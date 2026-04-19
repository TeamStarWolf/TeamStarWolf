# Hardware Security

> Securing the physical layer — from firmware and boot integrity to hardware-backed cryptography, embedded systems, and supply chain trust anchors.

## What Hardware Security Engineers Do

- Analyze firmware for vulnerabilities: UEFI/BIOS, BMC, bootloaders, and embedded firmware
- Implement and validate Secure Boot, measured boot, and TPM attestation chains
- Conduct hardware penetration testing: fault injection, side-channel attacks, JTAG/debug interface access
- Design hardware root of trust implementations (TPM, HSM, secure enclaves)
- Assess hardware supply chain integrity: component authentication, anti-counterfeiting
- Perform PCB analysis, chip decapping, and logic analyzer-based bus snooping
- Implement platform firmware resilience (NIST SP 800-193)
- Secure embedded systems: automotive ECUs, industrial PLCs, IoT devices, medical devices

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [NIST SP 800-193](https://csrc.nist.gov/publications/detail/sp/800-193/final) | Platform Firmware Resiliency Guidelines |
| [NIST SP 800-155](https://csrc.nist.gov/publications/detail/sp/800-155/draft) | BIOS Integrity Measurement Guidelines |
| [TCG TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/) | Trusted Platform Module standard |
| [UEFI Secure Boot](https://uefi.org/specifications) | Boot firmware integrity verification |
| [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final) | Cryptographic module security requirements |
| [Common Criteria (ISO 15408)](https://www.commoncriteriaportal.org/) | IT security evaluation framework |
| [MITRE ATLAS](https://atlas.mitre.org/) | Adversarial threats to ML/AI (includes hardware attacks) |

---

## Free & Open-Source Tools

### Firmware Analysis

| Tool | Purpose | Notes |
|---|---|---|
| [Binwalk](https://github.com/ReFirmLabs/binwalk) | Firmware extraction and analysis | Extracts file systems from firmware images |
| [Firmwalker](https://github.com/craigz28/firmwalker) | Firmware filesystem analysis | Searches for credentials, keys, config |
| [FACT (Firmware Analysis and Comparison Tool)](https://github.com/fkie-cad/FACT_core) | Automated firmware analysis | Unpacking, analysis, comparison framework |
| [Ghidra](https://ghidra-sre.org/) | Reverse engineering (NSA) | Full disassembler/decompiler for firmware RE |
| [Radare2](https://rada.re/) | Reverse engineering framework | Multi-arch; strong for embedded firmware |
| [Binary Ninja](https://binary.ninja/) | Binary analysis platform | Commercial with free personal tier |
| [QEMU](https://www.qemu.org/) | Firmware emulation | Emulate embedded ARM/MIPS firmware |
| [Unicorn Engine](https://www.unicorn-engine.org/) | CPU emulation framework | Emulate firmware code snippets |

### Boot Security & TPM

| Tool | Purpose | Notes |
|---|---|---|
| [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) | TPM 2.0 command-line tools | Read PCRs, manage keys, attest |
| [tpm2-pytss](https://github.com/tpm2-software/tpm2-pytss) | Python TPM 2.0 bindings | Scripted TPM operations |
| [BootStomp](https://github.com/ucsb-seclab/BootStomp) | Bootloader vulnerability analysis | Taint analysis for bootloader security |
| [chipsec](https://github.com/chipsec/chipsec) | Platform security assessment | Intel; checks UEFI, SPI flash, memory |

### Hardware Hacking & Physical Testing

| Tool | Purpose | Notes |
|---|---|---|
| [OpenOCD](https://openocd.org/) | JTAG/SWD debugging interface | Connect to embedded debug ports |
| [JTAGulator](http://www.grandideastudio.com/jtagulator/) | JTAG/UART pin identification | Identifies debug interface pins on PCBs |
| [Flashrom](https://www.flashrom.org/) | Flash chip read/write | Read SPI flash chips from PCBs |
| [logic2 (Saleae)](https://www.saleae.com/pages/downloads) | Logic analyzer software | Analyze SPI, I2C, UART, JTAG traffic |
| [Sigrok / PulseView](https://sigrok.org/) | Open-source logic analyzer | Works with low-cost logic analyzers |
| [ChipWhisperer](https://github.com/newaetech/chipwhisperer) | Side-channel + fault injection | Power analysis, glitching attacks |
| [ESP-IDF](https://docs.espressif.com/projects/esp-idf/) | ESP32 development + security | Flash encryption, secure boot for ESP32 |

### Secure Element & HSM

| Tool | Purpose | Notes |
|---|---|---|
| [PKCS#11 Tools](https://github.com/OpenSC/OpenSC) | Smart card / HSM interface | OpenSC; PKCS#11 operations |
| [SoftHSM2](https://www.opendnssec.org/softhsm/) | Software HSM emulator | Test HSM integrations without hardware |
| [Nitrokey](https://www.nitrokey.com/) | Open-source security key | GPG, FIDO2, HOTP hardware key |

---

## Commercial Platforms & Products

| Vendor | Capability | Notes |
|---|---|---|
| [Eclypsium](https://eclypsium.com/) | Firmware security platform | Continuous firmware monitoring; supply chain |
| [Binarly](https://binarly.io/) | Firmware vulnerability research | AI-powered firmware analysis |
| [Finite State](https://finitestate.io/) | IoT/embedded firmware analysis | SCA + binary analysis for connected devices |
| [Wind River](https://www.windriver.com/) | Real-time OS for embedded | VxWorks; Titanium security features |
| [Thales Luna HSM](https://cpl.thalesgroup.com/encryption/hardware-security-modules) | Network HSM | FIPS 140-3 Level 3; key management |
| [Yubico YubiHSM](https://www.yubico.com/products/hardware-security-module/) | USB HSM | Affordable HSM for small deployments |

---

## Attack Categories

### Firmware Attacks
| Attack | Description | Mitigation |
|---|---|---|
| UEFI rootkit | Malicious UEFI module persists across OS reinstalls | Secure Boot, firmware integrity monitoring |
| BMC compromise | Baseboard Management Controller attack (iDRAC, iLO) | BMC firmware updates, network segmentation |
| SPI flash implant | Rewrite SPI NOR flash with malicious firmware | Flash write protection, signed firmware |
| Evil Maid | Physical access to modify boot components | Full-disk encryption + TPM PCR sealing |

### Side-Channel Attacks
| Attack | Description | Mitigation |
|---|---|---|
| Power analysis (SPA/DPA) | Extract crypto keys from power consumption | Constant-time algorithms, power noise |
| EM emanations | Recover secrets from electromagnetic emissions | Shielding, distance controls |
| Timing attacks | Infer secrets from operation timing | Constant-time crypto implementations |
| Rowhammer | Bit flips in DRAM via repeated memory access | ECC RAM, memory controller mitigations |

---

## ATT&CK Coverage

| Technique | Description | Hardware Security Control |
|---|---|---|
| [T1542](https://attack.mitre.org/techniques/T1542/) | Pre-OS Boot | Secure Boot, TPM attestation |
| [T1542.001](https://attack.mitre.org/techniques/T1542/001/) | System Firmware | Firmware integrity monitoring, signed updates |
| [T1542.003](https://attack.mitre.org/techniques/T1542/003/) | Bootkit | UEFI Secure Boot enforcement |
| [T1542.004](https://attack.mitre.org/techniques/T1542/004/) | ROMMONkit | Cisco ROM Monitor integrity validation |
| [T1495](https://attack.mitre.org/techniques/T1495/) | Firmware Corruption | Firmware write protection; backup |
| [T1553.006](https://attack.mitre.org/techniques/T1553/006/) | Code Signing Policy Modification | TPM-measured boot detects policy changes |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [GIAC GREM](https://www.giac.org/certifications/reverse-engineering-malware-grem/) | GIAC | Reverse engineering (firmware/malware overlap) |
| [Offensive Security OSED](https://www.offensive-security.com/exp301-osed/) | OffSec | Exploit development (low-level) |
| [Hardware Security Training (SANS FOR610)](https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/) | SANS | Malware/firmware RE |
| [Certified Hardware Security Professional (CHSP)](https://www.hardwaresecurity.io/) | HSP Institute | Dedicated hardware security cert |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [The Hardware Hacking Handbook](https://nostarch.com/hardwarehacking) | Book | Practical hardware hacking from No Starch Press |
| [Hacking the Xbox (Bunnie Huang)](https://nostarch.com/xbox.htm) | Book | Classic hardware RE; free PDF available |
| [Embedded Security (Jasper van Woudenberg)](https://www.riscure.com/book/) | Book | Hardware side-channel and fault injection |
| [Chipsec Documentation](https://chipsec.github.io/) | Reference | Intel platform security assessment tool |
| [Hardwear.io](https://hardwear.io/) | Conference | Premier hardware security conference |
| [DEF CON Hardware Hacking Village](https://www.dc-hhv.com/) | Community | Annual hardware hacking competitions |
| [Embedded Systems Security (Coursera)](https://www.coursera.org/learn/embedded-systems-security) | Course | IoT/embedded security fundamentals |

---

## Related Disciplines

- [ICS / OT Security](ics-ot-security.md) — Industrial control systems and SCADA
- [Malware Analysis](malware-analysis.md) — Firmware reverse engineering overlaps with malware RE
- [Cryptography & PKI](cryptography-pki.md) — HSMs, TPMs, hardware-backed key management
- [Supply Chain Security](supply-chain-security.md) — Hardware supply chain integrity
- [Security Architecture](security-architecture.md) — Hardware root of trust in system design
