# Hardware Security

> Securing the physical layer — from firmware analysis and secure boot to side-channel attacks, hardware implants, and supply chain trust anchors.

Hardware security addresses the lowest layers of the computing stack: firmware, bootloaders, microcontrollers, debug interfaces, and physical silicon. Practitioners analyze firmware for embedded vulnerabilities, test hardware interfaces (JTAG, UART, SPI), perform side-channel attacks to extract cryptographic secrets, and harden platforms against physical-access adversaries. The field spans both offensive disciplines — fault injection, cold boot attacks, PCIe DMA exploitation — and defensive engineering — measured boot chains, firmware signing, TPM attestation, and memory encryption. As hardware supply chain attacks and firmware-resident implants become increasingly relevant to nation-state and advanced threat actor playbooks, hardware security has moved from a niche specialization to a critical component of enterprise and government security programs.

---

## Where to Start

| Level | Description | Free Resource |
|---|---|---|
| Beginner | Understand how firmware is structured, how UEFI/Secure Boot works, and what a TPM does. Practice with binwalk on firmware images and tpm2-tools on a test system. | [Chipsec Documentation](https://chipsec.github.io/) |
| Intermediate | Extract and reverse engineer firmware with Ghidra. Use OpenOCD for JTAG connectivity. Explore TPM PCR sealing/unsealing. Study the Secure Boot chain on real hardware. | [DEF CON Hardware Hacking Village Talks](https://www.dc-hhv.com/) |
| Advanced | Perform side-channel power analysis with ChipWhisperer, fault injection (voltage/clock glitching), and PCIe DMA attacks with pcileech. Research UEFI implant techniques and measured boot bypass. | [ChipWhisperer Wiki & Tutorials](https://wiki.newae.com/) |

---

## Free Training

| Platform | URL | What You Learn |
|---|---|---|
| ChipWhisperer Wiki | https://wiki.newae.com/ | Side-channel analysis, fault injection, hardware security fundamentals |
| Chipsec Documentation | https://chipsec.github.io/ | UEFI/BIOS security assessment, SPI flash inspection, platform security checks |
| DEF CON HHV (YouTube) | https://www.youtube.com/@DEFCONConference | Hardware hacking talks, soldering workshops, JTAG/UART labs |
| Hardwear.io Talks | https://hardwear.io/ | Conference presentations: secure boot, side-channel, embedded research |
| OpenOCD Docs | https://openocd.org/doc/html/index.html | JTAG/SWD interface configuration, debugging embedded targets |
| Azeria Labs (ARM Exploitation) | https://azeria-labs.com/ | ARM architecture, embedded exploitation, shellcode for IoT targets |

---

## Tools & Repositories

### Firmware Analysis & Extraction

| Tool | Purpose | Link |
|---|---|---|
| binwalk | Firmware extraction — identifies and extracts embedded file systems and binaries | https://github.com/ReFirmLabs/binwalk |
| Firmwalker | Searches extracted firmware for credentials, private keys, and config files | https://github.com/craigz28/firmwalker |
| Jefferson | JFFS2 (flash filesystem) extractor | https://github.com/sviehb/jefferson |
| ubireader | UBI/UBIFS flash filesystem extraction | https://github.com/jrspruitt/ubi_reader |
| FACT (Firmware Analysis and Comparison Tool) | Automated firmware unpacking, analysis, and vulnerability comparison | https://github.com/fkie-cad/FACT_core |
| Ghidra | Reverse engineering and decompilation of firmware binaries (ARM, MIPS, x86) | https://ghidra-sre.org/ |
| QEMU | Emulate embedded firmware (ARM/MIPS) for dynamic analysis | https://www.qemu.org/ |

### Debug Interfaces — JTAG, UART, SPI

| Tool | Purpose | Link |
|---|---|---|
| OpenOCD | JTAG/SWD interface for debugging embedded targets; supports hundreds of devices | https://openocd.org/ |
| JTAGulator | Identifies JTAG/UART pins on unknown PCBs via brute-force scanning | http://www.grandideastudio.com/jtagulator/ |
| flashrom | Read, write, and verify SPI/I2C flash chips directly from PCB pads | https://www.flashrom.org/ |
| Bus Pirate | Universal bus interface: SPI, I2C, UART, JTAG — beginner-friendly hardware tool | http://dangerousprototypes.com/docs/Bus_Pirate |
| HydraBus | Open-source multi-protocol hardware interface for security research | https://github.com/hydrabus/hydrabus |
| GreatFET | USB-based hardware hacking platform — GPIO, SPI, I2C, UART, JTAG | https://github.com/greatscottgadgets/greatfet |
| Sigrok / PulseView | Open-source logic analyzer software; works with low-cost logic analyzers | https://sigrok.org/ |

### Secure Boot & TPM

| Tool | Purpose | Link |
|---|---|---|
| tpm2-tools | TPM 2.0 command-line tools: read PCRs, manage keys, perform attestation | https://github.com/tpm2-software/tpm2-tools |
| chipsec | Intel platform security assessment: UEFI variables, SPI flash, memory protections | https://github.com/chipsec/chipsec |
| BootStomp | Taint analysis tool for bootloader vulnerability discovery | https://github.com/ucsb-seclab/BootStomp |
| pcileech | PCIe Direct Memory Access (DMA) attacks; read/write arbitrary physical memory | https://github.com/ufrisk/pcileech |

### Side-Channel & Fault Injection

| Tool | Purpose | Link |
|---|---|---|
| ChipWhisperer | Power analysis (SPA/DPA) and fault injection (voltage/clock glitching) platform | https://github.com/newaetech/chipwhisperer |
| Riscure Inspector (open eval) | Professional SCA platform; evaluation version available | https://www.riscure.com/ |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [Eclypsium](https://eclypsium.com/) | Firmware security platform | Continuous firmware monitoring; supply chain risk |
| [Binarly](https://binarly.io/) | AI-powered firmware vulnerability research | Discovers vulnerabilities across UEFI/BIOS at scale |
| [Finite State](https://finitestate.io/) | IoT/embedded firmware analysis | SCA + binary analysis for connected devices |
| [Thales Luna HSM](https://cpl.thalesgroup.com/encryption/hardware-security-modules) | Network HSM | FIPS 140-3 Level 3; key management |
| [Yubico YubiHSM 2](https://www.yubico.com/products/hardware-security-module/) | USB HSM | Affordable HSM for small deployments |
| [AWS CloudHSM](https://aws.amazon.com/cloudhsm/) | Cloud HSM | FIPS 140-3 Level 3; customer-controlled keys |

---

## Offensive Techniques

### Firmware Attacks

| Attack | Description | Defensive Control |
|---|---|---|
| UEFI rootkit | Malicious UEFI module persists across OS reinstalls | Secure Boot enforcement; firmware integrity monitoring |
| BMC compromise | Baseboard Management Controller exploitation (iDRAC, iLO) | BMC firmware updates; dedicated BMC network segment |
| SPI flash implant | Rewrite SPI NOR flash directly to embed backdoor in firmware | Flash write protection (BIOS_WE); signed firmware updates |
| Firmware backdoor via JTAG | JTAG access provides full debug control; can patch firmware at runtime | Disable/fuse JTAG in production; physical port controls |

### Physical & Cold Boot Attacks

| Attack | Description | Defensive Control |
|---|---|---|
| Cold boot attack | DRAM retains data for seconds-to-minutes when cold; attacker freezes RAM and reads keys | Memory encryption (AMD SME/SEV, Intel TME); encrypted hibernation |
| Evil maid attack | Physical access to an unattended, locked device to modify boot components | Full-disk encryption with TPM PCR sealing + PIN; tamper-evident seals |
| PCIe DMA attack (pcileech) | PCIe devices can read/write arbitrary physical memory via DMA | IOMMU enforcement (Intel VT-d, AMD-Vi); kernel DMA protection |

### Side-Channel Attacks

| Attack | Description | Target |
|---|---|---|
| Simple Power Analysis (SPA) | Single trace reveals key bits from power variations | Microcontrollers running unprotected crypto |
| Differential Power Analysis (DPA) | Statistical correlation of many traces extracts keys | AES, RSA, ECC implementations |
| Electromagnetic Analysis (EMA) | EM emissions carry same information as power traces | Smartcards, secure elements |
| Timing attacks | Execution time differences reveal secret key bits | Software crypto without constant-time implementations |
| Fault injection (voltage/clock glitching) | Induced faults skip security checks or corrupt computations | Secure boot signature verification, secure elements |
| Rowhammer | Repeated DRAM row access causes bit flips in adjacent rows | DRAM without ECC; used in privilege escalation chains |

### Hardware Implants

| Device | Capability | Notes |
|---|---|---|
| USB Rubber Ducky | Emulates keyboard; executes keystroke payloads on plug-in | Classic HID attack device |
| O.MG Cable | Wireless-enabled malicious USB cable with embedded implant | Used in red team and advanced supply chain attacks |
| LAN Turtle | Covert network tap and pivot device in USB Ethernet form factor | Passive network reconnaissance |
| USB Ninja | Bluetooth-controlled USB device emulating HID + storage | Remote-triggered payload execution |
| pcileech + FPGA | PCIe card or Thunderbolt DMA attack with full memory read/write | Requires physical PCIe/Thunderbolt access |

---

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---|---|---|
| SI-7 | System & Information Integrity | Firmware integrity — signed updates, measured boot, integrity monitoring |
| SA-12 | System & Services Acquisition | Supply chain risk management — hardware provenance verification |
| SC-28 | System & Communications Protection | Protection of information at rest — full-disk encryption, memory encryption |
| SC-51 | System & Communications Protection | Hardware-based protection — TPM, secure enclaves, hardware root of trust |
| PE-3 | Physical & Environmental Protection | Physical access controls for hardware — server room, device custody |
| CM-7 | Configuration Management | Least functionality — disable JTAG, UART, USB in production firmware |
| SA-3 | System & Services Acquisition | System development lifecycle — security requirements for hardware acquisition |
| SA-4 | System & Services Acquisition | Acquisition process — firmware security requirements in vendor contracts |
| SC-8 | System & Communications Protection | Transmission confidentiality — encrypted management interfaces (IPMI, BMC) |

---

## ATT&CK Coverage

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| [T1542](https://attack.mitre.org/techniques/T1542/) | Pre-OS Boot | Persistence, Defense Evasion | Secure Boot and TPM attestation detect pre-OS implants |
| [T1542.001](https://attack.mitre.org/techniques/T1542/001/) | System Firmware | Persistence, Defense Evasion | UEFI rootkits persist in SPI flash; firmware signing prevents |
| [T1542.003](https://attack.mitre.org/techniques/T1542/003/) | Bootkit | Persistence, Defense Evasion | Bootkits infect MBR/VBR; UEFI Secure Boot enforces chain |
| [T1091](https://attack.mitre.org/techniques/T1091/) | Replication Through Removable Media | Initial Access, Lateral Movement | USB implants (Rubber Ducky, O.MG Cable) deliver payloads |
| [T1200](https://attack.mitre.org/techniques/T1200/) | Hardware Additions | Initial Access | PCIe DMA cards, LAN Turtles, and Thunderbolt implants gain system access |
| [T1601](https://attack.mitre.org/techniques/T1601/) | Modify System Image | Defense Evasion | Attackers modify network device firmware to persist |
| [T1601.001](https://attack.mitre.org/techniques/T1601/001/) | Patch System Image | Defense Evasion | Firmware patching for persistent backdoor access |
| [T1601.002](https://attack.mitre.org/techniques/T1601/002/) | Downgrade System Image | Defense Evasion | Rollback to vulnerable firmware version to re-exploit |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [GIAC GREM](https://www.giac.org/certifications/reverse-engineering-malware-grem/) | GIAC | Reverse engineering malware and firmware; low-level binary analysis |
| [OffSec EXP-301 (OSED)](https://www.offensive-security.com/exp301-osed/) | OffSec | Windows exploit development; foundational for hardware-adjacent exploitation |
| [SANS FOR610](https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/) | SANS | Malware and firmware reverse engineering |
| [CompTIA Security+](https://www.comptia.org/certifications/security) | CompTIA | Broad security fundamentals including physical and hardware controls |
| [Certified Hardware Security Professional (CHSP)](https://www.hardwaresecurity.io/) | HSP Institute | Dedicated hardware security practitioner certification |
| [OSCP](https://www.offensive-security.com/pwk-oscp/) | OffSec | Penetration testing — includes physical, embedded, and IoT attack paths |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [The Hardware Hacker (bunnie huang)](https://nostarch.com/hardwarehacking) | Book | Practical hardware hacking, PCB analysis, firmware extraction |
| [Hacking the Xbox (bunnie huang)](https://nostarch.com/xbox.htm) | Book | Classic hardware RE; free PDF; security by obscurity failures |
| [Embedded Security (Jasper van Woudenberg)](https://www.riscure.com/book/) | Book | Side-channel analysis and fault injection — academic and practical |
| [Joe Grand DEF CON Talks](https://www.youtube.com/results?search_query=joe+grand+defcon) | Video | Wallet recovery, JTAG reconnaissance, hardware attack methodology |
| [Hardwear.io Conference](https://hardwear.io/) | Conference | Premier annual hardware security conference |
| [DEF CON Hardware Hacking Village](https://www.dc-hhv.com/) | Community | Annual competitions, beginner workshops, talks |
| [Chipsec Documentation](https://chipsec.github.io/) | Reference | Intel platform security assessment tool and framework |
| [NIST SP 800-193](https://csrc.nist.gov/publications/detail/sp/800-193/final) | Standard | Platform firmware resiliency: detect, protect, recover |

---


## Hardware Attack Techniques

### Side-Channel Attacks

**Power Analysis**
- Simple Power Analysis (SPA): single trace reveals key bits from power variations
- Differential Power Analysis (DPA): statistical correlation across many traces extracts secret keys

**Timing Attacks**
- Measure execution time variations to infer secret data (crypto key bits, password characters)
- Applies to software crypto without constant-time implementations

**Electromagnetic Emissions**
- EM radiation from chips leaks computation; measured with EM probe + oscilloscope
- ChipWhisperer: Open hardware platform for power analysis and glitching attacks; `chipwhisperer.io`

**Cache Side-Channel**
- Spectre/Meltdown class attacks — exploit CPU cache timing differences to read across privilege boundaries

### Fault Injection

**Voltage Glitching**
- Brief voltage spike causes CPU to skip instructions (bypass secure boot, authentication checks)

**Clock Glitching**
- Momentary clock signal manipulation causes setup/hold time violations → computation errors

**Laser Fault Injection**
- Focused laser induces bit flips in memory cells (most precise, expensive)

**Tools**: ChipWhisperer, Riscure Inspector, NewAE CW Husky

### JTAG and Debug Interface Attacks

**JTAG (IEEE 1149.1)**
- Test interface on nearly all embedded devices; provides full CPU control when active
- Discovery: JTAGulator — automated JTAG pin discovery; scan 24 I/O lines to find TCK/TDO/TDI/TMS/TRST
- Exploitation: OpenOCD + JTAG adapter → halt CPU → dump firmware → patch memory → read protected areas

**UART**
- Async serial interface (common default console); 115200 baud common
- `minicom -D /dev/ttyUSB0 -b 115200`

### Firmware Extraction and Analysis

**Chip-off**
- Physically remove flash chip → read with programmer (SOIC clip, VCC-GND-CLK-DATA-CS connections)

**In-Circuit Programming (ICSP)**
- Read flash in-circuit using SPI/I2C/JTAG without desoldering

**Key Tools**
- Binwalk: Identify embedded file systems, compression, crypto; `binwalk -e firmware.bin` extracts
- Firmwalker: Scripts for finding interesting files (passwords, keys, telnet/ssh config, admin interfaces)
- QEMU: Emulate ARM/MIPS firmware without hardware; `qemu-arm-static ./squashfs-root/usr/bin/httpd`

### Secure Boot Bypass Techniques

**Known Methods**
- BootROM vulnerabilities: Immutable code in ROM; if flawed, game over (Samsung BootROM, iPhone checkm8)
- Key extraction: Read signing keys from OTP (One-Time Programmable) memory via glitching
- Downgrade attack: Flash older vulnerable firmware if version checking not enforced
- U-Boot exploits: Interrupt boot sequence at U-Boot prompt if console accessible

---

## Trusted Platform Module (TPM) and Secure Enclaves

### TPM 2.0

- **Purpose**: Hardware root of trust; stores keys, certificates; measured boot; remote attestation
- **Key capabilities**: Key generation, signing/encryption, PCR sealing (bind key to system state), attestation
- **Attack**: TPM sniffing — intercept SPI bus between CPU and TPM; demonstrated on BitLocker-protected laptops
- **Defense**: Use TPM 2.0 with PIN/biometric second factor; PIN defeats direct SPI sniffing attack

### Intel SGX / AMD SEV

- **SGX (Software Guard Extensions)**: CPU-level memory encryption; enclaves isolated from OS/hypervisor
- **Attacks on SGX**: ÆPIC Leak (CVE-2022-21233), Foreshadow (L1TF), PlunderVolt (voltage fault injection)
- **AMD SEV**: Encrypt virtual machine memory; protect VMs from hypervisor; SEV-SNP adds integrity protection

### HSM (Hardware Security Module)

- FIPS 140-2/140-3 Level 3/4 hardware device for key storage and cryptographic operations
- Tamper-evident: Physical attack triggers key zeroization
- Products: Thales Luna, Entrust nShield, AWS CloudHSM, Azure Dedicated HSM

---

## Hardware Security Tools Reference

| Tool | Use Case | Skill Level |
|------|----------|-------------|
| ChipWhisperer | Power analysis and voltage glitching | Intermediate-Advanced |
| JTAGulator | JTAG/UART pin discovery | Beginner-Intermediate |
| Binwalk | Firmware analysis and extraction | Beginner |
| OpenOCD | JTAG/SWD debugger and programmer | Intermediate |
| Firmwalker | Firmware secret hunting | Beginner |
| QEMU | Firmware emulation | Intermediate |
| Bus Pirate | Serial/SPI/I2C/JTAG interface | Beginner-Intermediate |
| Logic analyzer (Saleae) | Protocol analysis | Intermediate |
| SOIC clip (Pomona) | In-circuit flash reading | Intermediate |
| Riscure Inspector | Commercial side-channel analysis platform | Advanced |

## Related Disciplines

- [ICS / OT Security](ics-ot-security.md) — Industrial control systems, PLCs, SCADA with embedded firmware
- [Malware Analysis](malware-analysis.md) — Firmware reverse engineering overlaps heavily with malware RE techniques
- [Cryptography & PKI](cryptography-pki.md) — HSMs, TPMs, hardware-backed key storage and attestation
- [Supply Chain Security](supply-chain-security.md) — Hardware supply chain integrity, component authentication
- [Security Architecture](security-architecture.md) — Hardware root of trust design in system architecture
- [Penetration Testing / Offensive Security](offensive-security.md) — Physical pentesting, red team hardware implants
