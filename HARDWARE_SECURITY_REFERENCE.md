# Hardware Security Reference

> A comprehensive reference for hardware security concepts, tools, and techniques used in offensive and defensive security.

---

## Table of Contents
1. [Hardware Security Fundamentals](#1-hardware-security-fundamentals)
2. [Trusted Platform Module (TPM)](#2-trusted-platform-module-tpm)
3. [Hardware Security Modules (HSM)](#3-hardware-security-modules-hsm)
4. [Secure Boot](#4-secure-boot)
5. [UEFI Firmware Security](#5-uefi-firmware-security)
6. [Side-Channel Attacks](#6-side-channel-attacks)
7. [Fault Injection](#7-fault-injection)
8. [JTAG / Debug Interface Security](#8-jtag--debug-interface-security)
9. [Hardware Attacks on Cryptographic Tokens](#9-hardware-attacks-on-cryptographic-tokens)
10. [Supply Chain Hardware Security](#10-supply-chain-hardware-security)
11. [Physical Unclonable Functions (PUF)](#11-physical-unclonable-functions-puf)
12. [Confidential Computing](#12-confidential-computing)
13. [Hardware Security Tools Reference](#13-hardware-security-tools-reference)

---

## 1. Hardware Security Fundamentals

### Why Hardware Security Matters
Software controls cannot fully protect against physical or hardware-level attacks. An attacker with physical access to a device can often bypass every software security control, from OS authentication to encrypted filesystems. Hardware security addresses this gap by establishing roots of trust that are anchored in silicon rather than software.

### Hardware Attack Categories
| Category | Description | Example |
|---|---|---|
| Side-channel | Extract secrets from physical implementation (power, EM, timing) | DPA against AES hardware |
| Fault injection | Cause hardware faults to bypass security checks | Voltage glitch to skip PIN verify |
| Physical tampering | Direct hardware modification or probing | PCB trace cuts, rework |
| Firmware attacks | Exploit or implant malicious code in firmware/UEFI | UEFI bootkits, persistent implants |
| Supply chain implants | Malicious components inserted during manufacturing | Nation-state hardware backdoors |
| Debug interface abuse | Use JTAG/UART to read memory or extract firmware | OpenOCD firmware dump |

### Threat Actors
- **Nation-state actors**: Advanced capabilities — PCB-level implants, custom ASICs, supply chain access (Bloomberg SuperMicro "The Big Hack" claims, 2018 — disputed but technically plausible)
- **Insiders**: Physical access to production hardware or manufacturing facilities
- **Criminal groups**: Target payment terminals, ATMs, HSM-protected payment systems
- **Security researchers**: Responsible disclosure of hardware vulnerabilities (e.g., Seunghun Han TPM research)

### Defense Layers
1. Physical access control (locks, cages, guards)
2. Tamper-evident seals and enclosures
3. Hardware roots of trust (TPM, Intel Boot Guard, ARM TrustZone)
4. Secure boot chains (UEFI Secure Boot, measured boot)
5. HSMs for key isolation
6. Supply chain verification and component authentication

---

## 2. Trusted Platform Module (TPM)

### Overview
The TPM (Trusted Platform Module) is a dedicated microcontroller designed to secure hardware through integrated cryptographic keys. The TPM 2.0 specification is published by the Trusted Computing Group (TCG). TPMs are present in most modern enterprise laptops, desktops, and servers, and are required for Windows 11.

### Core Functions
- **Sealed storage**: Encrypt data so it can only be decrypted when the system is in a known-good state (measured by PCRs)
- **Key generation and storage**: Hardware-protected RSA/ECC key generation — private keys never leave the TPM
- **PCR measurements**: Cryptographic hash of firmware, bootloader, and OS state stored in Platform Configuration Registers
- **Remote attestation**: Prove to a remote verifier that the system is in a trusted state
- **Random number generation**: Hardware true random number generator (TRNG)

### Platform Configuration Registers (PCRs)
PCR banks are available in SHA-1 (PCR 0-23) and SHA-256. Each register holds the cumulative hash of firmware or boot component state.

| PCR | Contents |
|-----|---------|
| 0 | BIOS/UEFI firmware code |
| 1 | BIOS configuration and data |
| 2 | Option ROMs (expansion card firmware) |
| 3 | Option ROM configuration |
| 4 | MBR / bootloader code |
| 5 | MBR configuration / GPT |
| 6 | Platform-specific |
| 7 | Secure Boot policy and state |
| 8-9 | GRUB / bootloader components (Linux) |
| 11 | BitLocker (Windows) |
| 14 | MOK (Machine Owner Key) |

PCR values are extended (not overwritten): `PCR_new = SHA256(PCR_old || new_measurement)`

### TPM Key Hierarchy
- **Endorsement Key (EK)**: RSA-2048 or ECC key burned in at manufacture; identifies the TPM; used for attestation
- **Storage Root Key (SRK)**: Master key for TPM key hierarchy, seeded when TPM is provisioned
- **Attestation Identity Keys (AIK)**: Pseudonymous keys used for remote attestation without revealing EK
- **Platform keys**: Created by software, stored in TPM's non-volatile memory

### TPM Commands (tpm2-tools)
```bash
# Generate 32 random bytes
tpm2_getrandom 32

# Read PCR values (SHA-256 bank, PCRs 0,1,2,7)
tpm2_pcrread sha256:0,1,2,7

# Create a primary key in the Endorsement hierarchy
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx

# Create a child RSA key under the primary
tpm2_create -C primary.ctx -g sha256 -G rsa -u key.pub -r key.priv

# Load the key into the TPM
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx

# Sign data
tpm2_sign -c key.ctx -g sha256 -f plain -o sig.out data.txt

# Verify signature
tpm2_verifysignature -c key.ctx -g sha256 -m data.txt -s sig.out

# Define NV (non-volatile) storage index
tpm2_nvdefine 0x1500016 -C o -s 32 -a "ownerread|ownerwrite"

# Write to NV storage
tpm2_nvwrite 0x1500016 -C o -i data.bin

# Read NV storage
tpm2_nvread 0x1500016 -C o

# Seal data to current PCR state
tpm2_create -C primary.ctx -g sha256 -G keyedhash -i secret.txt   -u sealed.pub -r sealed.priv -L "sha256:7"

# Quote (attest PCR values)
tpm2_quote -c key.ctx -l sha256:0,1,2,7 -q nonce.bin -m pcrs.msg -s pcrs.sig
```

### BitLocker TPM Integration
BitLocker uses the TPM to seal the Volume Master Key (VMK). The VMK is only unsealed when:
1. PCR values match expected values (firmware and bootloader unchanged)
2. Optionally: a pre-boot PIN or USB key is provided

Attack vector: if PCR values haven't changed (no firmware/bootloader update), BitLocker auto-unlocks at boot — TPM PIN provides an extra factor.

### Attacking TPM
- **TPM bus sniffing**: On older systems, the TPM communicates via the LPC bus (not encrypted). Seunghun Han demonstrated BitLocker key interception by sniffing LPC bus on a ThinkPad (2021). TPM 2.0 uses SPI on modern systems — still potentially sniffable.
- **TPM PIN brute force**: BitLocker without pre-boot PIN — attacker with physical access and a cloned drive can brute-force offline if TPM is not used or seal is bypassed.
- **Cold boot attack**: Freeze RAM (liquid nitrogen/CO2) to slow bit decay → read DRAM contents after power-off → extract BitLocker key from memory.
- **Mitigation**: Enable pre-boot PIN, use TPM+PIN mode, enable memory encryption (AMD SME/SEV).

### TPM in Cloud Environments
| Platform | TPM Type | Notes |
|---|---|---|
| Azure | vTPM (virtual TPM) | TPM 2.0 emulated in hypervisor, supports attestation |
| AWS | Nitro TPM | Available on Nitro-based instances |
| GCP | vTPM | Confidential VMs with AMD SEV + vTPM |

---

## 3. Hardware Security Modules (HSM)

### Purpose
An HSM is a dedicated hardware device for performing cryptographic operations. The critical property: **private keys are generated inside the HSM and never exported in plaintext**. Even if the host system is compromised, the keys remain protected.

### FIPS 140-2 / 140-3 Security Levels
| Level | Physical Security | Key Usage |
|---|---|---|
| 1 | Software only, no physical protection | Laboratory/development |
| 2 | Tamper-evident coatings/seals, role-based auth | Commercial applications |
| 3 | Tamper-responsive (zeroize keys on attack), identity-based auth | Financial/PKI |
| 4 | Complete envelope of protection, environmental attack resistance | Top secret / classified |

FIPS 140-3 (2019) aligned with ISO/IEC 19790, superseding FIPS 140-2. Many organizations still deploy FIPS 140-2 Level 3 HSMs.

### Hardware HSM Vendors
| Vendor | Product | Notes |
|---|---|---|
| Thales | Luna Network HSM 7 | Industry standard, FIPS 140-3 L3 |
| Entrust | nShield Connect | High-availability clustering |
| Utimaco | SecurityServer | German engineering, banking focused |
| Securosys | Primus HSM | Swiss-made, PCI HSM certified |
| IBM | 4769 Crypto Coprocessor | Mainframe HSM |

### Payment HSMs
- **Thales payShield 10K**: PCI PTS HSM v3/v4 certified — used for PIN block translation, card personalization, 3DS authentication
- **Utimaco PaymentServer**: EMV, PIN translation, key injection

### Cloud HSM Services
| Provider | Service | Tenancy | FIPS Level |
|---|---|---|---|
| AWS | CloudHSM | Single-tenant | FIPS 140-2 L3 |
| AWS | KMS | Multi-tenant (managed) | FIPS 140-2 L3 (HSM backend) |
| Azure | Key Vault Managed HSM | Single-tenant | FIPS 140-2 L3 |
| GCP | Cloud HSM | Single-tenant | FIPS 140-2 L3 |

### HSM Use Cases
- **Certificate Authority (CA) private key storage**: Root CA keys stored in HSM — signing only happens inside HSM
- **TLS private key protection**: Web servers offload TLS private key operations to HSM
- **Code signing**: Software publisher keys stored in HSM (prevents stolen signing keys)
- **Database encryption**: Column encryption keys wrapped by HSM master key
- **Blockchain / crypto custody**: Multi-sig keys stored in geographically distributed HSMs

### PKCS#11 Interface
PKCS#11 is the standard API for interacting with HSMs and smart cards.

```python
import pkcs11
from pkcs11 import Mechanism, KeyType

# Initialize PKCS#11 library (SoftHSM2 example)
lib = pkcs11.lib('/usr/lib/softhsm/libsofthsm2.so')

# Get token
token = lib.get_token(token_label='MyToken')

# Open session
with token.open(user_pin='1234') as session:
    # Generate AES-256 key
    key = session.generate_key(KeyType.AES, 256,
                               store=True,
                               label='my-aes-key')

    # Encrypt data
    iv = session.generate_random(128)  # 16-byte IV
    encrypted = key.encrypt(b'plaintext data here',
                             mechanism=Mechanism.AES_CBC_PAD,
                             mechanism_param=iv)

    # Decrypt data
    decrypted = key.decrypt(encrypted,
                            mechanism=Mechanism.AES_CBC_PAD,
                            mechanism_param=iv)

    # Generate RSA key pair
    pub, priv = session.generate_keypair(KeyType.RSA, 2048,
                                         store=True,
                                         label='my-rsa-key')

    # Sign with RSA
    signature = priv.sign(b'message to sign',
                          mechanism=Mechanism.SHA256_RSA_PKCS)
```

### SoftHSM2 (Development/Testing)
```bash
# Install
apt-get install softhsm2

# Initialize a token
softhsm2-util --init-token --slot 0 --label MyToken   --pin 1234 --so-pin 12345678

# List tokens
softhsm2-util --show-slots

# Use with OpenSSL via PKCS#11 engine
openssl engine pkcs11 -pre "MODULE_PATH:/usr/lib/softhsm/libsofthsm2.so"
```

---

## 4. Secure Boot

### Overview
UEFI Secure Boot verifies the cryptographic signature of each boot component before executing it. This prevents unauthorized bootloaders, kernels, and drivers from running — blocking bootkits and rootkits that persist below the OS level.

### Key Database Structure
| Database | Contents | Owner |
|---|---|---|
| PK (Platform Key) | OEM root of trust; controls KEK | OEM (Lenovo, Dell, HP) |
| KEK (Key Exchange Key) | OS vendor keys; signs db/dbx updates | Microsoft, Linux Foundation |
| db (Allowed Signatures) | Trusted bootloader/driver certificates/hashes | OEM + OS vendor |
| dbx (Forbidden Signatures) | Revoked binaries (by hash or certificate) | Microsoft (monthly updates) |
| MOKList | Machine Owner Key list (user-enrolled, GRUB) | System owner |

### Boot Chain Verification
```
UEFI Firmware (anchored by PK)
    → shim.efi (signed by Microsoft KEK → in db)
        → grub.efi (signed by distro → in MOKList or db)
            → vmlinuz (kernel, signed by distro)
                → initrd (integrity checked)
```

Each stage is verified against the db before execution. If a binary's signature is in dbx, it is blocked even if also in db.

### Secure Boot Status Checks
```bash
# Linux — check Secure Boot state
mokutil --sb-state
# Output: SecureBoot enabled

# More detail
bootctl status | grep "Secure Boot"

# Check enrolled keys
mokutil --list-enrolled

# Windows — PowerShell
Confirm-SecureBootUEFI
# Returns: True or False

# Windows — GUI
msinfo32
# Look for: Secure Boot State = On

# Windows — command line
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State /v UEFISecureBootEnabled
```

### Secure Boot Bypass Techniques
| Technique | Requirement | Notes |
|---|---|---|
| Exploit UEFI firmware vulnerability | Remote (if pre-boot reachable) or local | Many CVEs in UEFI implementations |
| BootHole / CVE-2020-10713 | GRUB2 buffer overflow | Allows arbitrary code in bootloader despite Secure Boot |
| BlackLotus (CVE-2023-24932) | Local admin | First in-the-wild UEFI bootkit bypassing Secure Boot on patched Win11 |
| MOKList enrollment | Physical access (reboot required) | Enroll custom certificate, then sign custom kernel |
| Legacy BIOS fallback | Physical BIOS access | Disable Secure Boot in UEFI settings |
| dbx bypass (stale revocation) | Unpatched db/dbx | Use old revoked-but-not-yet-dbx'd binary |

### Measured Boot
Measured Boot records all boot component hashes into TPM PCRs without blocking execution (unlike Secure Boot which blocks). Complements Secure Boot:
- Secure Boot: **prevent** untrusted code from running
- Measured Boot: **record** what ran for later attestation

---

## 5. UEFI Firmware Security

### Notable UEFI Vulnerabilities
| Vulnerability | Year | Impact |
|---|---|---|
| ThinkPwn | 2016 | Arbitrary SMM code execution on Lenovo ThinkPads |
| BootHole (CVE-2020-10713) | 2020 | GRUB2 buffer overflow, Secure Boot bypass |
| MosaicRegressor | 2020 | UEFI implant (SPI flash) in diplomatic laptops |
| CosmicStrand | 2022 | UEFI rootkit distributed via compromised firmware images |
| LogoFAIL (CVE-2023-40238+) | 2023 | Parser vulnerabilities in UEFI logo image handling — code exec from SPI flash |
| BlackLotus (CVE-2023-24932) | 2023 | First in-the-wild Secure Boot bypass bootkit on Windows 11 |

### UEFI Persistent Implants
UEFI firmware implants survive:
- OS reinstallation
- Hard drive/SSD replacement
- Factory reset

They are stored in SPI flash on the motherboard. Removal requires reflashing the SPI chip (if not write-protected) or replacing the motherboard.

### Firmware Security Tools
```bash
# CHIPSEC — comprehensive UEFI security testing framework
pip install chipsec
python chipsec_main.py  # Run all modules
python chipsec_main.py -m common.bios_wp  # Check BIOS write protection
python chipsec_main.py -m common.secureboot.variables  # Check Secure Boot variables

# UEFITool — GUI/CLI tool for analyzing UEFI firmware images
# Download firmware from vendor, open in UEFITool, search for modules

# Binwalk — extract components from firmware images
binwalk -e firmware.rom              # Extract filesystem
binwalk -M -e firmware.rom           # Recursive extraction
binwalk --signature firmware.rom     # Identify file signatures

# fwupd — Linux firmware update daemon
fwupdmgr get-devices                 # List updatable devices
fwupdmgr get-updates                 # Check for firmware updates
fwupdmgr update                      # Apply firmware updates

# uefi-firmware-parser
pip install uefi-firmware-parser
python -m uefi_firmware.guids        # List known GUIDs
```

### SPI Flash Write Protection
- **BIOS_WE / BIOSWE bit**: In the PCH (Platform Controller Hub), this bit controls whether the SPI flash region containing UEFI firmware is write-protected
- When BIOSWE=0: SPI flash is write-protected (correct state)
- When BIOSWE=1: SPI flash is writable — allows firmware modification (attack opportunity)
- CHIPSEC checks: `chipsec_main.py -m common.bios_wp`

### Hardware Root of Trust
- **Intel Boot Guard**: Hardware mechanism in PCH that verifies the initial boot block of UEFI firmware using a hash fused into the PCH. Prevents BIOS reflashing with unsigned firmware. Cannot be disabled once fused.
- **AMD Platform Secure Boot (PSB)**: AMD equivalent — roots trust in processor fuses, verifies AGESA (AMD Generic Encapsulated Software Architecture) before UEFI loads.
- Both mechanisms are one-time-programmable — once enabled by OEM, cannot be disabled.

---

## 6. Side-Channel Attacks

### Overview
Side-channel attacks extract secret information from the **physical implementation** of a cryptographic system rather than exploiting weaknesses in the algorithm itself. Even a mathematically perfect implementation can leak secrets through observable physical characteristics.

### Power Analysis
```
SPA (Simple Power Analysis)
├── Single power trace
├── Visual inspection reveals algorithm operations
├── Example: RSA square-and-multiply — different operations have distinct power signatures
└── Can reveal key bits directly

DPA (Differential Power Analysis)
├── Statistical analysis of many power traces
├── Correlate power consumption with hypothetical key values
├── Even noisy measurements yield key bits with enough traces
└── Kocher et al. 1999 — demonstrated against DES smartcards
```

**ChipWhisperer** (open-source platform for power analysis and fault injection):
```python
import chipwhisperer as cw

# Connect to target
scope = cw.scope()
target = cw.target(scope)
scope.default_setup()

# Capture power trace during AES encryption
key = bytearray(16)  # Known key for testing
text = bytearray(16)

scope.arm()
target.simpleserial_write('k', key)
target.simpleserial_write('p', text)
response = scope.capture()
trace = scope.get_last_trace()

# Use cwanalysis for DPA
import cwanalysis
results = cwanalysis.cpa(traces, texts, cwanalysis.leakage.sbox_output)
```

### Timing Attacks
Non-constant-time operations leak information through execution time differences.

```python
# VULNERABLE: short-circuit comparison
def verify_token_bad(expected, provided):
    return expected == provided  # Returns early on first mismatch

# SECURE: constant-time comparison
import hmac
def verify_token_good(expected, provided):
    return hmac.compare_digest(expected, provided)  # Always compares all bytes

# SECURE in C (OpenBSD / LibreSSL)
int timingsafe_bcmp(const void *b1, const void *b2, size_t n);
int timingsafe_memcmp(const void *b1, const void *b2, size_t n);
```

**Notable timing attack exploits:**
- **Lucky13** (2013): TLS MAC timing leaks padding oracle in CBC mode
- **Bleichenbacher's attack** (1998): RSA PKCS#1 v1.5 padding oracle — decrypts TLS sessions
- **Minerva** (2020): ECDSA nonce timing bias in hardware security tokens (YubiKey, Feitian)
- **Port contention** (2018): SMT timing attack (Portsmash, CVE-2018-5407)

### Cache-Based Attacks
```
Flush+Reload
├── Attacker flushes cache line
├── Victim accesses memory (or not)
├── Attacker reloads — fast = victim accessed (in cache), slow = victim didn't
└── Infer secret based on access pattern

Prime+Probe
├── Attacker fills cache set
├── Victim runs, evicts some attacker lines
├── Attacker probes — slow eviction = victim accessed that set
└── Works without shared memory (cross-VM)

Evict+Time
├── Attacker evicts cache lines
├── Measures victim execution time
└── Slower execution = cache miss = attacker can infer data access
```

Cross-VM cache attacks demonstrated in cloud environments (CVE-2013-2107, Ristenpart et al. 2009).

### Electromagnetic (EM) Analysis
- Similar to power analysis but measures electromagnetic emissions from the chip
- Does not require electrical contact with the target
- Near-field EM probes capture localized emissions from specific chip areas
- Can be more precise than power analysis (target specific functional units)

### Acoustic Cryptanalysis
Genkin, Shamir, and Tromer (2014) demonstrated RSA-4096 key extraction from laptop acoustics:
- Laptops emit distinct sounds during different computations
- Different RSA key bits produce different acoustic signatures
- Key extracted by analyzing audio from microphone or smartphone placed near laptop

### Spectre and Meltdown (2018)
```
Meltdown (CVE-2017-5754)
├── Exploit out-of-order execution
├── Read kernel memory from unprivileged user space
├── All x86 CPUs pre-2018 affected
└── Mitigation: KPTI (Kernel Page-Table Isolation) — separate page tables for user/kernel

Spectre Variant 1 (CVE-2018-3639) — Bounds Check Bypass
├── Exploit speculative execution past bounds check
├── Read out-of-bounds memory speculatively
└── Mitigation: lfence barriers, compiler __builtin_speculation_safe_value

Spectre Variant 2 (CVE-2018-3640) — Branch Target Injection
├── Poison branch prediction unit (BTB)
├── Force speculative execution of chosen gadgets
└── Mitigation: Retpoline (return trampoline), IBRS/eIBRS microcode

Spectre-BHI (2022)
├── Branch History Injection — bypasses eIBRS
├── Affects Intel Ice Lake, Alder Lake+
└── Mitigation: BHI_DIS_S microcode, IBPB on privilege transitions
```

**CPU mitigations status check:**
```bash
# Linux — check spectre/meltdown mitigations
grep -r . /sys/devices/system/cpu/vulnerabilities/

# Example output:
# spectre_v1: Mitigation: usercopy/swapgs barriers and __user pointer sanitization
# spectre_v2: Mitigation: Enhanced / Automatic IBRS; IBPB: conditional; RSB filling
# meltdown: Not affected (or: Mitigation: PTI)
```

---

## 7. Fault Injection

### Overview
Fault injection deliberately causes hardware faults to bypass security controls, corrupt cryptographic operations, or skip instruction sequences. The goal is often to make a conditional branch (like a PIN check) evaluate incorrectly.

### Voltage Glitching
A brief undershoot or overshoot in the supply voltage can cause a CPU to execute incorrectly.

```
Attack flow:
1. Identify target operation (e.g., PIN comparison, secure boot signature check)
2. Trigger glitch at precise timing (microsecond precision required)
3. Observe effect — did the device skip the check? Boot into unlocked mode?
4. Iterate timing and glitch parameters until success
```

**Tools:**
- **ChipWhisperer**: Open-source voltage glitcher + oscilloscope combo
  ```python
  import chipwhisperer as cw

  scope = cw.scope()
  scope.glitch.clk_src = "clkgen"
  scope.glitch.output = "glitch_only"
  scope.glitch.trigger_src = "ext_single"
  scope.glitch.width = 10     # Glitch width in clock cycles
  scope.glitch.offset = 1200  # Offset from trigger

  scope.arm()
  # Trigger the target operation
  scope.glitch.arm()
  ```
- **Riscure Voltage Glitcher**: Professional tool used in labs
- **GreatFET**: Open-source multi-tool with glitching capability

**Targets:**
- Microcontrollers with Code Read Protection (CRP) — e.g., NXP LPC series
- Secure elements in payment cards
- Embedded device secure boot checks
- Hardware wallet PIN verification

### Clock Glitching
Inject a glitch in the clock signal to force the CPU to skip clock cycles.

```
Normal: [CLK: _|-|_|-|_|-|_|-] → stable instruction execution
Glitch:  [CLK: _|-|_|--|_|-|_] → extra/missing cycle → instruction skip
```

### Laser Fault Injection
- Focused laser beam directed at specific transistors on the die
- Can flip individual bits in registers or SRAM
- Requires: chip decapping (remove packaging), optical microscope, laser cutter
- Very targeted and expensive but extremely precise
- Used in academic research to attack smart cards, microcontrollers, and secure elements

### Electromagnetic Fault Injection (EMFI)
- EM pulse induces fault via electromagnetic coupling
- No need for direct electrical contact or chip decapping
- ColiBreak: open-source EMFI tool
- Less precise than laser FI but more practical

### Real-World Applications
- Extracting firmware from locked microcontrollers (MCUs with read protection)
- Bypassing secure boot on embedded Linux devices (routers, IoT)
- Extracting cryptographic keys from hardware wallets (Ledger, Trezor research)
- Bypassing PIN retry counters on secure elements
- Breaking code read protection on ARM Cortex-M devices

---

## 8. JTAG / Debug Interface Security

### JTAG Overview
JTAG (IEEE 1149.1 — Joint Test Action Group) is a hardware debug interface designed for boundary scan testing of PCBs. It has become ubiquitous for firmware debugging and is present on virtually all modern embedded systems.

**JTAG capabilities:**
- Halt/resume CPU execution
- Read/write memory, registers, and flash
- Set hardware breakpoints
- Boundary scan (test PCB connections)

### Finding JTAG on a PCB
1. Look for test pads or pin headers (often unlabeled)
2. Use JTAGulator to probe possible pins:
   ```
   JTAGulator (hardware tool by Joe Grand)
   - Connect probe to suspected test pins
   - Set target voltage (1.8V, 3.3V, 5V)
   - Run IDCODE scan: tries all pin combinations
   - Output: TDI, TDO, TCK, TMS pin assignments
   ```
3. Identify via datasheets, FCC filings, or PCB silkscreen markings

### Exploiting JTAG with OpenOCD
```bash
# Start OpenOCD with J-Link adapter and STM32 target
openocd -f interface/jlink.cfg -f target/stm32f4x.cfg

# In another terminal, connect via telnet
telnet localhost 4444

# Halt CPU
> halt

# Read register state
> reg

# Dump flash memory to file (start addr, length)
> dump_image firmware.bin 0x08000000 0x100000

# Write firmware
> flash write_image erase new_firmware.bin 0x08000000

# Read memory
> mdw 0x20000000 64   # Read 64 words from SRAM

# Set breakpoint
> bp 0x08001234 2 hw

# Resume execution
> resume

# Reset target
> reset run
```

### UART Debug Interfaces
Many embedded devices expose UART consoles that provide root shell access:
```bash
# Identify UART pins on PCB
# - Usually 3 pins: TX, RX, GND (sometimes VCC)
# - Use multimeter or logic analyzer to identify

# Connect with USB-UART adapter (e.g., CH340, FT232)
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200

# May get:
# [    0.000000] Linux version 5.10.0 ...
# ...
# root@device:/#
```

### SWD (Serial Wire Debug)
ARM Cortex processors use SWD as a 2-wire alternative to JTAG:
- **SWDIO**: Combined data in/out (bidirectional)
- **SWDCLK**: Clock
- Compatible with OpenOCD and most debug probes (J-Link, ST-Link, CMSIS-DAP)
- Often exposed as 2-pad test point on PCB

### Protecting Debug Interfaces
| Protection | Method |
|---|---|
| OTP fuses | One-time programmable bit disables JTAG permanently |
| JTAG lock | Password-protected access to JTAG |
| TrustZone gating | Secure world controls debug access |
| Debug authentication | Challenge-response before JTAG access granted |
| Physical removal | Test pads not populated in production |

---

## 9. Hardware Attacks on Cryptographic Tokens

### USB Security Keys (FIDO2 / PIV)
Modern hardware security keys like YubiKey and Feitian keys use ECDSA (P-256) for FIDO2 authentication.

**Minerva Attack (2020) — CVE-2024-45678:**
- Certain YubiKey 5 series and Infineon security library had biased ECDSA nonces
- Lattice attack on biased nonces can recover the private key
- Requires ~6,000-10,000 authentication operations observed by attacker
- Practical in scenarios where attacker can observe many authentications (MITM)

```
ECDSA signing: r,s = sign(k, m, privkey)
  where k = random nonce

If k has bias (not uniformly random):
  Collect many (r,s,m) tuples
  Set up lattice problem
  Solve with LLL/BKZ algorithm
  → Recover privkey
```

**Practical FIDO2 security note:** For most threat models, hardware keys remain extremely effective — the Minerva attack requires specific conditions and was patched.

### Smart Card Attacks
```
Non-invasive attacks (no chip modification):
├── Power analysis (SPA/DPA) during cryptographic operations
├── EM analysis — EM probe near chip during operation
├── Timing attacks on PIN verification
└── Fault injection via voltage/clock glitch

Semi-invasive attacks:
├── UV light to clear EEPROM security fuses
├── Focused ion beam (FIB) for circuit modification
└── Laser fault injection

Invasive attacks:
├── Chip delayering via acid
├── Microprobing on internal buses
└── Complete reverse engineering
```

**PIN counter bypass via fault injection:**
- Many smart cards enforce a 3-attempt limit on PIN verification
- Voltage glitch during the failed attempt counter increment → counter not updated → unlimited attempts
- Demonstrated on various banking cards and security tokens

### TPM Bus Sniffing
As noted in the TPM section, on systems where TPM communicates via unencrypted LPC or SPI bus:
- Attacker with physical access can attach logic analyzer / bus sniffer
- Intercept key material during TPM unseal operation
- Demonstrated by Seunghun Han: BitLocker VMK extraction via LPC bus sniffing on ThinkPad

Mitigation: Use BitLocker with pre-boot PIN so TPM seal requires PIN input — key never transmitted in observable form at a predictable time.

---

## 10. Supply Chain Hardware Security

### Hardware Implants
Nation-state actors have the capability to insert malicious components into the hardware supply chain:
- **Bloomberg "The Big Hack" (2018)**: Claimed Chinese intelligence inserted tiny chips on SuperMicro server motherboards. SuperMicro, Apple, and Amazon denied. Technical community remains skeptical of specific claims, but attack is theoretically possible.
- **NSA ANT Catalog (Snowden 2013)**: Documented NSA hardware implants for routers, firewalls, and hard drives — IRONCHEF, COTTONMOUTH, GINSU.
- **Cisco router interdiction**: NSA reportedly intercepted routers in shipping to install implants.

### Threat Vectors
```
Manufacturing time:
├── Counterfeit components (fake ICs with altered functionality)
├── Trojan circuits (additional logic in legitimate chip)
├── Modified firmware in flash at factory
└── Backdoored microcontrollers

Transit time:
├── Package interdiction (NSA/adversary intercepts shipment)
└── Substitution of legitimate hardware

Integration time:
├── Malicious insider installs hardware implant during integration
└── Supply of compromised spare parts
```

### Detection and Prevention
```bash
# PCB inspection
# - X-ray analysis: compare component count and placement vs. reference design
# - Optical inspection: compare against known-good board photos
# - Component authentication: verify IC markings match expected part numbers

# Firmware verification
# - Verify firmware hash against vendor-signed manifest
# - LVFS (Linux Vendor Firmware Service) for Linux firmware: fwupdmgr verify

# Supply chain standards
# - NIST SP 800-161r1: Cybersecurity Supply Chain Risk Management
# - CISA SCRM guidelines: Hardware Bill of Materials (HBOM)
# - IPC-1401: Component Authenticity
```

### Component Authentication
- **NXP EdgeLock SE050**: Crypto-authenticated secure element — can prove component authenticity to host system
- **Microchip ATECC608B**: Turnkey hardware authentication IC used in IoT devices
- **Root of trust anchoring**: Devices can verify component authenticity at boot using certificate chains

### Firmware Supply Chain
- **Secure firmware signing**: Vendor signs firmware with hardware-stored private key
- **LVFS (Linux Vendor Firmware Service)**: Linux firmware update infrastructure — vendors upload signed firmware
- **PSIRT (Product Security Incident Response Team)**: Vendor team handling firmware vulnerability disclosure
- **SBOM → HBOM**: Software Bill of Materials concept extended to Hardware Bill of Materials for component tracking

---

## 11. Physical Unclonable Functions (PUF)

### Concept
A Physical Unclonable Function exploits the inherent, random manufacturing variations of silicon to create a unique "fingerprint" for each chip. These variations (gate delay, transistor threshold voltage, SRAM cell bias) are:
- **Unique**: No two chips are identical at the physical level
- **Unclonable**: Cannot be reproduced, even by the manufacturer
- **Unpredictable**: Cannot be modeled without measuring the specific chip

### How PUFs Work
```
Enrollment phase (at factory):
1. Apply challenge C to PUF circuit
2. Measure response R (determined by physical variations)
3. Store (C, R) pair in secure database

Authentication phase:
1. Send challenge C to device
2. Device computes R from PUF circuit
3. Verify R matches enrolled value (with error correction)

Fuzzy extraction:
- PUF responses may have bit errors (temperature, aging)
- Error-correcting codes reconstruct exact response from noisy measurement
```

### PUF Types
| Type | Mechanism | Notes |
|---|---|---|
| SRAM PUF | SRAM cell power-up state (random due to transistor mismatch) | Most common, used in NXP iMX chips |
| Ring Oscillator PUF | Frequency difference between matched oscillator chains | Stable but larger area |
| Arbiter PUF | Race condition in delay lines — arbiter records winner | Compact but vulnerable to ML modeling |
| Coating PUF | Random distribution of conductive particles in coating | Physical destruction = authentication failure |
| DRAM PUF | DRAM decay patterns (retention time variation) | No dedicated hardware needed |

### Use Cases
- **Device identity**: Unique hardware fingerprint without storing a secret key
- **Key generation**: Derive cryptographic key from PUF response — key never stored, regenerated on demand
- **Anti-counterfeiting**: Chip can prove authenticity without stored secrets
- **Secure provisioning**: Factory enrolls CRPs; no key material needs to be injected

### Attacks on PUFs
- **Machine learning modeling**: Collect enough CRPs → train ML model → predict responses for unseen challenges (Arbiter PUFs vulnerable)
- **Side-channel**: EM/power analysis during PUF evaluation to extract response
- **Physical cloning** (partial): With detailed physical access and equipment, partially characterize PUF variations

---

## 12. Confidential Computing

### Goal
Confidential computing protects data **in use** — data is encrypted not just at rest and in transit, but also while being processed by the CPU. This is achieved through Trusted Execution Environments (TEEs).

### Intel SGX (Software Guard Extensions)
```
SGX Architecture:
├── Enclave: isolated region of process address space
├── EPC (Enclave Page Cache): encrypted DRAM region
├── CPU encrypts/decrypts data at memory controller
├── OS/hypervisor cannot read enclave memory
└── Remote attestation: prove enclave code to remote party

Enclave lifecycle:
ECREATE → EADD (add pages) → EINIT (initialize) → EENTER (call enclave) → EEXIT

Remote attestation flow:
1. Enclave generates quote (signed measurement)
2. Quote contains MRENCLAVE (enclave measurement hash)
3. Remote verifier checks quote against Intel Attestation Service (IAS)
4. Verifier confirms correct enclave code is running
```

**SGX Attacks:**
- **LVI (Load Value Injection, 2020)**: Inject attacker-controlled values into transient execution gadgets inside enclave
- **PLATYPUS (2020)**: Read SGX enclave memory via RAPL power interface (unprivileged power readings)
- **Foreshadow / L1TF (CVE-2018-3615)**: Read SGX enclave memory via L1 cache speculative execution
- **SGAxe (2020)**: Extract SGX attestation keys from production Intel CPUs

### Intel TDX (Trust Domain Extensions)
- Successor to SGX for VM-level isolation (where SGX is process-level)
- Entire VMs run in encrypted "Trust Domains"
- Hypervisor cannot access TD memory
- Available on 4th Gen Xeon Scalable (Sapphire Rapids) and newer

### AMD SEV (Secure Encrypted Virtualization)
```
SEV: VM memory encrypted with VM-specific AES key
    - Hypervisor sees only ciphertext
    - Keys managed by AMD Secure Processor (AMD-SP)
    - No integrity protection

SEV-ES (Encrypted State):
    - Additionally encrypts CPU register state
    - Protects against hypervisor reading register values

SEV-SNP (Secure Nested Paging):
    - Adds memory integrity protection
    - Reverse Map Table (RMP) prevents hypervisor modifying/remapping VM memory
    - Strong attestation report signed by AMD-SP
    - Deployed in: Azure CVM, AWS Nitro Enclaves (partial), GCP Confidential VMs
```

### ARM TrustZone
```
TrustZone Architecture:
├── Normal World: Linux/Android, untrusted apps
├── Secure World: Trusted OS (OP-TEE), Trusted Applications (TAs)
├── Hardware enforced: NS (Non-Secure) bit on AXI bus
└── Secure Monitor (EL3): mediates world transitions

TZASC (TrustZone Address Space Controller):
- Partitions DRAM into secure/non-secure regions
- Non-secure world cannot access secure DRAM

Common TrustZone uses:
- Android Keystore: private key operations in secure world
- Mobile payments: NFC payment credentials in TA
- DRM (Widevine L1): media decryption in secure world
- Fingerprint/biometric: matching in secure world
- Secure boot validation

Attack surface:
- OP-TEE vulnerabilities (CVE-2021-44141, multiple others)
- Trusted Application vulnerabilities (poor sandboxing)
- SMC (Secure Monitor Call) interface vulnerabilities
- Cache side-channels between worlds
```

### Confidential Computing Consortium (CCC)
Open Governance Alliance under Linux Foundation promoting confidential computing standards:
- Members: Intel, AMD, ARM, Microsoft, Google, IBM, Red Hat
- Projects: Enarx (write-once, run anywhere TEE), Gramine (library OS for SGX), Veraison (attestation service)

---

## 13. Hardware Security Tools Reference

| Tool | Purpose | Platform | Source |
|------|---------|----------|--------|
| ChipWhisperer | Side-channel analysis + fault injection | Hardware + Python | newae.com/chipwhisperer |
| CHIPSEC | UEFI/firmware security testing | Python (Windows/Linux) | github.com/chipsec/chipsec |
| JTAGulator | JTAG/UART interface discovery | Hardware (PIC32) | github.com/grandideastudio/jtagulator |
| OpenOCD | JTAG/SWD debug interface | Cross-platform | openocd.org |
| UEFITool | UEFI firmware analysis/editing | Qt GUI + CLI | github.com/LongSoft/UEFITool |
| Binwalk | Firmware extraction and analysis | Python | github.com/ReFirmLabs/binwalk |
| tpm2-tools | TPM 2.0 command-line operations | Linux | github.com/tpm2-software/tpm2-tools |
| SoftHSM2 | Software HSM for development/testing | Cross-platform | softhsm.org |
| Riscure Inspector | Professional side-channel analysis | Commercial | riscure.com |
| Ghidra (+ extensions) | Firmware reverse engineering | Java | github.com/NationalSecurityAgency/ghidra |
| ColiBreak | EM fault injection (open-source) | Hardware + Python | GitHub |
| GreatFET | Open-source hardware hacking platform | Hardware + Python | greatscottgadgets.com/greatfet |
| flashrom | SPI flash read/write/erase | Linux | flashrom.org |
| PCILeech | DMA attack via PCIe | Hardware + C | github.com/ufrisk/pcileech |
| USB Armory | Secure USB computer for security research | ARM hardware | inversepath.com |

---

## Quick Reference: Common Attack Vectors

### Attack Decision Tree
```
Physical access available?
├── YES:
│   ├── JTAG/UART exposed? → OpenOCD / screen to dump firmware
│   ├── SPI flash accessible? → flashrom to read UEFI firmware
│   ├── PCIe slot available? → PCILeech DMA attack
│   ├── TPM via LPC/SPI? → Bus sniff to capture key material
│   └── Time unlimited? → Decap chip → laser fault injection
└── NO (remote/software):
    ├── UEFI vulnerability? → Exploit for persistent implant
    ├── Spectre/Meltdown? → Cross-privilege memory read
    ├── Side-channel (timing)? → Timing attack on crypto
    └── Hypervisor escape? → Break TEE isolation
```

### Key Standards and References
| Standard | Organization | Topic |
|---|---|---|
| TCG TPM 2.0 Specification | Trusted Computing Group | TPM architecture and commands |
| FIPS 140-3 | NIST | HSM security requirements |
| IEEE 1149.1 | IEEE | JTAG standard |
| NIST SP 800-193 | NIST | Platform Firmware Resiliency |
| NIST SP 800-155 | NIST | BIOS Integrity Measurement Guidelines |
| NIST SP 800-161r1 | NIST | Supply Chain Risk Management |
| UEFI Specification v2.10 | UEFI Forum | UEFI firmware interface |
| ISO/IEC 19790 | ISO | Security requirements for crypto modules |

---

*Hardware Security Reference — TeamStarWolf Cybersecurity Library*
*Last updated: 2026-04-26*
