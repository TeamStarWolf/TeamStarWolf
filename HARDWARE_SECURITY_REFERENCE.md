# Hardware Security Reference

> **In one minute** — This is the practitioner's field manual for the security that lives below the operating system: the chips, boot firmware, and debug ports that decide whether a machine can be trusted at all. It walks through TPMs and HSMs (dedicated crypto chips that guard keys), Secure Boot and UEFI, the side-channel and fault-injection attacks that pull secrets out of silicon, JTAG/debug-port access, and confidential-computing enclaves. Reach for it when the threat model includes someone who can touch the hardware, tamper with the boot chain, or measure a chip's power and timing.

| | |
|---|---|
| **Read this when** | hardening a device's boot chain or disk encryption, standing up or auditing an HSM and its key ceremony, assessing side-channel, fault-injection, or debug-port exposure on embedded hardware |
| **Start at** | [TPM 2.0 Deep Dive](#_1-tpm-20-deep-dive), [HSM & FIPS 140-3](#_2-hsm-amp-fips-140-3), [Hardware Security Testing Tools](#_9-hardware-security-testing-tools) |
| **Pairs with** | [FIRMWARE_IOT_SECURITY_REFERENCE.md](FIRMWARE_IOT_SECURITY_REFERENCE.md), [CRYPTOGRAPHY_REFERENCE.md](CRYPTOGRAPHY_REFERENCE.md), [PHYSICAL_SECURITY_REFERENCE.md](PHYSICAL_SECURITY_REFERENCE.md), [REVERSE_ENGINEERING_REFERENCE.md](REVERSE_ENGINEERING_REFERENCE.md) |

## 1. TPM 2.0 Deep Dive

### Architecture Overview

The Trusted Platform Module (TPM) 2.0 is a hardware-based security coprocessor defined by TCG (Trusted Computing Group) specification. Unlike TPM 1.2, TPM 2.0 supports multiple cryptographic algorithms simultaneously, uses a hierarchical key structure, and provides more flexible policy-based authorization.

**Key Components:**
- **Platform Hierarchy** – Used during manufacturing; primary seeds change at provisioning
- **Storage Hierarchy** – Persistent storage for user keys (SRK = Storage Root Key)
- **Endorsement Hierarchy** – Privacy-sensitive; contains the EK (Endorsement Key) used for attestation
- **Null Hierarchy** – Ephemeral; cleared on every boot

### PCR Banks

Platform Configuration Registers (PCRs) are hash accumulators. TPM 2.0 maintains multiple PCR banks (SHA-1, SHA-256, SHA-384, SHA-512). Each bank has 24 registers (PCR[0]-PCR[23]).

**Standard PCR Allocation (UEFI):**
| PCR | Content |
|-----|---------|
| 0   | SRTM, BIOS, Host Platform Extensions |
| 1   | Host Platform Config (BIOS config data) |
| 2   | Option ROM Code |
| 3   | Option ROM Config & Data |
| 4   | IPL Code (MBR/GPT, bootloader) |
| 5   | IPL Config Data (partition tables) |
| 6   | State Transitions & Wake Events |
| 7   | Secure Boot Policy (PK/KEK/db/dbx/mode) |
| 8-9 | Used by OS/Bootloader (GRUB2 uses 8,9) |
| 10  | MeasureBoot (IMA on Linux) |
| 11-13 | Reserved for OS |
| 14  | MOK (Machine Owner Key) |

**PCR Extension Mechanics:**
```
PCR[n] = H(PCR[n] || new_value)
```
A PCR starts at all-zeros and is extended by hashing the concatenation of the current value with the measurement. This makes PCR values a running hash chain — you cannot remove a measurement, only accumulate.

### Key Hierarchy

```
Platform Hierarchy
  └── Platform Primary Key (PPK) → platform-specific

Storage Hierarchy (most common)
  └── Storage Root Key (SRK) → typically RSA-2048 or ECC-P256
        ├── Sealing Keys (bind data to PCR state)
        ├── Signing Keys
        └── Child CAs

Endorsement Hierarchy
  └── Endorsement Key (EK) → burned in at manufacture
        └── AK (Attestation Key) derived from EK
```

### tpm2-tools Command Reference

```bash
# List all PCR values (SHA-256 bank)
tpm2_pcrread sha256

# Read specific PCRs
tpm2_pcrread sha256:0,1,2,7

# Create a primary key in storage hierarchy
tpm2_createprimary -C o -g sha256 -G rsa2048 -c primary.ctx

# Create an RSA signing child key
tpm2_create -C primary.ctx -g sha256 -G rsa2048   -u sign.pub -r sign.priv

# Load key
tpm2_load -C primary.ctx -u sign.pub -r sign.priv -c sign.ctx

# Sign data
echo "data" | tpm2_sign -c sign.ctx -g sha256 -o sig.rsa -

# Quote PCRs (remote attestation step 1)
tpm2_quote -c ak.ctx -l sha256:0,1,2,7   -q $(openssl rand -hex 20)   -m quote.msg -s quote.sig -o pcrs.out -g sha256

# Verify quote (on verifier side)
tpm2_checkquote -u ak.pub -m quote.msg -s quote.sig   -f pcrs.out -g sha256 -q <nonce>

# Seal a secret to PCR state (PCR 7 = secure boot policy)
tpm2_create -C primary.ctx -g sha256 -G keyedhash   -i secret.txt -u seal.pub -r seal.priv   -L "sha256:7"

# Unseal
tpm2_load -C primary.ctx -u seal.pub -r seal.priv -c seal.ctx
tpm2_unseal -c seal.ctx

# NV storage write/read (e.g., store a 32-byte secret at index 0x1500016)
tpm2_nvdefine 0x1500016 -C o -s 32 -a "ownerread|ownerwrite"
echo -n "my32bytesecretmy32bytesecretXXXX" | tpm2_nvwrite 0x1500016 -C o -i -
tpm2_nvread 0x1500016 -C o

# Get EK certificate chain
tpm2_getekcertificate -o ek_cert.pem

# Create Attestation Key bound to EK
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_createak -C ek.ctx -c ak.ctx -G rsa -g sha256 -s rsassa   -u ak.pub -r ak.priv
```

### Measured Boot

Measured Boot extends each stage of the boot chain into TPM PCRs before executing the next stage:

```
CRTM (Core Root of Trust for Measurement)
  → extends PCR[0] with BIOS firmware hash
  → extends PCR[2] with option ROM hashes
  → extends PCR[4] with bootloader hash (shim/GRUB)
  → GRUB2 extends PCR[8] with grub.cfg
  → GRUB2 extends PCR[9] with kernel cmdline
  → Linux kernel extends PCR[10] via IMA
```

**IMA (Integrity Measurement Architecture) setup:**
```bash
# /etc/kernel/cmdline
ima_policy=tcb ima_template=ima-ng ima_hash=sha256

# View IMA measurement log
cat /sys/kernel/security/integrity/ima/ascii_runtime_measurements
```

### Remote Attestation Protocol

```
Device (Prover)                    Attestation Service (Verifier)
     |                                          |
     |<------ nonce (challenge) ----------------|
     |                                          |
     | tpm2_quote with nonce                    |
     |------ {quote_msg, quote_sig, pcrs} ----->|
     |                                          |
     | (separately enroll EK cert)              |
     |------ EK cert chain -------------------->|
     |                                          |
     |                   verify sig with AK pub |
     |                   verify AK bound to EK  |
     |                   verify PCR values      |
     |<------ attestation result ---------------|
```

### BitLocker TPM Binding

BitLocker seals the VMK (Volume Master Key) to PCR values. Default profile: PCRs 0, 2, 4, 11.

```powershell
# Enable BitLocker with TPM only (PCRs 0,2,4,11)
Enable-BitLocker -MountPoint "C:" -TpmProtector

# Check PCR binding
manage-bde -protectors -get C:

# Change PCR profile (e.g., add PCR 7 for Secure Boot)
manage-bde -protectors -delete C: -Type TPM
Enable-BitLocker -MountPoint "C:" -TpmAndPinProtector -Pin $pin

# Or via registry
HKLM\SOFTWARE\Policies\Microsoft\FVE
  PlatformValidationProfile DWORD = 0x87 (PCRs 0,1,2,7)
```

### LUKS2 + TPM Binding via systemd-cryptenroll

```bash
# Enroll TPM2 device into LUKS2 slot, bind to PCRs 0,7
systemd-cryptenroll --tpm2-device=auto   --tpm2-pcrs=0+7 /dev/sda2

# Optionally require PIN as well
systemd-cryptenroll --tpm2-device=auto   --tpm2-pcrs=0+7 --tpm2-with-pin=yes /dev/sda2

# View enrolled slots
cryptsetup luksDump /dev/sda2

# Remove TPM slot
systemd-cryptenroll --wipe-slot=tpm2 /dev/sda2

# /etc/crypttab entry for auto-unlock
luks-<uuid> UUID=<uuid> - tpm2-device=auto,tpm2-pcrs=0+7
```

### SSH Keys Stored in TPM

```bash
# Using tpm2-pkcs11 and ssh-agent
# Initialize token
tpm2_ptool init
tpm2_ptool addtoken --pid=1 --sopin=mysopin --userpin=myuserpin --label=ssh

# Create RSA key
tpm2_ptool addkey --label=ssh --userpin=myuserpin --algorithm=rsa2048

# List objects
tpm2_ptool listobjects --label=ssh

# Use with OpenSSH via PKCS#11
ssh-add -s /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so
ssh -I /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so user@host
```

## 2. HSM & FIPS 140-3

### HSM Architecture

Hardware Security Modules are tamper-resistant cryptographic processors that protect key material. They provide:
- **Key Generation** inside tamper boundary (keys never leave in plaintext)
- **Cryptographic Operations** (sign, decrypt, derive) performed inside HSM
- **Tamper Detection/Response** (zeroize keys on physical attack)
- **Audit Logging** (cryptographically signed event logs)

**Physical Security Layers:**
1. Epoxy encapsulation of die
2. Active mesh (detects probing)
3. Environmental sensors (voltage, temperature, light)
4. Zeroization circuits (FRAM/SRAM clear on tamper)

### FIPS 140-3 Security Levels

FIPS 140-3 (aligned with ISO/IEC 19790:2012) defines four security levels:

| Level | Physical Requirements | Use Case |
|-------|----------------------|----------|
| **1** | Production-grade components, no physical security | Software HSM, cloud VM |
| **2** | Tamper-evident coatings/seals, role-based auth | Enterprise HSM, USB tokens |
| **3** | Tamper-resistant, identity-based auth, zeroize on tamper | Network HSM, payment terminals |
| **4** | Complete physical envelope, environmental attack protection | Military, air-gapped PKI |

**FIPS 140-3 vs 140-2 Key Differences:**
- 140-3 uses ISO/IEC 19790 + 24759 as base standards
- Adds Software/Firmware security requirements
- Non-invasive attack resistance (side-channel) at Level 3+
- Lifecycle assurance improvements
- Conditional algorithm testing on startup

### Vendor Comparison

**Thales Luna Network HSM (formerly SafeNet)**
```
Models: Luna 7 (FIPS 140-3 L3), Luna 7 PCIe (L3), Luna Cloud (SaaS)
Throughput: 10,000–20,000 RSA-2048 ops/sec
Partitions: up to 20 per appliance
Key capacity: 1M+ keys
HA: Active-active clustering, automatic failover
Client: Luna Client software, PKCS#11, JCE, CNG
```

**Entrust nShield (formerly Thales e-Security)**
```
Models: nShield Connect XC (FIPS 140-3 L3), nShield Solo PCIe
Security World: proprietary cluster key management
Throughput: 7,000 RSA-2048 ops/sec (Connect XC Base)
Unique: CodeSafe (run app code inside HSM boundary)
OCS: Operator Card Set for key recovery
```

**AWS CloudHSM**
```
Hardware: Cavium Nitrox (FIPS 140-2 L3 certified)
Access: PKCS#11, JCE, OpenSSL Dynamic Engine
Pricing: ~$1.45/hr per HSM
Clustering: Multi-AZ, client-side load balancing
Limitation: You manage keys; AWS has no access
Backup: Encrypted cluster backup to S3
```

**Azure Dedicated HSM**
```
Hardware: Thales Luna Network HSM 7 (FIPS 140-2 L3)
Model: Customer-managed, single-tenant
SLA: 99.9% availability
Networking: Injected into customer VNet
```

**Azure Managed HSM**
```
FIPS 140-2 L3, HSM-protected key vault
Backed by Marvell LiquidSecurity HSMs
Role-based access (RBAC)
Key: az keyvault key create --hsm-name <name> --kty RSA-HSM
```

**YubiHSM 2** (low-cost, developer-friendly)
```
FIPS 140-2 L3, USB-A form factor
2M key operations/sec (AES-128)
Max 127 key objects per device
API: PKCS#11, yubihsm-shell, REST via connector
Use case: Dev/test, edge, embedded signing
```

### PKCS#11 API Essentials

```c
// Initialize and get function list
CK_FUNCTION_LIST_PTR pFunctionList;
C_GetFunctionList(&pFunctionList);
pFunctionList->C_Initialize(NULL);

// Open session
CK_SLOT_ID slotId = 0;
CK_SESSION_HANDLE hSession;
pFunctionList->C_OpenSession(slotId,
    CKF_SERIAL_SESSION | CKF_RW_SESSION,
    NULL, NULL, &hSession);

// Login as user
pFunctionList->C_Login(hSession, CKU_USER,
    (CK_UTF8CHAR_PTR)"userpin", 7);

// Generate RSA-2048 key pair
CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
CK_ULONG modulus = 2048;
CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
CK_ATTRIBUTE pubTemplate[] = {
    {CKA_MODULUS_BITS, &modulus, sizeof(modulus)},
    {CKA_TOKEN, &yes, sizeof(yes)},
    {CKA_VERIFY, &yes, sizeof(yes)},
};
CK_ATTRIBUTE privTemplate[] = {
    {CKA_TOKEN, &yes, sizeof(yes)},
    {CKA_PRIVATE, &yes, sizeof(yes)},
    {CKA_SENSITIVE, &yes, sizeof(yes)},
    {CKA_EXTRACTABLE, &no, sizeof(no)},  // Key never leaves HSM
    {CKA_SIGN, &yes, sizeof(yes)},
};
CK_OBJECT_HANDLE hPub, hPriv;
pFunctionList->C_GenerateKeyPair(hSession, &mech,
    pubTemplate, 3, privTemplate, 5, &hPub, &hPriv);
```

```bash
# p11tool (GnuTLS) - list HSM objects
p11tool --provider /usr/lib/libCryptoki2.so --list-all

# pkcs11-tool (OpenSC)
pkcs11-tool --module /usr/lib/libCryptoki2.so --list-objects
pkcs11-tool --module /usr/lib/libCryptoki2.so --keypairgen   --key-type rsa:2048 --label "my-key" --login

# OpenSSL with PKCS#11 engine
openssl req -engine pkcs11 -keyform engine   -key "pkcs11:object=my-key;type=private"   -new -out csr.pem -subj "/CN=test"
```

### Key Ceremony Procedure

A key ceremony is the formal, audited process of generating and distributing a high-value key (e.g., Root CA key):

```
Pre-ceremony:
1. Schedule witnesses (auditors, security officers)
2. Verify HSM firmware integrity (check hash against vendor manifest)
3. Initialize Key Custodian smart cards (M-of-N scheme, e.g., 3-of-5)
4. Prepare air-gapped ceremony room (Faraday cage, no cameras)

During ceremony:
1. All participants sign attendance log
2. HSM factory-reset and re-initialized on camera
3. Generate Root CA key inside HSM (CKA_EXTRACTABLE=FALSE)
4. Export key backup shares to custodian cards (Shamir Secret Sharing)
5. Issue self-signed Root CA cert
6. Sign Intermediate CA CSR
7. Verify certificate chain
8. Seal HSM with tamper-evident tape (numbered seals, log serial numbers)

Post-ceremony:
1. Distribute custodian cards to separate custodians
2. Store cards in geographically distributed safes
3. Document procedure hash and witness signatures
4. Schedule quarterly HSM health checks
```

### HSM High Availability & Clustering

**Thales Luna HA:**
```bash
# On primary HSM
lunash:> ha register -haLabel MyHA -serialNum <hsm2-serial>   -passwd <partition-password>

# Client-side HA config
vi /etc/Chrystoki.conf
[HAConfiguration]
  HAAutoRecover=1
  HARecoveryPollInterval=60

# Test HA failover
lunacm:> ha synchronize
lunacm:> ha listmembers
```

**AWS CloudHSM Cluster:**
```bash
# Initialize cluster with first HSM
aws cloudhsmv2 initialize-cluster --cluster-id <id>   --signed-cert file://customerCA.crt   --trust-anchor file://customerCA.crt

# Add second HSM (different AZ)
aws cloudhsmv2 create-hsm --cluster-id <id>   --availability-zone us-east-1b

# CloudHSM client connects to both automatically
/opt/cloudhsm/bin/cloudhsm_mgmt_util /opt/cloudhsm/etc/cloudhsm_mgmt_util.cfg
```

### Common HSM Misconfigurations

| Misconfig | Risk | Remediation |
|-----------|------|-------------|
| Default SO/User PIN unchanged | Full key compromise | Change PINs at deployment |
| CKA_EXTRACTABLE=TRUE on sensitive keys | Key exfiltration | Audit key attributes; regenerate |
| No audit log monitoring | Undetected misuse | SIEM integration for HSM logs |
| Single HSM, no HA | Single point of failure | Deploy 2+ HSMs in different racks/AZs |
| Missing FIPS mode enforcement | Weak algorithms permitted | Enable FIPS mode in HSM config |
| Overly broad PKCS#11 permissions | Privilege escalation | Least-privilege partition assignment |
| Network HSM on flat network | Lateral movement risk | Dedicated VLAN, firewall rules |

## 3. Secure Boot & UEFI Security

### UEFI Secure Boot Chain

Secure Boot validates each component in the boot chain using a public key infrastructure stored in NVRAM:

```
PK  (Platform Key)      — One key; controls KEK updates; OEM-held
 └── KEK (Key Exchange Key) — Signs db/dbx updates; OEM + Microsoft
       ├── db  (Signature Database) — Allowed cert/hash whitelist
       └── dbx (Forbidden Signature Database) — Revocation list
```

**Secure Boot Verification Flow:**
```
Power On
  → UEFI Firmware (verified by ROM/fuse)
    → Check EFI binary signature against db
    → Check EFI binary hash NOT in dbx
    → Load shim.efi (signed by Microsoft CA)
      → shim verifies grubx64.efi against MOK + db
        → GRUB2 verifies kernel against GPG key
          → Kernel verifies modules (CONFIG_MODULE_SIG=y)
```

### Key Database Management

```bash
# Export current Secure Boot keys from Linux
efi-readvar -v PK -o PK.esl
efi-readvar -v KEK -o KEK.esl
efi-readvar -v db -o db.esl
efi-readvar -v dbx -o dbx.esl

# Generate new PK (self-signed for custom setup)
openssl req -newkey rsa:4096 -nodes -keyout PK.key   -new -x509 -sha256 -days 3650 -subj "/CN=Platform Key/" -out PK.crt
cert-to-efi-sig-list -g $(uuidgen) PK.crt PK.esl
sign-efi-sig-list -k PK.key -c PK.crt PK PK.esl PK.auth

# Generate KEK
openssl req -newkey rsa:4096 -nodes -keyout KEK.key   -new -x509 -sha256 -days 3650 -subj "/CN=Key Exchange Key/" -out KEK.crt
cert-to-efi-sig-list -g $(uuidgen) KEK.crt KEK.esl
sign-efi-sig-list -k PK.key -c PK.crt KEK KEK.esl KEK.auth

# Generate db signing key
openssl req -newkey rsa:4096 -nodes -keyout db.key   -new -x509 -sha256 -days 3650 -subj "/CN=DB Signing Key/" -out db.crt
cert-to-efi-sig-list -g $(uuidgen) db.crt db.esl
sign-efi-sig-list -k KEK.key -c KEK.crt db db.esl db.auth

# Enroll in UEFI (requires Setup mode)
efi-updatevar -e -f db.esl db
efi-updatevar -e -f KEK.esl KEK
efi-updatevar -f PK.auth PK  # Exits Setup mode

# Sign EFI binary with db key
sbsign --key db.key --cert db.crt --output grubx64.efi.signed grubx64.efi
sbverify --cert db.crt grubx64.efi.signed
```

### MOK (Machine Owner Key) for Linux

Used by shim to allow distributions to verify their own bootloaders without being signed by Microsoft:

```bash
# Enroll MOK
openssl req -newkey rsa:4096 -nodes -keyout MOK.key   -new -x509 -sha256 -days 3650 -subj "/CN=MOK/" -out MOK.crt
mokutil --import MOK.crt  # Requires reboot + MokManager password

# List enrolled MOKs
mokutil --list-enrolled

# Sign kernel module
/usr/src/linux-headers-$(uname -r)/scripts/sign-file   sha256 MOK.key MOK.crt mymodule.ko

# Check module signature
modinfo mymodule.ko | grep sig
```

### Notable Secure Boot Bypasses

**CVE-2020-10713 — BootHole (GRUB2)**
- Severity: CVSS 8.2
- Root Cause: Buffer overflow in GRUB2's config file parser (`grub.cfg`)
- Impact: Arbitrary code execution in bootloader context, bypass Secure Boot
- Vector: Attacker with root access can modify grub.cfg on EFI partition
- Fix: Updated shim with revocation of vulnerable GRUB2 binaries; massive dbx update
- Affected: All distros using GRUB2 + shim prior to 2020-07-29 patch
- Detection: `sbverify` against updated db/dbx; check GRUB2 version ≥ 2.06

**CVE-2023-21894 — BlackLotus UEFI Bootkit**
- Severity: CVSS 6.7 (requires physical or admin access)
- Root Cause: Exploited CVE-2022-21894 (Secure Boot bypass via Windows Boot Manager)
- Impact: First in-the-wild UEFI bootkit bypassing Secure Boot on fully-patched Win11
- Technique: Installs vulnerable signed bootmgr, then boots into malicious UEFI app
- Persistence: Writes to EFI System Partition, survives OS reinstall
- Detection: Check for suspicious files in \EFI\Microsoft\Boot\; unusual MokList entries
- Fix: KB5025885 — revocation via dbx; enable Secure Boot CVE-2023-21894 mitigation
- Indicators: `bootmgr.efi` with hash matching revoked list, unexpected SbPolicy changes

**CVE-2022-21894 — "Baton Drop"**
- Allows enrolling attacker-controlled Secure Boot policy
- Affects Windows boot manager versions before Jan 2022 patch
- BlackLotus uses this to downgrade to vulnerable bootmgr

### UEFITool Analysis

```bash
# Extract UEFI firmware for analysis
# Dump firmware from SPI flash (physical access required)
flashrom -p internal -r firmware.rom

# Or from running Linux
cat /sys/firmware/efi/efivars/SecureBoot-* | xxd

# UEFITool (GUI or NE CLI)
./UEFIExtract firmware.rom all  # Extract all volumes

# Search for suspicious modules
./UEFIFind firmware.rom body text "backdoor_string"

# Check for known malicious GUIDs
# Malicious UEFI implants often use GUIDs from legitimate modules

# binwalk firmware analysis
binwalk -e firmware.rom
binwalk --signature firmware.rom
```

### DRTM — Dynamic Root of Trust for Measurement

Unlike SRTM (Static, starts at power-on), DRTM establishes a new trust chain at runtime:

```
Intel TXT (Trusted Execution Technology):
  SENTER instruction → CPU micro-code measures SINIT ACM
  SINIT ACM measures MLE (Measured Launch Environment)
  MLE extends PCR[17] (DRTM measurement), PCR[18] (config)
  Starts TXT measured environment independent of BIOS state

AMD SKINIT:
  SKINIT instruction → CPU atomically measures SLB (Secure Loader Block)
  No BIOS involvement in measurement chain
  PSP (Platform Security Processor) validates

DRTM Tools:
  tboot (Intel TXT bootloader)
  txt-stat (verify TXT launch)
  txt-test (pre-launch TXT validation)
```

### UEFI Hardening Checklist

```
Firmware Security:
  [x] Enable Secure Boot in "deployed mode" (not Setup mode)
  [x] Set PK to OEM or custom key; do NOT use default OEM PK for prod
  [x] Set strong UEFI admin password
  [x] Disable legacy (CSM) boot
  [x] Update dbx with latest revocations (UEFI Revocation List File from uefi.org)
  [x] Disable unused boot devices (PXE, USB, optical)
  [x] Enable Intel Boot Guard (ACM-based firmware verification)
  [x] Enable AMD Platform Secure Boot (PSB)
  [x] Configure TCG measured boot with TPM PCRs
  [x] Enable SMM (System Management Mode) protections (TSEG lock, SMM_PROT)

Runtime Security:
  [x] Kernel lockdown mode enabled (restricts /dev/mem, kexec, etc.)
  [x] CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y
  [x] IMA/EVM enabled with TPM backing
  [x] dm-verity on read-only root filesystem
  [x] Module signing enforced (CONFIG_MODULE_SIG_FORCE=y)
```

## 4. Side-Channel Attacks

### Spectre & Meltdown Variants

**Meltdown (CVE-2017-5754) — Rogue Data Cache Load**
- Mechanism: Out-of-order execution reads kernel memory into CPU cache before privilege check completes; Flush+Reload leaks cached value
- Affected: Intel (primarily); some ARM; not AMD
- Mitigation: KPTI (Kernel Page Table Isolation) — separates kernel/user page tables
```bash
# Check KPTI status
cat /sys/devices/system/cpu/vulnerabilities/meltdown
# "Mitigation: PTI" = patched
# Verify kernel boot: grep pti /proc/cmdline (nopti disables it)
```

**Spectre v1 (CVE-2017-5753) — Bounds Check Bypass**
- Mechanism: Speculative execution bypasses array bounds check; side-channel leaks
- Mitigation: Compiler retpoline (`__builtin_load_no_speculate`); lfence barriers
```c
// Spectre v1 safe array access pattern
if (index < array1_size) {
    // lfence prevents speculative access past this point
    __asm__ volatile("lfence" ::: "memory");
    value = array2[array1[index] * 512];
}
```

**Spectre v2 (CVE-2017-5715) — Branch Target Injection**
- Mechanism: Poison indirect branch predictor to redirect speculative execution
- Mitigation: Retpoline (thunk-based indirect call replacement); microcode IBRS/IBPB/STIBP

```bash
# Check Spectre v2 mitigation
cat /sys/devices/system/cpu/vulnerabilities/spectre_v2
# Ideal: "Mitigation: Enhanced IBRS, IBPB: conditional, RSB filling"

# Kernel parameters
spectre_v2=retpoline   # Software mitigation
spectre_v2=ibrs        # Hardware IBRS (slower)
```

**Spectre v4 (CVE-2018-3639) — Speculative Store Bypass**
```bash
cat /sys/devices/system/cpu/vulnerabilities/spec_store_bypass
# "Mitigation: Speculative Store Bypass disabled via prctl"
# Per-process mitigation:
prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0);
```

**MDS Attacks (Microarchitectural Data Sampling):**
- RIDL (CVE-2018-12127): Leak from Line Fill Buffers
- Fallout (CVE-2018-12126): Leak from Store Buffers
- ZombieLoad (CVE-2018-12130): Leak from Fill Buffers
```bash
# Check MDS
cat /sys/devices/system/cpu/vulnerabilities/mds
# Mitigation: Clear CPU buffers; SMT vulnerable
# Disable SMT for full mitigation: nosmt in cmdline (30-40% perf hit)
```

### Cache-Based Attacks

**Flush+Reload:**
```
1. Attacker flushes target cache line (clflush)
2. Victim accesses secret-dependent memory address
3. Attacker reloads — fast = cached (victim accessed it), slow = not cached
4. Threshold: ~200 cycles = cached; >300 cycles = not cached (LLC miss)
```

**Prime+Probe:**
```
1. Attacker "primes" cache sets by filling with own data
2. Victim runs and accesses its data, evicting attacker's data
3. Attacker "probes" — measures which sets were evicted
4. Infers victim's memory access pattern without shared memory
```

**Rowhammer (CVE-2014-3122, CVE-2015-0573):**
```c
// Classic rowhammer loop
void hammer(volatile uint64_t *addr1, volatile uint64_t *addr2) {
    for (int i = 0; i < 1000000; i++) {
        *addr1;
        *addr2;
        __asm__ volatile("clflush (%0)" :: "r"(addr1));
        __asm__ volatile("clflush (%0)" :: "r"(addr2));
        __asm__ volatile("mfence");
    }
}
// Rapidly accessing two rows causes bit flips in adjacent DRAM row
// Exploited for privilege escalation: flip bit in page table entry
```

**Rowhammer Defenses:**
- Target Row Refresh (TRR) — vendor-specific, bypassable
- ECC memory (corrects 1-bit errors, detects 2-bit)
- LPDDR4X with higher refresh rate
- Guard rows in memory allocators
- Google's rowhammer.py test utility

### Power Analysis Against AES

**Simple Power Analysis (SPA):**
Direct visual inspection of power trace to identify operations

**Differential Power Analysis (DPA) — Kocher et al. 1999:**
```python
# DPA attack skeleton against AES first round
import numpy as np

def aes_sbox(x):
    return SBOX[x]

def hypothetical_power(plaintext_byte, key_guess):
    # Hamming weight of S-Box output models power consumption
    intermediate = aes_sbox(plaintext_byte ^ key_guess)
    return bin(intermediate).count('1')

# For each key guess (0-255)
for kg in range(256):
    # Compute hypothetical power for each trace
    hyp = [hypothetical_power(pt[i], kg) for i, pt in enumerate(traces)]
    # Correlate with actual power at each time sample
    corr = np.corrcoef(hyp, traces_matrix)[0, 1:]
    # Highest correlation peak = correct key byte
```

**ChipWhisperer Toolchain:**
```python
# ChipWhisperer-Lite AES capture
import chipwhisperer as cw

scope = cw.scope()
target = cw.target(scope)
scope.default_setup()

# Configure trigger
scope.adc.samples = 5000
scope.adc.offset = 0

# Capture traces
traces = []
for i in range(1000):
    pt = cw.bytearray(16)  # random plaintext
    cw.capture_trace(scope, target, pt)
    traces.append(scope.get_last_trace())

# Run CPA
import chipwhisperer.analyzer as cwa
attack = cwa.cpa()
results = attack.run(project)
print(results.find_maximums())
```

### Timing Attacks on RSA

**Kocher's Timing Attack on RSA (1996):**
- Square-and-multiply exponentiation leaks bit pattern of private exponent via timing
- Longer time = multiply operation (bit=1); shorter = just square (bit=0)

**Countermeasures:**
```c
// RSA blinding (OpenSSL's approach)
// Before: m' = m * r^e mod n  (r = random blinding factor)
// Compute: s' = (m')^d mod n  (timing doesn't reveal d)
// After: s = s' * r^(-1) mod n

// Constant-time comparison (critical for MAC verification)
int constant_time_memcmp(const void *a, const void *b, size_t len) {
    const uint8_t *x = a, *y = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= x[i] ^ y[i];  // No early exit
    return diff;  // 0 = equal
}
```

### T-Table AES Cache Timing

Classic AES implementations use 4KB lookup tables. Access pattern leaks key via cache timing:

```
AES T-table attack:
1. Observe which cache lines are accessed during encryption
2. T-table index = plaintext_byte XOR key_byte (mod 256)
3. Multiple encryptions with known plaintext reveal key bytes
```

**Countermeasure:** Bit-sliced AES (no table lookups; processes 128 blocks in parallel using bitwise ops):
```c
// AES-NI hardware instruction (cache-timing immune)
#include <wmmintrin.h>
__m128i aes_encrypt(__m128i plaintext, __m128i key) {
    __m128i r = _mm_xor_si128(plaintext, key);
    r = _mm_aesenc_si128(r, round_keys[1]);
    // ... 9 more rounds
    return _mm_aesenclast_si128(r, round_keys[10]);
}
```

### Acoustic Cryptanalysis

Genkin et al. (2014) extracted 4096-bit RSA keys from laptop sounds:
- GnuPG's RSA square-and-multiply emits acoustic signatures
- Microphone placed near laptop or phone call recording sufficient
- **Countermeasure:** GnuPG 2.1+ uses blinding by default; constant-time exponentiation

### EM Analysis

```
Electromagnetic leakage from:
  - CPU execution (each instruction type has distinct EM signature)
  - Memory bus activity
  - Power regulator switching

Tools:
  - Near-field EM probes (HydraBus + RF probe)
  - Software-defined radio (RTL-SDR, HackRF)
  - Langer RF-U 5-2 near-field probe set

Countermeasures:
  - Faraday shielding
  - Ground planes in PCB design
  - Randomized execution timing (jitter injection)
  - Decoupling capacitors on power lines
```

## 5. Fault Injection & Physical Attacks

### Voltage Fault Injection

Voltage glitching introduces brief power supply disturbances to cause CPU/MCU to skip instructions, mis-execute conditionals, or corrupt registers.

**Attack Mechanism:**
```
Normal: VCC = 3.3V stable
Glitch:  VCC drops to 0V for 50-200ns
Effect:  CPU misses memory read, skips instruction, or reads wrong value
Target:  Security checks, CRC verifications, loop counters, key derivations
```

**ChipWhisperer Glitch Parameters:**
```python
import chipwhisperer as cw

scope = cw.scope(cw.scopes.OpenADC)
scope.glitch.clk_src = 'clkgen'
scope.glitch.output = 'enable_only'
scope.glitch.trigger_src = 'ext_single'

# Voltage glitch parameters
scope.glitch.width = 10    # Glitch width in ns (10-1000ns typical)
scope.glitch.offset = 0    # Offset from trigger (samples)
scope.glitch.repeat = 1    # Number of glitches

# Power glitcher setup (CW308 UFO board)
scope.glitch.output = 'glitch_only'
scope.io.glitch_lp = True  # Low-power MOSFET glitch

# Parameter sweep
for width in range(5, 50):
    for offset in range(-100, 100):
        scope.glitch.width = width
        scope.glitch.offset = offset
        result = target_reset_and_try()
        if result == GLITCH_SUCCESS:
            print(f"Success: width={width}, offset={offset}")
```

### Clock Glitching

Instead of manipulating voltage, inject extra clock edges or stretches:

```python
# ChipWhisperer clock glitch
scope.glitch.clk_src = 'clkgen'
scope.glitch.output = 'clock_xor'  # XOR extra pulse into clock

# Effect: Double-clock cycle causes two instruction fetches
# CPU may execute same instruction twice, or skip next instruction

# ARM Cortex-M0 clock glitch to bypass CRP check
# Target: LPC1343 secure boot CRP bit check at 0x02FC
scope.glitch.width = 8
scope.glitch.offset = 1234  # Tuned to align with CRP read instruction
```

### Laser/EMFI Fault Injection

**Laser Fault Injection:**
- Focused laser beam induces transient faults in transistors
- Requires decapping (removing IC package)
- Precision: Can target single transistors on 28nm process
- Cost: $50,000–$500,000 for precision laser station

```
Procedure:
1. Decap chip (fuming nitric acid or plasma etching for plastic; mechanical for ceramic)
2. Map die using optical microscope or SEM
3. Align laser to target gate (e.g., security fuse latch, CRC logic)
4. Fire 532nm green or 1064nm IR laser
5. Observe fault effect (UART output, debug port response)
```

**EMFI (Electromagnetic Fault Injection):**
- Near-field EM pulse coil placed near chip
- Induces current in die without decapping
- Less precise than laser but non-invasive (no decap needed)

```python
# Riscure EM-FI Transient Probe (or DIY: ChipSHOUTER)
# ChipSHOUTER setup
import chipshout

cs = chipshout.ChipSHOUTER('/dev/ttyUSB0')
cs.voltage = 150    # Pulse voltage (V)
cs.pulse_length = 80  # Pulse length (ns)

# XYZ table sweep
for x in range(0, 100, 5):    # mm
    for y in range(0, 100, 5):
        cs.armed = True
        trigger_device()
        cs.pulse()
        result = read_uart()
        if is_fault(result):
            print(f"EMFI fault at x={x}, y={y}")
```

### ChipWhisperer Hardware Comparison

| Model | Glitch Type | ADC | Max Sample Rate | Best For |
|-------|------------|-----|-----------------|----------|
| **CW-Nano** | Voltage | 20MS/s | 20 MS/s | Learning, Arduino |
| **CW-Lite** | Voltage + Clock | 105 MS/s | 105 MS/s | 8/32-bit MCUs |
| **CW-Pro** | Voltage + Clock | 200 MS/s | 200 MS/s | Complex SoCs, FPGA |
| **CW305 (FPGA target)** | External glitch | N/A | N/A | FPGA crypto research |
| **CW308 UFO** | Swappable targets | N/A | N/A | Multi-target testing |

### Bypassing Secure Boot on STM32

**STM32 RDP (Read-out Protection) Levels:**
- **RDP 0:** No protection; flash readable over SWD
- **RDP 1:** Flash read-protected; SRAM readable; debug functional
- **RDP 2:** Full protection; jtag/SWD locked; permanent (no downgrade without erase)

**STM32 RDP1→RDP0 Voltage Glitch:**
```
Vulnerability: Downgrade from RDP1 to RDP0 is supposed to erase flash
               but a glitch can abort the erase during the protection change

Procedure:
1. Power cycle with SWD connected
2. Trigger glitch ~100µs after power-on (during RDP check)
3. Attempt to read flash via SWD
4. On success: flash content readable without erase

Patch: STM32H7 series fixed this; use H7 for security-critical applications
```

### NXP CRP (Code Read Protection) Bypass

**LPC1343/LPC2148 CRP Bypass:**
```
Magic Word: 0x87654321 at flash offset 0x02FC enables CRP2
CRP1 (0x4E697370): Disables flash read; SWD functional
CRP2 (0x87654321): Stronger; ISP disabled
CRP3 (0x43218765): Full lockout

Voltage glitch attack on CRP1:
1. Set up glitch trigger on RESET release
2. Glitch timing: 2-5ms after boot (CRP check window)
3. On success: UART ISP responds to read-memory command
```

### RP2040 Glitching

Raspberry Pi RP2040 has no hardware secure boot by default:
```
Attack surface: OTP (One-Time Programmable) boot key verification
Target: Second stage bootloader signature check
Method: Clock glitch to skip signature verification

Defense (RP2040):
- Use secure element (ATECC608) for attestation
- Implement software fault detection:
  - Verify critical values twice
  - Use redundant checks with different variables
  - Error correction codes on security flags
```

### Defense Mechanisms

**Voltage/Clock Monitor Circuits:**
```
On-chip countermeasures:
  - Voltage detector (brown-out detector): Reset if VCC < threshold
  - Clock frequency monitor: Reset if CLK frequency deviates > ±20%
  - Temperature sensor: Reset if die temp outside -40°C to +125°C
  - Light sensor (photo detector): Reset if die exposed to light (decap detection)
  - Active metal mesh: Continuity check; short/open triggers zeroize

Typical secure microcontroller (e.g., STSAFE-A, SE050):
  - 9+ environmental sensors
  - Cryptographic fault detection (recalculate and compare)
  - Dual-rail logic (CMOS + inverse logic simultaneously)
  - Randomized clock (spreads power signature)
  - Memory scrambling (address and data XOR with random seed)
```

**Software Countermeasures:**
```c
// Double-check critical security decisions
bool authenticate_user(const uint8_t *pin, size_t len) {
    // First check
    bool result1 = constant_time_memcmp(stored_hash,
                                         compute_hash(pin, len), 32) == 0;
    // Inject random delay (jitter)
    random_delay();
    // Second check (different code path, different registers)
    volatile bool result2 = verify_pin_alternative(pin, len);

    // Both must agree; XOR-based check detects glitch on either
    if (result1 != result2) {
        log_fault_attack();
        zeroize_keys();
        hard_reset();
    }
    return result1 && result2;
}

// Stack canaries for fault injection
#define CANARY_VALUE 0xDEADBEEFCAFEBABE
uint64_t canary = CANARY_VALUE;
// ... security-critical code ...
if (canary != CANARY_VALUE) {
    // Fault injection detected
    zeroize_and_halt();
}
```

### TI CC2640 Bluetooth SoC Case Study

**Attack: Firmware Extraction via Voltage Glitching**
```
Target: Texas Instruments CC2640 (BLE SoC)
Protection: JTAG debug port locked via CCFG (Customer Config)
             JTAG_INTERFACE_DISABLE bit in flash at 0x50003FAB

Attack sequence:
1. Connect JTAG + power glitcher
2. Power on chip, glitch within 5ms of boot
3. Timing window: ~500ns; width: ~50ns; offset: sweep 3000-4000 samples
4. On success: JTAG responds; dump flash via OpenOCD
5. Success rate: ~1 in 500 attempts (iterate with automation)

Countermeasure:
  - Upgrade to CC2652R1 (improved CRP)
  - Use TI's secure boot with code encryption
  - Implement software glitch detection (voltage measurement via ADC)
```

**Defense: Glitch Detection via On-chip ADC:**
```c
// Monitor VCC via ADC on TI CC2640
void init_vcc_monitor(void) {
    ADC_open(VCC_ADC_CHANNEL, NULL);
}

bool vcc_in_range(void) {
    uint16_t raw;
    ADC_convert(handle, &raw);
    uint32_t mv = (raw * 3300) / 4096;
    return (mv >= 2900 && mv <= 3700);  // ±~12% tolerance
}

// Call in security-critical paths
if (!vcc_in_range()) {
    // Possible glitch attack
    zeroize_keys();
    reboot();
}
```


## 6. JTAG & Debug Interface Security

### JTAG TAP State Machine

JTAG (IEEE 1149.1) defines a 16-state TAP (Test Access Port) controller driven by the TMS signal:

```
                     ┌──────────────────────────────┐
                     │         Test-Logic-Reset       │ ← TMS=1 (×5 from any state)
                     └──────────────┬───────────────┘
                                    │ TMS=0
                             ┌──────▼──────┐
                             │   Run-Test  │
                             │   /Idle     │
                             └──────┬──────┘
                    TMS=1 ──────────┘─────────── TMS=1
              ┌─────▼─────┐               ┌──────▼──────┐
              │  Select   │               │   Select    │
              │  DR-Scan  │               │   IR-Scan   │
              └─────┬─────┘               └──────┬──────┘
              TMS=0 │                     TMS=0  │
              ┌─────▼─────┐               ┌──────▼──────┐
              │  Capture  │               │   Capture   │
              │    DR     │               │     IR      │
              └─────┬─────┘               └──────┬──────┘
```

**Key Signals:**
- **TCK** — Test Clock (drives state machine)
- **TMS** — Test Mode Select (navigates states)
- **TDI** — Test Data In (serial input)
- **TDO** — Test Data Out (serial output)
- **TRST** — Test Reset (optional, async reset)

### IR/DR Registers

**Instruction Register (IR):**
- Selects active DR register and operation mode
- Common instructions:
  - `BYPASS` (all 1s) — single-bit bypass DR
  - `IDCODE` (device-specific) — reads 32-bit device ID
  - `EXTEST` — test board-level interconnects
  - `SAMPLE/PRELOAD` — capture/drive boundary scan
  - `DEBUG` (ARM-specific) — enable debug access port

**Device ID Format (IDCODE, 32-bit):**
```
Bit 31-28: Version
Bit 27-12: Part Number
Bit 11-1:  Manufacturer ID (JEDEC)
Bit 0:     Always 1 (JTAG compliance)

Example: STM32F4 IDCODE = 0x10016413
  Version=1, Part=0x0641, Mfr=0x020 (ST Microelectronics)
```

### OpenOCD — Open On-Chip Debugger

```bash
# Start OpenOCD with ST-Link and STM32F4 target
openocd -f interface/stlink.cfg -f target/stm32f4x.cfg

# Connect telnet
telnet localhost 4444

# Basic commands in OpenOCD console
> halt                          # Halt CPU
> reg                           # Dump all registers
> mdw 0x08000000 64             # Read 64 words from flash start
> dump_image firmware.bin 0x08000000 0x80000  # Dump 512KB flash
> flash write_image erase fw_new.bin 0x08000000  # Flash new firmware
> reset run                     # Resume execution

# Read from running system without halt (non-invasive)
> mem2array data 32 0x20000000 256  # Read SRAM
```

**OpenOCD config for Raspberry Pi RP2040 SWD:**
```tcl
# rp2040.cfg
source [find interface/raspberrypi-swd.cfg]
transport select swd
source [find target/rp2040.cfg]
adapter speed 5000
```

### SWD vs JTAG

| Feature | JTAG | SWD (Serial Wire Debug) |
|---------|------|------------------------|
| Signal pins | TCK, TMS, TDI, TDO [, TRST] | SWCLK, SWDIO |
| Standard | IEEE 1149.1 | ARM ADIv5 |
| Topology | Daisy-chain (multi-device) | Single device |
| Speed | Up to 30 MHz | Up to 50 MHz |
| Boundary scan | Yes | No |
| Common on | FPGAs, CPLDs, complex SoCs | ARM Cortex-M |

```bash
# Switch from JTAG to SWD (OpenOCD)
transport select swd
swd newdap $_CHIPNAME cpu -enable
dap create $_CHIPNAME.dap -chain-position $_CHIPNAME.cpu
```

### Boundary Scan

IEEE 1149.1 boundary scan allows testing board-level connections:

```bash
# Using BSDL (Boundary Scan Description Language) files
# Enumerate ICs via IDCODE
openocd -c "jtag scan_chain"

# Python boundary scan with pyBSDL
pip install python-bsdl

# SVF (Serial Vector Format) playback
openocd -f interface/jlink.cfg -c "svf firmware_test.svf"

# JTAG boundary scan tools:
#   UrJTAG: open-source, supports 400+ devices
#   OpenOCD: primary debug; limited boundary scan
#   Lauterbach TRACE32: commercial, full boundary scan
```

### Firmware Dumping via JTAG

```bash
# Dump full flash memory of target MCU
# 1. OpenOCD approach
openocd -f board/stm32f4discovery.cfg   -c "init; halt; dump_image dump.bin 0x08000000 0x100000; shutdown"

# 2. GDB approach
arm-none-eabi-gdb -ex "target remote localhost:3333"   -ex "dump binary memory dump.bin 0x08000000 0x08100000"   -ex "quit"

# 3. Analyze dump
binwalk -e dump.bin          # Extract filesystem / components
strings dump.bin | grep -i password  # Quick win
hexdump -C dump.bin | grep -i "key"

# Recover source via Ghidra
# Load as ARM Cortex-M binary, base address 0x08000000
# Auto-analyze, look for security checks, key storage
```

### ARM CoreSight Authentication

ARM CoreSight provides hardware authentication to disable debug access:

```
DBGEN  — Invasive debug enable (halt, step, register access)
NIDEN  — Non-invasive debug enable (trace only)
SPIDEN — Secure privileged invasive debug (TrustZone secure world)
SPNIDEN — Secure non-invasive debug

Authentication Interface (AUTHSTATUS register):
  Bits [1:0] = NSID — Non-secure invasive debug supported/enabled
  Bits [3:2] = NSNID — Non-secure non-invasive debug
  Bits [5:4] = SID — Secure invasive debug
  Bits [7:6] = SNID — Secure non-invasive debug
```

**Disabling Debug in Production (STM32 example):**
```c
// Permanently disable JTAG (OTP-equivalent via option bytes)
// WARNING: Irreversible on some devices
#define FLASH_OPTCR_nJTAG_SEL  (1 << 2)
// Set via STM32CubeProgrammer or:
HAL_FLASH_OB_Unlock();
FLASH->OPTCR |= FLASH_OPTCR_RDP_Pos;  // Set RDP to Level 2
HAL_FLASH_OB_Lock();
HAL_FLASH_OB_Launch();
```

### Fuse Bit Lockdown

```bash
# AVR fuse bits (ATmega328P example)
# Lock bits: prevent flash read, disable programming
avrdude -p m328p -c usbtiny -U lock:w:0x0C:m
# 0x0C = BLB11 BLB10 set: No read from application, no write from bootloader

# Check current fuse state
avrdude -p m328p -c usbtiny -U lfuse:r:-:h -U hfuse:r:-:h -U efuse:r:-:h

# TI MSP430 BSL (Bootstrap Loader) password lock
# BSL is unlocked by sending correct 32-byte password (= flash interrupt vectors)
# Wrong password triggers mass erase
```

### UART Discovery

```bash
# Find UART on unknown hardware
# 1. Measure with multimeter: TX idles HIGH (3.3V or 5V)
# 2. Look for test points labeled RX/TX/GND/VCC on PCB

# 3. Logic analyzer (Saleae) - UART protocol auto-detection
# 4. baudrate bruteforce
minicom -D /dev/ttyUSB0 -b 115200  # Try common baud rates
# Common: 9600, 19200, 38400, 57600, 115200, 230400, 921600

# Interact with U-Boot bootloader (common on embedded Linux)
# Press any key within 3 seconds of boot to stop autoboot
# U-Boot commands:
# md.b 0x80000000 0x100   - memory display
# nand dump 0 0x10000     - NAND flash dump
# env print               - show environment variables
```

### JTAGulator

JTAGulator is a purpose-built JTAG/UART discovery tool:

```
Hardware: Parallax P8X32A Propeller microcontroller
Supported: JTAG, SWD, UART
Features:
  - Auto-scan for JTAG pinout on 24-channel target interface
  - Works on 1.2V–3.3V targets
  - IDCODE-based device enumeration

Usage:
  1. Connect unknown PCB test points to JTAGulator channels 0–7
  2. Serial interface: 115200 baud
  3. Command 'J' to scan JTAG (brute-forces pin combinations)
  4. Output: "Found JTAG!" with TCK/TMS/TDI/TDO pin assignments

# Serial session
screen /dev/ttyUSB0 115200
> J  # JTAG scan
> U  # UART scan
> Target voltage: 3.3
> Channels to scan: 0-7
```

## 7. Confidential Computing

### Intel SGX (Software Guard Extensions)

SGX provides hardware-enforced memory encryption and isolation for user-mode code called **enclaves**. The Enclave Page Cache (EPC) is encrypted with a processor-managed key (MEK); host OS cannot read enclave memory.

**SGX Architecture:**
```
Host Application (untrusted)
  │
  ├── ECALL ─────────────────────────────► Enclave Code (trusted)
  │                                           │
  ◄── OCALL ◄────────────────────────────────┘
  │
  └── Attestation ──► Intel IAS/DCAP ──► Verifier

EPC (Enclave Page Cache): encrypted DRAM region, 128MB default (expandable)
MEK: Memory Encryption Key, derived per-boot from fuses
MRSIGNER: Hash of enclave signing key
MRENCLAVE: Hash of enclave measurement (code + data layout)
```

**Writing SGX Enclaves (Intel SGX SDK):**
```c
// enclave.edl — Interface definition
enclave {
    trusted {
        // ECALLs: untrusted → enclave
        public int seal_secret([in, size=len] const uint8_t *data,
                               size_t len,
                               [out, size=sealed_size] uint8_t *sealed,
                               size_t sealed_size);
        public int unseal_secret([in, size=sealed_len] const uint8_t *sealed,
                                 size_t sealed_len,
                                 [out, size=out_len] uint8_t *out,
                                 size_t out_len);
    };
    untrusted {
        // OCALLs: enclave → untrusted (for I/O, etc.)
        void ocall_print([in, string] const char *str);
    };
};

// enclave.cpp
#include "sgx_tseal.h"

int seal_secret(const uint8_t *data, size_t len,
                uint8_t *sealed, size_t sealed_size) {
    sgx_sealed_data_t *p = (sgx_sealed_data_t *)sealed;
    // Seal binds to MRENCLAVE (same enclave only) or MRSIGNER (same signer)
    return sgx_seal_data(0, NULL, len, data,
                         sealed_size, p);
}
```

**SGX Remote Attestation (DCAP — Data Center Attestation Primitives):**
```
1. Enclave generates RSA/ECDSA attestation key pair
2. Enclave calls sgx_get_quote() → produces SGX Quote (signed by PCK)
3. Quote sent to Verifier + Intel PCS (Provisioning Certificate Service)
4. PCS returns PCK cert chain + CRL
5. Verifier checks:
   a. Quote signature valid against PCK cert
   b. PCK cert chain valid (trusted Intel root)
   c. MRENCLAVE matches expected measurement
   d. ISV SVN ≥ minimum
   e. TCB status = UpToDate (not vulnerable to known CVEs)
```

```bash
# Intel DCAP setup
apt install libsgx-dcap-ql libsgx-dcap-default-qpl

# Verify SGX platform
sgx_capable  # Check if SGX enabled in BIOS
sgx_detect   # Detailed SGX feature detection

# Build enclave
cmake -DSGX_MODE=HW -DSGX_BUILD=RELEASE ..
make

# Run attestation demo
./app --attest
```

### Intel TDX (Trust Domain Extensions)

TDX protects entire Virtual Machines rather than individual processes:

```
TDX Trust Domain (TD) = encrypted, isolated VM
TD runs on TDX Module (SEAM Module in SEAM range)
VMM (hypervisor) cannot read TD memory
TDVMCALL: TD exits to VMM for I/O (analogous to OCALL)

TD Attestation:
  TDX TDREPORT → signed by TDEL (TD Execution Layer)
  → Intel TD Quoting Enclave → TDX Quote
  → Same DCAP verification flow as SGX
```

### AMD SEV (Secure Encrypted Virtualization)

**SEV:** Each VM encrypted with unique VM Encryption Key (VEK); hypervisor sees ciphertext
**SEV-ES (Encrypted State):** Also encrypts CPU register state on VM exit
**SEV-SNP (Secure Nested Paging):** Adds memory integrity protection + RMP (Reverse Map Table)

```bash
# Check SEV support
dmesg | grep -i sev
cat /sys/module/kvm_amd/parameters/sev   # 1 = enabled
cat /sys/module/kvm_amd/parameters/sev_es
cat /sys/module/kvm_amd/parameters/sev_snp

# Launch SEV-SNP VM with QEMU
qemu-system-x86_64   -machine q35,memory-encryption=sev0,vmport=off   -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,          policy=0x30000,measurement-policy=0x1   -m 2G -smp 2   -drive file=ubuntu.qcow2,format=qcow2

# SNP attestation
# Guest runs: snpguest report attestation.bin random-nonce.bin
# Verifier: snpguest verify attestation
```

### ARM CCA (Confidential Compute Architecture)

ARM CCA introduces **Realms** — hardware-isolated VMs protected from hypervisor:

```
Exception Levels:
  EL3: Secure Monitor (trusted firmware, RMM entry)
  EL2: Hypervisor (Normal World) / RMM (Realm Management Monitor)
  EL1: OS (Realm or Normal World)
  EL0: Application

Realm lifecycle:
  RMI_REALM_CREATE → RMI_REC_CREATE → RMI_REALM_ACTIVATE
  → RMI_REC_ENTER (run realm) → RMI_REALM_DESTROY

CCA attestation uses:
  - Realm Token (signed by Realm Signing Key)
  - Platform Token (signed by device attestation key)
  Combined via CBOR EAT (Entity Attestation Token)
```

### Confidential Containers

```bash
# Kata Containers with AMD SEV-SNP
# /etc/kata-containers/configuration-qemu-snp.toml
[hypervisor.qemu]
  machine_type = "q35"
  confidential_guest = true
  sev_snp_guest = true

# Run container in confidential pod (Kubernetes)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: confidential-pod
  annotations:
    io.katacontainers.config.hypervisor.machine_type: "q35"
    io.containerd.cri.runtime-handler: kata-qemu-snp
spec:
  runtimeClassName: kata-qemu-snp
  containers:
  - name: app
    image: myapp:latest
EOF
```

### Attestation Services

| Service | Backing TEE | Protocol | SLA |
|---------|------------|----------|-----|
| Intel IAS (deprecated) | SGX v1 | REST/JSON | - |
| Intel PCS/PCCS | SGX DCAP, TDX | REST/JSON | - |
| AWS Nitro Attestation | Nitro Enclaves | NitroTPM | 99.99% |
| Azure MAA (Microsoft Azure Attestation) | SGX, SEV-SNP, TDX | JWT/JWK | 99.9% |
| Veraison | Generic | EAT/CBOR | Open source |

**Azure MAA Example:**
```bash
# Get attestation token from inside SGX enclave
az attestation attest-sgx-enclave   --attestation-provider-name myattest   --resource-group myRG   --quote "$(cat sgx_quote.b64)"   --enclave-held-data "$(echo -n 'nonce' | base64)"

# JWT claims include:
# x-ms-sgx-mrenclave, x-ms-sgx-mrsigner
# x-ms-sgx-is-debuggable: false (production)
# x-ms-sgx-product-id, x-ms-sgx-svn
```

**AWS Nitro Enclave Attestation:**
```python
import boto3
import json
import base64
from aws_nitro_enclaves_nsm_api import nsm_get_attestation_doc

# Inside Nitro Enclave
doc = nsm_get_attestation_doc(
    user_data=b"my-nonce",
    nonce=b"verifier-nonce",
    public_key=my_pub_key_der
)
# doc is CBOR-encoded COSE_Sign1 structure
# Contains PCRs 0-7 (enclave measurements)
# Send to verifier for validation
```

## 8. Embedded System Security

### ARM TrustZone-M

TrustZone for Cortex-M (ARMv8-M) provides hardware-enforced separation of Secure and Non-Secure worlds on microcontrollers:

```
Security Attribution Unit (SAU):
  - Configures which address regions are Secure vs Non-Secure
  - Up to 8 SAU regions (or more via IDAU from SoC vendor)

NSC (Non-Secure Callable) regions:
  - Special code region accessible from Non-Secure world
  - Contains "SG" (Secure Gateway) instructions for controlled entry

Thread execution:
  Secure Thread Mode (privileged or unprivileged)
  Non-Secure Thread Mode (untrusted application)
  Transitions via SG instruction → veneer → Secure function
```

**TF-M (Trusted Firmware-M) PSA Architecture:**
```c
// Secure service definition (PSA API)
#include "psa/client.h"
#include "psa/service.h"

// Non-Secure client calls (from application)
psa_handle_t handle = psa_connect(CRYPTO_SERVICE_SID, CRYPTO_VERSION);
psa_status_t status = psa_call(handle, PSA_IPC_CALL,
    in_vecs, IOVEC_LEN(in_vecs),
    out_vecs, IOVEC_LEN(out_vecs));
psa_close(handle);

// Secure service implementation
void crypto_main(void) {
    psa_msg_t msg;
    while (1) {
        psa_wait(CRYPTO_SERVICE_SIGNAL, PSA_BLOCK);
        if (psa_get(CRYPTO_SERVICE_SIGNAL, &msg) == PSA_SUCCESS) {
            switch (msg.type) {
            case PSA_IPC_CALL:
                handle_crypto_request(&msg);
                break;
            }
            psa_reply(msg.handle, PSA_SUCCESS);
        }
    }
}
```

### Flash RDP (Read-out Protection) Levels

**STM32 Option Bytes:**
```
RDP Level 0 (0xAA): No protection
  - JTAG/SWD: Full access to flash, SRAM, debug
  - ISP: Read, write, erase allowed

RDP Level 1 (any non-AA/CC value):
  - JTAG/SWD: Debug access to SRAM; flash reads blocked
  - ISP (UART/USB): Write and erase allowed; read blocked
  - Regression to Level 0: Triggers mass erase

RDP Level 2 (0xCC): Permanent
  - JTAG/SWD: Completely disabled (cannot reconnect)
  - ISP: Disabled
  - OTP: Cannot be reversed; device is locked forever
  WARNING: Set Level 2 only in final production build

# Set RDP via STM32CubeProgrammer CLI
STM32_Programmer_CLI -c port=SWD -ob RDP=0xBB
# Or in code:
FLASH_OBProgramInitTypeDef ob = {0};
ob.OptionType = OPTIONBYTE_RDP;
ob.RDPLevel = OB_RDP_LEVEL_1;
HAL_FLASHEx_OBProgram(&ob);
HAL_FLASH_OB_Launch();
```

### Code Signing for Embedded Systems

```bash
# Generate signing key pair
openssl ecparam -name prime256v1 -genkey -noout -out signing_key.pem
openssl ec -in signing_key.pem -pubout -out signing_key_pub.pem

# Sign firmware binary
openssl dgst -sha256 -sign signing_key.pem   -out firmware.bin.sig firmware.bin

# Verify signature
openssl dgst -sha256 -verify signing_key_pub.pem   -signature firmware.bin.sig firmware.bin

# Embed public key in bootloader (as C array)
xxd -i signing_key_pub.pem > pub_key.h
```

**MCUboot Secure Bootloader:**
```yaml
# mcuboot.yaml
boot:
  signature-type: ECDSA-P256
  key: signing_key.pem
  slot-size: 0x60000
  upgrade-only: false   # Allow rollback?
  security-counter: 1   # Anti-rollback counter

# Sign image
imgtool sign   --key signing_key.pem   --align 4   --version 1.0.0   --header-size 0x200   --slot-size 0x60000   firmware.bin firmware_signed.bin

# Verify
imgtool verify --key signing_key_pub.pem firmware_signed.bin
```

### RTOS Security

**FreeRTOS with MPU (Memory Protection Unit):**
```c
// Create task with restricted memory access
static StackType_t ucTaskStack[256] __attribute__((aligned(256)));

TaskParameters_t xParams = {
    .pvTaskCode    = vSecureTask,
    .pcName        = "SecureTask",
    .usStackDepth  = 256,
    .pvParameters  = NULL,
    .uxPriority    = 2 | portPRIVILEGE_BIT,  // Privileged
    .puxStackBuffer = ucTaskStack,
    .xRegions = {
        // Allow read-write to specific SRAM region only
        { ucSharedBuffer, 0x400, portMPU_REGION_READ_WRITE },
        { 0, 0, 0 },  // Sentinel
    }
};
xTaskCreateRestricted(&xParams, NULL);

// Zeroize sensitive data in task cleanup
void vTaskCleanup(void *pvParam) {
    memset(session_key, 0, sizeof(session_key));
    memset(pvParam, 0, sizeof(SensitiveData_t));
    vTaskDelete(NULL);
}
```

### CAN Bus Security

```python
# CAN bus sniffing (Python-CAN)
import can

bus = can.Bus(channel='can0', interface='socketcan')
for msg in bus:
    print(f"ID: {msg.arbitration_id:#05x} DLC: {msg.dlc} Data: {msg.data.hex()}")

# CAN injection attack
bus.send(can.Message(
    arbitration_id=0x7DF,  # OBD-II broadcast
    data=[0x02, 0x01, 0x0D, 0, 0, 0, 0, 0],  # Request vehicle speed
    is_extended_id=False
))

# CAN FD with authentication (AUTOSAR SecOC)
# HMAC-based Message Authentication Code appended to payload
# Requires shared key and freshness counter (anti-replay)
```

**CANalyzer / Wireshark for CAN:**
```bash
# Linux SocketCAN setup
ip link set can0 type can bitrate 500000
ip link set up can0

# Wireshark CAN capture
tcpdump -i can0 -w can_capture.pcap

# candump
candump -l can0   # Log to candump_YYYYMMDD.log format

# cansend
cansend can0 7DF#0201010000000000

# canreplay (replay attack)
canplayer -I capture.log
```

### Secure Element: ATECC608A

Microchip ATECC608A provides hardware crypto acceleration and secure key storage:

```python
# Using cryptoauthlib
import cryptoauthlib as cal

# Initialize I2C connection
cal.atcab_init(cal.cfg_ateccx08a_i2c_default())

# Generate ECDSA P-256 key in slot 0 (non-extractable)
cal.atcab_genkey(0)   # Generates and stores internally

# Get public key
pub_key = bytearray(64)
cal.atcab_get_pubkey(0, pub_key)

# Sign data
msg_digest = bytearray(32)   # SHA-256 hash
signature = bytearray(64)    # ECDSA r+s
cal.atcab_sign(0, msg_digest, signature)

# Verify
verified = bytearray(1)
cal.atcab_verify_extern(msg_digest, signature, pub_key, verified)

# ECDH key exchange (slot 2 configured for ECDH)
their_pub_key = bytearray(64)
pmk = bytearray(32)   # Pre-Master Key
cal.atcab_ecdh(2, their_pub_key, pmk)

# Random number generation
random_bytes = bytearray(32)
cal.atcab_random(random_bytes)
```

### ETSI EN 303 645 (IoT Security Baseline)

```
Mandatory provisions (shall):
  1. No universal default passwords (unique per device or user-settable)
  2. Implement a means to manage vulnerability reports (security@, HackerOne)
  3. Keep software updated (OTA mechanism required)
  4. Securely store sensitive security parameters (use secure element)
  5. Communicate securely (TLS 1.2+ with cert validation)
  6. Minimize exposed attack surfaces (close unused ports)
  7. Ensure software integrity (signed firmware with verification)
  8. Ensure personal data is secure (encryption at rest)
  9. Make systems resilient to outages (watchdog, fallback)
  10. Monitor system telemetry data (anomaly detection)
  11. Make it easy for users to delete personal data (factory reset)
  12. Make installation and maintenance of devices easy (docs, UX)
  13. Validate input data (input validation for all interfaces)

Compliance assessment:
  ETSI TS 103 701: Test spec for EN 303 645
  CSA IoT Security label (Singapore)
  UK PSTI Act 2022 (mandatory for UK market from April 2024)
```

## 9. Hardware Security Testing Tools

### Test Bench Equipment

**Saleae Logic Analyzer:**
```
Models: Logic 8 (8-ch, 100MHz digital / 10MHz analog)
        Logic Pro 8 (100MHz analog)
        Logic Pro 16 (16-ch, 500MHz digital)

Protocols supported: UART, SPI, I2C, 1-Wire, CAN, USB, I2S, Manchester,
                     JTAG, SWD, Modbus, DMX-512, MDIO, PS/2, SMBus

Usage:
  1. Connect probes to target signals
  2. Open Logic 2 software
  3. Add protocol analyzer (e.g., I2C): set SCL/SDA pins
  4. Capture and decode traffic
  5. Export as CSV or binary for offline analysis

# CLI capture (Saleae CLI)
./Logic2_cli --capture --duration 5 --output capture.sal   --channels 0,1,2,3 --sample-rate 24000000
```

**Oscilloscope Requirements for Side-Channel:**
```
Minimum for SCA:
  - Bandwidth: 1 GHz (to capture nanosecond power spikes)
  - Sample rate: 2-4 GS/s (Nyquist for 1GHz)
  - Vertical resolution: 12-bit ADC preferred (Rohde & Schwarz RTO2000)
  - Memory depth: 100M points per channel

Budget options:
  - Rigol DS1054Z: 50MHz, 4ch, $350 (limited for SCA)
  - Rigol DS1104Z-Plus: 100MHz, $450
  - Keysight DSOX1204G: 200MHz, $800

Professional:
  - Rohde & Schwarz RTO2014: 1GHz, 4ch, ~$20k
  - Tektronix MSO6B: 10GHz, ~$50k
```

**Current Probe (for power analysis):**
```
Method 1: Shunt resistor (10Ω in VCC line → voltage ∝ current)
  Resolution: ΔV = I × R; 1mA → 10mV across 10Ω
  Limitation: Reduces supply voltage

Method 2: Magnetic current probe (non-invasive)
  Stiermer EMC-1 or Rigol RP1025D
  Clamps around power wire; no circuit modification
```

### Bus Pirate

Universal serial protocol analyzer and debugger:

```bash
# Connect Bus Pirate to target via UART
screen /dev/ttyUSB0 115200

# Bus Pirate interactive commands
m        # Mode menu (1=HiZ, 2=1-WIRE, 3=UART, 4=I2C, 5=SPI...)
> 3      # Select UART
Baud: 1  # 115200

# UART mode
>        # Type characters to send
[ r ]    # Read one byte

# I2C scan (find device addresses)
m 4      # I2C mode
(1)      # Macro 1: I2C scan
# Output: I2C address scan: Found device at 0x68 (MPU-6050)

# SPI flash read (25-series flash chip)
m 5      # SPI mode
W        # Power on 3.3V supply
{ 0x9F r:3 }  # Send JEDEC ID command, read 3 bytes
# 0xEF 0x40 0x18 = Winbond W25Q128 (16MB)
{ 0x03 0x00 0x00 0x00 r:256 }  # Read 256 bytes from address 0x000000
```

### Proxmark3

Industry-standard RFID/NFC security research tool:

```bash
# Proxmark3 RDV4.01 (recommended hardware)
pm3 --port /dev/ttyACM0

# HID Prox (125kHz) card clone
pm3 --> lf hid read          # Read card
pm3 --> lf hid sim -r <raw>  # Simulate cloned card
pm3 --> lf hid clone -r <raw> --b t5577  # Clone to T5577 blank

# MIFARE Classic attack (CRYPTO1 weakness)
pm3 --> hf mf autopwn        # Auto-crack all sectors using nested attack
# Nested authentication attack: ~minutes to recover all keys
# Darkside attack: ~seconds if one default key known
pm3 --> hf mf dump --gen1a   # Dump card after cracking

# MIFARE Ultralight (NTAG)
pm3 --> hf mfu info           # Card info + page dump
pm3 --> hf mfu dump           # Full dump

# iClass (HID Seos)
pm3 --> hf iclass info        # Reader mode
pm3 --> hf iclass sniff       # Sniff reader-card comms
```

### HackRF One (SDR)

```bash
# Record raw RF for replay attacks
hackrf_transfer -r capture.bin -f 433920000 -s 2000000 -g 40

# Replay recorded signal
hackrf_transfer -t capture.bin -f 433920000 -s 2000000 -x 47

# GNU Radio companion for signal analysis
# Load capture.bin, demodulate ASK/FSK/OOK
# Common IoT protocols: 315MHz/433MHz (key fobs), 868/915MHz (LoRa/Zigbee)

# URH (Universal Radio Hacker) - GUI tool for RF analysis
urh  # Open .bin file, auto-detect modulation, demodulate, decode
```

### PCB Analysis (X-ray / Decap)

```
X-ray analysis:
  Equipment: North Star Imaging M-5000 CT, Phoenix Nanotom
  Purpose: Non-destructive PCB layer analysis, BGA ball inspection
  Security use: Detect hidden chips/mesh shields, verify BOM matches X-ray

Decapsulation (removing IC packaging):
  Plastic packages:
    - Fuming nitric acid (98%): Dissolve epoxy at 60°C
    - Hot Jet decapper: Heated acid jet
    - Plasma decap: Clean removal for FIB preparation
  Ceramic packages:
    - Mechanical: Diamond saw or chisel

  After decap:
    - Optical microscope (up to 1000×)
    - SEM (Scanning Electron Microscope): 100,000×
    - FIB (Focused Ion Beam): Mill and image cross-sections
    - EDX (Energy-Dispersive X-ray): Material composition
```

### UART/SPI/I2C/JTAG Identification Methodology

```
Step 1: Visual inspection
  - Count test points/pads; measure pin pitch
  - Label clues: TP_TX, TP_RX, J1 (JTAG header)
  - 2.54mm pitch = UART/JTAG header; 1.27mm = SWD header

Step 2: Multimeter
  - UART TX: idles HIGH (3.3V or 1.8V); pulses LOW on boot
  - JTAG TCK: idle LOW, pulses during programming
  - I2C SCL: idles HIGH; SDA pulses during comms
  - GND: continuity to chassis/shield

Step 3: Logic analyzer
  - Trigger on falling edge of suspected TX
  - Auto-decode UART at detected baud rate
  - I2C: Look for START condition (SDA falls while SCL high)

Step 4: JTAGulator (for JTAG pinout)
  - Connect 4-8 unknown pins
  - Run IDCODE scan
```

### Firmware Extraction from SPI Flash

```bash
# Desolder or clip-connect to SPI flash (Winbond W25Q series, common)
# Tools: SOIC-8 clip + Bus Pirate or dedicated programmer (CH341A)

# Using flashrom with CH341A programmer
flashrom -p ch341a_spi -r firmware_dump.bin

# Using Bus Pirate
# (as shown above with SPI read-all macro)

# Verify dump integrity
md5sum firmware_dump.bin  # Save hash; read again and compare

# Identify filesystem
binwalk firmware_dump.bin
# Example output:
# 0x50        SquashFS, little endian, version 4.0, compression: lzma
# 0x180000    JFFS2, little endian

# Extract
binwalk -e firmware_dump.bin
# Extract SquashFS
unsquashfs -d squashfs_root firmware_dump.bin.extracted/squashfs-root.squashfs

# Look for secrets
find squashfs_root -name "*.conf" -exec grep -il "password\|key\|secret" {} \;
find squashfs_root -name "*.pem" -o -name "*.key" -o -name "*.p12"
strings squashfs_root/usr/bin/httpd | grep -i password
```

### Glue Logic Attacks

```
Target: Inter-chip communication on PCB
Buses: SPI, I2C, UART between main SoC and peripheral (e.g., TPM, crypto IC, flash)

Attack: Man-in-the-middle on SPI bus
  1. Desolder SPI flash from PCB
  2. Insert FPGA (Lattice iCE40 or Artix-7) as SPI bridge
  3. FPGA records all read/write transactions
  4. Modify data on-the-fly (e.g., flip bit in firmware during read)

Example: Nintendo Switch SPI boot ROM bypass
  - Boot ROM reads encrypted firmware from NAND via SPI
  - Attacker replaces NAND with FPGA
  - FPGA returns crafted payload to trigger bootrom bug
```

### Riscure Inspector

Commercial SCA platform:
```
Features:
  - High-speed trace acquisition (up to 1GS/s, 12-bit)
  - Built-in DPA/CPA/DEMA attacks against AES, DES, RSA, ECC
  - Inspector Java API for custom attacks
  - Trace Inspector: visual alignment and filtering

Workflow:
  1. Setup: Define target device, connect oscilloscope + trigger
  2. Acquisition: Capture 10K-1M traces with random input data
  3. Analysis: Run CPA with Hamming Weight power model
  4. Results: Key byte confidence scores; highest = recovered key
```

### Hardware Pentest Methodology

```
Phase 1: Reconnaissance
  - Obtain device (eBay, manufacturer, retailer)
  - FCC ID search (fcc.io) for internal photos, test reports
  - FCC teardown photos reveal PCB layout before disassembly
  - Shodan for firmware versions, exposed admin interfaces

Phase 2: Physical Access
  - Non-destructive first: open screws, find hidden screws (under labels)
  - PCB photography: both sides, high resolution
  - Component identification: look up ICs on datasheet databases

Phase 3: Firmware Acquisition
  - Priority 1: Update package download (vendor website, app store)
  - Priority 2: UART console with U-Boot shell (least invasive)
  - Priority 3: SPI/NAND flash direct read (clip or desolder)
  - Priority 4: JTAG dump (if not locked)
  - Priority 5: Glitching to bypass RDP

Phase 4: Firmware Analysis
  - Static: binwalk, Ghidra, radare2, strings, grep for secrets
  - Dynamic: QEMU emulation (for Linux targets), GDB remote debugging
  - Web interface: crawl for hidden endpoints, check auth bypass

Phase 5: Runtime Testing
  - Protocol fuzzing: boofuzz, sulley, custom fuzzers
  - RF attacks: HackRF replay, Proxmark RFID attacks
  - Side-channel: ChipWhisperer power analysis
  - Fault injection: glitch security checks, bypass RDP
```

## 10. Supply Chain & Hardware Integrity

### Counterfeit PCB/Component Detection

Counterfeit electronic components are a major supply chain risk, estimated at $169B/year globally.

**Visual Inspection Techniques:**
```
Marking irregularities:
  - Font inconsistencies (compare to genuine datasheet photos)
  - Blurry or inconsistent laser markings (sign of remarking)
  - Date codes that post-date current year
  - Incorrect package outline (compare to datasheet dimensions)

Under microscope (10-40×):
  - Lead finish quality (genuine = smooth matte; counterfeit = grainy/pitted)
  - Die visibility through package (genuine = consistent color)
  - Solder balls on BGA (genuine = uniform sphere size, pitch)

X-ray inspection:
  - Wire bond pattern inside package (compare to reference sample)
  - Die size mismatch (smaller die glued into larger package)
  - Missing or incorrect internal metallization
```

**Electrical Testing:**
```python
# Automated test using boundary scan (ICT — In-Circuit Test)
# JTAG boundary scan verifies IO cell behavior

# Functional verification script (example for AES IC)
def verify_aes_ic(port):
    dut = connect_uart(port, 115200)
    # Known-answer test vectors (NIST FIPS-197)
    plaintext = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    expected = bytes.fromhex('3ad77bb40d7a3660a89ecaf32466ef97')

    result = dut_encrypt(dut, plaintext, key)
    if result != expected:
        log_fail(f"AES KAT failed: got {result.hex()}")
        return False
    return True

# Thermal profile (counterfeit ICs may have different power dissipation)
# Use thermal camera during burn-in test; outliers indicate remarked dies
```

### Supply Chain Attack Vectors

**Hardware Implant Attacks:**
- **Interception attacks:** Package interception during shipping; add implant IC
- **Insider threats:** Malicious component substitution at contract manufacturer
- **Rogue supplier:** Counterfeit IC with added functionality (hardware trojan)

**Notable Case Studies:**
```
Bloomberg "Big Hack" (2018) — disputed but informative:
  - Alleged: Tiny IC (~pencil tip) added to server motherboards at Supermicro's
    Chinese contract manufacturer
  - Purported capability: Intercept BMC communications, create backdoor
  - Industry response: Intensified supply chain auditing regardless of veracity

Cisco Router Implants (documented by NSA/TAO, Snowden documents):
  - JETPLOW: Persistent implant in Cisco PIX/ASA firewall
    Method: NSA interdiction of equipment in transit (QUANTUM INSERT)
  - HALLUXWATER: Huawei router backdoor implant
  - Countermeasure: Verify router firmware hash immediately on delivery

SolarWinds Orion (2020) — Software supply chain:
  - Malicious code injected into build system
  - Signed update distributed to 18,000+ customers
  - Hardware equivalent: Subverted programming station at manufacturer

Supermicro BMC Vulnerabilities (legitimate, documented):
  - CVE-2019-16649: Unauthenticated code execution in BMC web interface
  - CVE-2020-15362: BMC IPMI authentication bypass
  - Lesson: BMC firmware must be treated as supply chain risk
```

### X-Supply Chain Security Framework

```
NIST SSDF (Secure Software Development Framework) for Hardware:
  PW.4: Reuse existing, well-secured software/hardware where feasible
  PW.6: Configure environments to support security
  PS.1: Protect all forms of code (hardware design files, HDL, BSDL)
  RV.1: Identify and confirm vulnerabilities during testing

Hardware SBOM (Software Bill of Materials → Hardware Bill of Materials):
  Contents:
    - Component manufacturer, part number, revision
    - Manufacturer country of origin
    - Contract manufacturer (CM) information
    - Component certification (AEC-Q100, automotive; HIREL for mil/aero)
    - EOL (End-of-Life) status
    - Known vulnerability references (CVE cross-reference)

  Format: emerging standards include CycloneDX (supports hardware)
```

### NIST SP 800-161r1 — C-SCRM (Cybersecurity Supply Chain Risk Management)

```
Core SCRM practices (aligned to NIST CSF):
IDENTIFY:
  ID.SC-1: Cyber supply chain risk management policies established
  ID.SC-2: Identify, prioritize, assess suppliers
  ID.SC-3: Contracts include cybersecurity requirements
  ID.SC-4: Suppliers routinely assessed (audits, test results, CVEs)
  ID.SC-5: Response/recovery planning for supply chain events

Key controls from 800-161r1 appendix:
  SR-2:  Supply chain risk assessment
  SR-3:  Supply chain controls and processes
  SR-5:  Acquisition strategies, tools, and methods
  SR-6:  Supplier assessments and reviews
  SR-9:  Tamper resistance and detection
  SR-10: Inspection of systems, components, or services
  SR-11: Component authenticity
  SR-12: Component disposal

Questionnaire for supplier assessment:
  - Does the supplier have an ISO 27001 or SOC 2 Type II certification?
  - Is hardware designed in a FABS country trusted per CHIPS Act criteria?
  - What is the component traceability chain (OEM → distributor → CM)?
  - Are firmware/FPGA bitstreams signed and stored securely (HSM)?
  - Is there a vulnerability disclosure program and patch SLA?
```

### Hardware Bill of Materials (HBOM) Attestation

```bash
# Generate HBOM from design files using CycloneDX
pip install cyclonedx-bom

# For PCB (KiCad BOM export + CycloneDX)
cyclonedx-py --bom bom.xml   --component-type hardware   --manufacturer "AcmeCorp"   --name "SecurityController v2"

# Verify HBOM signature (vendor-signed HBOM)
openssl dgst -sha256 -verify vendor_pub.pem   -signature hbom.xml.sig hbom.xml

# HBOM entry example (JSON)
{
  "type": "hardware",
  "manufacturer": "NXP Semiconductors",
  "name": "SE050C2HQ1/Z",
  "version": "AR00.03.00",
  "description": "EdgeLock SE050 Secure Element",
  "licenses": [],
  "hashes": [{"alg": "SHA-256", "content": "a3f5..."}],
  "externalReferences": [{
    "type": "advisories",
    "url": "https://www.nxp.com/products/SE050"
  }],
  "properties": [{
    "name": "country-of-origin",
    "value": "Netherlands"
  }]
}
```

### Tamper-Evident Packaging

```
Levels of tamper evidence:

Level 1: Visual tamper evidence
  - Holographic seals with serial numbers
  - Breakaway screws / shear screws
  - Void labels (VOID pattern reveals on removal)
  - Numbered security seals with audit log

Level 2: Mechanical tamper resistance (FIPS 140-3 Level 2+)
  - Epoxy potting of internal components
  - Chassis bolts torqued and sealed with lacquer
  - PCB conformal coating (visible if disturbed)

Level 3: Active tamper detection
  - Capacitive sense: detects case removal
  - Light sensors: detect decap or case opening
  - Conductive mesh over entire PCB (mesh break = zeroize)
  - Pressure-sensitive adhesive with conductive traces

Implementation (battery-backed tamper detection):
  - Separate battery maintains tamper detect logic
  - If tamper triggered: crypto accelerator zeroizes keys in <1ms
  - Log event with timestamp to non-volatile tamper register

Testing:
  - Shock (MIL-STD-810H, Method 516.8)
  - Vibration (MIL-STD-810H, Method 514.8)
  - Temperature cycling (-40°C to +85°C) — does sealing maintain integrity?
```

### COTS Risk Assessment

Commercial Off-the-Shelf hardware risk framework:

```
Risk Matrix:
  Likelihood: How often is this component class targeted?
  Impact: What access does compromise of this component provide?

High-risk COTS categories:
  1. Network equipment (routers, switches, firewalls)
     - BMC/iDRAC/iLO firmware (Baseboard Management Controllers)
     - JTAG/UART debug left exposed (CVE-2019-16649 Supermicro BMC)

  2. Storage controllers (SAS HBA, NVMe controllers)
     - Firmware updates typically unsigned
     - Example: Seagate HDD firmware implant research (2015, Equation Group)

  3. USB peripherals (keyboards, mice, hubs)
     - BadUSB: Reprogrammable firmware on unprotected USB controllers
     - HID injection attacks

Mitigation by risk level:
  Critical (classified, financial, healthcare):
    - 100% X-ray inspection of incoming PCBs
    - Firmware hash verification before deployment
    - Air-gapped procurement and inspection network
    - Known-good sample comparison

  High (enterprise, infrastructure):
    - Approved vendor list (AVL) enforcement
    - Authorized distributor only (no spot buys or broker market)
    - Incoming inspection sampling per MIL-STD-1916 or AQL 0.65
    - Hash firmware against vendor-published values

  Standard (commercial):
    - Authorized distributor
    - Certificate of conformance from supplier
    - Counterfeit screening per SAE AS6081 (distributor standard)
```

### DoD CMMC Hardware Requirements

```
CMMC Level 2 (Advanced, 110 practices from NIST 800-171):
  SA.L2-3.14.7: Identify unauthorized use of systems
  MP.L2-3.8.7: Control use of removable media
  CM.L2-3.4.1: Establish/maintain baseline configs (hardware inventory)
  CM.L2-3.4.2: Establish/enforce security config settings
  SR.L2-3.14.6 (from 800-171r3): Assess supply chain risks

Hardware-specific CMMC controls:
  - Maintain hardware inventory (CMDB with serial numbers, firmware versions)
  - Firmware patching SLA: critical CVEs ≤ 72 hours, high ≤ 30 days
  - Removable media: encrypt (FIPS 140-2/3 validated) or prohibit
  - Debug interfaces: physically disabled on production hardware
  - Side-channel mitigations for systems handling CUI (Controlled Unclassified Info)

CMMC Level 3 (Expert, NIST 800-172):
  - Employ hardware-based security (TPM, HSM, secure boot)
  - Protect firmware using cryptographic mechanisms
  - Detect and respond to supply chain anomalies
  - Conduct red team exercises targeting hardware attack vectors
```

### Anti-Tamper Techniques (Military/Aerospace)

```
MIL-STD-3048: DoD Anti-Tamper specification
NSA CSfC (Commercial Solutions for Classified):
  - Requires defense-in-depth hardware controls

Techniques:
  1. Zeroization: FIPS-validated zeroize on tamper
     (SRAM clear + key register clear in <1ms)

  2. Potting: Entire PCB encased in hard epoxy
     (drill/cut = destroy function + trigger detect)

  3. Secure enclave: Physical envelope with mesh
     - Dallas/Maxim DS3640 secure microcontroller
     - Covers: light, temp, voltage, attack mesh

  4. Optical fiber mesh: Fiber woven through epoxy
     - Light continuity monitored; break = tamper

  5. Code obfuscation + encryption of FPGA bitstream:
     - Xilinx/Intel FPGAs: AES-256 bitstream encryption
     - Key stored in battery-backed SRAM on FPGA

  6. Supply chain provenance tracking:
     - Physically Unclonable Functions (PUF) — unique IC fingerprint
     - Device responds to challenge with PUF-derived response
     - Cannot be cloned (manufactured variation used as ID)

PUF implementation:
  - SRAM PUF: Power-on state of uninitialized SRAM is device-unique
  - Ring oscillator PUF: Manufacturing variation in oscillator frequency
  - Arbiter PUF: Race condition in D-FF varies by chip
  Used for: Key generation without storage, device authentication
```

