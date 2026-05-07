# Hardware Security Reference

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

