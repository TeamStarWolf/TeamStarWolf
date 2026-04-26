# Password Security Reference

> **Scope**: Password hash formats, cracking tools (Hashcat, John the Ripper), attack techniques, secure storage algorithms, enterprise password policies, LAPS, gMSA, MFA, and detection.
> Mapped to NIST SP 800-63B, OWASP Password Storage Cheat Sheet, CIS Benchmarks, and MITRE ATT&CK credential-access techniques (T1110.x).

---

## Table of Contents

- [Password Hash Formats](#password-hash-formats)
- [Password Cracking with Hashcat](#password-cracking-with-hashcat)
- [John the Ripper](#john-the-ripper)
- [Password Attack Types](#password-attack-types)
- [Password Generation and Wordlist Creation](#password-generation-and-wordlist-creation)
- [Secure Password Storage — Developer Reference](#secure-password-storage--developer-reference)
- [Enterprise Password Policies](#enterprise-password-policies)
- [Privileged Account Password Management](#privileged-account-password-management)
- [MFA as Password Supplement](#mfa-as-password-supplement)
- [Detection and Response](#detection-and-response)

---

## Password Hash Formats

### Hash Identification Table

| Hash | Format / Example | Hashcat Mode | Length / Notes |
|------|------------------|--------------|----------------|
| MD5 | `5f4dcc3b5aa765d61d8327deb882cf99` | 0 | 32 hex chars |
| SHA-1 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | 100 | 40 hex chars |
| SHA-256 | `65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5` | 1400 | 64 hex chars |
| SHA-512 | `b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86` | 1700 | 128 hex chars |
| NTLM | `8846f7eaee8fb117ad06bdd830b7586c` | 1000 | 32 hex chars (Windows SAM/NTDS) |
| NTLMv1 | `user::domain:challenge:HASH:HASH` | 5500 | Challenge-response (older Windows auth) |
| NTLMv2 | `user::domain:challenge:HASH:blob` | 5600 | Challenge-response (modern Windows auth) |
| Net-NTLMv2 | `User::Domain:challenge:hash:blob` | 5600 | Active Directory network auth; from Responder capture |
| bcrypt | `$2a$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy` | 3200 | 60 chars; `$2a$`, `$2b$`, `$2y$` prefixes |
| scrypt | `$s2$16384$8$1$SALT$HASH` | 8900 | Memory-hard; less common in databases |
| Argon2id | `$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$RdescudvJCsgt3ub+b+dWRWJTmaaJObG` | 13400 | PHC winner; preferred KDF |
| PBKDF2-SHA256 | `pbkdf2_sha256$260000$SALT$HASH` | 10900 | Django default; FIPS-compliant |
| MD5crypt | `$1$SALT$HASH` | 500 | Old Linux/BSD passwords |
| SHA512crypt | `$6$SALT$HASH` | 1800 | Modern Linux `/etc/shadow` |
| sha256crypt | `$5$SALT$HASH` | 7400 | Linux alternative |
| DES crypt | 13-character string | 1500 | Legacy UNIX; 56-bit key |
| Kerberos TGS-REP 23 | `$krb5tgs$23$*user*domain*service*...` | 13100 | Kerberoasting; RC4-HMAC encrypted ticket |
| Kerberos AS-REP 23 | `$krb5asrep$23$user@domain:HASH` | 18200 | AS-REP roasting; accounts without pre-auth |
| Kerberos TGS AES256 | `$krb5tgs$18$*user*domain*service*...` | 19700 | AES-256 Kerberoasting (harder to crack) |
| DPAPI MasterKey | Binary blob (80 bytes typically) | — | Windows credential store; encrypted with user password |
| WPA/WPA2 Handshake | PMKID / hccapx format | 22000 / 2500 | Wi-Fi pre-shared key cracking |
| WPA-PMKID | `WPA*01*PMKID*BSSID*STA*ESSID*` | 22801 | Clientless WPA capture (hcxtools) |
| SHA-1 salted | `SALT:HASH` or `HASH:SALT` | various | Many web apps; identify by context |
| MySQL 4.x | `606717496665bcba` | 200 | Older MySQL hashes |
| MySQL 5.x | `*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19` | 300 | Current MySQL password hashes |
| Cisco Type 5 | `$1$SALT$HASH` | 500 | MD5crypt; IOS enable secret |
| Cisco Type 8 | `$8$SALT$HASH` | 9200 | PBKDF2-SHA256; IOS 15.3(3)+ |
| Cisco Type 9 | `$9$SALT$HASH` | 9300 | scrypt; IOS 15.3(3)+ |
| Oracle 11g | `S:HASH` | 112 | SHA-1 with salt |
| MSSQL 2012+ | `0x0200HASH` | 1731 | SHA-512; `sys.sql_logins` |
| SAP CODVN B | `{SHA}HASH` | 10300 | SAP application passwords |
| vBulletin 3.x | `HASH:SALT` | 2611 | MD5 salted |
| phpBB3 | `$H$SALT$HASH` | 400 | Phpass portable hash |

### Hash Identification Tools

```bash
# hashid — Python tool for hash format identification
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
hashid -m '5f4dcc3b5aa765d61d8327deb882cf99'  # Show Hashcat mode
hashid -e '5f4dcc3b5aa765d61d8327deb882cf99'  # Show extended info
hashid -f hashes.txt                            # Process file

# hash-identifier — Interactive Python tool
hash-identifier
# Paste hash at prompt; lists likely algorithms

# Hashcat built-in identification
hashcat --identify hash.txt
hashcat --identify --quiet hash.txt | awk '{print $1}'  # Just the mode

# Name That Hash (nth) — modern tool with confidence scores
nth -t '5f4dcc3b5aa765d61d8327deb882cf99'    # Single hash
nth -f hashes.txt                              # File of hashes
nth -t hash --no-banner -g                    # Grep-friendly output

# Manual identification patterns
# $1$ = MD5crypt
# $2a$/$2b$/$2y$ = bcrypt
# $5$ = sha256crypt
# $6$ = sha512crypt
# $argon2id$ = Argon2id
# $krb5tgs$23$ = Kerberos TGS RC4
# $krb5asrep$23$ = AS-REP RC4
```

### Hash Extraction Commands

```bash
# Windows — dump SAM/NTDS hashes
# Impacket secretsdump (remote)
secretsdump.py domain/admin@dc01 -just-dc-ntlm
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

# CrackMapExec hash dump
crackmapexec smb 192.168.1.10 -u admin -p password --ntds

# Mimikatz (local, needs SeDebugPrivilege)
# lsadump::sam — SAM database (local accounts)
# lsadump::dcsync /domain:corp.local /all — DCSync all users
# sekurlsa::logonpasswords — memory credentials

# Linux — shadow file
sudo cat /etc/shadow  # hashtype:$6$... for SHA512crypt

# Network capture — NTLM challenge-response
responder -I eth0 -wrf  # Poison LLMNR/NBT-NS; captures NTLMv2
# Hashes saved to /usr/share/responder/logs/

# Web application hash extraction (example: MySQL)
mysql -u root -p -e "SELECT user, authentication_string FROM mysql.user;"
```

---

## Password Cracking with Hashcat

### Architecture and Hardware

Hashcat is GPU-accelerated using NVIDIA CUDA or AMD OpenCL/ROCm, achieving massively parallel hash computations. CPU-only cracking is feasible only for slow hashes (bcrypt, Argon2id) where GPU advantages diminish.

**Performance benchmarks (approximate):**

| Hardware | MD5 (mode 0) | NTLM (mode 1000) | bcrypt w=12 (mode 3200) |
|----------|-------------|------------------|------------------------|
| RTX 4090 | ~164 GH/s | ~300 GH/s | ~105 kH/s |
| RTX 3090 | ~68 GH/s | ~130 GH/s | ~45 kH/s |
| RTX 2080 Ti | ~32 GH/s | ~60 GH/s | ~22 kH/s |
| Intel i9-13900K (CPU) | ~1.5 GH/s | ~3 GH/s | ~5 kH/s |
| AMD EPYC 7742 (CPU) | ~800 MH/s | ~1.5 GH/s | ~3 kH/s |

**Key implication**: RTX 4090 cracks 8-character NTLM passwords with full ASCII charset (`?a?a?a?a?a?a?a?a`) in approximately 2 hours. Argon2id/bcrypt make GPU cracking impractical even with modern hardware.

### Attack Modes Reference

| Mode (-a) | Name | Description | Use Case |
|-----------|------|-------------|----------|
| 0 | Dictionary | Try words from wordlist | Known breach words, rockyou.txt |
| 1 | Combinator | Concatenate pairs from two wordlists | "password" + "123" = "password123" |
| 3 | Mask (brute force) | Try all combinations matching pattern | Known complexity requirements |
| 6 | Hybrid wordlist + mask | Word from list, append mask | "password123" type patterns |
| 7 | Hybrid mask + wordlist | Prepend mask to word | "123password" type patterns |
| 9 | Prince | PACK-based combinatorial markov chain | Intelligent brute force |

### Basic Usage

```bash
# Dictionary attack (-a 0)
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 0 -a 0 md5_hashes.txt rockyou.txt                         # MD5
hashcat -m 1800 -a 0 shadow_hashes.txt rockyou.txt                   # SHA512crypt
hashcat -m 3200 -a 0 bcrypt_hashes.txt rockyou.txt                   # bcrypt
hashcat -m 13100 -a 0 kerberoast.txt rockyou.txt                     # Kerberos TGS

# Dictionary + rules (-a 0 with -r)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r rules/OneRuleToRuleThemAll.rule
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r best64.rule -r combinator.rule  # Stack rules

# Brute force mask (-a 3)
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?d?d?d?s  # 9-char: Upper+5lower+2digit+special
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a     # 8-char all printable ASCII
hashcat -m 1000 -a 3 hashes.txt ?d?d?d?d?d?d?d?d     # 8-digit PIN
hashcat -m 1000 -a 3 hashes.txt ?l?l?l?l?l?l         # 6 lowercase letters

# Increment mode (try all lengths up to specified)
hashcat -m 1000 -a 3 hashes.txt --increment --increment-min=6 ?a?a?a?a?a?a?a?a

# Combinator (-a 1): concatenate words from two lists
hashcat -m 1000 -a 1 hashes.txt wordlist1.txt wordlist2.txt
# With modification rules applied to left/right word
hashcat -m 1000 -a 1 hashes.txt wordlist1.txt wordlist2.txt -j '$-' -k 'u'

# Hybrid: wordlist + mask (-a 6)
hashcat -m 1000 -a 6 hashes.txt rockyou.txt ?d?d?d      # word + 3 digits
hashcat -m 1000 -a 6 hashes.txt rockyou.txt ?d?d?d?d    # word + 4 digits
hashcat -m 1000 -a 6 hashes.txt rockyou.txt ?s           # word + special char

# Hybrid: mask + wordlist (-a 7)
hashcat -m 1000 -a 7 hashes.txt ?d?d?d rockyou.txt     # 3 digits + word

# Prince attack (-a 9)
hashcat -m 1000 -a 9 hashes.txt wordlist.txt

# Session management for long cracks
hashcat -m 1000 hashes.txt rockyou.txt -r best64.rule --session=crack1
hashcat --session=crack1 --restore   # Resume interrupted session
hashcat --status                     # Show real-time status
hashcat --status-timer=60            # Status update every 60s

# Output options
hashcat -m 1000 hashes.txt rockyou.txt -o cracked.txt                    # Save cracked
hashcat -m 1000 hashes.txt rockyou.txt --outfile-format=3 -o cracked.txt # hash:plain format
hashcat -m 1000 hashes.txt rockyou.txt --show                            # Show already cracked
hashcat -m 1000 hashes.txt --potfile-path=custom.pot --show              # Custom potfile
```

### Hashcat Mask Charset Reference

```
?l = lowercase letters (abcdefghijklmnopqrstuvwxyz) — 26 chars
?u = uppercase letters (ABCDEFGHIJKLMNOPQRSTUVWXYZ) — 26 chars
?d = digits (0123456789) — 10 chars
?s = special characters (space!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~) — 33 chars
?a = all printable ASCII = ?l?u?d?s — 95 chars
?b = all bytes 0x00-0xff — 256 values (use for binary hashes)

# Custom charsets: -1, -2, -3, -4
hashcat -m 1000 -a 3 -1 '!@#$%^&*' hashes.txt ?u?l?l?l?l?l?1?d  # Custom special chars
hashcat -m 1000 -a 3 -1 '0123456789!@#$' hashes.txt ?u?l?l?l?l?l?1?1?1

# Corporate password patterns (very common in enterprises)
# Format: Capital + 5-7 lowercase + 2-3 digits + special
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?d?d?s     # 9 chars
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?l?d?d!    # 9 chars, ends in !
# Season + Year patterns
hashcat -m 1000 -a 0 hashes.txt seasons_years.txt       # Pre-built seasonal wordlist

# PIN / numeric patterns
hashcat -m 1000 -a 3 hashes.txt ?d?d?d?d                # 4-digit PIN
hashcat -m 1000 -a 3 hashes.txt ?d?d?d?d?d?d            # 6-digit PIN (OTP bypass risk)

# Known prefix/suffix attacks
hashcat -m 1000 -a 6 hashes.txt wordlist.txt ?d?d?d?d   # word + 4 digits (Company2024)
hashcat -m 1000 -a 7 hashes.txt ?u wordlist.txt         # Capital + word (CompanyName)
```

### Hashcat Rules Syntax

Rules transform candidate passwords before hashing. A rule file contains one rule per line; each line is applied to every word in the wordlist.

```
# Rule function reference
:    = no-op (identity; leave unchanged)
l    = lowercase all characters
u    = uppercase all characters
c    = capitalize first character, lowercase rest
C    = uppercase first, lowercase rest (inverse of c)
r    = reverse the word
d    = duplicate the word (password → passwordpassword)
f    = reflect/mirror (password → passworddrowssap)
{    = rotate left one position (password → asswordp)
}    = rotate right one position (password → dpasswor)
[ X  = delete first character (or character at position X)
] X  = delete last character (or character at position X)
t    = toggle case of all characters
T N  = toggle case of character at position N
$ X  = append character X to end
^ X  = prepend character X to beginning
s X Y = replace all occurrences of X with Y
S N X = replace character at position N with X
i N X = insert character X before position N
D N  = delete character at position N
p N  = duplicate word N times
' N  = truncate to first N characters
@ X  = remove all occurrences of character X
z N  = duplicate first character N times
Z N  = duplicate last character N times
q    = duplicate every character
k    = swap first two characters
K    = swap last two characters
E    = title case (first letter of each word uppercase)
e X  = title case by separator X

# Conditionally apply rules
>N rule  = apply rule only if length > N
<N rule  = apply rule only if length < N
=N rule  = apply rule only if length == N

# Examples of common rule combinations (one rule per line in rule file):
$1              # append 1
$2              # append 2
$!              # append !
$1$2$3          # append 123
c               # capitalize
c$1             # capitalize + append 1
c$!             # capitalize + append !
l$1             # lowercase + append 1
$2$0$2$4        # append 2024
^2^0^2^4        # prepend 2024 (reversed order)
u$!             # uppercase all + !
r               # reverse
d               # duplicate
$1$!            # append 1!
sa@             # replace a with @
se3             # replace e with 3
so0             # replace o with 0
si1             # replace i with 1
c sa@ se3 so0   # capitalize + leet speak
```

### Key Rule Sets

| Rule File | Location | Rules | Notes |
|-----------|----------|-------|-------|
| `best64.rule` | Hashcat included | 64 | Best 64 rules derived from analysis of real cracks |
| `rockyou-30000.rule` | Hashcat included | 30,000 | Generated from rockyou.txt analysis |
| `dive.rule` | Hashcat included | 99,000+ | Massive comprehensive rule set |
| `OneRuleToRuleThemAll.rule` | GitHub community | ~52,000 | Community-compiled; most effective single ruleset |
| `T0XlC.rule` | Hashcat included | 4,300+ | Corporate password pattern focus |
| `combinator.rule` | Hashcat included | ~166 | Combinatorial modifications |
| `unix-ninja-all.rule` | Community | various | Unix password pattern-aware |

```bash
# Locate hashcat rule directory
find /usr -name "*.rule" -path "*/hashcat/*" 2>/dev/null
# Common path: /usr/share/hashcat/rules/ or /opt/hashcat/rules/

# Run multiple rules simultaneously (combine -r flags)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/T0XlC.rule

# Generate rules from successfully cracked passwords (debug mode)
hashcat -m 1000 hashes.txt rockyou.txt -r best64.rule \
  --debug-mode=4 --debug-file=found_rules.txt
```

### Hashcat Performance Tuning

```bash
# Workload profiles (-w)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -w 1   # Low (responsive system)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -w 2   # Default
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -w 3   # High (dedicated cracking)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -w 4   # Nightmare (unresponsive; max GPU load)

# OpenCL/CUDA optimization
hashcat -m 1000 hashes.txt rockyou.txt -O           # Optimized kernels (slight speed gain)
hashcat -m 1000 hashes.txt rockyou.txt --force      # Ignore warnings (use cautiously)

# Temperature monitoring
hashcat -m 1000 hashes.txt rockyou.txt --gpu-temp-abort=90  # Abort if GPU > 90°C

# Benchmark a specific mode
hashcat -b -m 1000         # Benchmark NTLM
hashcat -b -m 3200         # Benchmark bcrypt
hashcat -b                 # Benchmark all modes

# Use specific GPU devices
hashcat -m 1000 hashes.txt rockyou.txt -d 1        # Use device 1
hashcat -m 1000 hashes.txt rockyou.txt -d 1,2,3    # Use devices 1, 2, 3
hashcat -I                                          # List OpenCL devices
```

---

## John the Ripper

John the Ripper (JtR) is a versatile CPU-focused password cracker with broad format support and a suite of extraction utilities for various file types.

### Basic Cracking

```bash
# Basic crack with auto-format detection
john hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Specify format explicitly
john --format=NT hashes.txt --wordlist=rockyou.txt         # NTLM
john --format=bcrypt hashes.txt --wordlist=rockyou.txt     # bcrypt
john --format=sha512crypt shadow.txt --wordlist=rockyou.txt # Linux shadow
john --format=md5crypt hashes.txt --wordlist=rockyou.txt   # MD5crypt
john --format=krb5tgs hashes.txt --wordlist=rockyou.txt    # Kerberoasting
john --format=krb5asrep hashes.txt --wordlist=rockyou.txt  # AS-REP roasting

# List available formats
john --list=formats                    # All formats
john --list=formats | grep -i ntlm    # Search for NTLM formats
john --list=formats | grep -i krb     # Search for Kerberos formats

# Show cracked passwords
john --show hashes.txt
john --show --format=NT hashes.txt

# Incremental mode (character set brute force)
john --incremental hashes.txt                    # Default charset
john --incremental=Digits hashes.txt             # Digits only
john --incremental=Alpha hashes.txt              # Alpha only
john --incremental=LowerNum hashes.txt           # Lowercase + digits

# Rules-based cracking
john --rules hashes.txt --wordlist=rockyou.txt
john --rules=Jumbo hashes.txt --wordlist=rockyou.txt  # Jumbo ruleset
john --rules=KoreLogic hashes.txt --wordlist=rockyou.txt

# Single crack mode (uses account name/GECOS data to generate candidates)
john --single hashes.txt

# Resume interrupted session
john --restore
john --restore=session_name

# Cracking with multiple wordlists
cat rockyou.txt cewl_output.txt | john --pipe --format=NT hashes.txt
```

### Hash Extraction Utilities

The `*2john` family of tools converts protected files into JtR-crackable hash formats:

```bash
# Archive files
zip2john archive.zip > zip.hash
rar2john archive.rar > rar.hash
7z2john archive.7z > 7z.hash

# Documents
pdf2john.py file.pdf > pdf.hash           # PDF user password
office2john.py document.docx > office.hash  # Office 2007+ docs (.doc, .xls, .ppt, etc.)

# SSH private keys
ssh2john id_rsa > ssh.hash
ssh2john id_ed25519 > ssh_ed25519.hash

# Other
keepass2john database.kdbx > keepass.hash   # KeePass 2.x database
bitlocker2john -i drive.img > bitlocker.hash # BitLocker partition
pfx2john cert.pfx > pfx.hash                # PKCS#12 certificate
signal2john.py signal_db > signal.hash      # Signal encrypted DB
luks2john /dev/sdb1 > luks.hash             # LUKS full-disk encryption
# Then crack:
john --wordlist=rockyou.txt zip.hash
john --wordlist=rockyou.txt keepass.hash
```

### John Configuration and Rules

```bash
# John config file: /etc/john/john.conf or ~/.john/john.conf
# Add custom rules under [List.Rules:Custom]

# Example custom rule in john.conf:
# [List.Rules:Corporate]
# Az"[0-9][0-9][0-9]"   # append 3 digits
# Az"[!@#$%]"           # append special
# Az"[0-9][0-9][0-9][0-9]"Az"[!@#$%]"  # append 4 digits + special

# Performance
john --fork=8 hashes.txt --wordlist=rockyou.txt   # Use 8 CPU cores
john --node=1/3 hashes.txt ...                     # Distributed cracking (node 1 of 3)

# Pot file (previously cracked)
john --pot=mycrack.pot --show hashes.txt
john --pot=/dev/null hashes.txt  # Don't save results (testing)
```

---

## Password Attack Types

### Credential Stuffing (T1110.004)

Credential stuffing uses previously breached username/password pairs from public breach databases to authenticate against other services, exploiting password reuse.

**Attack flow:**
1. Obtain breach database (email:password pairs)
2. Identify target service login endpoint
3. Automate authentication attempts at scale (often via residential proxy networks to evade rate limiting)
4. Collect successful logins (typically 0.5–2% success rate against non-MFA accounts)

**Common tools:**
- **Snipr** — commercial credential stuffing tool with combo list support
- **Storm** — community tool for credential testing
- **OpenBullet / SilverBullet** — configurable credential testing framework (config files per target site)
- **Patator** — multi-purpose brute force tool supporting HTTP, SSH, FTP, MySQL, etc.
- **Burp Suite Intruder** — manual/semi-automated testing

**Breach data sources:**
- Have I Been Pwned (HIBP): `https://haveibeenpwned.com`
- Breach compilation datasets (DeHashed, IntelX, COMB)
- Dark web credential markets

**Defense:**
- MFA — eliminates most credential stuffing risk
- Breached password detection (HIBP API during login / password change)
- Rate limiting per IP, per account, per ASN
- CAPTCHA / bot detection (reCAPTCHA v3, hCaptcha)
- Behavioral analytics (impossible travel, unusual geolocation)
- Credential stuffing-specific signals: many accounts hit from single IP, user-agent patterns

```python
# Example: Check if password appears in breaches (HIBP k-anonymity API)
import hashlib, requests

def is_password_breached(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                     headers={"Add-Padding": "true"})
    for line in r.text.splitlines():
        h, count = line.split(':')
        if h == suffix:
            return int(count)  # Number of times in breaches
    return 0
```

### Password Spraying (T1110.003)

Password spraying tests one or a few common passwords across many accounts to avoid account lockout thresholds (typically 5–10 failed attempts).

**Common spray passwords (in order of effectiveness):**

| Password | Reason Effective |
|----------|-----------------|
| `Season+Year+!` (e.g., `Spring2024!`, `Fall2023!`) | Predictable mandatory rotation compliance |
| `Company123!` / `CompanyName1!` | New-hire default or common pattern |
| `Welcome1` / `Welcome1!` | IT helpdesk reset default |
| `Password1` / `Password1!` | Satisfies most complexity requirements |
| `Monday1` / `January2024!` | Day/month patterns |
| `[CITY][YEAR]!` | Local knowledge spray |
| `Passw0rd` / `P@ssw0rd` | Common leet substitution |
| `[sport team][year]!` | Local sports team reference |

**Tools:**

```bash
# Kerbrute — Kerberos-based spray (no lockout risk on misconfigured DCs)
kerbrute passwordspray -d corp.local --dc 192.168.1.10 users.txt 'Spring2024!'
kerbrute passwordspray -d corp.local --dc 192.168.1.10 users.txt 'Company123!'

# CrackMapExec — SMB spray
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Spring2024!' --continue-on-success
crackmapexec smb dc01 -u users.txt -p passwords.txt --no-bruteforce  # 1:1 pairing

# DomainPasswordSpray (PowerShell)
Invoke-DomainPasswordSpray -Password "Spring2024!" -OutFile spray_results.txt
Invoke-DomainPasswordSpray -UserList users.txt -Password "Company123!" -Delay 30

# MSOLSpray — Office 365 spray
Invoke-MSOLSpray -UserList users.txt -Password "Spring2024!"

# Spray365 — Microsoft 365 / Azure AD
spray365.py spray --spray-file spray_file.s365 --count 1 --lockout 5.0

# Metasploit
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.0/24
set USER_FILE users.txt
set PASS_FILE passwords.txt
set STOP_ON_SUCCESS false
```

**Defense:**
- Microsoft Entra Password Protection: ban `Spring2024!`, `Company123!`, seasonal patterns
- Smart lockout: Entra default 10 failed attempts → 60-second lockout (exponentially grows)
- Conditional Access: require MFA; block legacy authentication protocols (which bypass MFA)
- Monitor for Event ID 4625 (failed logon) spikes across multiple accounts from single IP
- Alert on >50 4625 events in 5 minutes with same password across different accounts

### Brute Force (T1110.001)

Exhaustive combination attack; only practical for short passwords with fast hashes or when specific character sets are known.

```bash
# Hashcat brute force examples (all printable ASCII)
hashcat -m 0 -a 3 md5_hashes.txt ?a?a?a?a?a?a       # MD5 up to 6 chars — seconds
hashcat -m 1000 -a 3 ntlm.txt ?a?a?a?a?a?a?a?a      # NTLM 8 chars — ~2 hours RTX 4090
hashcat -m 3200 -a 3 bcrypt.txt ?a?a?a?a?a?a?a?a    # bcrypt 8 chars — years

# Targeted: known charset (e.g., complex requirement: Upper+lower+digit+special)
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?d?d?s  # 9-char pattern

# Online brute force (Hydra)
hydra -l admin -P rockyou.txt ssh://192.168.1.10 -t 4 -f
hydra -l admin -P rockyou.txt ftp://192.168.1.10
hydra -L users.txt -P passwords.txt 192.168.1.10 http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid credentials"
hydra -l admin@corp.com -P rockyou.txt smtp://mail.corp.com

# Medusa — parallel online brute force
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M ssh -t 4

# Ncrack
ncrack -U users.txt -P rockyou.txt ssh://192.168.1.10
```

**Defense:**
- Enforce long minimum length (≥12 characters): dramatically expands search space
- Account lockout: 5-10 failed attempts → 30+ minute lockout (on-premises)
- Network-level rate limiting: fail2ban, iptables, nginx limit_req
- MFA: renders brute force useless for live services

### Rainbow Tables (T1110)

Pre-computed hash chains mapping plaintext → hash for fast lookup. Defeated by salting.

**How they work:**
1. Pre-compute chains: `plaintext → hash → reduce → hash → reduce → ...` (chain)
2. Store only chain start and end
3. To crack: run hash through reduction function chain until endpoint found in table
4. Trace chain from start to find plaintext

**Defeated by salting:**
- Each password stored as `hash(salt + password)` where salt is random and unique per account
- Even if two users have identical passwords, their hashes differ due to unique salts
- Attacker would need a separate rainbow table for every possible salt value

**Relevant tools:**
```bash
# Ophcrack — Windows SAM/NTLM rainbow table cracker (GUI)
ophcrack -g              # GUI mode
ophcrack -t /path/to/tables -f hashes.txt -o cracked.txt  # CLI

# RainbowCrack — generic rainbow table attack
rcrack /path/to/tables -h HASH
rcrack /path/to/tables -f hashes.txt

# Generate custom rainbow tables (rtgen)
rtgen md5 loweralpha 1 7 0 3800 33554432 0  # MD5, lowercase a-z, 1-7 chars
rtsort *.rt                                   # Sort table for lookup
```

---

## Password Generation and Wordlist Creation

### CeWL (Custom Word List Generator)

Crawls target websites and generates wordlists from page content — highly effective when targeting organization-specific passwords.

```bash
# Basic crawl with 3 levels depth, minimum 5 chars
cewl https://company.com -d 3 -m 5 -w company_words.txt

# Include email addresses
cewl https://company.com -d 2 -m 5 -e -w words_with_email.txt

# Follow offsite links
cewl https://company.com -d 2 -m 4 --offsite -w extended.txt

# Include numbers and handle authentication
cewl https://portal.company.com -d 2 -m 5 --auth_type basic \
  --auth_user admin --auth_pass password -w portal_words.txt

# Verbose output to see what's being scraped
cewl https://company.com -d 2 -v -w output.txt

# Common workflow: CeWL → Hashcat hybrid
cewl https://target.com -d 2 -m 4 -w target.txt
hashcat -m 1000 -a 6 hashes.txt target.txt ?d?d?d?d  # word + 4 digits
hashcat -m 1000 -a 0 hashes.txt target.txt -r best64.rule
```

### CUPP (Common User Passwords Profiler)

Generates targeted wordlists based on OSINT about a specific person (name, birthday, significant dates, pet names, etc.).

```bash
cupp -i   # Interactive mode — prompts for target info:
           # First name, last name, nickname, birthdate
           # Partner name, partner birthdate
           # Child name, pet name, company
           # Keywords (hobbies, interests)
           # Leet mode: replace letters with numbers/symbols
           # Generates file: firstname.txt

cupp -l   # Download pre-built wordlists from CUPP repository
cupp -a   # Parse alecto.db (default user/pass combos for devices)
cupp -w existing_wordlist.txt  # Enhance existing wordlist with profile words
```

### Mentalist (GUI Wordlist Generator)

GUI tool for rule-based wordlist generation. Allows visual construction of complex transformation chains without memorizing rule syntax. Available at `github.com/sc0tfree/mentalist`.

### Wordlist Sources

| Source | Size | URL | Notes |
|--------|------|-----|-------|
| rockyou.txt | 14.3M passwords | Pre-installed on Kali/Parrot | 2009 RockYou breach; most common |
| rockyou2024.txt | 10 billion entries | GitHub/various mirrors | Compiled from multiple breaches |
| SecLists | Various | `github.com/danielmiessler/SecLists` | Curated; passwords/, usernames/, web/ |
| Probable-Wordlists | Various | `github.com/berzerk0/Probable-Wordlists` | Frequency-sorted; great for targeted attacks |
| CrackStation | 1.5B entries | `crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm` | Human + hash wordlists |
| PWDB (Pwdb-Public) | 1B+ | `github.com/ignis-sec/Pwdb-Public` | Passwords from public breaches |
| Weakpass | Various | `weakpass.com` | Collection of password lists; sortable by target |
| Hashes.org | Various | (archived) | Pre-cracked hashes searchable |

```bash
# Download and prepare rockyou.txt (Kali)
ls /usr/share/wordlists/rockyou.txt    # Already present
gunzip /usr/share/wordlists/rockyou.txt.gz  # If compressed

# SecLists common password lists
ls /usr/share/seclists/Passwords/
# Common: darkweb2017-top10000.txt, Common-Credentials/top-passwords-shortlist.txt
# usernames: names.txt, top-usernames-shortlist.txt

# Prepare custom wordlist (sort, dedup, min length)
sort -u combined_wordlist.txt | awk 'length >= 6' > prepared.txt
wc -l prepared.txt  # Count entries

# Merge and deduplicate multiple wordlists
cat rockyou.txt company_words.txt cupp_output.txt | sort -u > mega_wordlist.txt

# Extract words meeting complexity requirements (min 8 chars, has upper/digit/special)
grep -P '^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*]).{8,}$' rockyou.txt > complex_only.txt

# Generate numeric patterns
crunch 4 4 0123456789 -o pins.txt                  # All 4-digit PINs
crunch 8 8 0123456789 -o 8digit_pins.txt           # All 8-digit PINs
crunch 6 10 abcdefghijklmnopqrstuvwxyz -o alpha.txt # 6-10 char lowercase
# Crunch with pattern
crunch 10 10 -t Company@@## -o company_pattern.txt # Company + 2 alpha + 2 digit
```

---

## Secure Password Storage — Developer Reference

### Algorithms to NEVER Use for Passwords

The following algorithms are cryptographically fast — designed for speed, which makes them catastrophically unsuitable for password storage:

| Algorithm | Why Unsuitable | Example Attack Speed (RTX 4090) |
|-----------|---------------|-------------------------------|
| MD5 (unsalted) | Reversible via rainbow table; ~164 GH/s cracking | All 8-char passwords cracked in ~seconds |
| MD5 (salted) | Still 164 GH/s per salt; GPU makes salting irrelevant at scale | Minutes-hours for most passwords |
| SHA-1 (salted) | ~68 GH/s; same issue | Minutes-hours |
| SHA-256 (salted) | ~22 GH/s; still too fast | Hours-days for complex |
| SHA-512 (salted) | ~8 GH/s; still too fast | Hours-days for complex |
| DES crypt | Weak 56-bit key; legacy | Near-instant |
| bcrypt cost < 10 | Too fast on modern hardware | Minutes for short passwords |

**Rule**: If an algorithm was designed for speed (checksums, data integrity), do not use it for passwords.

### Recommended Algorithms (OWASP + NIST SP 800-63B)

#### Argon2id — First Choice (OWASP Primary Recommendation)

Winner of the Password Hashing Competition (PHC) 2015. Memory-hard algorithm that maximizes resistance to GPU/ASIC cracking.

```python
# Python — argon2-cffi library
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

ph = PasswordHasher(
    time_cost=3,        # Number of iterations (increase if hardware is fast)
    memory_cost=65536,  # Memory in KiB (64 MiB; increase to 128+ for high security)
    parallelism=4,      # Parallel threads (match server core count)
    hash_len=32,        # Output hash length in bytes
    salt_len=16         # Salt length in bytes (16 = 128 bits; minimum)
)

# Hash a password
hashed = ph.hash("user_supplied_password")
# Output: $argon2id$v=19$m=65536,t=3,p=4$SALT$HASH

# Verify password
try:
    ph.verify(hashed, "user_supplied_password")   # Returns True if correct
    # Optionally: check if parameters need upgrading
    if ph.check_needs_rehash(hashed):
        new_hash = ph.hash("user_supplied_password")
        # Update database with new_hash
except VerifyMismatchError:
    pass  # Wrong password — do not reveal to user
except (VerificationError, InvalidHashError):
    pass  # Corrupted hash

# PHP — password_hash() with PASSWORD_ARGON2ID
$hash = password_hash($password, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,  // 64 MiB
    'time_cost'   => 3,
    'threads'     => 4,
]);
$valid = password_verify($password, $hash);
```

**OWASP 2023 minimum parameters:**
- `m=19456` (19 MiB), `t=2`, `p=1` — absolute minimum
- `m=65536` (64 MiB), `t=3`, `p=4` — recommended
- `m=262144` (256 MiB), `t=4`, `p=8` — high-security contexts

#### bcrypt — Second Choice (Wide Compatibility)

Battle-tested algorithm with excellent library support. Note 72-byte input limit.

```python
# Python — bcrypt library
import bcrypt

# Hash a password
password = b"user_supplied_password"
salt = bcrypt.gensalt(rounds=12)   # Work factor: 2^12 = 4,096 iterations
                                    # rounds=14 for high-security (slower)
hashed = bcrypt.hashpw(password, salt)
# Output: $2b$12$SALT/HASH (60 chars)

# Verify
is_valid = bcrypt.checkpw(password, hashed)  # Returns True/False

# Handle 72-byte limit: hash long passwords first
import hashlib, base64
def bcrypt_hash_long_password(password: str) -> bytes:
    # Pre-hash with SHA-256 to handle passwords > 72 bytes
    pre_hashed = base64.b64encode(hashlib.sha256(password.encode()).digest())
    return bcrypt.hashpw(pre_hashed, bcrypt.gensalt(rounds=12))

# Node.js — bcryptjs
const bcrypt = require('bcryptjs');
const saltRounds = 12;
const hash = await bcrypt.hash(password, saltRounds);
const match = await bcrypt.compare(password, hash);

# PHP — built-in
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
$valid = password_verify($password, $hash);
// Check if rehash needed (e.g., cost increased)
if (password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => 14])) {
    $newHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 14]);
}
```

**Work factor guidance:**
- Minimum: 10 (OWASP 2023 minimum; deprecated)
- Recommended: 12 (hash takes ~0.3 seconds; good balance)
- High security: 14 (hash takes ~1.5 seconds; privileged accounts)
- Target ~1 second hash time on target hardware; adjust rounds accordingly

#### PBKDF2-HMAC-SHA256 — FIPS/Compliance Environments

NIST-approved and FIPS-compliant. Not memory-hard (GPU can parallelize), but acceptable with high iteration counts.

```python
# Python — standard library
import hashlib, os, base64

def pbkdf2_hash(password: str) -> str:
    salt = os.urandom(32)                         # 256-bit salt
    iterations = 600000                            # OWASP 2023: 600,000 for SHA-256
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
        dklen=32                                   # 256-bit output
    )
    # Store: iterations:salt_hex:hash_hex
    return f"{iterations}:{salt.hex()}:{key.hex()}"

def pbkdf2_verify(password: str, stored: str) -> bool:
    iterations, salt_hex, hash_hex = stored.split(':')
    salt = bytes.fromhex(salt_hex)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, int(iterations))
    return hmac.compare_digest(key.hex(), hash_hex)  # Constant-time comparison

# Django uses PBKDF2-SHA256 by default with 600,000 iterations (Django 4.2+)
# Format: pbkdf2_sha256$600000$SALT$HASH

# Java — Spring Security
PasswordEncoder encoder = new Pbkdf2PasswordEncoder("", 16, 600000,
    Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);
String encoded = encoder.encode(rawPassword);
boolean matches = encoder.matches(rawPassword, encoded);
```

**Iteration count guidance (OWASP 2023):**
- PBKDF2-SHA1: 1,300,000 iterations
- PBKDF2-SHA256: 600,000 iterations
- PBKDF2-SHA512: 210,000 iterations

#### scrypt — Memory-Hard Alternative

Memory-hard algorithm; excellent GPU resistance. Harder to configure correctly than Argon2id.

```python
# Python — standard library (Python 3.6+)
import hashlib, os

def scrypt_hash(password: str) -> str:
    salt = os.urandom(32)
    # OWASP recommendation: N=2^17, r=8, p=1 (128 MiB memory)
    # Minimum: N=2^15 (32 MiB), r=8, p=1
    key = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=131072,   # N = 2^17 = 131,072 (CPU/memory cost; must be power of 2)
        r=8,        # Block size factor (memory per block = 128*r = 1024 bytes)
        p=1,        # Parallelization factor
        dklen=64    # 512-bit output
    )
    return f"{n}:{r}:{p}:{salt.hex()}:{key.hex()}"

# Note: scrypt memory = 128 * N * r bytes
# N=131072, r=8: 128 * 131072 * 8 = 128 MiB per hash
# N=32768, r=8: 128 * 32768 * 8 = 32 MiB (minimum for OWASP)
```

### Parameters Comparison (OWASP 2023)

| Algorithm | OWASP Minimum Parameters | Memory Required | GPU-Resistant | FIPS-Compliant |
|-----------|--------------------------|----------------|---------------|----------------|
| Argon2id | t=2, m=19456 KiB (19 MiB), p=1 | 19 MiB min | Yes (memory-hard) | No (not FIPS) |
| bcrypt | work factor ≥ 10 (recommend 12) | ~4 KiB | Moderate | No |
| scrypt | N=2^15 (32768), r=8, p=1 | 32 MiB min | Yes (memory-hard) | No |
| PBKDF2-SHA256 | 600,000 iterations | Minimal | No | Yes |
| PBKDF2-SHA512 | 210,000 iterations | Minimal | No | Yes |

### Pepper (Application-Level Secret)

A pepper is a secret value added to the password before hashing, stored separately from the database (e.g., in application config, HSM, or secrets manager). Unlike a salt, the pepper is:
- The same across all passwords (not stored per-password)
- Known only to the application, not to a database attacker

```python
import os, hmac, hashlib
from argon2 import PasswordHasher

PEPPER = os.environ['PASSWORD_PEPPER']  # From secrets manager; never hardcode

def hash_with_pepper(password: str) -> str:
    # HMAC the password with the pepper before passing to Argon2id
    peppered = hmac.new(PEPPER.encode(), password.encode(), hashlib.sha256).hexdigest()
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
    return ph.hash(peppered)
```

---

## Enterprise Password Policies

### NIST SP 800-63B (2024 Revision) Key Guidelines

NIST guidance has dramatically changed from legacy complexity rules. The 2024 revision codifies these modern recommendations:

**What to REQUIRE:**
- Minimum 8 characters for memorized secrets (longer strongly encouraged)
- Allow up to at least 64 characters
- Accept all printable ASCII and Unicode (including spaces — enables passphrases)
- Check against breached password lists at creation and change
- Offer strength meter feedback (optional but recommended)

**What to PROHIBIT (from the standard itself):**
- DO NOT require periodic rotation unless compromise is suspected — rotation reduces security by causing predictable patterns (`Spring2024!` → `Summer2024!`)
- DO NOT impose complexity rules (uppercase/digit/special requirements) — complexity rules reduce security by causing predictable patterns and reducing passphrase use
- DO NOT use knowledge-based authentication (KBA/security questions) as a primary or additional factor
- DO NOT truncate passwords
- DO NOT allow paste to be disabled (disabling paste blocks password manager use)

**Breached password check implementation:**
```python
# Check at registration and password change
def validate_password_not_breached(password: str) -> bool:
    '''Returns True if password is safe (not in known breaches).'''
    count = check_hibp(password)  # From Section 4 HIBP function
    if count > 0:
        raise ValueError(f"This password has appeared in {count:,} data breaches. "
                         "Please choose a different password.")
    return True

# For offline check: maintain local copy of HIBP SHA-1 prefix list
# Download from: https://haveibeenpwned.com/Passwords (download the full SHA-1 ordered by count)
# Update periodically (monthly)
```

### Microsoft Entra (Azure AD) Password Protection

Microsoft Entra Password Protection prevents use of common and organization-specific weak passwords in both cloud (Azure AD) and on-premises (Windows Server AD) environments.

**Components:**
- **Global banned password list**: Microsoft-maintained; continuously updated; includes seasonal patterns, common substitutions (P@ssw0rd, Passw0rd, etc.)
- **Custom banned password list**: Organization-specific terms (company name, products, locations, mascots)
- **DC Agent**: Windows Server AD component; enforces policy at domain controllers
- **Proxy Service**: Forwards DC Agent policy requests to cloud API

```powershell
# View Entra Password Protection configuration
Get-MgPoliciesAuthenticationMethodsPolicy
Get-AzureADMSPasswordAuthenticationMethod  # Legacy cmdlet

# Configure custom banned passwords (Entra admin portal or Graph API)
# Settings > Authentication methods > Password protection

# On-premises DC Agent installation
# 1. Install Microsoft Entra Password Protection Proxy on member server
# 2. Install DC Agent on each domain controller
# 3. Register proxy: Register-AzureADPasswordProtectionProxy -AccountUpn admin@corp.com
# 4. Register forest: Register-AzureADPasswordProtectionForest -AccountUpn admin@corp.com

# Check DC agent status and last policy download
Get-AzureADPasswordProtectionDCAgent
Get-AzureADPasswordProtectionSummaryReport  # Policy effectiveness report

# Smart Lockout settings (Entra)
# Default: 10 failed attempts → 60-second lockout
# Threshold and duration increase with subsequent lockouts
# Configure via: Entra admin center > Security > Authentication methods > Password protection
```

### CIS Benchmark Password Recommendations

| Setting | CIS Level 1 Recommendation | NIST SP 800-63B |
|---------|---------------------------|-----------------|
| Minimum password length | 14 characters | 8 characters (encourage longer) |
| Maximum password length | 128+ characters | At least 64 characters |
| Complexity requirements | Not required | Not required |
| Password rotation | Not required (only on breach) | Only on suspected compromise |
| Password history | 24 passwords remembered | Not specified |
| Account lockout threshold | 5-10 failed attempts | Implement; avoid over-restriction |
| Account lockout duration | 15 minutes (or admin reset) | Contextual |
| MFA | Required for privileged accounts | AAL2 required for sensitive |
| Breached password check | Recommended | Required at set/change |

### Active Directory Password Fine-Grained Policies (PSO)

Apply different password policies to specific users or groups via Password Settings Objects:

```powershell
# Create a Fine-Grained Password Policy (PSO)
New-ADFineGrainedPasswordPolicy -Name "ServiceAccounts" `
    -Precedence 10 `
    -MinPasswordLength 20 `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false `
    -LockoutThreshold 3 `
    -LockoutDuration "00:30:00" `
    -LockoutObservationWindow "00:30:00" `
    -MaxPasswordAge "00.00:00:00"  # 0 = never expires (for managed service accounts)

# Apply PSO to a group
Add-ADFineGrainedPasswordPolicySubject -Identity "ServiceAccounts" `
    -Subjects "SVC_Accounts_Group"

# View resultant PSO for a user
Get-ADUserResultantPasswordPolicy -Identity "svc_webapp"

# View all PSOs
Get-ADFineGrainedPasswordPolicy -Filter *

# Default domain policy
Get-ADDefaultDomainPasswordPolicy
Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -LockoutThreshold 10
```

---

## Privileged Account Password Management

### LAPS (Local Administrator Password Solution)

Windows LAPS (built into Windows 11 22H2+ and Server 2022 22H2+) automatically manages and rotates local administrator account passwords, storing them in Active Directory with access controls.

```powershell
# Legacy LAPS (Microsoft LAPS download) vs Windows LAPS (built-in)
# Windows LAPS preferred — use built-in cmdlets

# Active Directory: extend schema for Windows LAPS
Update-LapsADSchema

# Set permissions: allow computer objects to write their own password
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=corp,DC=local"

# Set permissions: who can READ LAPS passwords (restrict tightly)
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=corp,DC=local" `
    -AllowedPrincipals "Helpdesk_Group", "Domain Admins"

# Configure LAPS policy via Group Policy or Intune
# Settings: password length, complexity, rotation frequency
# GPO path: Computer Config > Admin Templates > System > LAPS

# Retrieve LAPS password (authorized users only)
Get-LapsADPassword -Identity "WORKSTATION01" -AsPlainText
Get-LapsADPassword -Identity "WORKSTATION01"  # Shows expiry without plaintext

# Force immediate password rotation
Invoke-LapsPolicyProcessing  # On the target computer
Reset-LapsPassword -Identity "WORKSTATION01"  # From DC (schedules next rotation)

# Find computers with expiring LAPS passwords
Get-ADComputer -Filter * -Properties "msLAPS-PasswordExpirationTime" |
  Where-Object { $_."msLAPS-PasswordExpirationTime" -lt (Get-Date) }
```

**Security controls:**
- Only authorized security groups can read LAPS passwords
- Each workstation has a unique, random local admin password
- Automatic rotation prevents pass-the-hash attacks using harvested admin credentials
- Audit access: AD audit logs capture all LAPS password reads

### Group Managed Service Accounts (gMSA)

gMSAs automatically manage service account passwords — no human ever knows or sets the password. Windows Key Distribution Service (KDS) rotates passwords every 30 days (default configurable).

```powershell
# Prerequisites: KDS root key (one-time setup per forest)
Add-KdsRootKey -EffectiveImmediately   # Wait ~10 hours in production (DC replication)
Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)  # For lab use

# Create gMSA
New-ADServiceAccount `
    -Name "svc_webapp" `
    -DNSHostName "webapp.corp.local" `
    -PrincipalsAllowedToRetrieveManagedPassword "WebServers_Group" `  # Computer objects or groups
    -ManagedPasswordIntervalInDays 30 `
    -Description "gMSA for IIS web application pool"

# Install gMSA on target server(s)
Install-ADServiceAccount -Identity "svc_webapp"
Test-ADServiceAccount -Identity "svc_webapp"  # Verify installation

# Configure IIS application pool to use gMSA (no password field)
# Set Identity to: corp\svc_webapp$ (note the $)

# Configure Windows service to use gMSA
sc.exe config "MyService" obj="corp\svc_webapp$" password=""

# Remove gMSA
Remove-ADServiceAccount -Identity "svc_webapp" -Confirm:$false
```

**Advantages over traditional service accounts:**
- Automatic password rotation — no maintenance required
- Password is 240-character random value; resistant to brute force
- Multiple servers share same gMSA identity; eliminates credential sync issues
- Cannot be used interactively (no human password)
- Kerberos delegation configurable per gMSA

### PAM Vault Integration

Enterprise Privileged Access Management (PAM) solutions provide just-in-time (JIT) access and automatic password rotation for privileged accounts:

| Solution | Key Features |
|----------|-------------|
| CyberArk Privileged Cloud | Vaulted credentials; session recording; automated rotation; Dual Control |
| HashiCorp Vault | Dynamic secrets; just-in-time credentials; database plugins; audit logs |
| BeyondTrust Password Safe | Session management; SSH key rotation; cloud integration |
| Delinea Secret Server | Web-based vault; approval workflows; checkout/check-in model |

```bash
# HashiCorp Vault — just-in-time AD credentials
vault secrets enable ad
vault write ad/config \
    binddn="CN=vault,OU=ServiceAccounts,DC=corp,DC=local" \
    bindpass="$VAULT_AD_PASSWORD" \
    url="ldaps://dc01.corp.local" \
    userdn="OU=ServiceAccounts,DC=corp,DC=local"

vault write ad/roles/sql-admin \
    service_account_name="svc_sqladmin@corp.local" \
    ttl=1h

# Request just-in-time credential (rotated automatically after TTL)
vault read ad/creds/sql-admin
# Returns: username, current_password, last_vault_rotation, password_next_rotation
```

---

## MFA as Password Supplement

### Why MFA Defeats Most Password Attacks

| Attack Type | Defeated by MFA? | Notes |
|-------------|-----------------|-------|
| Credential stuffing | Yes | Stolen password alone is insufficient |
| Password spraying | Yes | Even correct password requires second factor |
| Brute force (online) | Yes | Can't bruteforce the second factor |
| Brute force (offline hash) | No | Attacker already has hash; MFA not in play |
| Phishing (standard) | Partial | TOTP codes can be phished in real-time (AiTM) |
| Phishing (AiTM proxy) | No — unless phishing-resistant | Evilginx2 bypasses TOTP |
| SIM swap | No | Defeats SMS OTP; not TOTP/hardware keys |

### NIST AAL Levels (SP 800-63B)

| Level | Description | Factors Required | Examples | Use Cases |
|-------|-------------|-----------------|---------|-----------|
| AAL1 | Single factor | Password alone acceptable | Password | Low-risk, general public |
| AAL2 | Two factors, one cryptographic | Password + OTP/push | TOTP app, push notification | Most enterprise applications |
| AAL3 | Hardware cryptographic device | Password + hardware key | FIDO2 YubiKey, PIV/CAC | High-value targets, privileged access |

### MFA Types by Phishing Resistance

**Phishing-resistant MFA (AAL3 / FIDO2):**
- **FIDO2/WebAuthn hardware keys**: YubiKey, Google Titan Key, Feitian keys
  - Binds authentication to origin domain — cannot be phished by fake sites
  - Passkeys: same cryptography as hardware keys but stored in device TPM/iCloud/Google
- **PIV/CAC smart cards**: US government standard; certificate-based; phishing-resistant
- **Windows Hello for Business**: Hardware-backed key stored in TPM; tied to device+user identity

**Phishing-susceptible but generally sufficient (AAL2):**
- **TOTP apps**: Google Authenticator, Microsoft Authenticator, Authy, 1Password TOTP
  - Vulnerable to real-time phishing (AiTM): attacker relays OTP code in real-time
  - Mitigate AiTM: Conditional Access policies, token binding
- **Push notification with number matching**: Approve/Deny prompt + verify displayed number
  - Number matching prevents MFA fatigue attacks
  - Microsoft Authenticator, Duo, Okta Verify
- **Hardware TOTP tokens**: RSA SecurID, Yubico OTP (not FIDO2 mode)

**Weak/Avoid for sensitive systems:**
- SMS OTP: vulnerable to SIM swap, SS7 attacks, malware interception
- Email OTP: dependent on email account security; same attack surface as account itself
- Security questions: not MFA; knowledge-based; phishable; do not use

### Entra Conditional Access MFA Policies

```powershell
# Require MFA for all users (PowerShell Graph SDK)
$conditions = @{
    Users = @{ IncludeUsers = @("All") }
    Applications = @{ IncludeApplications = @("All") }
}
$grantControls = @{
    Operator = "OR"
    BuiltInControls = @("Mfa")
}
New-MgIdentityConditionalAccessPolicy -DisplayName "Require MFA - All Users" `
    -State "enabled" -Conditions $conditions -GrantControls $grantControls

# Require phishing-resistant MFA for admins (FIDO2/Windows Hello)
$adminConditions = @{
    Users = @{ IncludeRoles = @("Global Administrator", "Privileged Role Administrator") }
    Applications = @{ IncludeApplications = @("All") }
}
$phishingResistantGrant = @{
    Operator = "OR"
    AuthenticationStrength = @{ Id = "00000000-0000-0000-0000-000000000004" }  # Phishing-resistant strength
}

# Block legacy authentication (prevents MFA bypass)
$legacyConditions = @{
    Users = @{ IncludeUsers = @("All") }
    ClientAppTypes = @("exchangeActiveSync", "other")  # Legacy auth protocols
}
$blockGrant = @{ BuiltInControls = @("Block") }
New-MgIdentityConditionalAccessPolicy -DisplayName "Block Legacy Authentication" `
    -State "enabled" -Conditions $legacyConditions -GrantControls $blockGrant
```

---

## Detection and Response

### Attack Detection

#### Windows Event IDs

| Event ID | Description | Attack Indicator |
|----------|-------------|-----------------|
| 4625 | An account failed to log on | Brute force / spray source |
| 4740 | A user account was locked out | Spray/brute force victim |
| 4776 | NTLM authentication | Pass-the-hash or spray via NTLM |
| 4768 | Kerberos TGT requested | Normal; spikes indicate enumeration |
| 4769 | Kerberos service ticket requested | Kerberoasting (look for encryption type 0x17 = RC4) |
| 4771 | Kerberos pre-authentication failed | AS-REP roasting attempts; spray against Kerberos |
| 4648 | Logon with explicit credentials | Lateral movement / pass-the-hash |
| 4672 | Special privileges assigned | Admin logon; track for unusual accounts |
| 4663 | Object access attempt | NTDS.dit access (credential dumping) |
| 4656 | Handle to object requested | SAM/NTDS.dit access attempts |
| 4657 | Registry value modified | SAM database access via registry |

**Sysmon Events (if deployed):**
- Event ID 10 (ProcessAccess): LSASS access → credential dumping (Mimikatz, ProcDump)
- Event ID 1 (ProcessCreate): hashcat.exe, john.exe, mimikatz.exe, pwdump.exe process creation

#### Linux / Unix Detection

```bash
# Monitor auth.log for brute force patterns
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20
# Shows: count + source IP; high counts = brute force

# Real-time monitoring
tail -f /var/log/auth.log | grep "Failed password"
journalctl -fu sshd | grep "Failed"

# Detect successful logins after failures (brute force success)
grep -E "Failed password|Accepted password" /var/log/auth.log | \
  awk '{print $1, $2, $3, $11}' | sort | uniq -c

# fail2ban status
fail2ban-client status sshd    # Show banned IPs
fail2ban-client status         # All jails
```

### Alert Thresholds (SIEM Rules)

```
# Brute Force Detection (single account)
ALERT if:
  EventID = 4625 AND
  TargetAccount = SAME and
  Count > 10 WITHIN 5 minutes AND
  IpAddress = SAME
→ Severity: HIGH

# Password Spraying Detection (single source, multiple accounts)
ALERT if:
  EventID = 4625 AND
  IpAddress = SAME AND
  COUNT(DISTINCT TargetAccount) > 20 WITHIN 5 minutes
→ Severity: CRITICAL (definitively spray)

# Account Lockout Spike
ALERT if:
  EventID = 4740 AND
  COUNT(DISTINCT TargetAccount) > 5 WITHIN 5 minutes
→ Severity: HIGH (spray with lockouts)

# Kerberoasting Detection
ALERT if:
  EventID = 4769 AND
  TicketEncryptionType = 0x17 (RC4-HMAC) AND  # Unusual for modern AD
  Count > 5 WITHIN 10 minutes
→ Severity: HIGH

# AS-REP Roasting Detection
ALERT if:
  EventID = 4768 AND
  PreAuthType = 0 AND  # Pre-auth not required
  COUNT(DISTINCT TargetAccount) > 3 WITHIN 5 minutes
→ Severity: HIGH

# LSASS Access (Credential Dumping)
ALERT if:
  Sysmon EventID = 10 AND
  TargetImage CONTAINS "lsass.exe" AND
  GrantedAccess IN (0x1010, 0x1410, 0x143a, 0x1fffff)  # Known dump access masks
→ Severity: CRITICAL (immediate response)
```

### Detection of Hashcat in Environment

Hashcat running inside a corporate environment (not just cracking external dumps) indicates:
- Insider threat cracking corporate credentials
- Attacker running cracking on compromised high-GPU workstation
- Red team / authorized testing

```
# Endpoint detection signals
Sysmon EventID 1: Process creation
  ProcessName: hashcat.exe, hashcat64.exe
  CommandLine contains: -m 1000, -m 1800, -m 13100

# GPU process monitoring
Performance Counter: GPU utilization sustained > 95% for > 30 minutes
  Combined with: hashcat/john process name

# Network detection (cloud cracking)
ALERT: Large outbound file transfer (.hccapx, shadow, ntds.dit files)
  Followed by: Large compute instance spin-up in cloud account
```

### Incident Response — Credential Compromise

```
Playbook: Suspected Credential Compromise

1. CONTAIN
   □ Force password reset for affected accounts immediately
   □ Revoke active sessions (Entra: Revoke-MgUserSignInSession, Azure AD: Revoke-AzureADUserAllRefreshToken)
   □ If service account compromised: rotate gMSA or reset service account + all services using it
   □ Enable MFA immediately if not already enforced

2. INVESTIGATE
   □ Pull Event ID 4625/4624 logs for the affected account
   □ Identify source IPs and geolocations
   □ Check for successful authentications during / after attack window
   □ Determine if NTDS.dit, SAM, or LSASS was accessed (Event 4663, Sysmon 10)
   □ Review Azure AD / Entra sign-in logs for unusual access patterns

3. REMEDIATE
   □ If domain-wide dump suspected: reset ALL privileged account passwords (Domain Admins, Enterprise Admins, Schema Admins)
   □ Reset krbtgt password TWICE (48 hours apart) to invalidate all Kerberos tickets
   □ Audit and remove unauthorized persistence (accounts, scheduled tasks, registry run keys)
   □ Deploy phishing-resistant MFA for all privileged accounts

4. HARDEN
   □ Implement Entra Password Protection with banned password list
   □ Deploy Windows LAPS for all workstations and servers
   □ Convert service accounts to gMSA where possible
   □ Enable Credential Guard (prevents LSASS memory dumps)
   □ Enable Protected Users security group for privileged accounts
   □ Consider tiered administration model (Tier 0/1/2 separation)

# PowerShell: Reset krbtgt (must do twice)
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$(New-Guid)$(New-Guid)" -Force)
# Wait 48+ hours (2x domain replication interval), then reset again

# Revoke Entra sessions for compromised user
Revoke-MgUserSignInSession -UserId "user@corp.com"
# Or via Azure AD PowerShell
Revoke-AzureADUserAllRefreshToken -ObjectId "user-object-id"
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Tool Examples |
|-----------|-----|--------|---------------|
| Brute Force: Password Guessing | T1110.001 | Credential Access | Hydra, Medusa, Ncrack |
| Brute Force: Password Cracking | T1110.002 | Credential Access | Hashcat, John the Ripper |
| Brute Force: Password Spraying | T1110.003 | Credential Access | Kerbrute, CME, MSOLSpray |
| Brute Force: Credential Stuffing | T1110.004 | Credential Access | OpenBullet, Patator |
| OS Credential Dumping: LSASS Memory | T1003.001 | Credential Access | Mimikatz, ProcDump, Cobalt Strike |
| OS Credential Dumping: SAM | T1003.002 | Credential Access | secretsdump.py, reg.exe |
| OS Credential Dumping: NTDS | T1003.003 | Credential Access | secretsdump.py, ntdsutil, VSS |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Credential Access | Rubeus, GetUserSPNs.py |
| Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 | Credential Access | Rubeus, GetNPUsers.py |
| Network Sniffing | T1040 | Credential Access | Responder, Inveigh, tcpdump |
| Adversary-in-the-Middle | T1557 | Credential Access | Responder, MITM6, Evilginx2 |
| Modify Authentication Process | T1556 | Defense Evasion | Skeleton key, DC Shadow |
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | Lateral Movement | Mimikatz, CrackMapExec, Impacket |
| Use Alternate Authentication Material: Pass the Ticket | T1550.003 | Lateral Movement | Rubeus, Mimikatz |

---

## Compliance Cross-Reference

| Standard | Password/Auth Requirements |
|----------|--------------------------|
| NIST SP 800-63B Rev. 4 | Argon2id/PBKDF2/bcrypt/scrypt for storage; 8-char min; ban breached passwords; no forced rotation |
| OWASP ASVS 2.1 | Argon2id preferred; bcrypt/scrypt/PBKDF2 acceptable; 12-char min recommended; MFA required for sensitive |
| PCI DSS 4.0 | MFA for all non-console admin access; min 12 characters; 90-day rotation (or behavioral controls) |
| HIPAA | Strong authentication; unique user IDs; automatic logoff; encryption of credentials |
| SOC 2 CC6.1 | Logical access controls; MFA for remote access; credential management |
| CIS Control 5 | Account management; MFA; privileged account separation; LAPS |
| ISO 27001 A.9 | Access control policy; user authentication; privileged access management |
| FedRAMP / FISMA | NIST SP 800-63B alignment; PIV/CAC for federal systems (AAL3); FIPS 140-3 validated modules |

---

*Reference compiled from OWASP Password Storage Cheat Sheet (2023), NIST SP 800-63B Rev. 4, CIS Benchmark v8, Microsoft Security Documentation, Hashcat documentation, MITRE ATT&CK v14, and community research on password security.*
