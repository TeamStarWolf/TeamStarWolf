# hashcat Command Reference

hashcat is a password-recovery tool that tests captured hashes against candidate passwords using GPU or CPU compute. Security teams use it for authorized password audits, recovery of their own locked data, and validating that a password policy resists offline cracking. Run it only on hashes you are authorized to test under a signed audit scope. This page covers hash modes, attack modes, tuning, and the defenses that make offline cracking impractical.

## What it is and where it runs

hashcat runs on Linux, Windows, and macOS, and uses OpenCL or CUDA to drive GPUs. Input is a file of hashes in a format matching the selected hash mode. Candidate passwords come from wordlists, rules, or generated masks. Cracked results are written to a potfile and shown on demand. The tool does not touch the target system: it works offline against hashes already collected during an authorized engagement.

List supported hash modes and verify the device setup:

```
hashcat --help | less
hashcat -I
```

## Core commands

Select the hash type with `-m` and the attack mode with `-a`. A straight (dictionary) attack is `-a 0`.

```
hashcat -m 0 -a 0 hashes.txt rockyou.txt
```

Common hash modes:

| `-m` | Hash type |
| --- | --- |
| `0` | MD5 |
| `100` | SHA1 |
| `1400` | SHA-256 |
| `1800` | sha512crypt (`$6$`) |
| `3200` | bcrypt (`$2*$`) |
| `1000` | NTLM |
| `5600` | NetNTLMv2 |
| `22000` | WPA-PBKDF2 / WPA2 |

Attack modes set how candidates are built:

| `-a` | Attack mode | Use |
| --- | --- | --- |
| `0` | Straight | Wordlist, optionally with rules |
| `1` | Combinator | Join words from two lists |
| `3` | Mask (brute force) | Pattern of character sets |

A rule file mutates each wordlist entry, for example appending digits or toggling case.

```
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r rules/best64.rule
```

A mask attack walks a defined pattern. Built-in charsets are `?l` lowercase, `?u` uppercase, `?d` digit, `?s` special, `?a` all.

```
hashcat -m 0 -a 3 hashes.txt ?u?l?l?l?l?d?d
```

A combinator attack concatenates each word from one list with each word from another.

```
hashcat -m 0 -a 1 hashes.txt listA.txt listB.txt
```

Show what has already been recovered, and remove solved hashes from the queue.

```
hashcat -m 1000 ntlm.txt --show
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r rules/best64.rule --remove
```

Control runtime behavior and visibility.

| Flag | Purpose |
| --- | --- |
| `-w` | Workload profile, `1` low to `4` nightmare |
| `--status` | Print periodic status updates |
| `--status-timer` | Seconds between status lines |
| `-o` | Write cracked results to a file |
| `--potfile-path` | Set a custom potfile location |
| `--session` | Name a session for restore |
| `--restore` | Resume a named session |
| `-b` | Run the built-in benchmark |

Benchmark the hardware across modes, or for one mode:

```
hashcat -b
hashcat -b -m 22000
```

The potfile at `~/.hashcat/hashcat.potfile` records every solved `hash:plaintext` pair. hashcat skips hashes already in the potfile, which is why a repeat run can finish instantly. Treat the potfile as sensitive audit data.

## Common workflows

Audit a set of NTLM hashes from an authorized Active Directory assessment.

```
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r rules/best64.rule -w 3 --status
hashcat -m 1000 ntlm.txt --show -o cracked.txt
```

Test WPA2 strength for a wireless network you own.

```
hashcat -m 22000 -a 3 capture.hc22000 ?d?d?d?d?d?d?d?d -w 4
```

Targeted mask when the policy shape is known (one uppercase, lowercase body, two digits).

```
hashcat -m 1400 -a 3 sha256.txt -1 ?u ?1?l?l?l?l?l?d?d
```

Start a named session and resume it after a reboot.

```
hashcat -m 1800 -a 0 shadow.txt wordlist.txt --session audit1
hashcat --session audit1 --restore
```

## Flags and options worth knowing

| Flag | Meaning |
| --- | --- |
| `-m` | Hash mode (hash type) |
| `-a` | Attack mode |
| `-r` | Rule file for mutating candidates |
| `-1` to `-4` | Define custom charsets for masks |
| `--increment` | Step mask length from min to max |
| `--show` | Print already-cracked plaintexts |
| `--remove` | Drop solved hashes from the input file |
| `-w` | Workload profile |
| `--force` | Ignore device warnings (use sparingly) |
| `--runtime` | Abort after N seconds |

## Detection and defense

Offline cracking succeeds when hashes are weak or unsalted. The defense is to store passwords with a slow, salted, adaptive function: bcrypt, scrypt, or Argon2, with a work factor tuned so each guess is expensive. Fast hashes like MD5, SHA1, and plain SHA-256, and any unsalted scheme, fall to GPU attacks quickly. This weakness is CWE-916 (use of a password hash with insufficient computational effort); related issues are CWE-759 (missing salt) and CWE-760 (predictable salt). Apply the password-storage guidance in /SECURE_CODING_REFERENCE.md.

Strong password policy raises the cost of every attack mode. Length defeats mask and brute-force attacks faster than complexity rules do; blocking known-breached passwords defeats wordlist and rule attacks. Multi-factor authentication limits the value of a recovered password.

Defenders cannot watch the cracking itself, since it happens offline. They detect the precursors: access to hash stores such as the SAM, `ntds.dit`, `/etc/shadow`, or a database credential table; dumping tools and `DCSync`-style replication; and exfiltration of files that look like hash dumps. Monitor for bulk reads of credential stores, alert on hash-dumping techniques, and treat any exfiltrated hash set as a breach that requires a forced password reset.

## Resources

- hashcat official wiki and documentation
- hashcat `--help` mode and charset reference
- OWASP Password Storage Cheat Sheet

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/metasploit.md
- /commands/nmap.md
- /commands/sqlmap.md
