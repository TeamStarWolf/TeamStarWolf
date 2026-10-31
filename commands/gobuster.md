# gobuster Command Reference

gobuster is an open-source content and DNS discovery tool that brute-forces paths, subdomains, and virtual hosts using a wordlist. Penetration testers use it to find directories, files, and hostnames that are reachable but not linked. This page is for authorized testing: run it only against targets you own or have written permission to assess. Keep scope to lab systems or signed engagements, and respect any rate or traffic limits in the rules of engagement.

## What it is and where it runs

gobuster is a Go binary that sends many requests against a target and reports which ones return meaningful responses. It is a single static executable on Linux, macOS, and Windows, with no runtime dependencies. It works in modes: `dir` for web paths, `dns` for subdomains, `vhost` for virtual hosts, and `fuzz` for custom placeholder injection. Wordlist quality drives results, so pair it with lists such as those from SecLists.

## Core commands

Directory and file discovery against an authorized web host.

```bash
gobuster dir -u https://lab.example -w /usr/share/wordlists/common.txt
```

Add file extensions to find pages and scripts.

```bash
gobuster dir -u https://lab.example -w common.txt -x php,txt,html
```

Subdomain discovery against a domain you control.

```bash
gobuster dns -d lab.example -w subdomains.txt
```

Virtual host discovery on a shared web server in scope.

```bash
gobuster vhost -u https://lab.example -w vhosts.txt
```

Custom fuzzing with the `FUZZ` placeholder.

```bash
gobuster fuzz -u "https://lab.example/FUZZ" -w common.txt
```

| Mode | Purpose |
|------|---------|
| `dir` | Brute-force paths and files |
| `dns` | Brute-force subdomains |
| `vhost` | Brute-force virtual hosts |
| `fuzz` | Inject wordlist entries at a `FUZZ` marker |

## Common workflows

Enumerate directories and common file types on a lab target, saving output.

```bash
gobuster dir -u https://lab.example -w directory-list.txt -x php,txt,bak -t 40 -o dirs.txt
```

Find subdomains of an authorized domain, then feed hits into further scans.

```bash
gobuster dns -d lab.example -w subdomains.txt -t 50 -o subs.txt
```

Discover hidden virtual hosts on a server you are permitted to test.

```bash
gobuster vhost -u https://lab.example -w vhosts.txt --append-domain -o vhosts.txt
```

Filter noise on an app that returns soft 404s by matching status codes.

```bash
gobuster dir -u https://lab.example -w common.txt -b 404,403 -t 30
```

## Flags and options worth knowing

Common flags apply across modes; some are mode-specific.

| Flag | Meaning |
|------|---------|
| `-u` | Target URL (`dir`, `vhost`, `fuzz`) |
| `-d` | Target domain (`dns` mode) |
| `-w` | Wordlist path |
| `-x` | File extensions to append (`dir` mode) |
| `-t` | Number of concurrent threads |
| `-s` | Status codes to include (whitelist) |
| `-b` | Status codes to exclude (blacklist) |
| `-k` | Skip TLS certificate verification |
| `-o` | Write results to a file |

Tune `-t` to the target's capacity; high thread counts speed discovery but raise load and detection risk, so stay within the engagement's limits. Use `-s` to show only codes you care about, or `-b` to hide noise like `404` and `403`. `-k` helps against lab hosts with self-signed certificates. In `vhost` mode, `--append-domain` builds full hostnames from the wordlist. Always set `-o` so results are preserved for the report.

## Detection and defense

gobuster supports authorized content and subdomain discovery. Teams use it to find forgotten admin panels, backup files, and stale subdomains before an attacker does, then remove or protect them.

Defenders see gobuster clearly in web and DNS logs. Directory brute-forcing produces a burst of `404` responses from one source in a short window, often with a default or unusual user agent. DNS mode generates many lookups for nonexistent names. These bursts are straightforward to alert on with log analysis and WAF rules. Rapid sequential requests to many nonexistent paths are a reliable signature.

Mitigation starts with not relying on obscurity. A resource that is only hidden by an unguessed path is still exposed; this maps to CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor). Enforce authentication and authorization on every sensitive endpoint, remove backup and temporary files from web roots, and return consistent responses so presence cannot be inferred from status codes. Rate limiting and WAF controls slow brute-forcing and trigger alerts, and monitoring for 404 spikes catches scans in progress. Secure configuration and access-control guidance is in /SECURE_CODING_REFERENCE.md.

## Resources

- gobuster documentation and `gobuster --help` (official usage reference)
- SecLists project, the standard wordlist collection used with gobuster
- OWASP Testing Guide, the directory and resource enumeration sections

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/sqlmap.md
- /commands/nmap.md
- /commands/curl.md
- /commands/networking-commands.md
