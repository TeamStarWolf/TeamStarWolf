# OSINT Reference

> **Scope**: This reference is for defensive security practitioners, authorized penetration testers, and threat intelligence analysts. All techniques described are for use only within explicitly authorized engagements and legal frameworks.

---

## Table of Contents

1. [OSINT Methodology](#osint-methodology)
2. [Domain & IP Intelligence](#domain--ip-intelligence)
3. [Web & Technology Fingerprinting](#web--technology-fingerprinting)
4. [Search Engine OSINT (Dorking)](#search-engine-osint-dorking)
5. [People & Email Intelligence](#people--email-intelligence)
6. [GitHub / Code Repository OSINT](#github--code-repository-osint)
7. [Infrastructure & Cloud OSINT](#infrastructure--cloud-osint)
8. [Social Media OSINT](#social-media-osint)
9. [Document & Metadata OSINT](#document--metadata-osint)
10. [Threat Actor OSINT](#threat-actor-osint)
11. [OSINT Tools Reference Table](#osint-tools-reference-table)
12. [ATT&CK Mapping](#attck-mapping)

---

## OSINT Methodology

### Intelligence Cycle (OSINT Edition)

```
Define Objective
      │
      ▼
Identify Sources
      │
      ▼
Collect Data  ──────────────────────┐
      │                             │
      ▼                             │
Verify / Validate  (back to collect if gaps)
      │
      ▼
Analyze & Correlate
      │
      ▼
Report & Disseminate
```

### Intelligence Requirements

Before beginning any collection, answer:

| Question | Purpose |
|----------|---------|
| What is the target? (org / person / infrastructure / threat actor) | Scopes collection and avoids noise |
| What is the end-state? (vulnerability mapping / personnel profiling / brand monitoring) | Drives source selection |
| What is the sensitivity / classification of output? | Determines handling and distribution |
| What is the authorized scope? | Legal and contractual boundary |
| What is the time-box? | Resource allocation |

### Operational Security (OpSec) for OSINT

Never conduct reconnaissance from personal infrastructure. Violations leave attributable footprints in target logs.

**Tiered OpSec levels**:

| Tier | Approach | Use Case |
|------|----------|---------|
| Tier 1 (Low) | VPN + clean browser profile | Casual open-source research |
| Tier 2 (Medium) | VPN + Tor + hardened VM (Whonix/Tails) | Sensitive passive collection |
| Tier 3 (High) | Sock puppet accounts + dedicated infrastructure + residential proxy | Active enumeration, social engineering scenarios |

**Sock puppet account hygiene**:
- Separate email provider, phone number, and device fingerprint per persona
- Age accounts naturally before use (weeks of organic activity)
- Consistent persona story — location, employer, interests, tone
- Never cross-contaminate personas (no shared login IP, no linked accounts)
- Rotate personas after use — treat as one-time consumable

**Burner VM checklist**:
- Fresh snapshot per engagement
- DNS over Tor or DoH to neutral resolver
- No autofill, no browser sync, no cloud backups
- Clipboard isolation (avoid cross-VM paste of real credentials)
- Destroy or revert snapshot post-collection

### Legal and Ethical Boundaries

| Framework | Implication |
|-----------|-------------|
| GDPR (EU) | Personal data of EU residents requires lawful basis even in security research; minimize retention |
| CCPA (California) | Similar consent/data-minimization obligations for CA residents |
| CFAA / Computer Fraud & Abuse Act | Unauthorized access to systems is criminal even if data is technically "public" |
| Terms of Service | LinkedIn, Twitter, GitHub prohibit scraping — civil liability and account bans; use official APIs |
| Engagement scope | Written authorization required; screenshot and store before collection |

**Key principles**:
1. Passive before active — exhaust passive sources before touching target infrastructure
2. Minimize footprint — collect only what is necessary
3. Document authorization — keep signed scoping agreements accessible
4. Data retention limits — destroy sensitive findings per agreement, not indefinitely

---

## Domain & IP Intelligence

### WHOIS Lookup

```bash
# Standard WHOIS
whois domain.com
whois 192.0.2.1

# WHOIS via CLI with output formatting
whois -h whois.iana.org domain.com

# Historical WHOIS (paid services)
# ViewDNS.info: https://viewdns.info/whois/
# DomainTools: https://whois.domaintools.com/
# SecurityTrails: https://securitytrails.com/

# API-based historical lookups
curl "https://api.securitytrails.com/v1/domain/example.com/whois" \
  -H "APIKEY: YOUR_KEY"
```

**WHOIS fields of interest**:
- Registrar, registration/expiration dates (registration age = trust signal)
- Registrant org, email, phone (often privacy-protected but historically exposed)
- Name servers — identify DNS provider and detect fast-flux
- Status codes (clientTransferProhibited, serverHold, etc.)

### DNS Enumeration

```bash
# Basic record types
dig domain.com A
dig domain.com AAAA
dig domain.com MX
dig domain.com NS
dig domain.com TXT
dig domain.com SOA
dig domain.com ANY +noall +answer

# Short output format
dig +short domain.com A

# Specify resolver
dig @8.8.8.8 domain.com A

# Reverse DNS (PTR)
dig -x 192.0.2.1

# Zone transfer attempt (usually blocked but worth trying)
dig axfr @ns1.domain.com domain.com
# Using host
host -t axfr domain.com ns1.domain.com

# dnsx - fast multi-probe
dnsx -l domains.txt -a -mx -ns -txt -resp -o dns_results.json
dnsx -d domain.com -w /path/to/subdomains.txt -a -resp

# dnsrecon
dnsrecon -d domain.com -t std          # standard enumeration
dnsrecon -d domain.com -t brt -D wordlist.txt  # bruteforce
dnsrecon -d domain.com -t axfr        # zone transfer
dnsrecon -d domain.com -t rvl -r 192.0.2.0/24  # reverse lookup range
```

**Passive DNS sources**:
- SecurityTrails (historical record changes)
- VirusTotal passive DNS (`https://www.virustotal.com/gui/domain/example.com/relations`)
- CIRCL passive DNS (`https://www.circl.lu/services/passive-dns/`)
- Shodan reverse DNS
- RiskIQ PassiveTotal (Microsoft Defender TI)

### Subdomain Enumeration

```bash
# Amass (comprehensive, combines passive + active)
amass enum -d domain.com -passive -o subdomains_passive.txt
amass enum -d domain.com -active -brute -w wordlist.txt -o subdomains_active.txt
amass db -d domain.com -names  # query stored results

# Subfinder (fast passive)
subfinder -d domain.com -all -o subdomains.txt
subfinder -d domain.com -all -recursive -o recursive_subs.txt

# Assetfinder
assetfinder --subs-only domain.com

# Chaos (ProjectDiscovery dataset)
chaos -d domain.com -o chaos_subs.txt

# Certificate Transparency (crt.sh)
curl -s "https://crt.sh/?q=%.domain.com&output=json" | \
  jq -r '.[].name_value' | \
  sort -u | \
  sed 's/\*\.//g'

# Shodan subdomain discovery
shodan search "ssl.cert.subject.CN:\"*.domain.com\"" --fields hostnames
shodan search "hostname:\"domain.com\""

# Combine and deduplicate
cat subdomains_*.txt | sort -u > all_subdomains.txt

# Resolve to filter live hosts
cat all_subdomains.txt | dnsx -resp -o resolved.txt
cat all_subdomains.txt | httpx -silent -o live_web.txt
```

### IP and ASN Intelligence

```bash
# Basic IP info
curl -s ipinfo.io/192.0.2.1 | jq .
curl -s "https://ipapi.co/192.0.2.1/json/" | jq .

# ASN lookup
curl -s "https://api.bgpview.io/asn/AS15169" | jq '.data'
whois -h whois.radb.net AS15169

# BGP route queries
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169"

# Hurricane Electric BGP Toolkit
# https://bgp.he.net/AS15169

# Regional Internet Registry WHOIS
# ARIN (Americas): https://search.arin.net/
# RIPE (Europe/Middle East): https://apps.db.ripe.net/
# APNIC (Asia-Pacific): https://wq.apnic.net/
# LACNIC (Latin America): https://query.milacnic.lacnic.net/
# AFRINIC (Africa): https://afrinic.net/

# Shodan ASN/org search
shodan search 'org:"Target Corporation"'
shodan search 'asn:AS12345'
shodan search 'net:192.0.2.0/24'
```

### Reverse IP Lookup

```bash
# Find other domains hosted on same IP
curl -s "https://api.hackertarget.com/reverseiplookup/?q=192.0.2.1"

# ViewDNS reverse IP
# https://viewdns.info/reverseip/

# SecurityTrails
curl "https://api.securitytrails.com/v1/ips/192.0.2.1/domains" \
  -H "APIKEY: YOUR_KEY" | jq '.records[].hostname'
```

---

## Web & Technology Fingerprinting

### Shodan

```bash
# Install and configure
pip install shodan
shodan init YOUR_API_KEY

# Host lookup
shodan host 192.0.2.1

# Organization search
shodan search 'org:"Target Corp"'
shodan search 'ssl:"domain.com"'
shodan search 'http.title:"Target Dashboard"'
shodan search 'net:192.0.2.0/24'

# Combined filters
shodan search 'org:"Target" port:8080 http.title:"admin"'
shodan search 'ssl.cert.subject.cn:"domain.com" http.status:200'

# Download results
shodan download --limit 1000 results.json.gz 'org:"Target Corp"'
shodan parse results.json.gz --fields ip_str,port,transport,hostnames

# Interesting Shodan dorks
shodan search 'product:"Apache" version:"2.4.49"'           # known vuln version
shodan search 'http.html:"default password"'                # default creds pages
shodan search 'port:3389 os:"Windows Server 2012"'          # outdated RDP
shodan search '"MongoDB Server Information" port:27017'     # open MongoDB
shodan search 'port:5900 authentication disabled'           # open VNC
```

### Censys

```bash
# Python API
pip install censys

# CLI search
censys search 'autonomous_system.name="Target Corp"' --index hosts
censys search 'parsed.names: domain.com' --index certificates
censys view 192.0.2.1 --index hosts

# Python SDK example
from censys.search import CensysHosts
h = CensysHosts()
for host in h.search("autonomous_system.name=`Target Corp`", pages=2):
    print(host["ip"], host.get("services"))
```

### Web Technology Fingerprinting

```bash
# WhatWeb - comprehensive fingerprinting
whatweb -a 1 https://target.com              # stealth (1 request)
whatweb -a 3 https://target.com              # aggressive
whatweb -a 3 https://target.com --log-json=whatweb.json
whatweb -a 3 -i urls.txt --log-brief=results.txt

# Wappalyzer CLI
npm install -g wappalyzer
wappalyzer https://target.com
wappalyzer https://target.com --pretty

# curl-based fingerprinting
curl -sI https://target.com | grep -iE 'server|x-powered-by|x-generator|cf-ray|via'

# HTTP security headers audit
curl -sI https://target.com | grep -iE \
  'strict-transport|content-security|x-frame|x-xss|referrer-policy|permissions-policy|cache-control'
```

**Headers of interest**:

| Header | Presence Indicates |
|--------|-------------------|
| `Server: Apache/2.4.51` | Version-specific fingerprint |
| `X-Powered-By: PHP/7.4` | Backend language version |
| `X-Generator: Drupal 9` | CMS version |
| `CF-Ray: ...` | CloudFlare CDN |
| `X-Served-By: cache-...` | Fastly CDN |
| Missing `Strict-Transport-Security` | HSTS not enforced |
| Missing `Content-Security-Policy` | XSS mitigation absent |

---

## Search Engine OSINT (Dorking)

### Google Dorks

| Dork | Purpose |
|------|---------|
| `site:domain.com filetype:pdf` | All indexed PDFs |
| `site:domain.com filetype:xlsx confidential` | Exposed spreadsheets |
| `site:domain.com filetype:sql` | Exposed SQL dumps |
| `site:domain.com filetype:log` | Exposed log files |
| `site:domain.com filetype:bak OR filetype:backup` | Backup files |
| `inurl:admin site:domain.com` | Admin interfaces |
| `inurl:login site:domain.com` | Login portals |
| `inurl:wp-admin site:domain.com` | WordPress admin |
| `inurl:phpmyadmin site:domain.com` | phpMyAdmin instances |
| `site:domain.com "index of /"` | Open directory listings |
| `site:domain.com "not for distribution"` | Accidentally published sensitive docs |
| `site:domain.com "internal use only"` | Internal documents |
| `"@domain.com" site:linkedin.com` | Employee LinkedIn profiles |
| `"@domain.com" site:pastebin.com` | Email addresses in pastes |
| `"domain.com" site:github.com` | Org references on GitHub |
| `intext:"sql syntax" site:domain.com` | SQL errors in production |
| `intext:"Fatal error" site:domain.com` | PHP error disclosure |
| `site:domain.com inurl:swagger` | API documentation |
| `site:domain.com ext:env` | Exposed .env files |
| `site:domain.com ext:config` | Configuration files |
| `"domain.com" "password"` | Password references anywhere |

### Bing Dorks

```
site:domain.com filetype:pdf
ip:192.0.2.1                    # pages on specific IP
contains:domain.com             # pages linking to domain
```

### DuckDuckGo Operators

```
site:domain.com
filetype:pdf site:domain.com
inurl:admin site:domain.com
```

### Google Hacking Database (GHDB)

- URL: `https://www.exploit-db.com/google-hacking-database`
- Browseable by category: Files Containing Passwords, Sensitive Directories, Error Messages, etc.
- Automate with `pagodo`: `python3 pagodo.py -d domain.com -g ghdb.json`

### Shodan Dorks

```
"default password" http.title:"router"
product:"Cisco IOS" port:23         # Telnet Cisco
"Authentication: disabled" port:5900  # Open VNC
http.html:"phpMyAdmin" port:80
org:"Target" country:"US" port:22
```

---

## People & Email Intelligence

### LinkedIn OSINT

```bash
# linkedin2username - generate username permutations from company employees
python3 linkedin2username.py -u your_linkedin_email -p your_password \
  -c company-name -n 2

# LinkedInt (headless browser scraping)
python3 LinkedInt.py -u your_email -p your_password -c "Target Company"

# Manual approach via search
# site:linkedin.com/in "Target Company"
# site:linkedin.com/in "@domain.com"
```

**Intelligence from LinkedIn**:
- Employee count and growth trend (hiring = expansion areas)
- Job titles → org structure inference
- Job postings → technology stack (Python, Kubernetes, Okta, CrowdStrike)
- Skills endorsements → technology familiarity
- Recent job changes → potential disgruntled insiders or knowledge transfer

### Email Format Discovery

```bash
# Hunter.io API
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY" | \
  jq '.data.pattern'

# Format permutations to test (most common patterns)
# {first}.{last}@domain.com
# {first}{last}@domain.com
# {f}{last}@domain.com
# {first}@domain.com
# {first}{l}@domain.com

# Verify specific email
curl "https://api.hunter.io/v2/email-verifier?email=john.doe@domain.com&api_key=KEY"

# email-format.com (browser: https://email-format.com/i/search/)

# theHarvester email collection
theHarvester -d domain.com -b all -f results
theHarvester -d domain.com -b google,bing,linkedin -l 500
```

### Data Breach Intelligence

```bash
# Have I Been Pwned API v3
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/user@domain.com" \
  -H "hibp-api-key: YOUR_KEY" | jq '.[].Name'

# Check all breaches for a domain
curl -s "https://haveibeenpwned.com/api/v3/breacheddomain/domain.com" \
  -H "hibp-api-key: YOUR_KEY" | jq '.[]'

# Dehashed (paid, shows plaintext/hash)
curl "https://api.dehashed.com/search?query=email:@domain.com" \
  -u "email:api_key" | jq '.entries[]'

# BreachDirectory (free tier)
curl "https://breachdirectory.p.rapidapi.com/?func=auto&term=user@domain.com" \
  -H "X-RapidAPI-Key: YOUR_KEY"
```

### Username OSINT

```bash
# Sherlock - username across 300+ platforms
pip install sherlock-project
sherlock username
sherlock username --timeout 10 --output results.txt
sherlock username --site Twitter --site GitHub --site Reddit

# Maigret - advanced, includes profile data extraction
pip install maigret
maigret username
maigret username --pdf report.pdf

# WhatsMyName (web UI + API)
# https://whatsmyname.app/
```

---

## GitHub / Code Repository OSINT

### GitHub Search Dorking

Navigate to `https://github.com/search?type=code` or use the API:

```bash
# API-based code search
gh api "search/code?q=org:TargetOrg+filename:.env" --jq '.items[].html_url'
gh api "search/code?q=org:TargetOrg+password+in:file" --jq '.items[].html_url'
gh api "search/code?q=org:TargetOrg+api_key+in:file" --jq '.items[].html_url'
gh api "search/code?q=org:TargetOrg+BEGIN+RSA+PRIVATE+KEY" --jq '.items[].html_url'
gh api "search/code?q=org:TargetOrg+AWS_SECRET_ACCESS_KEY" --jq '.items[].html_url'
gh api "search/code?q=org:TargetOrg+smtp_password" --jq '.items[].html_url'
gh api "search/code?q=org:TargetOrg+database_password" --jq '.items[].html_url'
gh api "search/code?q=org:TargetOrg+internal.domain.com" --jq '.items[].html_url'

# GitDorker (automates bulk GitHub dorks)
python3 gitdorker.py -tf tokensfile.txt -q TargetOrg -d dorks/medium_dorks.txt
```

**High-value GitHub dorks**:

| Dork | Target |
|------|--------|
| `org:TargetOrg filename:.env` | Environment files |
| `org:TargetOrg filename:config.yml password` | Config with creds |
| `org:TargetOrg "BEGIN RSA PRIVATE KEY"` | Private keys |
| `org:TargetOrg "BEGIN PGP PRIVATE KEY"` | PGP keys |
| `org:TargetOrg "AWS_ACCESS_KEY_ID"` | AWS credentials |
| `org:TargetOrg "client_secret"` | OAuth secrets |
| `org:TargetOrg "db_password"` | Database passwords |
| `org:TargetOrg "Authorization: Bearer"` | Bearer tokens |
| `org:TargetOrg "-----BEGIN CERTIFICATE-----"` | Certificates |
| `org:TargetOrg filename:id_rsa` | SSH private keys |
| `org:TargetOrg filename:*.pem` | PEM files |

### Trufflehog - Secret Scanning

```bash
# Install
pip install trufflehog3
# or
docker pull trufflesecurity/trufflehog:latest

# Scan entire GitHub org (verified secrets only)
trufflehog github --org=TargetOrg --only-verified

# Scan specific repo
trufflehog git https://github.com/TargetOrg/repo --only-verified
trufflehog git https://github.com/TargetOrg/repo --json

# Scan local repo including history
trufflehog git file://. --since-commit HEAD~100

# Scan with Docker
docker run --rm -it trufflesecurity/trufflehog:latest \
  github --org=TargetOrg --only-verified --json
```

### GitLeaks - Pattern-based Secret Detection

```bash
# Install
brew install gitleaks  # or download from releases

# Scan current repo
gitleaks detect --source=. --report-format=json --report-path=leaks.json

# Scan with verbose output
gitleaks detect --source=. --verbose

# Scan specific commit range
gitleaks detect --source=. --log-opts="HEAD~50..HEAD"

# Scan remote repo
gitleaks detect --source=https://github.com/org/repo \
  --report-format=sarif --report-path=results.sarif
```

### Historical Commit Analysis

```bash
# View full commit history
git log --oneline --all --graph

# Search commit messages for sensitive keywords
git log --all --oneline --grep="password\|secret\|key\|token\|credential"

# Search file content across all commits
git grep "password" $(git rev-list --all)

# Find deleted files that may contain secrets
git log --all --full-history -- "*.env"
git log --all --full-history -- "*.pem"
git log --all --full-history -- "*secret*"

# Recover deleted file content
git show COMMIT_HASH:path/to/deleted/file

# Search for specific string in all history
git log -p -S "password" --all

# Find large committed files (potential data dumps)
git rev-list --objects --all | \
  git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | \
  awk '/^blob/ {print substr($0,6)}' | \
  sort -k2 -n -r | head -20
```

### Dependency Intelligence

```bash
# Extract internal package names (dependency confusion targets)
cat package.json | jq '.dependencies | keys[]'
cat requirements.txt
cat go.mod | grep -v "^module\|^go " | awk '{print $1}'

# Check for private package names on public registries
# If internal packages are not published publicly, they're dependency confusion candidates

# Identify technology stack from dependencies
cat package.json | jq '.dependencies' | grep -iE \
  'react|vue|angular|express|nest|next|nuxt'
```

---

## Infrastructure & Cloud OSINT

### S3 Bucket Discovery

```bash
# Manual check
aws s3 ls s3://target-bucket-name 2>/dev/null && echo "PUBLIC"

# s3scanner
pip install s3scanner
s3scanner scan --bucket target-company-backup
s3scanner scan --bucket-file bucket_names.txt

# bucket_finder
ruby bucket_finder.rb wordlist.txt --region us-east-1

# cloud_enum - multi-cloud
pip install cloud-enum
cloud_enum -k targetcompany -k target-company -k targetcorp

# GrayhatWarfare.com - searchable public bucket database
# https://buckets.grayhatwarfare.com/

# Common naming patterns to try
# target-backup, target-data, target-logs, target-assets
# target.com-backup, targetcompany-prod, targetcompany-dev
# targetcompany-uploads, targetcompany-static, targetcompany-files
```

### Azure Blob and GCP Bucket Discovery

```bash
# Azure Blob Storage
# Pattern: https://ACCOUNT.blob.core.windows.net/CONTAINER/
# Enumerate containers
for container in backup data logs assets files uploads images; do
  curl -s "https://targetcompany.blob.core.windows.net/$container?restype=container&comp=list" \
    | grep -q "EnumerationResults" && echo "FOUND: $container"
done

# GCP Storage buckets
for bucket in backup data logs assets files; do
  gsutil ls gs://targetcompany-$bucket 2>/dev/null && echo "FOUND: $bucket"
done

# microBurst (Azure-focused OSINT)
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base targetcompany
```

### Cloud Asset Discovery via OSINT

```bash
# Identify cloud provider from DNS
dig target.com CNAME | grep -iE 'aws|azure|gcp|cloudfront|amazonaws|azurewebsites|appspot'

# S3 bucket via SSL cert SAN names
curl -s "https://crt.sh/?q=%.s3.amazonaws.com&output=json" | \
  jq -r '.[].name_value' | grep targetcompany

# Shodan cloud asset discovery
shodan search 'org:"Amazon" "Target Corp"'
shodan search 'ssl.cert.subject.CN:"*.amazonaws.com" ssl.cert.subject.O:"Target Corp"'

# Cloud metadata endpoint exposure check (from external - they shouldn't respond)
curl -m 3 http://169.254.169.254/latest/meta-data/  # AWS IMDSv1 (should not be external)
```

### Email Gateway & MX Intelligence

```bash
# Identify email security vendor from MX
dig target.com MX +short

# MX record patterns
# *.mimecast.com      → Mimecast email security
# *.pphosted.com      → Proofpoint
# *.ess.barracuda.com → Barracuda
# mail.protection.outlook.com → Microsoft 365
# aspmx.l.google.com  → Google Workspace
# *.inbound.sendgrid.net → SendGrid

# SPF record analysis (reveals email infrastructure)
dig target.com TXT | grep "v=spf1"
# include:sendgrid.net → SendGrid
# include:salesforce.com → Salesforce
# include:mailchimp.com → Mailchimp
# ip4:x.x.x.x → On-prem mail server IPs
```

### SSL/TLS Certificate Intelligence

```bash
# crt.sh - certificate transparency search
curl -s "https://crt.sh/?q=domain.com&output=json" | \
  jq -r '.[] | [.id, .logged_at, .not_before, .not_after, .name_value] | @csv'

# SAN name extraction (reveals internal hostnames)
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"

# Certificate chain issuing CA
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -issuer

# Identify certificate pinning
# Applications with pinned certs reject untrusted proxies (Burp/mitmproxy)
# Test: route mobile app traffic through proxy and check for SSL errors
```

---

## Social Media OSINT

### Twitter / X OSINT

```bash
# Advanced search operators (search.twitter.com)
# from:target_user since:2023-01-01 until:2023-12-31
# to:target_user
# "@target_user" filter:links
# near:"New York" within:5mi "Target Corp"

# Twint (archived, use alternatives like snscrape)
snscrape --jsonl twitter-search "from:targetuser" > tweets.jsonl
snscrape --jsonl twitter-user targetuser > user_tweets.jsonl

# Wayback Machine for deleted tweets
# https://web.archive.org/web/*/https://twitter.com/user/status/*

# Social graph analysis
# Map followers/following for influence and connections
```

### LinkedIn Deep Dive

```bash
# Employee enumeration via Google
# site:linkedin.com/in/ "Target Company" "Software Engineer"
# site:linkedin.com/in/ "Target Company" "Security"
# site:linkedin.com/in/ "Target Company" "DevOps"

# Technology inference from job postings
# Search "Target Company" on LinkedIn Jobs
# Look for: security tools, cloud platforms, software stacks, compliance requirements

# Recent hires (potential knowledge gap)
# Filter employees by "joined" date

# Mutual connections (social engineering vectors)
# Common contacts who could serve as pretexting pivots
```

### OSINT Frameworks

```bash
# Maltego (GUI-based link analysis)
# Transforms for: DNS, WHOIS, LinkedIn, Shodan, VirusTotal, etc.
# Community edition: limited transforms/results
# Commercial: full API access

# SpiderFoot (automated, web UI + CLI)
pip install spiderfoot
# Web UI
python3 sf.py -l 127.0.0.1:5001
# CLI
python3 sfcli.py -s target.com -m all -o JSON -f results.json

# Recon-ng (modular, like Metasploit for OSINT)
recon-ng
> marketplace install all
> workspaces create target_engagement
> modules load recon/domains-hosts/bing_domain_web
> options set SOURCE domain.com
> run
```

---

## Document & Metadata OSINT

### ExifTool

```bash
# Install
sudo apt install exiftool  # or: brew install exiftool

# Extract all metadata
exiftool document.pdf
exiftool image.jpg
exiftool -r /path/to/directory/  # recursive

# Specific fields
exiftool -Author -Creator -Software document.pdf
exiftool -GPSLatitude -GPSLongitude -GPSAltitude photo.jpg

# GPS coordinates from photo
exiftool -n -p '$GPSLatitude, $GPSLongitude' photo.jpg

# Batch extract to CSV
exiftool -csv -r /path/to/docs/ > metadata.csv

# Strip metadata (for operational security on your own files)
exiftool -all= document.pdf  # removes all metadata
```

### FOCA (Windows-based)

- Download: `https://github.com/ElevenPaths/FOCA`
- Crawls target domain for documents (PDF, DOCX, XLSX, PPTX)
- Automatically extracts metadata: usernames, paths, software, printers
- Maps internal network topology from document metadata

### Google Dorks for Documents

```
site:domain.com filetype:pdf
site:domain.com filetype:docx
site:domain.com filetype:xlsx
site:domain.com filetype:pptx
site:domain.com filetype:pdf OR filetype:docx OR filetype:xlsx
site:domain.com filetype:pdf "confidential"
site:domain.com filetype:pdf "draft"
```

### Metadata Intelligence Indicators

| Indicator | Implication |
|-----------|-------------|
| Author: `jsmith` | Username format (potential AD username) |
| Creator: `\\CORP\share\path` | UNC path reveals internal share structure |
| Producer: `Microsoft Word 2016` | Office version (patch level inference) |
| Creator: `Adobe Acrobat 9.0` | Outdated software |
| Printer: `HP LaserJet P2015 on CORPPRINTER01` | Internal printer/host name |
| GPS coordinates | Physical location of photo taken |
| Last Modified By: `contractor_name` | Third-party access |

```bash
# Quick PDF metadata via strings
strings document.pdf | grep -E 'Author|Creator|Producer|Subject|Keywords|ModDate|CreationDate'

# Metagoofil - automated document metadata harvesting
python3 metagoofil.py -d domain.com -t pdf,docx,xlsx -l 100 -o /output/
```

---

## Threat Actor OSINT

### Ransomware & Leak Site Monitoring

| Resource | URL | Notes |
|----------|-----|-------|
| Ransomware.live | `https://www.ransomware.live/` | Aggregates leak site posts |
| RansomLook | `https://www.ransomlook.io/` | Multi-group tracker |
| DarkFeed | `https://darkfeed.io/` | Commercial, higher signal |
| ID Ransomware | `https://id-ransomware.malwarehunterteam.com/` | Sample identification |

```bash
# Monitor via Ransomware.live API (if available)
curl https://api.ransomware.live/victims | jq '.[] | select(.group=="lockbit")'
```

### Malware and IOC Repositories

```bash
# MalwareBazaar - sample search
curl -X POST https://mb-api.abuse.ch/api/v1/ \
  -d 'query=get_taginfo&tag=Cobalt Strike&limit=50'

# URLhaus - malicious URL lookup
curl -X POST https://urlhaus-api.abuse.ch/v1/url/ \
  -d 'url=http://malicious.example.com'

# VirusTotal (requires API key)
curl "https://www.virustotal.com/api/v3/domains/malicious.com" \
  -H "x-apikey: YOUR_KEY" | jq '.data.attributes.last_analysis_stats'

# OTX (AlienVault Open Threat Exchange)
curl "https://otx.alienvault.com/api/v1/indicators/domain/malicious.com/general" \
  -H "X-OTX-API-KEY: YOUR_KEY"

# Abuse.ch ThreatFox
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -d '{"query":"search_ioc","search_term":"192.0.2.1"}'
```

### Threat Actor Infrastructure Patterns

Identifying recurring infrastructure across campaigns:

```bash
# Shodan historical for known C2 indicators
shodan search 'ssl.cert.serial:KNOWN_SERIAL'
shodan search 'http.html_hash:KNOWN_HASH'

# Certificate reuse (same cert across IPs)
# crt.sh: search by organization name in cert fields
curl "https://crt.sh/?o=TargetActorOrg&output=json" | jq '.[].name_value'

# ASN clustering
# Check if multiple IOC IPs share same ASN (common with bulletproof hosting)
for ip in $IOC_LIST; do
  curl -s ipinfo.io/$ip | jq -r '"$ip: " + .org'
done

# RiskIQ / Microsoft Defender TI infrastructure analysis
# (Commercial) — pivot on IP → hosting history → co-hosted domains → certs
```

### Forum and Dark Web Intelligence

**Caution**: Accessing dark web forums carries legal and OpSec risks. Use isolated infrastructure.

| Platform | Access | Notes |
|----------|--------|-------|
| BreachForums | Tor + clearnet | Stolen data marketplace |
| RAMP Forum | Tor | Russian-language ransomware affiliate |
| XSS.is | Clearnet | Russian-language cybercrime |
| Exploit.in | Tor | Credentials and database market |
| VX-Underground | Clearnet | Malware samples, research |

**Passive monitoring approach**:
- Commercial services (Recorded Future, Flashpoint, Cybersixgill) provide sanitized monitoring
- Free alternative: keyword alerts via Google for indexed leak content
- Never register accounts or engage — creates legal exposure and attribution

---

## OSINT Tools Reference Table

| Tool | Category | Key Command / URL | Cost | Notes |
|------|----------|-------------------|------|-------|
| **Amass** | Subdomain enum | `amass enum -d domain.com -passive` | Free | OWASP project, most comprehensive |
| **Subfinder** | Subdomain enum | `subfinder -d domain.com -all` | Free | Fast, passive sources |
| **Assetfinder** | Subdomain enum | `assetfinder --subs-only domain.com` | Free | Tomnomnom, lightweight |
| **Chaos** | Subdomain enum | `chaos -d domain.com` | Free (API key) | ProjectDiscovery dataset |
| **dnsx** | DNS resolution | `dnsx -l subs.txt -a -resp` | Free | Fast multi-probe DNS |
| **dnsrecon** | DNS enum | `dnsrecon -d domain.com -t brt` | Free | Bruteforce + zone transfer |
| **Shodan** | Internet scanning | `shodan host IP` | Free/Paid | Best internet-wide scanner |
| **Censys** | Internet scanning | `censys search 'org=Target'` | Free/Paid | Certificate + host search |
| **FOFA** | Internet scanning | `https://en.fofa.info/` | Free/Paid | Chinese alternative to Shodan |
| **ZoomEye** | Internet scanning | `https://www.zoomeye.org/` | Free/Paid | Alternative internet scanner |
| **Maltego** | Framework | GUI — transforms | Free/Paid | Link analysis, commercial transforms |
| **SpiderFoot** | Framework | `python3 sf.py -l 0.0.0.0:5001` | Free/Paid | Automated, 200+ modules |
| **Recon-ng** | Framework | `recon-ng` REPL | Free | Modular, Metasploit-style |
| **theHarvester** | Email/people | `theHarvester -d domain.com -b all` | Free | Email + subdomain harvesting |
| **Hunter.io** | Email | `https://hunter.io/` API | Free/Paid | Email format + verification |
| **Clearbit** | Email/people | Chrome extension + API | Free/Paid | Real-time email enrichment |
| **Trufflehog** | Code repos | `trufflehog github --org=Target` | Free | Secret detection, verified only |
| **GitLeaks** | Code repos | `gitleaks detect --source=.` | Free | Pattern-based secret scan |
| **GitDorker** | Code repos | `python3 gitdorker.py -q Target` | Free | Automated GitHub dorks |
| **Sherlock** | Username | `sherlock username` | Free | 300+ platform checks |
| **Maigret** | Username | `maigret username --pdf report.pdf` | Free | Advanced, profile extraction |
| **ExifTool** | Metadata | `exiftool document.pdf` | Free | Industry standard |
| **FOCA** | Metadata | GUI (Windows) | Free | Bulk document metadata harvest |
| **Metagoofil** | Metadata | `metagoofil.py -d domain.com -t pdf` | Free | Automated Google doc harvest |
| **Wayback Machine** | Web archives | `https://web.archive.org/` | Free | Historical web snapshots |
| **CachedView** | Web archives | `https://cachedview.nl/` | Free | Google/Bing cache viewer |
| **BuiltWith** | Fingerprinting | `https://builtwith.com/` | Free/Paid | Tech stack identification |
| **Wappalyzer** | Fingerprinting | `wappalyzer https://target.com` | Free/Paid | Browser extension + CLI |
| **WhatWeb** | Fingerprinting | `whatweb -a 3 target.com` | Free | Aggressive fingerprinting |
| **s3scanner** | Cloud | `s3scanner scan --bucket name` | Free | S3 bucket enumeration |
| **cloud_enum** | Cloud | `cloud_enum -k targetcompany` | Free | Multi-cloud asset discovery |
| **GrayhatWarfare** | Cloud | `https://buckets.grayhatwarfare.com/` | Free/Paid | Public bucket search |
| **HIBP API** | Breach data | `https://haveibeenpwned.com/API/` | Free/Paid | Breach account lookup |
| **DeHashed** | Breach data | `https://dehashed.com/` | Paid | Plaintext/hash credential DB |
| **linkedin2username** | LinkedIn | `python3 linkedin2username.py` | Free | Username generation from employees |

---

## ATT&CK Mapping

OSINT activities map primarily to **MITRE ATT&CK Tactic TA0043 — Reconnaissance**.

| ATT&CK Technique | ID | OSINT Activity |
|------------------|----|----------------|
| Active Scanning | T1595 | Shodan/Censys searches, port scanning |
| Scanning IP Blocks | T1595.001 | `net:192.0.2.0/24` Shodan searches |
| Vulnerability Scanning | T1595.002 | Identifying outdated versions via banners |
| Gather Victim Host Info | T1592 | WhatWeb, Wappalyzer, HTTP headers |
| Hardware/Firmware | T1592.001 | Banner grabbing for device type |
| Software | T1592.002 | Technology fingerprinting |
| Client Configurations | T1592.004 | Browser/OS fingerprinting |
| Gather Victim Identity | T1589 | Employee enumeration, email harvesting |
| Credentials | T1589.001 | HIBP, DeHashed, breach data |
| Email Addresses | T1589.002 | Hunter.io, theHarvester, LinkedIn |
| Employee Names | T1589.003 | LinkedIn enumeration |
| Gather Victim Network Info | T1590 | DNS enum, WHOIS, BGP/ASN |
| Domain Properties | T1590.001 | WHOIS, registration data |
| DNS | T1590.002 | dig, dnsx, passive DNS |
| Network Topology | T1590.004 | Traceroute, BGP analysis |
| IP Addresses | T1590.005 | ipinfo.io, ASN lookups |
| Network Security Appliances | T1590.006 | MX record → security vendor ID |
| Gather Victim Org Info | T1591 | LinkedIn, job postings, org chart |
| Determine Physical Locations | T1591.001 | ExifTool GPS, satellite imagery |
| Business Relationships | T1591.002 | Vendor/partner identification |
| Identify Business Tempo | T1591.003 | Social media monitoring |
| Identify Roles | T1591.004 | LinkedIn job title enumeration |
| Search Open Technical Databases | T1596 | Shodan, Censys, crt.sh, WHOIS |
| DNS/Passive DNS | T1596.001 | SecurityTrails, VirusTotal |
| WHOIS | T1596.002 | Direct WHOIS, historical lookups |
| Digital Certificates | T1596.003 | crt.sh, certificate transparency |
| CDNs | T1596.004 | CDN identification from headers/DNS |
| Scan Databases | T1596.005 | Shodan/Censys result analysis |
| Search Open Websites/Domains | T1593 | Google dorks, social media |
| Social Media | T1593.001 | LinkedIn, Twitter OSINT |
| Search Engines | T1593.002 | Google dorks, GHDB |
| Code Repositories | T1593.003 | GitHub dorking, Trufflehog |
| Search Victim-Owned Websites | T1594 | Spider target site, metadata harvest |
| Phishing for Information | T1598 | (Social engineering — authorized only) |

---

## Defensive Recommendations

Use these OSINT findings to drive defensive improvements:

| Finding | Defensive Action |
|---------|-----------------|
| Exposed subdomains (dev/staging) | Restrict to VPN/allowlist; remove DNS records |
| WHOIS personal data exposed | Enable registrar privacy protection |
| Secrets in GitHub history | Rotate credentials immediately; use `git filter-repo` |
| Open S3 buckets | Apply bucket policy: block public access |
| Outdated software in Shodan banners | Patch or suppress version in server headers |
| Employee data in breaches | Force password resets; enforce MFA |
| Sensitive documents indexed | Remove from web; add to robots.txt; request de-index |
| Internal paths in document metadata | Strip metadata before publishing (`exiftool -all=`) |
| Email security vendor exposed via MX | Expected, but review SPF/DKIM/DMARC alignment |
| Cloud metadata endpoint reachable | Enable IMDSv2; restrict metadata to instance only |

---

*ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation.*
