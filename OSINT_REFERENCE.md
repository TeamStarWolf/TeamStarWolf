# OSINT Reference

> **Scope**: This reference is for defensive security practitioners, authorized
> penetration testers, and threat intelligence analysts. All techniques are for
> use only within explicitly authorized engagements and legal frameworks.

---

## Table of Contents

1. [OSINT Fundamentals and Legal Framework](#1-osint-fundamentals-and-legal-framework)
2. [Search Engine OSINT](#2-search-engine-osint)
3. [Domain and IP Intelligence](#3-domain-and-ip-intelligence)
4. [Social Media OSINT (SOCMINT)](#4-social-media-osint-socmint)
5. [People and Identity OSINT](#5-people-and-identity-osint)
6. [Geospatial OSINT (GEOINT)](#6-geospatial-osint-geoint)
7. [Corporate and Business OSINT](#7-corporate-and-business-osint)
8. [Threat Intelligence OSINT](#8-threat-intelligence-osint)
9. [OSINT Frameworks and Tools](#9-osint-frameworks-and-tools)
10. [OSINT Investigation Methodology](#10-osint-investigation-methodology)
11. [OSINT Tools Reference Table](#11-osint-tools-reference-table)
12. [ATT&CK Reconnaissance Mapping](#12-attck-reconnaissance-mapping)

---

## 1. OSINT Fundamentals and Legal Framework

### 1.1 Definition and Reconnaissance Spectrum

**Open Source Intelligence (OSINT)** is intelligence collected from publicly
available sources without requiring covert access or unauthorized interaction
with target systems.

| Reconnaissance Type | Description | Target Awareness | Examples |
|---------------------|-------------|-----------------|----------|
| **Passive** | No direct contact with target infrastructure | None | WHOIS, Shodan, crt.sh, archive.org, Google dorks |
| **Semi-passive** | Minimal interaction indistinguishable from normal internet traffic | Very low | Resolving DNS records, fetching robots.txt |
| **Active** | Direct interaction with target (probes, scans, port sweeps) | Possible | Nmap, nikto, directory brute-force -- **requires explicit authorization** |

> Rule of thumb: Exhaust passive and semi-passive sources before touching the
> target. Active techniques may trigger IDS/WAF alerts and legal exposure.

### 1.2 Intelligence Types

| Acronym | Full Name | OSINT Sources |
|---------|-----------|--------------|
| HUMINT | Human Intelligence | LinkedIn, social media, job postings, conference talks |
| SIGINT | Signals Intelligence | Network traffic metadata, RF emissions (public scanner feeds) |
| GEOINT | Geospatial Intelligence | Google Earth, Sentinel Hub, MarineTraffic, Flightradar24 |
| SOCMINT | Social Media Intelligence | Twitter/X, Facebook, Instagram, TikTok, Reddit |
| TECHINT | Technical Intelligence | CVE databases, Shodan, firmware repositories, code repositories |
| FININT | Financial Intelligence | SEC EDGAR filings, OpenCorporates, Companies House |
| IMINT | Imagery Intelligence | Satellite imagery, street-view temporal analysis |

### 1.3 OSINT Lifecycle

```
1. REQUIREMENTS
   Define target scope, end-state, authorized boundaries, time-box

2. COLLECTION PLANNING
   Identify source categories (DNS, social, corporate, technical)
   Select tools, build OpSec infrastructure

3. COLLECTION
   Passive -> semi-passive -> (authorized active)
   Document every source and timestamp

4. PROCESSING
   Parse raw data into structured records
   Deduplicate, normalize, enrich (e.g., IP -> ASN -> org)

5. ANALYSIS
   Correlate data points (email -> breach -> credential -> infrastructure)
   Build timeline, attribution hypothesis, confidence scoring

6. DISSEMINATION
   Deliver report with evidence, confidence levels, and recommendations
   Classify and handle per engagement agreement
```

### 1.4 Legal Considerations

| Framework | Key Implication |
|-----------|----------------|
| **CFAA** (US) | Accessing a computer without authorization -- or exceeding authorized access -- is criminal even if data is technically visible |
| **GDPR** (EU) | Processing personal data of EU residents requires a lawful basis; security research exemptions are narrow; data minimization mandatory |
| **CCPA** (California) | Similar consent/data-minimization obligations for California residents |
| **Terms of Service** | LinkedIn, Twitter, GitHub prohibit automated scraping; civil liability and account termination risk; use official APIs |
| **Wiretap Act** | Intercepting communications in transit is illegal; cached/public content is different |
| **Computer Misuse Act** (UK) | Similar to CFAA; unauthorized access to data is criminal |

**Checklist before starting any OSINT engagement:**
- [ ] Written authorization (scope document, statement of work, bug-bounty rules)
- [ ] Defined in-scope and out-of-scope assets
- [ ] Data handling and retention agreement
- [ ] OpSec infrastructure ready (burner VM, VPN/Tor, sock puppets if needed)
- [ ] Evidence capture tooling configured (Hunchly, screenshots with timestamps)

### 1.5 Operational Security During OSINT

**Tiered OpSec Model**

| Tier | Infrastructure | Use Case |
|------|---------------|---------|
| 1 -- Low | VPN + clean browser profile + private browsing | Casual research |
| 2 -- Medium | VPN + Tor + hardened VM (Whonix / Tails) | Sensitive passive collection |
| 3 -- High | Dedicated VPS + residential proxy + aged sock-puppet accounts | Active enum, social engineering scenarios |

**Sock puppet account hygiene:**
- Separate email, phone, device fingerprint per persona
- Age accounts weeks/months with organic activity before operational use
- Consistent backstory: location, employer, interests, writing style
- Never cross-contaminate personas (no shared IPs, no linked accounts)
- Rotate and retire personas after engagement

**Burner VM checklist:**
- Fresh snapshot per engagement; revert or destroy after
- DNS over HTTPS / Tor to a neutral resolver (not ISP)
- No browser autofill, sync, or cloud backups
- Clipboard isolation -- never paste real credentials into burner VM
- Disable WebRTC leaks in browser

### 1.6 Documentation and Chain of Custody

Every piece of collected evidence should be recorded with:

| Field | Example |
|-------|---------|
| Collection timestamp (UTC) | 2024-03-15T14:22:01Z |
| Source URL | `https://crt.sh/?q=%.example.com` |
| Collector identity (persona or analyst ID) | OSINT-Analyst-01 |
| Raw data hash (SHA-256) | `e3b0c44298fc1c149a...` |
| Processing notes | Extracted 47 subdomains; 12 resolved |
| Confidence level | High / Medium / Low |

Tools: **Hunchly** (browser extension), **OSINT Combine WebCapture**,
**CyberChef** (data transformation + hashing), plain git-committed markdown.

---

## 2. Search Engine OSINT

### 2.1 Google Dork Complete Reference

Google advanced search operators (also called "dorks") allow precise
targeting of indexed content.

#### Core Operators

| Operator | Syntax | Description | Example |
|----------|--------|-------------|---------|
| `site:` | `site:domain.com` | Restrict results to a domain | `site:target.com filetype:pdf` |
| `filetype:` / `ext:` | `filetype:xlsx` | Filter by file extension | `site:gov.uk filetype:xlsx budget` |
| `inurl:` | `inurl:admin` | Keyword must appear in URL | `inurl:wp-admin site:target.com` |
| `intext:` | `intext:"password"` | Keyword must appear in page body | `intext:"api_key" site:target.com` |
| `intitle:` | `intitle:"index of"` | Keyword in page title | `intitle:"index of" site:target.com` |
| `cache:` | `cache:target.com` | Google's cached version of a page | `cache:target.com/login` |
| `link:` | `link:target.com` | Pages that link to the target | `link:target.com` |
| `related:` | `related:target.com` | Conceptually similar sites | `related:target.com` |
| `"..."` | `"exact phrase"` | Exact phrase match | `"internal use only"` |
| `-` | `-inurl:www` | Exclude results | `site:target.com -inurl:blog` |
| `OR` / `|` | `ext:env OR ext:cfg` | Boolean OR | `site:target.com ext:env OR ext:bak` |
| `*` | `"admin * password"` | Wildcard | `"smtp * password"` |

#### High-Value Dork Combinations

```bash
# Exposed configuration and credential files
site:target.com ext:env OR ext:config OR ext:bak OR ext:cfg OR ext:ini

# Login and admin panels
inurl:admin intitle:"login" site:target.com
inurl:"/wp-admin/admin-ajax.php" site:target.com

# Exposed directory listings
intitle:"index of" site:target.com

# PDF documents (annual reports, internal policies)
site:target.com filetype:pdf "confidential" OR "internal" OR "proprietary"

# Excel spreadsheets
site:target.com filetype:xlsx OR filetype:csv

# PHP info pages
intitle:"phpinfo()" site:target.com

# Open redirect / SSRF vectors
inurl:"redirect=" site:target.com
inurl:"url=" site:target.com

# Exposed git repos
inurl:".git/config" site:target.com

# Error messages leaking paths
intext:"Fatal error: Uncaught" site:target.com
intext:"Warning: include(" site:target.com

# Jenkins / CI dashboards
intitle:"Dashboard [Jenkins]"

# Kibana dashboards
inurl:"/app/kibana#" intitle:"Kibana"

# Exposed Swagger / API docs
inurl:"/api/swagger" OR inurl:"/swagger-ui.html"

# Camera/IoT dashboards
intitle:"webcam 7" OR intitle:"Live View / - AXIS" OR intitle:"Network Camera"
```

#### GHDB (Google Hacking Database) Categories

The Exploit-DB GHDB (https://www.exploit-db.com/google-hacking-database)
catalogs dorks by category:

| Category | Examples |
|----------|---------|
| Footholds | Login panels, admin interfaces |
| Files Containing Juicy Info | Passwords, API keys in source code |
| Sensitive Directories | Config dirs, backup dirs |
| Web Server Detection | Server headers, default pages |
| Vulnerable Files | Old scripts with known CVEs |
| Error Messages | Stack traces with path disclosure |
| Files Containing Passwords | .htpasswd, shadow, config.php |
| Various Online Devices | Webcams, printers, routers |
| Advisories and Vulnerabilities | Vendor advisories |

### 2.2 Other Search Engines

**Bing Dorks**

| Operator | Description |
|----------|-------------|
| `site:` | Domain restriction |
| `filetype:` | File type filter |
| `ip:1.2.3.4` | Search by IP address |
| `inbody:` | Keyword in body |
| `intitle:` | Keyword in title |
| `feed:` | Search RSS/Atom feeds |

**DuckDuckGo Operators**

DuckDuckGo supports `site:`, `filetype:`, `inurl:`, `intitle:`, and
bang-redirects (`!g` for Google, `!s` for Shodan, `!w` for Wikipedia).

**Yandex**

Yandex indexes some Eastern European infrastructure not in Google.
Supports `site:`, `url:`, `inurl:`, `mime:` (filetype equivalent).
Yandex reverse image search often outperforms Google for facial recognition
style lookups due to its own neural net indexing.

**Baidu**

Useful for Chinese-hosted infrastructure.
Operators: `site:`, `filetype:`, `inurl:`, `intitle:`.
Use when targeting organizations with significant China presence.

### 2.3 Wayback Machine and Web Archives

```bash
# Enumerate all URLs archived for a domain
curl "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey"

# Specific date range
curl "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&from=20200101&to=20201231"

# Find archived robots.txt (may reveal hidden paths)
curl "https://web.archive.org/web/*/https://target.com/robots.txt"

# Retrieve specific cached page
curl "https://web.archive.org/web/20230101000000/https://target.com/login"

# List all snapshots for a URL
curl "https://web.archive.org/cdx/search/cdx?url=target.com/admin&output=json&fl=timestamp,statuscode"
```

**Other archive sources:**
- `https://cachedview.nl/` -- multi-engine cached page viewer
- `https://archive.ph/` (formerly archive.is) -- on-demand snapshots
- `https://CommonCrawl.org` -- petabyte-scale web crawl index
- `https://timetravel.mementoweb.org/api/` -- unified Memento API

### 2.4 Cached Page Analysis

Cached pages can expose content that has since been removed or changed:

```bash
# Google cache
cache:https://target.com/internal-docs

# Bing cache
# Search: site:target.com, click dropdown arrow -> "Cached"

# Yandex cache via search result "Cached copy" link

# Check if page exists in multiple caches simultaneously
# cachedview.nl aggregates Google, Bing, Yandex caches in one interface
```

---

## 3. Domain and IP Intelligence

### 3.1 WHOIS and Domain Registration

```bash
# Current WHOIS
whois target.com

# IANA root WHOIS (authoritative registrar info)
whois -h whois.iana.org target.com

# Historic WHOIS -- use web interfaces:
# DomainTools History: domaintools.com/research/whois-history/
# SecurityTrails: securitytrails.com/domain/target.com/history/whois
```

**Bypassing WHOIS privacy services:**
- Check WHOIS records before privacy service was applied (DomainTools history)
- Look for SSL certificate email leakage (crt.sh shows registration emails for some CAs)
- Historical DNS records may show original registrant IP
- Breach databases sometimes contain domain registration emails
- Reverse WHOIS: viewdns.info/reversewhois -- find all domains by same registrant email

### 3.2 DNS Enumeration

```bash
# --- Passive DNS (no direct contact with target nameservers) ---

# Subdomain enumeration with Amass (passive mode)
amass enum -passive -d target.com -o amass_passive.txt

# Subfinder -- aggregates 50+ passive sources
subfinder -d target.com -all -recursive -o subfinder_out.txt

# Certificate transparency logs (no rate limit)
curl "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# SecurityTrails API (requires free API key)
curl -H "apikey: $ST_KEY" "https://api.securitytrails.com/v1/domain/target.com/subdomains?includeInactive=true"

# --- Semi-passive DNS ---

# Resolve subdomains to IPs
cat subdomains.txt | dnsx -a -resp -o resolved.txt

# Probe for live HTTP(S) services
cat resolved.txt | httpx -title -status-code -tech-detect

# --- Zone transfer attempt (active, may trigger alerts) ---
dig AXFR @ns1.target.com target.com

# --- DNS brute force (active) ---
dnsx -d target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -resp

# gobuster DNS mode
gobuster dns -d target.com -w /path/to/wordlist.txt -t 50
```

**DNS record types to enumerate:**

| Record | Information Value |
|--------|-----------------|
| A / AAAA | IPv4/IPv6 addresses -- IP infrastructure mapping |
| MX | Mail servers -- email provider, potential email spoofing intel |
| TXT | SPF, DKIM, DMARC, domain verification tokens (Google, AWS, Stripe) |
| NS | Nameservers -- DNS hosting provider |
| CNAME | Aliases -- may reveal cloud providers (s3.amazonaws.com, *.azurewebsites.net) |
| SOA | Zone admin contact, serial (update frequency indicator) |
| SRV | Service records -- VoIP, XMPP, LDAP, Kerberos presence |
| PTR | Reverse DNS -- hostname-to-IP mapping |

**TXT record intelligence:**

```bash
# Get all TXT records
dig TXT target.com +short

# Interesting TXT record patterns:
# "v=spf1 include:sendgrid.net ..."  -> uses SendGrid for email
# "google-site-verification=..."     -> has Google Workspace
# "MS=ms..."                         -> has Microsoft 365
# "stripe-verification=..."          -> uses Stripe payments
# "atlassian-domain-verification=..."-> uses Atlassian products
# "_amazonses..."                     -> uses AWS SES
# "docusign=..."                      -> uses DocuSign
# "zoom-domain-verification=..."     -> uses Zoom
```

### 3.3 Shodan

Shodan indexes internet-connected devices by crawling banners on common ports.

**Key search operators:**

| Operator | Description | Example |
|----------|-------------|---------|
| `hostname:` | Filter by hostname/domain | `hostname:target.com` |
| `org:` | Filter by organization name | `org:"Target Corp"` |
| `net:` | Filter by CIDR range | `net:203.0.113.0/24` |
| `port:` | Specific port | `port:8080` |
| `country:` | Two-letter country code | `country:US` |
| `city:` | City name | `city:"New York"` |
| `os:` | Operating system | `os:"Windows Server 2019"` |
| `product:` | Software product | `product:"Apache httpd"` |
| `version:` | Software version | `version:"2.4.49"` |
| `ssl.cert.subject.cn:` | SSL cert CN | `ssl.cert.subject.cn:"*.target.com"` |
| `ssl.cert.issuer.cn:` | Cert issuer | `ssl.cert.issuer.cn:"Let's Encrypt"` |
| `http.title:` | HTTP page title | `http.title:"admin panel"` |
| `http.html:` | HTML body content | `http.html:"powered by target"` |
| `before:` / `after:` | Date filters | `after:01/01/2024` |
| `vuln:` | CVE present | `vuln:CVE-2021-44228` |

```bash
# CLI examples
shodan search "org:'Target Corp' port:443" --fields ip_str,port,hostnames
shodan host 1.2.3.4

# Search for expired/self-signed certs in org
shodan search "org:'Target Corp' ssl.cert.expired:true"

# Find Jenkins instances
shodan search "http.title:'Dashboard [Jenkins]' org:'Target Corp'"

# Find log4shell vulnerable instances
shodan search "vuln:CVE-2021-44228 org:'Target Corp'"

# Count results without revealing (free tier friendly)
shodan count "org:'Target Corp'"

# Export to CSV
shodan search --limit 1000 --fields ip_str,port,org,hostname "org:'Target Corp'" > shodan_results.csv
```

### 3.4 Censys

Censys scans the entire IPv4 space for common ports and indexes TLS certificates.

```
# Censys Search syntax (v2 API)
services.port: 8443 and autonomous_system.name: "Target Corp"
services.tls.certificates.leaf_data.subject.common_name: "*.target.com"
services.http.response.html_title: "admin"

# Certificate search
parsed.names: "target.com"
parsed.subject.organization: "Target Corp"
parsed.issuer.common_name: "Let's Encrypt"

# Find hosts with self-signed certs
parsed.issuer.common_name = parsed.subject.common_name
```

```bash
# Censys CLI
pip3 install censys
censys search "services.tls.certificates.leaf_data.names: target.com" --index-type hosts
censys view 1.2.3.4 --index-type hosts
```

### 3.5 Other Internet Scanning Platforms

| Platform | Strength | Notes |
|----------|---------|-------|
| **FOFA** | Chinese infrastructure, IoT, ICS | Syntax: `domain="target.com"`, `ip="1.2.3.4"`, `app="Nginx"` |
| **ZoomEye** | Chinese platform, broad coverage | `site:target.com`, `app:nginx`, `service:ssh` |
| **GreyNoise** | Context on mass-internet scanners | Differentiates benign scanners (Shodan, Censys) from malicious ones |
| **BinaryEdge** | Real-time scanning, vulnerability data | Subscription-based API; good for certificate data |
| **LeakIX** | Exposed services, data leaks | Free tier; focuses on sensitive exposures |
| **Netlas** | Modern Shodan alternative | WHOIS + DNS + port data; newer index |
| **Criminal IP** | Korean platform | Strong on IoT and credential exposure |

### 3.6 ASN Enumeration

```bash
# Find all ASNs for an organization
# bgp.he.net web interface: search org name

# Get all prefixes for an ASN
whois -h whois.radb.net -- '-i origin AS12345'

# Team Cymru IP-to-ASN mapping
whois -h whois.cymru.com " -v 203.0.113.1"

# Bulk ASN lookups
echo "203.0.113.1" | nc whois.cymru.com 43

# RIPE stat API
curl "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS12345"
curl "https://stat.ripe.net/data/as-overview/data.json?resource=AS12345"

# BGP.tools
curl "https://bgp.tools/as/12345#prefixes"

# Hurricane Electric BGP toolkit
# https://bgp.he.net/ip/203.0.113.1 -- shows ASN, prefix, org, peers
```

### 3.7 IP Geolocation and Reverse Lookups

```bash
# IP geolocation (note: city-level accuracy +/- 50 km typical)
curl "https://ipinfo.io/203.0.113.1/json"
curl "https://ip-api.com/json/203.0.113.1"

# MaxMind GeoLite2 (downloadable database)
# pip3 install geoip2
python3 -c "import geoip2.database; r=geoip2.database.Reader('GeoLite2-City.mmdb'); print(r.city('203.0.113.1').city.name)"

# Reverse IP -- find all domains hosted on same IP
curl "https://api.hackertarget.com/reverseiplookup/?q=203.0.113.1"
# viewdns.info/reverseip/?host=203.0.113.1
```

**Accuracy limitations:**
- CDN IPs (Cloudflare, Akamai, Fastly) geo-locate to CDN PoP, not origin server
- Cloud IPs (AWS, Azure, GCP) resolve to data-center regions, not company HQ
- VPN/proxy IPs show VPN server location
- Mobile carrier IPs may show gateway location

---

## 4. Social Media OSINT (SOCMINT)

### 4.1 LinkedIn

LinkedIn is the most valuable SOCMINT source for corporate targets.

```
# Google dorks for LinkedIn
site:linkedin.com/in "Target Company" "security engineer"
site:linkedin.com/company "Target Company"
site:linkedin.com/in "Target Company" "cloud architect"
site:linkedin.com/in "Target Company" "devops"

# Find former employees (often more talkative)
site:linkedin.com/in "former" "Target Company"

# Find employees at specific seniority
site:linkedin.com/in "Target Company" "CISO" OR "VP of Engineering"
```

**Manual techniques:**
- Org chart reconstruction via "People" tab on company page
- Skills endorsements -> infer technology stack
- Post history -> project announcements, technology migrations
- Education -> likely alma mater, security conference attendance
- Connection count -- low count may indicate fake/monitoring account
- "Open to work" tags on employees -> potential disgruntled staff

**Tools:**
- **linkedin2username** -- generates likely username combinations from LinkedIn
- **CrossLinked** -- name-format enumeration for email generation

### 4.2 Twitter / X

```
# Advanced Search URL
https://twitter.com/search?q=from%3Atarget_account&src=typed_query&f=live

# All tweets from an account
from:username

# Geo-tagged tweets near a location
geocode:37.7749,-122.4194,1km

# Tweets mentioning target in a date range
from:ceo_account since:2023-01-01 until:2023-06-01

# Find leaked credentials mentioned
"target.com" "password" OR "api_key" OR "token"

# Filter by media type
from:username filter:media

# Deleted tweet recovery:
# Wayback Machine: https://web.archive.org/web/*/https://twitter.com/user/status/*
# Politwoops (monitors public figures)
# archive.org search for twitter.com/username
```

### 4.3 Facebook

Post-2019 Graph API restrictions significantly limited automated enumeration.
Remaining OSINT vectors:

- Public group posts and membership lists
- Event attendees for corporate events
- Photo metadata in public posts (location tags, timestamps)
- "Check-in" history of employees at office locations
- Business pages: about section, team members tagged in posts
- Facebook Marketplace for employee personal listings tied to work location

**Graph URL patterns (manual exploration):**
```
https://www.facebook.com/search/people/?q=John%20Smith&filters={"employee_of":[{"name":"employer","args":"Target Corp"}]}
```

### 4.4 Instagram

- Location tagging: search by location to find photos taken at target's office/site
- Story highlights: employees sometimes post office/lab content
- Hashtag search: `#targetcompany`, `#worklife`, `#teamtarget`
- Tagged photos: employees tagged by colleagues
- EXIF note: Instagram strips GPS EXIF but preserves approximate location tag from posting UI

### 4.5 GitHub OSINT

```bash
# Google dorks for GitHub
site:github.com "target.com" password
site:github.com "target.com" api_key
site:github.com "target.com" "BEGIN RSA PRIVATE KEY"
site:github.com "target.com" "aws_access_key_id"
site:github.com "target.com" secret_key
site:github.com "target.com" token

# GitHub native search
org:TargetOrg language:python "api_key"
org:TargetOrg filename:.env
org:TargetOrg filename:config.yml password

# Automated secret scanning
trufflehog github --org=TargetOrg --token=$GITHUB_TOKEN --json

# gitleaks -- scan a cloned repo
gitleaks detect --source /path/to/repo --report-format json

# GitDorker -- bulk dork search
python3 gitdorker.py -tf /path/to/token_file -q target.com -p dorks/gitdork_sensitive.txt

# Enumerate org members
gh api orgs/TargetOrg/members --paginate | jq '.[].login'

# Get user contribution history (shows active repos)
gh api users/username/events --paginate | jq '.[].repo.name' | sort -u

# List org repos
gh api orgs/TargetOrg/repos --paginate | jq '.[].full_name'
```

### 4.6 Paste Sites and Dark Web

```bash
# Paste site monitoring
# Pastebin: https://pastebin.com/search?q=target.com (limited without API)
# Ghostbin, Pastefy, rentry.co, Hastebin

# Automated paste monitoring
# psbdmp.ws API:
curl "https://psbdmp.ws/api/v3/search/target.com"

# Dark web presence (requires Tor)
# ahmia.fi -- dark web search engine (clearnet accessible)
# tor2web proxies (not anonymous for the researcher)

# .onion site enumeration
# Hunchly dark web module
# OnionSearch aggregator
# DarkSearch.io -- dark web search API
```

---

## 5. People and Identity OSINT

### 5.1 Email Discovery

```bash
# Hunter.io -- email pattern discovery for a domain
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$HUNTER_KEY"

# Get email format used at a company
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$HUNTER_KEY" | jq '.data.pattern'

# theHarvester -- combines multiple sources
theHarvester -d target.com -l 500 -b all -f output.html

# Phonebook.cz -- bulk email discovery
# https://phonebook.cz/?q=target.com&type=2

# Manual permutation patterns to try:
# first.last@target.com
# flast@target.com
# firstl@target.com
# first@target.com
# f.last@target.com
# firstname@target.com
# lastf@target.com

# EmailHippo permutation tool
# Mailmeteor email permutator
```

### 5.2 Email Verification

```bash
# SMTP VRFY command (if not disabled by server)
telnet mail.target.com 25
EHLO attacker.com
VRFY john.smith@target.com

# RCPT TO method (bypasses VRFY restrictions)
MAIL FROM:<test@test.com>
RCPT TO:<john.smith@target.com>

# Catch-all detection -- send to nonexistent address first
# If 250 OK returned for garbage address -> catch-all configured

# Email verification APIs (check deliverability without sending)
curl "https://api.hunter.io/v2/email-verifier?email=john@target.com&api_key=$KEY"

# Disposable/temp email detection
# Mailcheck.ai
# Debounce.io
```

### 5.3 Username Enumeration

```bash
# Sherlock -- check 300+ platforms
python3 sherlock username --output results.txt --print-found

# WhatsMyName -- OSINT Framework username tool
# https://whatsmyname.app/
# python3 WhatsMyName.py -u username

# Namechk.com -- availability checker (also confirms existing accounts)

# Social Analyzer
python3 -m social_analyzer --query "username" --mode "fast"

# Holehe -- email-to-platform account checker
holehe john.doe@gmail.com

# Maigret -- username OSINT (Sherlock fork with more sites)
python3 -m maigret username --html --pdf
```

### 5.4 Phone Number OSINT

- **Truecaller** -- crowdsourced phone book; names linked to numbers
- **Carrier lookup APIs** -- identify carrier, line type (mobile/VoIP/landline)
- **GetContact** -- similar to Truecaller; community-sourced labels
- **OpenCNAM** -- CNAM (Caller ID Name) lookup
- **Reverse lookup:** whitepages.com, spokeo.com (US focus)
- **Numverify API** -- line type, carrier, country validation

```bash
# Carrier and line type lookup
curl "http://apilayer.net/api/validate?access_key=$KEY&number=+15551234567"

# OSINT Industries phone lookup
# https://osint.industries -- aggregates multiple phone sources
```

### 5.5 Public Records

| Record Type | Source |
|-------------|--------|
| Court records | PACER (US federal), state court portals |
| Property records | County assessor / GIS portals |
| Business registrations | Secretary of State portals, OpenCorporates |
| Voter registration | State boards of elections (varies by state) |
| Professional licenses | State licensing board portals |
| FAA pilot certificates | https://amsrvs.registry.faa.gov |
| FCC license database | https://wireless2.fcc.gov/UlsApp/UlsSearch/ |
| UCC filings | State UCC databases (business liens) |
| Marriage/divorce | State vital records, county clerk |
| Bankruptcy | PACER federal bankruptcy search |

### 5.6 Data Breach Lookup

```bash
# HaveIBeenPwned API
curl -H "hibp-api-key: $HIBP_KEY" "https://haveibeenpwned.com/api/v3/breachedaccount/email@target.com"

# Get all breaches (for context on what data was exposed)
curl "https://haveibeenpwned.com/api/v3/breaches"

# IntelX (intelligence X) -- paste + breach search
curl -H "x-key: $INTELX_KEY" "https://2.intelx.io/intelligent/search" \
  -d '{"term":"target.com","buckets":[],"lookuplevel":0,"maxresults":100}'

# DeHashed -- credential database search (subscription)
# https://dehashed.com/search?query=target.com

# Leak-Lookup
curl "https://leak-lookup.com/api/search" -d "key=$LL_KEY&type=domain&query=target.com"

# COMB (Collection of Many Breaches) -- local search if downloaded
# grep -i "target.com" COMB/*.txt (local copy only, do not distribute)
```

### 5.7 Photo and Image OSINT

```bash
# EXIF metadata extraction
exiftool -all image.jpg

# Extract GPS coordinates
exiftool -GPSLatitude -GPSLongitude -GPSAltitude photo.jpg

# Convert GPS from DMS to decimal
python3 -c "
def dms_to_decimal(dms, ref):
    d, m, s = dms
    decimal = d + m/60 + s/3600
    if ref in ['S', 'W']:
        decimal = -decimal
    return decimal
# Usage: dms_to_decimal((37, 46, 29.4), 'N')
"

# Batch extract from all images in directory
exiftool -csv -GPSLatitude -GPSLongitude *.jpg > gps_data.csv

# Remove EXIF before sharing (operational security)
exiftool -all= -overwrite_original output.jpg

# Bulk strip metadata from directory
exiftool -all= -overwrite_original /path/to/images/
```

**Reverse image search:**
- Google Images: upload or paste URL (`images.google.com`)
- Yandex Images: best for facial recognition style lookups
- TinEye: exact duplicate tracking, first-seen dating (`tineye.com`)
- PimEyes: face-based reverse search (subscription for full features)
- Bing Visual Search: good general alternative

**Image analysis tools:**
- **Jeffrey's Exif Viewer**: online EXIF display with map integration
- **GeoSetter**: batch GPS data editor/viewer
- **Pic2Map**: GPS coordinates to map visualization

---

## 6. Geospatial OSINT (GEOINT)

### 6.1 Satellite and Aerial Imagery

| Source | Resolution | Notes |
|--------|-----------|-------|
| Google Earth Pro | 0.3 m (commercial areas) | Historical imagery time-slider; free |
| Sentinel Hub | 10 m (Sentinel-2), 30 m (Landsat) | Free API; near real-time |
| Planet Labs | 3-5 m daily global | Subscription required |
| Maxar/DigitalGlobe | 30 cm | Commercial/government; public via Google Earth |
| Microsoft Bing Maps | 0.3 m (urban) | Useful alternative to Google |
| ESRI World Imagery | Varies | ArcGIS Online viewer |
| NASA Worldview | 250 m-1 km | Free; good for large-area analysis |
| Copernicus Emergency | Varies | Disaster response, free activation |
| USGS Earth Explorer | 15-30 m | Landsat, free download |

### 6.2 Photo Timestamp Verification

**SunCalc** (https://suncalc.org):
- Input location + date -> generates sun position arc
- Compare shadow direction/length in photo to calculated sun position
- Validates or falsifies claimed timestamp and location

**Chronolocation workflow:**
1. Identify distinctive landmarks in photo (buildings, mountains, street signs)
2. Reverse image search to find location (Google, Yandex, TinEye)
3. Cross-validate with street view and satellite imagery
4. Use SunCalc or Timeanddate.com sun calculator for shadow analysis
5. Cross-reference with weather records (cloud cover, snow depth) for date validation
6. Check local astronomical data (moon phase if visible)

**Tools for chronolocation:**
- SunCalc.org -- sun position calculator
- Timeanddate.com/sun -- sun/moon position and shadows
- Wolfram Alpha -- astronomical queries
- Weather Underground historical -- cloud cover, precipitation, snow

### 6.3 OpenStreetMap / Overpass API

```bash
# Extract all buildings in a bounding box (lat_min, lon_min, lat_max, lon_max)
curl "https://overpass-api.de/api/interpreter" \
  --data '[out:json];(way["building"](51.5,-0.12,51.52,-0.1););out geom;'

# Find all hospitals in a city
curl "https://overpass-api.de/api/interpreter" \
  --data '[out:json];node["amenity"="hospital"](51.5,-0.2,51.6,0.0);out body;'

# Find security camera locations (community-tagged)
curl "https://overpass-api.de/api/interpreter" \
  --data '[out:json];node["man_made"="surveillance"](bbox);out body;'

# Export to GeoJSON for visualization
curl "https://overpass-api.de/api/interpreter" \
  --data '[out:json];way["name"="Target Street"](bbox);out geom;' | python3 -c "
import json, sys
data = json.load(sys.stdin)
# Convert to GeoJSON for QGIS/kepler.gl
"
```

### 6.4 Transportation Tracking

**Maritime (AIS):**
- MarineTraffic (https://marinetraffic.com) -- live vessel tracking
- VesselFinder -- alternative AIS viewer
- AIS Hub -- raw AIS data feeds
- ShipFinder -- mobile-focused AIS app
- Search by: vessel name, IMO number, MMSI, company

**Aviation (ADS-B):**
- Flightradar24 -- live commercial flight tracking
- FlightAware -- historical flight data, delays
- ADSB Exchange -- unfiltered (includes military, private)
- OpenSky Network -- free API for historical ADS-B data

```python
# OpenSky Network API -- historical flight data
import requests
res = requests.get("https://opensky-network.org/api/flights/aircraft",
    params={"icao24": "a835af", "begin": 1609459200, "end": 1609545600})
flights = res.json()
for f in flights:
    print(f["callsign"], f["estDepartureAirport"], f["estArrivalAirport"])
```

**Ground transport:**
- Waze real-time alerts (crowd-sourced incidents)
- Apple Maps / Google Maps -- congestion patterns
- Transit APIs (GTFS feeds) -- public transit schedule data

### 6.5 Cell Tower and Wi-Fi Geolocation

```bash
# OpenCellID -- crowdsourced cell tower database
curl "https://opencellid.org/cell/get?key=$OCID_KEY&mcc=310&mnc=410&lac=41001&cellid=22151"

# Mozilla Location Services (archived data available)
# mlsdata.mozilla.org/v1/export/ -- downloadable CSV database

# WiGLE -- Wi-Fi network geolocation (useful for finding corporate offices)
curl -u "apiname:apitoken" "https://api.wigle.net/api/v2/network/search?ssid=TargetWifi"

# Estimate location from SSID
# Corporate SSIDs often follow patterns: COMPANY-Corp, COMPANY-Guest, COMPANY_SEC
# Cross-reference with physical address in WiGLE results
```

---

## 7. Corporate and Business OSINT

### 7.1 Company Registration and Filings

| Source | Jurisdiction | Data Available |
|--------|-------------|----------------|
| SEC EDGAR | US public companies | 10-K, 10-Q, 8-K, proxy statements, beneficial ownership |
| Companies House | UK | Registration, directors, accounts, charges |
| OpenCorporates | Global aggregator | 200M+ company records, officer relationships |
| EU BRIS | EU | Cross-border company search |
| SEDAR+ | Canada | Public company filings |
| ASIC | Australia | Company registration, officers |
| MCA | India | Ministry of Corporate Affairs registry |

```bash
# SEC EDGAR full-text search
curl "https://efts.sec.gov/LATEST/search-index?q=%22target+company%22&dateRange=custom&startdt=2023-01-01&enddt=2024-01-01&forms=10-K"

# EDGAR XBRL data (structured financial data)
curl "https://data.sec.gov/submissions/CIK0000320193.json"

# Get all filings for a company
curl "https://data.sec.gov/submissions/CIK0000320193.json" | jq '.filings.recent.form'
```

**What to look for in SEC filings:**
- 10-K: "Risk Factors" section for cybersecurity disclosures
- 8-K: Material cybersecurity incidents (required post-SEC rule 2023)
- Proxy statements: executive names, compensation, board composition
- S-1 (IPO filing): detailed technology infrastructure description

### 7.2 Technology Stack Fingerprinting

```bash
# Wappalyzer CLI
wappalyzer https://target.com

# WhatWeb
whatweb target.com

# Built With API
curl "https://api.builtwith.com/free1/api.json?KEY=$BW_KEY&LOOKUP=target.com"

# Netcraft site report
# https://sitereport.netcraft.com/?url=https://target.com

# httpx with technology detection
echo "target.com" | httpx -tech-detect -json -o tech_results.json

# Analyze HTTP response headers manually
curl -I https://target.com

# Key headers for fingerprinting:
# Server: Apache/2.4.49 -> web server and version
# X-Powered-By: PHP/7.4.3 -> backend language
# Set-Cookie: PHPSESSID -> PHP
# Set-Cookie: JSESSIONID -> Java/Spring
# X-AspNet-Version -> .NET version
# Via: nginx -> reverse proxy
# CF-Ray -> Cloudflare protected
# X-Cache: HIT from Varnish -> Varnish cache
```

**Inferences from job postings:**
- Search LinkedIn Jobs / Indeed / Greenhouse / Lever for "target company"
- Required skills -> current tech stack
- "Migrating from X to Y" -> in-progress infrastructure projects
- Cloud provider (AWS/Azure/GCP) certifications required -> cloud strategy
- Security tooling mentioned -> EDR/SIEM/XDR vendors in use

### 7.3 Cloud Storage Exposure

```bash
# S3 bucket naming patterns to try:
# target-backup, target-dev, target-prod, target-logs, target-data
# target-assets, target-uploads, target-media, target-static

# Test public access
aws s3 ls s3://target-bucket --no-sign-request

# lazys3 -- systematic bucket enumeration
python3 lazys3.py target

# cloud_enum -- multi-cloud (AWS, Azure, GCP)
python3 cloud_enum.py -k target -k targetcompany -k target-inc

# GrayhatWarfare -- searchable public bucket index
# https://buckets.grayhatwarfare.com

# Azure Blob Storage patterns
# https://target.blob.core.windows.net/$web/
# https://target.blob.core.windows.net/backup/

# GCP buckets
curl -s "https://storage.googleapis.com/target-bucket/" | grep -i "key\|name"

# Firebase database exposure check
curl "https://target-default-rtdb.firebaseio.com/.json?shallow=true"

# Elasticsearch exposure (often via Shodan)
shodan search "product:Elastic port:9200 org:'Target Corp'"
curl "http://1.2.3.4:9200/_cat/indices?v"
```

### 7.4 Document Metadata

```bash
# Extract metadata from Office documents
exiftool -Author -Creator -LastSavedBy -Company document.docx

# Bulk metadata extraction from website documents
# metagoofil -- downloads and extracts metadata from public documents
metagoofil -d target.com -t pdf,doc,xls,ppt -l 100 -n 50 -o /output

# FOCA (Windows) -- automated metadata extraction and analysis
# GUI tool; automatic metadata harvesting from Google/Bing indexed docs

# Interesting metadata fields and their OSINT value:
# Author -> employee names -> email permutation
# Company -> confirm target org name, subsidiaries
# LastSavedBy -> most recent editor (IT admin?)
# Template -> internal template paths (reveals internal hostnames/file shares)
# Revision count -> development iteration info
# Software -> version of Office/Adobe used (patch level)
# Created/Modified timestamps -> work hours (timezone inference)
```

### 7.5 SSL Certificate Intelligence

```bash
# crt.sh -- certificate transparency log search
curl "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Find wildcard certs
curl "https://crt.sh/?q=*.target.com&output=json" | jq '.[].id,.issuer_name'

# Censys certificate search
# parsed.names: "target.com" and parsed.subject.organization: "Target Corp"

# Extract email from cert (sometimes reveals registrant/admin email)
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text | grep -A2 "Subject:"

# Find all IPs presenting a target's certificate (CDN bypass)
# Censys: services.tls.certificates.leaf_data.names: target.com
```

### 7.6 Supply Chain Mapping

```bash
# Identify JavaScript/CDN dependencies
curl -s https://target.com | grep -oP 'src="[^"]*"' | grep -v 'target.com'

# BuiltWith technology profile -- supplier list
# https://builtwith.com/target.com -> "Hosting", "CDN", "Analytics", "Payment"

# Common subdomain CNAME -> supplier mapping:
# *.awsapps.com -> AWS WorkMail
# *.servicenow.com -> ServiceNow ITSM
# *.okta.com -> Okta IdP
# *.zendesk.com -> Zendesk support
# *.salesforce.com -> Salesforce CRM
# *.workday.com -> Workday HR/Finance
# *.bamboohr.com -> BambooHR
# *.greenhouse.io -> Greenhouse ATS

# Software BOM inference from public repos
# Check package.json, requirements.txt, pom.xml, go.mod in public GitHub repos
```

---

## 8. Threat Intelligence OSINT

### 8.1 Indicator of Compromise (IoC) Lookup

```bash
# VirusTotal -- file, URL, IP, domain
curl -H "x-apikey: $VT_KEY" "https://www.virustotal.com/api/v3/domains/malicious.com"
curl -H "x-apikey: $VT_KEY" "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"
curl -H "x-apikey: $VT_KEY" "https://www.virustotal.com/api/v3/files/{sha256_hash}"

# Get all domains related to an IP on VirusTotal
curl -H "x-apikey: $VT_KEY" "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/resolutions"

# AbuseIPDB
curl -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" \
  "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90"

# URLscan.io
curl -H "API-Key: $URLSCAN_KEY" "https://urlscan.io/api/v1/search/?q=domain:malicious.com"

# Screenshot a URL safely via URLscan
curl -X POST -H "API-Key: $URLSCAN_KEY" -H "Content-Type: application/json" \
  "https://urlscan.io/api/v1/scan/" -d '{"url":"https://suspicious.com","visibility":"private"}'

# Hybrid Analysis (free sandbox)
curl -H "api-key: $HA_KEY" -H "User-Agent: Falcon Sandbox" \
  "https://www.hybrid-analysis.com/api/v2/search/hash" -d "hash={sha256}"

# Pulsedive -- IoC enrichment
curl "https://pulsedive.com/api/?indicator=1.2.3.4&pretty=1&key=$PD_KEY"
```

### 8.2 Malware Databases

| Platform | Focus | Access |
|---------|-------|--------|
| **MalwareBazaar** | Malware samples (upload/download) | Free API |
| **Threatfox** | IoCs (IPs, domains, URLs, hashes) | Free API |
| **OpenPhish** | Phishing URLs feed | Free feed |
| **PhishTank** | Community-verified phishing | Free API |
| **VirusTotal** | Multi-AV scan results + relationship graph | Free + paid |
| **CAPE Sandbox** | Dynamic analysis reports | Free (capefiles.net) |
| **ANY.RUN** | Interactive sandbox | Free tier |
| **Joe Sandbox** | Deep static/dynamic analysis | Subscription |
| **Triage** | Cloud malware sandbox | Free community tier |

```bash
# MalwareBazaar API -- search by hash
curl "https://mb-api.abuse.ch/api/v1/" \
  -d "query=get_info&hash=abc123..."

# MalwareBazaar -- search by tag
curl "https://mb-api.abuse.ch/api/v1/" \
  -d "query=get_taginfo&tag=Emotet&limit=100"

# Threatfox IoC search
curl "https://threatfox-api.abuse.ch/api/v1/" \
  -d '{"query": "search_ioc", "search_term": "1.2.3.4"}'

# Threatfox -- get all IoCs for a malware family
curl "https://threatfox-api.abuse.ch/api/v1/" \
  -d '{"query": "taginfo", "tag": "Cobalt Strike"}'
```

### 8.3 Threat Actor Tracking

```bash
# MITRE ATT&CK actor profiles (raw JSON)
curl "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/intrusion-set/intrusion-set--8a7e79d3-00d4-4e80-b84d-ab3f7e93e0f3.json"

# Get all ATT&CK groups
curl "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" | \
  jq '[.objects[] | select(.type=="intrusion-set") | {name: .name, aliases: .aliases}]'

# OpenCTI REST API (requires local instance)
curl -H "Authorization: Bearer $OPENCTI_KEY" \
  "https://opencti.local/graphql" \
  -d '{"query": "{ threatActors { edges { node { name aliases } } } }"}'

# MISP feed search (community instance)
# https://misp.circl.lu -- public demo instance
```

**STIX/TAXII Feeds:**

| Feed | Provider | Notes |
|------|---------|-------|
| CISA AIS | US-CERT | Free, registration required; taxii.us-cert.gov |
| FS-ISAC | Financial Sector | Member-only premium; limited public |
| H-ISAC | Healthcare Sector | Member organization required |
| MS-ISAC | Multi-State (US Gov) | cisecurity.org |
| CIRCL MISP | Luxembourg CERT | Free public MISP feeds |
| AlienVault OTX | AT&T / OTX community | Free; broad coverage |

### 8.4 Brand Monitoring and Typosquat Detection

```bash
# dnstwist -- typosquat domain detection
dnstwist --registered target.com

# URLCrazy -- typo domain generation
urlcrazy target.com

# Catphish -- phishing domain detection
python3 catphish.py -d target.com

# CertStream -- real-time certificate transparency monitoring
# Look for newly registered certs with target name variants
python3 -c "
import certstream
def callback(message, context):
    if message['message_type'] == 'certificate_update':
        domains = message['data']['leaf_cert']['all_domains']
        for domain in domains:
            if 'target' in domain.lower():
                print(domain)
certstream.listen_for_events(callback, url='wss://certstream.calidog.io/')
"
```

### 8.5 Paste and Credential Leak Monitoring

```bash
# Pawnbin -- Pastebin monitoring
python3 pwnbin.py target.com

# Pastehunter -- self-hosted paste monitoring
# github.com/kevthehermit/PastHunter

# PSBDMP.ws API -- search pastebin archives
curl "https://psbdmp.ws/api/v3/search/target.com" | jq '.data[].id'

# GitHub secret monitoring (continuous / scheduled)
trufflehog github --org=TargetOrg --token=$GITHUB_TOKEN --since-commit HEAD~100

# GitGuardian -- automated secret scanning for GitHub orgs (SaaS)
# Runs as GitHub App; alerts on exposed secrets in real time
```

---

## 9. OSINT Frameworks and Tools

### 9.1 Maltego

Maltego is a graphical link analysis platform that visualizes relationships
between OSINT entities.

**Entity types:**
- Domain, DNS Name, IP Address, Netblock
- Person, Phone Number, Email Address
- Organization, Location
- Social media profiles, Website, Document

**Key transforms (Community Edition):**
- DNS to IP, IP to ASN
- Domain to WHOIS registrant
- Email to social profiles (via Pipl, PeekYou)
- Phone to owner via TrueCaller

```
# Maltego workflow for domain reconnaissance
1. New graph -> add entity: Domain = target.com
2. Run "To DNS Name [Found in Zone Transfer]"
3. Run "To IP Address [DNS]" on DNS nodes
4. Run "To Netblock [IP]" on IP nodes
5. Run "To Organization [Netblock Owner]"
6. Run "To Email Address [WHOIS]" on domain
7. Add entity: Email addresses found
8. Run "To Social Networks [Full Contact]" on emails
9. Export graph as PDF for report
```

### 9.2 SpiderFoot

SpiderFoot is an automated OSINT platform with 200+ modules.

```bash
# Install
pip3 install spiderfoot

# Start SpiderFoot web UI
python3 sf.py -l 127.0.0.1:5001

# CLI mode
python3 sfcli.py -s target.com -t INTERNET_NAME -u all -o csv > results.csv

# Key modules:
# sfp_dnsresolve -- DNS resolution
# sfp_shodan -- Shodan integration
# sfp_whois -- WHOIS data
# sfp_hunter -- Hunter.io email discovery
# sfp_linkedin -- LinkedIn scraping
# sfp_hibp -- Have I Been Pwned
# sfp_virustotal -- VirusTotal lookups
# sfp_crt -- Certificate transparency
# sfp_github -- GitHub search
# sfp_pastebin -- Pastebin monitoring
```

### 9.3 Recon-ng

Recon-ng is a modular reconnaissance framework inspired by Metasploit.

```bash
recon-ng

# Install all marketplace modules
> marketplace install all

# Create a workspace per target
> workspaces create target_com

# Add seed data
> db insert domains
> (enter) target.com

# Subdomain enumeration
> modules load recon/domains-hosts/bing_domain_web
> options set SOURCE target.com
> run

> modules load recon/domains-hosts/certificate_transparency
> options set SOURCE target.com
> run

> modules load recon/hosts-ports/shodan_hostname
> keys add shodan_api $SHODAN_KEY
> run

# Email discovery
> modules load recon/domains-contacts/hunter_io
> keys add hunter_io $HUNTER_KEY
> options set SOURCE target.com
> run

# Credential breach lookup
> modules load recon/contacts-credentials/hibp_breach
> keys add hibp_api $HIBP_KEY
> run

# Generate HTML report
> reporting load reporting/html
> options set FILENAME /tmp/target_report.html
> run
```

**Key module categories:**
- `recon/domains-hosts/` -- subdomain enumeration
- `recon/hosts-ports/` -- port discovery
- `recon/domains-contacts/` -- email/contact discovery
- `recon/contacts-credentials/` -- breach data lookup
- `recon/profiles-profiles/` -- social media pivoting
- `reporting/` -- output generation

### 9.4 theHarvester

```bash
# Basic domain harvest
theHarvester -d target.com -l 500 -b all

# Specific sources
theHarvester -d target.com -b google,bing,linkedin,twitter,shodan

# Output formats
theHarvester -d target.com -b all -f output  # generates output.html and output.json

# Common sources available:
# anubis, baidu, bevigil, binaryedge, bing, bingapi,
# bufferoverun, certspotter, crtsh, dnsdumpster, duckduckgo,
# fullhunt, github-code, hackertarget, hunter, intelx, linkedin,
# omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns,
# rocketreach, securityTrails, shodan, sublist3r, threatcrowd,
# threatminer, trello, twitter, urlscan, virustotal, yahoo
```

### 9.5 Additional Tools Reference

| Tool | Function | Install |
|------|---------|---------|
| **Amass** | Subdomain enumeration + ASN mapping | `go install github.com/owasp-amass/amass/v4/...@latest` |
| **Subfinder** | Fast passive subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **httpx** | HTTP probing + tech fingerprint | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **dnsx** | DNS toolkit | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| **nuclei** | Template-based scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **Sherlock** | Username enumeration | `pip3 install sherlock-project` |
| **Holehe** | Account existence by email | `pip3 install holehe` |
| **Maigret** | Username OSINT (Sherlock fork) | `pip3 install maigret` |
| **Sn0int** | Semi-automatic OSINT framework (Rust) | `cargo install sn0int` |
| **IVRE** | Network recon database | `pip3 install ivre` |
| **Lampyre** | Visual OSINT platform (Windows) | Installer from lampyre.io |
| **OSINT Framework** | Tool directory/categorization | https://osintframework.com |
| **Mitaka** | Browser extension, IoC lookup | Chrome/Firefox extension |

---

## 10. OSINT Investigation Methodology

### 10.1 Target Profile Template

```markdown
## Target: [Company Name]

### Identity
- Legal name:
- DBA names / subsidiaries:
- Founded:
- Headquarters (physical + mailing):
- Industry / sector:
- Stock ticker (if public):

### Infrastructure
- Primary domains: []
- Known subdomains: []
- IP ranges / CIDRs / ASNs: []
- Cloud providers (AWS/Azure/GCP/other): []
- CDN provider: []
- DNS registrar + registrar lock status:
- Email provider (MX records):
- Name servers:

### Technology Stack
- Web framework / CMS:
- Authentication provider (SSO/IdP):
- CDN/WAF:
- Analytics platform:
- Payment processor:
- ITSM / Ticketing:
- Security tooling detected:

### Personnel
| Name | Role | Email | LinkedIn | Notes |
|------|------|-------|---------|-------|

### Subsidiaries / Acquisitions
| Entity | Relationship | Domains |
|--------|-------------|---------|

### Threat Surface
- Exposed services: []
- Interesting files found: []
- Data exposure incidents: []
- Typosquat domains: []

### Timeline of Key Events
| Date | Event | Source | Confidence |
|------|-------|-------|-----------|
```

### 10.2 Pivot Point Matrix

```
Email Address
    |-- Breach database     -> plaintext credentials, other accounts
    |-- Hunter.io           -> email pattern -> other employee emails
    |-- HaveIBeenPwned      -> breach list -> what data was exposed
    |-- Holehe/Sherlock     -> platform accounts registered with email
    `-- OSINT Industries    -> social/professional profile links

Domain
    |-- WHOIS               -> registrant email -> other domains by same registrant
    |-- DNS records         -> MX -> email provider, IP ranges, cloud services
    |-- crt.sh              -> subdomains via certificate transparency
    |-- Shodan/Censys       -> open ports, services, banners, vulnerabilities
    `-- Wayback Machine     -> historical content, old login panels, legacy paths

IP Address
    |-- Reverse DNS         -> hostname -> domain
    |-- ASN lookup          -> adjacent IPs in same org netblock
    |-- Shodan              -> running services, software versions, banners
    |-- Passive DNS         -> other domains historically on same IP
    `-- AbuseIPDB/VT        -> threat context, past malicious activity

Person
    |-- Name                -> LinkedIn -> employer history, tech exposure
    |-- Email               -> breach -> credentials -> password patterns
    |-- Username            -> Sherlock -> platform presence -> additional info
    |-- Photo               -> reverse image search -> additional accounts/profiles
    `-- Phone               -> Truecaller -> name, carrier -> linked accounts

Organization
    |-- SEC EDGAR           -> financials, incident disclosures, exec names
    |-- Job postings        -> technology stack, security controls in use
    |-- GitHub org          -> code, secrets, employee usernames
    |-- Shodan org filter   -> all internet-facing infrastructure
    `-- Certificate CT      -> all subdomains ever issued certificates
```

### 10.3 Attribution Methodology

When attributing threat actor infrastructure or activity:

**Level 1 -- Technical Indicators (Low confidence alone):**
- Shared IP/ASN
- Reused SSL certificate fingerprint
- Same registrar/registration pattern (WHOIS similarity)
- Common hosting provider

**Level 2 -- Behavioral Indicators (Medium confidence):**
- Same malware family with similar configuration
- Same C2 communication protocol and URIs
- Operational schedule overlaps (timezone inference from commit/activity times)
- Similar victimology (same sectors targeted)

**Level 3 -- Strategic Indicators (High confidence when combined):**
- Overlapping TTPs matching known actor profile (MITRE ATT&CK)
- Victimology consistent with known actor geopolitical interests
- Intelligence community corroboration
- Code reuse with distinctive artifacts (unique strings, function naming, compiler flags)
- Infrastructure reuse across multiple campaigns over time

**Confidence levels:**
- **High**: Multiple independent corroborating sources; verifiable by third party
- **Medium**: Consistent with hypothesis; limited independent corroboration
- **Low**: Single source; circumstantial; requires further investigation before attribution

### 10.4 Report Format

```markdown
# OSINT Investigation Report

## Classification: [TLP:GREEN / TLP:AMBER / TLP:RED]

## Executive Summary
[2-3 sentence summary of findings and key risks or conclusions]

## Scope and Authorization
- Target: [entity name]
- Authorization reference: [SOW number / bug-bounty program / legal memo]
- Collection period: [start date] -- [end date]
- Analyst: [ID or handle]
- Report date: [UTC]

## Findings Summary Table
| ID | Finding | Severity | Confidence | Evidence Ref |
|----|---------|---------|-----------|-------------|

## Detailed Findings

### Finding 001: [Descriptive Title]
- **Severity**: Critical / High / Medium / Low / Informational
- **Confidence**: High / Medium / Low
- **Source**: [URL, tool name, method]
- **Timestamp of collection**: [UTC]
- **Description**: [What was found and why it matters]
- **Evidence**: [Screenshot filename + SHA-256 hash]
- **Recommendation**: [Specific remediation action]

## Infrastructure Map
[ASCII diagram or link to visualization]

## Personnel Identified
[Table -- handle carefully per data protection requirements]

## Timeline of Events
| Timestamp (UTC) | Event | Source | Confidence |
|----------------|-------|-------|-----------|

## Appendix A: Evidence Index
| Filename | SHA-256 | Collection Time | Source |
|---------|---------|----------------|-------|

## Appendix B: Tools Used
[List tools, versions, configuration]
```

### 10.5 Evidence Preservation Tools

| Tool | Description | Platform |
|------|-------------|---------|
| **Hunchly** | Browser extension; auto-captures every visited page with metadata | Chrome |
| **OSINT Combine WebCapture** | Online screenshot + PDF archiving with timestamping | Web |
| **SingleFile** | Browser extension; saves complete page as single HTML file | Chrome/Firefox |
| **Waybackpy** | Python library for Wayback Machine interaction and archiving | Python |
| **HTTrack** | Website mirroring tool for offline analysis | Linux/Windows |
| **CyberChef** | Data encoding/hashing/transformation + evidence fingerprinting | Web/local |
| **FOCA** | Document metadata extraction and analysis | Windows |
| **ExifTool** | Universal metadata extraction for all file types | Cross-platform |
| **ScreenshotGo** | Mobile screenshot organization | Android |

---

## 11. OSINT Tools Reference Table

| Tool | Category | Description | URL / Install |
|------|---------|-------------|--------------|
| Amass | Subdomain | Comprehensive subdomain + ASN enumeration | `go install github.com/owasp-amass/amass/v4/...@latest` |
| Subfinder | Subdomain | Fast passive subdomain aggregation from 50+ sources | `go install ...subfinder@latest` |
| dnsx | DNS | DNS toolkit (resolve, brute, validate, extract) | `go install ...dnsx@latest` |
| httpx | HTTP | HTTP probing, tech detection, screenshots | `go install ...httpx@latest` |
| Shodan CLI | IP Intel | Shodan search from command line | `pip3 install shodan` |
| theHarvester | Email/Domain | Email, domain, host gathering from 40+ sources | `pip3 install theHarvester` |
| Recon-ng | Framework | Modular recon framework (Metasploit-style) | `pip3 install recon-ng` |
| SpiderFoot | Framework | Automated 200+ module OSINT platform | `pip3 install spiderfoot` |
| Maltego CE | Visualization | Graph-based link analysis | maltego.com |
| Sherlock | Username | Cross-platform username OSINT (300+ sites) | `pip3 install sherlock-project` |
| Holehe | Email | Check email registration on platforms | `pip3 install holehe` |
| Maigret | Username | OSINT from username across 3000+ sites | `pip3 install maigret` |
| TruffleHog | Secret Scanning | Detect secrets in git repos and org-wide | `pip3 install trufflehog` |
| Gitleaks | Secret Scanning | SAST for secrets in code (fast, Go-based) | `go install ...gitleaks@latest` |
| dnstwist | Typosquat | Permutation-based domain monitoring | `pip3 install dnstwist` |
| URLCrazy | Typosquat | Typo domain generation and lookup | `gem install urlcrazy` |
| ExifTool | Metadata | Universal metadata extraction | exiftool.org |
| Metagoofil | Doc Metadata | Bulk document metadata extraction from websites | `pip3 install metagoofil` |
| cloud_enum | Cloud OSINT | AWS/Azure/GCP asset enumeration | `pip3 install cloud-enum` |
| lazys3 | S3 OSINT | Targeted S3 bucket enumeration | github.com/nahamsec/lazys3 |
| FOCA | Metadata | Document metadata analysis with network graph (Windows) | elevenpaths.com |
| Sn0int | Framework | Semi-automated OSINT framework (Rust) | `cargo install sn0int` |
| IVRE | Network | Network recon database + visualization | `pip3 install ivre` |
| Hunchly | Evidence | Browser-based evidence capture extension | hunch.ly |
| CertStream | Cert CT | Real-time certificate transparency monitoring feed | github.com/CaliDog/certstream-python |
| URLScan | URL Intel | URL scanning + screenshot + DOM + network API | urlscan.io |
| IntelX | Search | Cross-source OSINT search (pastes, breaches, dark web) | intelx.io |
| OpenCTI | Threat Intel | Open source threat intelligence platform | opencti.io |
| MISP | Threat Intel | Threat intelligence sharing platform | misp-project.org |
| Katana | Web Crawling | Fast web crawler for JS-heavy sites | `go install ...katana@latest` |
| GoSpider | Web Crawling | Fast web spider for endpoint discovery | `go install ...gospider@latest` |
| Nuclei | Scanning | Community template-based scanner | `go install ...nuclei@latest` |
| Osmedeus | Automation | Automated recon workflow engine | osmedeus.org |
| ReconFTW | Automation | Full automated recon pipeline | github.com/six2dez/reconftw |

---

## 12. ATT&CK Reconnaissance Mapping

MITRE ATT&CK v14 Reconnaissance (TA0043) techniques and OSINT tool mapping:

| Technique ID | Technique Name | OSINT Approach | Tools |
|-------------|----------------|---------------|-------|
| T1590 | Gather Victim Network Information | ASN/CIDR enumeration, Shodan | Amass, Shodan, bgp.he.net |
| T1590.001 | Domain Properties | WHOIS, DNS records, registrar info | whois, dig, SecurityTrails |
| T1590.002 | DNS | DNS enumeration, zone transfer | Amass, Subfinder, dnsx |
| T1590.003 | Network Trust Dependencies | Supplier mapping, CDN analysis | BuiltWith, crt.sh |
| T1590.004 | Network Topology | Traceroute, BGP route analysis | traceroute, bgp.he.net |
| T1590.005 | IP Addresses | IP range discovery via ASN | Shodan, Censys, ARIN/RIPE |
| T1590.006 | Network Security Appliances | Banner grabbing, WAF detection | Shodan, Censys, wafw00f |
| T1591 | Gather Victim Org Information | Corporate intelligence gathering | LinkedIn, SEC EDGAR |
| T1591.001 | Determine Physical Locations | HQ/office addresses from OSINT | Google Maps, LinkedIn, EDGAR |
| T1591.002 | Business Relationships | Supply chain and partner mapping | BuiltWith, OpenCorporates |
| T1591.003 | Identify Business Tempo | Job postings, event calendars | LinkedIn Jobs, Google |
| T1591.004 | Identify Roles | Org chart reconstruction | LinkedIn, company website |
| T1592 | Gather Victim Host Information | Technology fingerprinting | Wappalyzer, Shodan |
| T1592.001 | Hardware | IoT/device discovery | Shodan, Censys |
| T1592.002 | Software | CMS/framework detection | Wappalyzer, WhatWeb, httpx |
| T1592.003 | Firmware | IoT device identification via Shodan | Shodan firmware filters |
| T1592.004 | Client Configurations | Browser/OS inference | passive web logs |
| T1593 | Search Open Websites/Domains | Google dorking, GHDB | Google, Bing dorks |
| T1593.001 | Social Media | SOCMINT collection | Sherlock, Maigret, Maltego |
| T1593.002 | Search Engines | Dorks, GHDB queries | Google, Bing, Yandex, DuckDuckGo |
| T1593.003 | Code Repositories | GitHub/GitLab secret scanning | TruffleHog, Gitleaks, GitDorker |
| T1594 | Search Victim-Owned Websites | robots.txt, sitemap, JS analysis | GoSpider, Katana |
| T1595 | Active Scanning | Port scanning, vuln scanning | **Requires explicit authorization** |
| T1595.001 | Scanning IP Blocks | Network sweep | nmap (authorized only) |
| T1595.002 | Vulnerability Scanning | CVE detection, nuclei | nuclei, Nessus (authorized only) |
| T1595.003 | Wordlist Scanning | Directory/file brute force | ffuf, feroxbuster (authorized only) |
| T1596 | Search Open Technical Databases | Shodan, Censys, crt.sh | All passive scanning platforms |
| T1596.001 | DNS/Passive DNS | Historical DNS records | SecurityTrails, DNSDB, PassiveDNS |
| T1596.002 | WHOIS | Domain registration data | whois, DomainTools, WhoisXML |
| T1596.003 | Digital Certificates | crt.sh, Censys cert search | crt.sh, Censys, certstream |
| T1596.004 | CDNs | CDN provider identification | BuiltWith, header analysis |
| T1596.005 | Scan Databases | Shodan/Censys/FOFA historical data | Shodan, Censys, FOFA, ZoomEye |
| T1597 | Search Closed Sources | Paid threat intel, dark web | IntelX, Recorded Future |
| T1597.001 | Threat Intel Vendors | Commercial feeds | Mandiant, CrowdStrike, Recorded Future |
| T1597.002 | Purchase Technical Data | Credential markets (monitor only) | (monitor only -- never purchase) |
| T1598 | Phishing for Information | Pretext calls/emails for information | Social engineering (authorized only) |
| T1598.001 | Spearphishing Service | Via third-party messaging service | -- |
| T1598.002 | Spearphishing Attachment | Weaponized document with tracking | -- |
| T1598.003 | Spearphishing Link | Credential harvesting page | -- |

---

*Last updated: 2026-04-26 | Maintained by the TeamStarWolf Cybersecurity Reference Library*
