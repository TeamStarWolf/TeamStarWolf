# Detection Rule Writing Reference

A comprehensive reference for writing detection rules in Sigma, YARA, Suricata/Snort, Splunk SPL, and Microsoft Sentinel KQL — covering rule structure, example detections, conversion workflows, and detection engineering best practices.

---

## Table of Contents

1. [Overview of Detection Rule Formats](#1-overview-of-detection-rule-formats)
2. [Sigma Rules](#2-sigma-rules)
3. [YARA Rules](#3-yara-rules)
4. [Suricata / Snort Rules](#4-suricata--snort-rules)
5. [Splunk SPL Detection Queries](#5-splunk-spl-detection-queries)
6. [KQL for Microsoft Sentinel](#6-kql-for-microsoft-sentinel)
7. [Best Practices for Detection Engineering](#7-best-practices-for-detection-engineering)
8. [Useful References](#8-useful-references)

---

## 1. Overview of Detection Rule Formats

| Format | What It Detects | Primary Use Case | Output / Query Format | Conversion Tools |
|--------|----------------|------------------|-----------------------|-----------------|
| **Sigma** | Log-based host/network events | SIEM rule authoring (vendor-agnostic) | YAML → SPL, KQL, Lucene, etc. | sigmac, pySigma |
| **YARA** | File/memory byte patterns | Malware identification & triage | Boolean match (hit/no-hit) | yarGen, YARA-X |
| **Suricata/Snort** | Network traffic patterns | IDS/IPS packet inspection | Alert, drop, or pass actions | Pulled Pork, suricata-update |
| **Splunk SPL** | Indexed log events | Threat hunting & SIEM detection | Search results / dashboards | N/A (native) |
| **KQL (Sentinel)** | Azure / M365 log events | Cloud SIEM detection & hunting | Table results / incidents | N/A (native) |

---

## 2. Sigma Rules

### What Sigma Is

Sigma is a vendor-agnostic, open-source SIEM rule format that allows security analysts to write detection logic once and convert it to any SIEM query language. Rules are written in YAML and describe log-based detections mapped to MITRE ATT&CK techniques. The central repository is [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

### Basic Rule Structure

```yaml
title: <Human-readable rule name>
id: <UUID v4 — unique identifier>
status: stable          # stable | test | experimental | deprecated
description: >
  <What the rule detects and why it matters>
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Your Name
date: 2024/01/15
modified: 2024/06/01
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation   # process_creation | network_connection | file_event | etc.
  product: windows             # windows | linux | macos | azure | aws | gcp
detection:
  selection:
    EventID: 4688
    CommandLine|contains|all:
      - 'powershell'
      - '-enc'
  condition: selection
falsepositives:
  - Legitimate admin scripts using encoded commands
  - Software packaging tools
level: high    # informational | low | medium | high | critical
```

**Key field explanations:**

| Field | Purpose |
|-------|---------|
| `title` | Short, descriptive name shown in SIEM |
| `id` | UUID for tracking across repositories |
| `status` | Maturity level — only deploy `stable` to production |
| `tags` | MITRE ATT&CK tactic/technique IDs (e.g., `attack.t1059.001`) |
| `logsource` | Tells converters which log type to query |
| `detection` | Named selection blocks + condition logic |
| `condition` | Boolean expression combining selection blocks |
| `level` | Severity for alert triage prioritization |

### Detection Block Modifiers

```yaml
# Field modifiers (pipe-separated after field name)
CommandLine|contains: 'mimikatz'          # substring match
CommandLine|contains|all:                 # ALL values must match
  - 'sekurlsa'
  - 'logonpasswords'
CommandLine|startswith: 'powershell'      # prefix match
CommandLine|endswith: '.ps1'              # suffix match
CommandLine|re: '.*-[Ee][Nn][Cc].*'      # regex match
Image|endswith|all:
  - '\winword.exe'
ParentImage|contains:
  - '\office\'
```

### Example Rules

#### Rule 1 — PowerShell Encoded Command (T1059.001)

```yaml
title: PowerShell Encoded Command Execution
id: 8ff1c4a8-9b6e-4d6a-a9d2-1e3f5c7b9a12
status: stable
description: >
  Detects execution of PowerShell with Base64-encoded commands, a common
  technique used by attackers to obfuscate malicious scripts from casual inspection.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Detection Engineering Team
date: 2024/01/15
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1059.001
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_flags:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -ec '
      - ' -en '
  condition: selection_img and selection_flags
falsepositives:
  - Legitimate administrative scripts
  - Software deployment tools (SCCM, PDQ Deploy)
level: high
```

#### Rule 2 — Mimikatz via Command Line (T1003.001)

```yaml
title: Mimikatz Credential Dumping via Command Line
id: fc3b4e15-9b2d-4f1a-b2c3-7e8d9a0b1c2d
status: stable
description: >
  Detects common Mimikatz invocation patterns via command-line arguments
  used for LSASS credential dumping. Covers both interactive and script-driven usage.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://github.com/gentilkiwi/mimikatz
author: Detection Engineering Team
date: 2024/01/15
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_tools:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'sekurlsa::wdigest'
      - 'lsadump::sam'
      - 'lsadump::dcsync'
      - 'privilege::debug'
      - 'token::elevate'
  selection_binary:
    Image|endswith: '\mimikatz.exe'
  condition: selection_tools or selection_binary
falsepositives:
  - Security research and red team exercises (expected in controlled environments)
level: critical
```

#### Rule 3 — Scheduled Task Creation (T1053.005)

```yaml
title: Suspicious Scheduled Task Creation via schtasks.exe
id: 92a1b2c3-d4e5-f6a7-b8c9-d0e1f2a3b4c5
status: stable
description: >
  Detects suspicious scheduled task creation that may indicate persistence
  establishment. Focuses on tasks created to run scripts from common attacker
  staging locations such as temp and public directories.
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: Detection Engineering Team
date: 2024/02/01
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains|all:
      - '/create'
      - '/tr'
  filter_temp:
    CommandLine|contains:
      - '\AppData\Local\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
      - '%TEMP%'
      - '%TMP%'
  condition: selection and filter_temp
falsepositives:
  - Software installers creating legitimate tasks from temp directories
  - Some enterprise management agents
level: high
```

#### Rule 4 — Suspicious Network Connection from Office Application (T1566.001 Post-Execution)

```yaml
title: Office Application Initiating Suspicious Network Connection
id: d1e2f3a4-b5c6-d7e8-f9a0-b1c2d3e4f5a6
status: stable
description: >
  Detects Microsoft Office applications making outbound network connections
  to non-Microsoft destinations, which may indicate macro-based malware
  or phishing payload execution following document open.
references:
  - https://attack.mitre.org/techniques/T1566/001/
author: Detection Engineering Team
date: 2024/02/15
tags:
  - attack.initial_access
  - attack.execution
  - attack.t1566.001
  - attack.t1059.005
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    Image|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\msaccess.exe'
  filter_legitimate:
    DestinationHostname|endswith:
      - '.microsoft.com'
      - '.office.com'
      - '.office365.com'
      - '.live.com'
  condition: selection and not filter_legitimate
falsepositives:
  - Office add-ins with external data connections
  - Mail merge with external data sources
level: medium
```

### Converting Sigma to SIEM Queries

#### Using pySigma (modern, recommended)

```bash
# Install pySigma and a backend
pip install pySigma pySigma-backend-splunk pySigma-backend-elasticsearch

# Convert to Splunk SPL
sigma convert -t splunk rule.yml

# Convert to Elastic Lucene
sigma convert -t elastic-lucene rule.yml

# Convert to Microsoft 365 Defender KQL
sigma convert -t microsoft365defender rule.yml

# Convert to Azure Sentinel KQL
sigma convert -t azure-sentinel rule.yml

# Convert to QRadar AQL
sigma convert -t qradar rule.yml

# Convert entire directory
sigma convert -t splunk /path/to/sigma/rules/windows/

# Specify pipeline for field mapping
sigma convert -t splunk -p sysmon rule.yml
```

#### Using sigmac (legacy)

```bash
# Install
pip install sigmatools

# Convert to Splunk
sigmac -t splunk rule.yml

# Convert with field mapping config
sigmac -t splunk -c sysmon rule.yml

# List available backends
sigmac --list-backends
```

### Best Practices

- **Use specific fields**: Broad `CommandLine|contains` matches generate false positives. Prefer matching on `Image` + specific `CommandLine` combos.
- **Tag every rule with ATT&CK IDs**: Enables coverage mapping and prioritization.
- **Use `status: experimental` until validated**: Only promote to `stable` after testing against production logs.
- **Write filter blocks**: Use negated filter blocks (`not filter_legitimate`) rather than complex conditions — improves readability and maintainability.
- **Test against known-good**: Run the rule against 30 days of baseline data before deploying to reduce alert fatigue.
- **Version with `modified` field**: Track every change with an updated `modified` date.

### Sigma Rule Repositories

| Repository | Description |
|-----------|-------------|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Main community repository — thousands of rules |
| [Florian Roth's rules](https://github.com/Neo23x0/sigma) | High-quality rules from the creator of Sigma |
| [MDATP Sigma Rules](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries) | Microsoft's own Defender hunting queries |
| [Elastic Detection Rules](https://github.com/elastic/detection-rules) | Elastic SIEM rules (many Sigma-compatible) |

---

## 3. YARA Rules

### What YARA Is

YARA is a pattern-matching tool designed to identify and classify malware samples. Rules describe characteristics of malware families using string patterns, byte sequences, and Boolean logic. YARA can scan files on disk, memory dumps, and running processes.

### Rule Structure

```yara
rule RuleName : tag1 tag2
{
    meta:
        description = "Detects suspicious behavior"
        author      = "Detection Engineering Team"
        date        = "2024-01-15"
        hash        = "d41d8cd98f00b204e9800998ecf8427e"
        reference   = "https://example.com/malware-analysis"
        tlp         = "WHITE"

    strings:
        // Text string (default: case-sensitive, ASCII)
        $str1 = "MaliciousString"

        // Wide (Unicode) string
        $str2 = "MaliciousString" wide

        // Case-insensitive, both ASCII and wide
        $str3 = "cmd.exe" nocase wide ascii

        // Full word match (not substring)
        $str4 = "eval" fullword

        // XOR-obfuscated string (single-byte XOR, any key)
        $str5 = "malware" xor

        // Hex byte pattern
        $hex1 = { 4D 5A 90 00 03 00 00 00 }   // MZ PE header

        // Hex with wildcards
        $hex2 = { 6A 40 68 00 30 00 00 6A 14 8D ?? }

        // Regex pattern
        $re1 = /[A-Za-z0-9+\/]{100,}={0,2}/    // Long Base64 string

    condition:
        any of them
}
```

### String Modifiers

| Modifier | Effect |
|----------|--------|
| `nocase` | Case-insensitive matching |
| `wide` | Match as 2-byte Unicode (UTF-16LE) |
| `ascii` | Match as ASCII (default if `wide` not specified) |
| `fullword` | Only match if delimited by non-alphanumeric characters |
| `xor` | Match with any single-byte XOR key (0x00–0xFF) |
| `xor(0x01-0xff)` | XOR with a specific key range |
| `base64` | Match Base64-encoded variants |
| `base64wide` | Match wide Base64-encoded variants |

### Condition Keywords

```yara
condition:
    // Count-based
    2 of ($str*)           // At least 2 of strings matching $str*
    all of ($hex*)         // All hex patterns must match
    any of them            // Any defined string matches

    // Offset/position constraints
    $str1 at 0             // String at file offset 0
    $hex1 in (0..256)      // Hex pattern in first 256 bytes

    // File size
    filesize < 1MB
    filesize > 100KB and filesize < 10MB

    // PE entry point (requires import "pe")
    $shellcode at pe.entry_point

    // Boolean logic
    ($str1 or $str2) and $hex1 and not $str3
```

### PE Module

```yara
import "pe"

rule SuspiciousPE
{
    condition:
        pe.imports("kernel32.dll", "VirtualAlloc") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.number_of_sections < 4 and
        pe.sections[0].name == ".text" and
        math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) > 7.0 and
        pe.timestamp < 1000000 and
        pe.number_of_resources == 0 and
        uint16(0) == 0x5A4D
}
```

### Example Rules

#### Rule 1 — Mimikatz String Detection

```yara
rule Mimikatz_Strings
{
    meta:
        description = "Detects Mimikatz credential dumping tool by characteristic strings"
        author      = "Detection Engineering Team"
        date        = "2024-01-15"
        reference   = "https://github.com/gentilkiwi/mimikatz"
        mitre_att   = "T1003.001"

    strings:
        $s1 = "sekurlsa::logonpasswords" nocase wide ascii
        $s2 = "sekurlsa::wdigest" nocase wide ascii
        $s3 = "lsadump::sam" nocase wide ascii
        $s4 = "lsadump::dcsync" nocase wide ascii
        $s5 = "privilege::debug" nocase wide ascii
        $s6 = "mimikatz" nocase wide ascii fullword
        $s7 = "gentilkiwi" nocase wide ascii
        $s8 = "Benjamin DELPY" wide ascii
        $hex_kiwi = { 6B 69 77 69 }

    condition:
        2 of ($s*) or $hex_kiwi
}
```

#### Rule 2 — Packed / Suspicious PE

```yara
import "pe"
import "math"

rule SuspiciousPE_Packed
{
    meta:
        description = "Detects packed or obfuscated PE files with high entropy and few imports"
        author      = "Detection Engineering Team"
        date        = "2024-01-15"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0 and
        filesize < 5MB and
        pe.number_of_sections > 0 and
        (
            math.entropy(0, filesize) > 7.2 or
            pe.number_of_imports < 3
        ) and
        (pe.characteristics & pe.DLL) == 0
}
```

#### Rule 3 — Webshell Detection

```yara
rule Webshell_PHP_Eval_Base64
{
    meta:
        description = "Detects PHP webshells using eval() with base64_decode obfuscation"
        author      = "Detection Engineering Team"
        date        = "2024-01-15"
        mitre_att   = "T1505.003"

    strings:
        $php_tag  = "<?php" nocase
        $eval_fn  = "eval(" nocase
        $b64dec   = "base64_decode(" nocase
        $gzinfl   = "gzinflate(" nocase
        $str_rot  = "str_rot13(" nocase
        $sys_fn   = "system(" nocase fullword
        $shell_fn = "shell_exec(" nocase fullword
        $pass_fn  = "passthru(" nocase fullword
        $proc_fn  = "proc_open(" nocase fullword
        $obf_pat  = /eval\s*\(\s*base64_decode/

    condition:
        $php_tag and
        (
            $obf_pat or
            ($eval_fn and ($b64dec or $gzinfl or $str_rot)) or
            ($eval_fn and (1 of ($sys_fn, $shell_fn, $pass_fn, $proc_fn)))
        )
}
```

#### Rule 4 — Ransomware Note Pattern

```yara
rule Ransomware_Note_Generic
{
    meta:
        description = "Detects generic ransomware note files by characteristic content patterns"
        author      = "Detection Engineering Team"
        date        = "2024-02-01"
        mitre_att   = "T1486"

    strings:
        $phrase1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $phrase2 = "All your files are encrypted" nocase
        $phrase3 = "your files are now encrypted" nocase
        $phrase4 = "IMPORTANT - READ CAREFULLY" nocase
        $pay1 = "bitcoin" nocase
        $pay2 = "BTC wallet" nocase
        $pay3 = ".onion" nocase
        $pay4 = "TOR browser" nocase
        $pay5 = "decrypt your files" nocase
        $contact1 = "contact us" nocase
        $contact2 = "recovery@" nocase
        $contact3 = "do not try to recover" nocase

    condition:
        (1 of ($phrase*)) and
        (2 of ($pay*)) and
        filesize < 100KB
}
```

### Running YARA

```bash
# Basic scan of a file
yara rule.yar /path/to/suspicious.exe

# Recursive directory scan
yara -r rule.yar /path/to/directory/

# Print matching strings
yara -s rule.yar /path/to/file

# Scan process memory (Linux)
yara -p rule.yar $(pgrep suspicious_process)

# Use multiple rule files
yara rule1.yar rule2.yar /path/to/scan/

# Output to file
yara -r rules/ /malware/samples/ > results.txt

# Fast mode (stop after first match per file)
yara -f rule.yar /path/to/scan/

# Compile rules for faster repeated scanning
yarac rules/ compiled.yarc
yara compiled.yarc /path/to/scan/
```

### YARA Tooling

| Tool | Purpose |
|------|---------|
| [yarGen](https://github.com/Neo23x0/yarGen) | Auto-generate YARA rules from malware samples |
| [YARA-X](https://github.com/VirusTotal/yara-x) | Rust rewrite of YARA — faster, safer |
| [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2) | Automated malware analysis with YARA extraction |
| [Valhalla](https://valhalla.nextron-systems.com/) | Commercial YARA rule feed from Florian Roth |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) | Malware corpus with associated YARA rules |
| [VirusTotal](https://virustotal.com) | YARA retrohunt scanning across billions of files |

---

## 4. Suricata / Snort Rules

### What Suricata Is

Suricata is a high-performance, open-source network IDS/IPS engine maintained by the Open Information Security Foundation (OISF). It performs deep packet inspection, protocol analysis, and file extraction using a rule-based detection language compatible with (and extending) the Snort rule format.

### Rule Anatomy

```
action  proto  src_ip  src_port  direction  dst_ip  dst_port  (options)

alert tcp any any -> $HOME_NET 443 (msg:"Suspicious TLS Connection"; content:"evil.c2.com"; sid:1000001; rev:1;)
```

**Full annotated example:**

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Potential PowerShell Download Cradle";
    flow:established,to_server;
    http.method; content:"GET";
    http.uri; content:"/download"; nocase;
    http.user_agent; content:"PowerShell" nocase;
    threshold: type limit, track by_src, count 1, seconds 60;
    reference:url,attack.mitre.org/techniques/T1059/001/;
    classtype:trojan-activity;
    sid:9000001;
    rev:2;
)
```

### Actions

| Action | Effect |
|--------|--------|
| `alert` | Generate an alert and log the packet |
| `drop` | Drop the packet (IPS mode only) and generate alert |
| `pass` | Allow the packet through, suppress further rule matching |
| `reject` | Drop + send TCP RST or ICMP unreachable + alert |
| `rejectsrc` | Send RST only to source |
| `rejectdst` | Send RST only to destination |

### Important Rule Options

| Option | Purpose |
|--------|---------|
| `msg` | Alert message string |
| `content` | Byte/string pattern to match |
| `nocase` | Case-insensitive content match |
| `pcre` | Perl-compatible regex pattern |
| `flow` | Connection state and direction filter |
| `flags` | TCP flag matching (S, A, F, R, P, U) |
| `sid` | Unique rule ID (1–999999 reserved, 1000000+ user) |
| `rev` | Rule revision number |
| `reference` | External reference URL or CVE |
| `classtype` | Alert classification category |
| `threshold` | Limit alert frequency |
| `metadata` | Key-value metadata (ATT&CK tags, severity) |

### Flow Keywords

```
# Established session going to server (most common for C2)
flow:established,to_server;

# Established session returning from server
flow:established,to_client;

# Match regardless of connection state
flow:stateless;

# New connections only (not yet established)
flow:not_established;
```

### Content Modifiers (Suricata Sticky Buffers)

```
http.uri;           content:"/malicious/path";
http.header;        content:"X-Custom-Header:";
http.request_body;  content:"password=";
http.response_body; content:"<script>evil";
http.user_agent;    content:"Wget/1.0";
http.method;        content:"POST";
tls.sni;            content:"evil.c2.com";
tls.cert_subject;   content:"CN=localhost";
dns.query;          content:"malware.example.com";
```

### PCRE Examples for C2 Detection

```
# Cobalt Strike malleable profile URI pattern
pcre:"/\/[a-z]{4,8}\/[A-Za-z0-9]{10,20}\.(gif|png|ico|css)/";

# DNS tunneling — long encoded subdomain
pcre:"/[A-Za-z0-9+\/]{40,}\.[a-z]{2,6}$/";

# HTTP C2 with random query parameters
pcre:"/\?[a-z]{1,3}=[A-Za-z0-9]{16,32}(&[a-z]{1,3}=[A-Za-z0-9]{16,32}){2,}/";
```

### Example Rules

#### Rule 1 — Cobalt Strike Default HTTPS C2 Beacon

```
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"MITRE T1071.001 - Cobalt Strike Default HTTPS Beacon";
    flow:established,to_server;
    tls.sni; content:"."; nocase;
    pcre:"/^[a-zA-Z0-9\-]{5,20}\.[a-z]{2,6}$/";
    tls.cert_subject; content:"CN="; pcre:"/CN=[a-z]{3,8}\.[a-z]{2,4}$/";
    threshold: type both, track by_src, count 5, seconds 300;
    reference:url,attack.mitre.org/techniques/T1071/001/;
    classtype:trojan-activity;
    metadata:attack_target Client_Endpoint, deployment Perimeter;
    sid:9001001;
    rev:3;
)
```

#### Rule 2 — Suspicious DNS Tunneling (Long Subdomain)

```
alert dns $HOME_NET any -> any 53 (
    msg:"MITRE T1071.004 - Possible DNS Tunneling Long Subdomain";
    flow:stateless;
    dns.query;
    pcre:"/^[A-Za-z0-9+\/\-_]{40,}\.[a-z]{2,10}\.[a-z]{2,6}$/";
    threshold: type threshold, track by_src, count 10, seconds 60;
    reference:url,attack.mitre.org/techniques/T1071/004/;
    classtype:policy-violation;
    sid:9001002;
    rev:2;
)
```

#### Rule 3 — Log4Shell Exploit Attempt (T1190 / CVE-2021-44228)

```
alert http any any -> $HTTP_SERVERS any (
    msg:"MITRE T1190 - Log4Shell RCE Attempt CVE-2021-44228";
    flow:established,to_server;
    http.uri; content:"${jndi:"; nocase;
    pcre:"/\$\{jndi:(ldap|rmi|dns|ldaps|iiop|corba|nds|http):/i";
    reference:cve,2021-44228;
    classtype:web-application-attack;
    sid:9001003;
    rev:4;
)
```

#### Rule 4 — PowerShell Download Cradle in HTTP

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MITRE T1059.001 - PowerShell Download Cradle User-Agent";
    flow:established,to_server;
    http.user_agent; content:"PowerShell" nocase;
    http.uri; content:".ps1"; nocase;
    reference:url,attack.mitre.org/techniques/T1059/001/;
    classtype:trojan-activity;
    sid:9001004;
    rev:2;
)

alert http any any -> $HOME_NET any (
    msg:"MITRE T1059.001 - PowerShell IEX DownloadString in HTTP Response";
    flow:established,to_client;
    http.response_body;
    content:"IEX"; nocase;
    content:"DownloadString"; nocase; within:100;
    classtype:trojan-activity;
    sid:9001005;
    rev:1;
)
```

### Rule Sets

| Rule Set | Cost | Description |
|----------|------|-------------|
| [Emerging Threats Open](https://rules.emergingthreats.net/open/) | Free | Community-maintained, updated daily |
| [Proofpoint ET Pro](https://www.proofpoint.com/us/products/et-intelligence) | Paid | Commercial version with faster updates and more rules |
| [CISA Alerts](https://www.cisa.gov/news-events/cybersecurity-advisories) | Free | Rules released with CVE advisories |
| [SSLBL Suricata Rules](https://sslbl.abuse.ch/) | Free | SSL/TLS blacklist from abuse.ch |
| [Snort Community Rules](https://www.snort.org/downloads) | Free | Official Snort community rule set |

### Tuning and Suppression

```bash
# threshold.conf — suppress by rule ID and source IP range
suppress gen_id 1, sig_id 9001001, track by_src, ip 192.168.1.0/24

# Event filter — reduce alert volume without disabling rule
event_filter gen_id 1, sig_id 9001002, type limit, track by_src, count 1, seconds 300

# Update rules with suricata-update
suricata-update
suricata-update list-sources
suricata-update enable-source et/open
```

---

## 5. Splunk SPL Detection Queries

Splunk Search Processing Language (SPL) is the native query language for Splunk SIEM. The queries below target common Windows Security Event Log IDs and cover high-value detection scenarios.

### PowerShell Encoded Commands (T1059.001)

```spl
index=windows EventCode=4688
(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-ec *")
CommandLine="*powershell*"
| table _time, ComputerName, Account_Name, CommandLine, ParentCommandLine
| sort -_time
```

### Failed Logon Brute Force Detection

```spl
index=windows EventCode=4625
| bucket _time span=5m
| stats count by Account_Name, Source_Network_Address, _time
| where count > 10
| sort -count
| table _time, Account_Name, Source_Network_Address, count
```

### Lateral Movement via PsExec (T1021.002)

```spl
index=windows (EventCode=7045 OR EventCode=4697)
(Service_Name="PSEXESVC" OR Service_Name="*PSEXEC*" OR ImagePath="*PSEXESVC*")
| table _time, ComputerName, Service_Name, ImagePath, Account_Name
| sort -_time
```

### Large Outbound Data Transfers (T1041)

```spl
index=proxy bytes_out > 10000000
| stats sum(bytes_out) as total_bytes_out, count as requests by src_ip, dest_host
| where total_bytes_out > 50000000
| eval total_MB = round(total_bytes_out / 1024 / 1024, 2)
| sort -total_MB
| table src_ip, dest_host, total_MB, requests
```

### New Local Administrator Account (T1098)

```spl
index=windows (EventCode=4728 OR EventCode=4732)
Group_Name="Administrators"
| table _time, ComputerName, Account_Name, Subject_Account_Name, Group_Name
| sort -_time
```

### Pass-the-Hash Detection (T1550.002)

```spl
index=windows EventCode=4624
Logon_Type=3 NOT Account_Name="*$"
Authentication_Package="NTLM"
| stats count by Account_Name, Source_Network_Address, ComputerName
| where count > 3
| sort -count
```

### Kerberoasting Detection (T1558.003)

```spl
index=windows EventCode=4769
Ticket_Encryption_Type=0x17
Service_Name!="*$"
| stats count by Account_Name, Service_Name, Client_Address
| where count > 5
| sort -count
```

### Suspicious Process Spawned from Office (T1566.001)

```spl
index=windows EventCode=4688
(ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe")
(NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\wscript.exe"
 OR NewProcessName="*\\cscript.exe" OR NewProcessName="*\\mshta.exe")
| table _time, ComputerName, Account_Name, ParentImage, NewProcessName, CommandLine
| sort -_time
```

---

## 6. KQL for Microsoft Sentinel

Kusto Query Language (KQL) is used by Microsoft Sentinel, Microsoft Defender XDR, and Azure Monitor. KQL uses a pipe-based syntax for filtering, projecting, aggregating, and joining data.

### KQL Syntax Basics

```kql
// Basic filter
TableName
| where TimeGenerated > ago(24h)
| where EventID == 4688

// Project specific columns
| project TimeGenerated, Computer, Account, CommandLine

// Summarize (aggregate)
| summarize count() by Account, Computer

// Join tables
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
) on Account

// Extend (add computed column)
| extend BytesMB = BytesOut / 1024 / 1024

// Order and limit
| order by TimeGenerated desc
| take 100

// String operators
| where CommandLine contains "-enc"
| where CommandLine has_any ("-enc", "-EncodedCommand")
| where ProcessName matches regex @"(?i)powershell\.exe"
```

### Sign-in from Impossible Travel (T1078)

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated, 1),
         PrevLocation = prev(Location, 1),
         PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiffMinutes < 60
| where Location != PrevLocation
| project TimeGenerated, UserPrincipalName, Location, PrevLocation, IPAddress, TimeDiffMinutes
```

### PowerShell Process Creation with Encoded Command (T1059.001)

```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-ec ", "-en ")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### Email Forwarding Rules to External Address (T1114.003)

```kql
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType == "New-InboxRule"
| where RawEventData has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo")
| extend RuleDetails = parse_json(RawEventData)
| extend
    ForwardTo = tostring(RuleDetails.Parameters[0].Value),
    UserAgent = tostring(RuleDetails.UserAgent)
| where ForwardTo !has "@yourcompany.com"
| project TimeGenerated, AccountDisplayName, ForwardTo, UserAgent, IPAddress
| order by TimeGenerated desc
```

### Azure Resource Creation in New Region (T1578)

```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue contains "Microsoft.Resources/deployments/write"
| where ActivityStatusValue == "Success"
| summarize ResourcesCreated=count(), Regions=make_set(ResourceGroup) by Caller, _ResourceId
| join kind=inner (
    AzureActivity
    | where TimeGenerated between (ago(90d) .. ago(30d))
    | summarize HistoricalRegions=make_set(ResourceGroup) by Caller
) on Caller
| extend NewRegions = set_difference(Regions, HistoricalRegions)
| where array_length(NewRegions) > 0
| project Caller, NewRegions, ResourcesCreated
```

### MFA Disabled for a User (T1556)

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Disable Strong Authentication"
       or OperationName == "Update user"
| where TargetResources has "StrongAuthenticationRequirements"
| extend
    Actor = tostring(InitiatedBy.user.userPrincipalName),
    Target = tostring(TargetResources[0].userPrincipalName),
    IPAddress = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, Actor, Target, IPAddress, OperationName
| order by TimeGenerated desc
```

---

## 7. Best Practices for Detection Engineering

### MITRE ATT&CK Mapping

Map every detection rule to one or more ATT&CK technique IDs at authoring time. This enables coverage gap analysis, prioritization by threat actor profile, and alignment between red team and blue team using a common taxonomy.

```yaml
# Sigma: use tags field
tags:
  - attack.execution
  - attack.t1059.001
```

```
# Suricata: use metadata or reference
metadata:attack_target Client_Endpoint;
reference:url,attack.mitre.org/techniques/T1059/001/;
```

### Test Against Known-Good AND Known-Bad

| Test Type | Goal | Tool |
|-----------|------|------|
| Known-bad (TP validation) | Confirm rule fires on real attacker activity | Atomic Red Team, Caldera |
| Known-good (FP validation) | Confirm rule does not fire on legitimate traffic | Baseline log replay |
| Adversarial testing | Confirm common evasion attempts are caught | Manual TTP variation |

### The Pyramid of Pain

Detections higher on the pyramid are harder for attackers to evade and more durable over time:

```
         /\
        /  \        TTPs (Behavior — highest value, most durable)
       /----\
      /      \      Network/Host Artifacts
     /--------\
    /          \    Domain Names
   /------------\
  /              \  IP Addresses
 /----------------\
/                  \ File Hashes (trivial to change — lowest value)
```

Focus detection investment on TTP-based behavioral rules rather than hash or IP block lists.

### Detection Lifecycle

1. **Identify** — threat intel, red team findings, or CVE triggers a detection need
2. **Author** — write the rule with ATT&CK tags and `status: experimental`
3. **Test** — validate against known-bad samples and known-good baselines
4. **Deploy** — push to SIEM/IDS in monitoring mode
5. **Tune** — address false positives aggressively in the first 30 days
6. **Promote** — update to `status: stable` after tuning
7. **Review** — quarterly review of all stable rules for continued relevance

### Atomic Red Team Testing

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) provides test cases mapped to ATT&CK techniques. Use to validate that rules fire correctly after deployment:

```powershell
# Install
Install-Module -Name invoke-atomicredteam

# Run a specific technique test
Invoke-AtomicTest T1059.001
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Clean up after test
Invoke-AtomicTest T1059.001 -Cleanup

# List all tests for a technique
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```

### ATT&CK Navigator Coverage Tracking

Export deployed rule tags to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage gaps:

```python
import yaml, glob

techniques = set()
for f in glob.glob("rules/**/*.yml", recursive=True):
    with open(f) as fh:
        rule = yaml.safe_load(fh)
    for tag in rule.get("tags", []):
        if tag.startswith("attack.t"):
            techniques.add(tag.replace("attack.", "").upper())

print(f"Coverage: {len(techniques)} techniques")
```

### False Positive Management Checklist

- Run new rule against 30 days of historical data before live deployment
- Add filter blocks for known-legitimate applications, paths, and accounts
- Set `level` conservatively until FP rate is understood
- Document expected false positives in the rule's `falsepositives` field
- Create a suppression/exception workflow for confirmed benign alerts
- Review top alerting rules monthly for FP-driven tuning opportunities

### Detection Changelog

Maintain a changelog alongside rules:

```
2024-06-01  Promoted powershell_encoded_cmd.yml to stable after 0 FP in 30 days
2024-05-15  Added filter block to schtasks_persistence.yml — excluded SCCM paths
2024-05-01  New rule: lsass_dump_via_procdump.yml (T1003.001)
2024-04-15  Deprecated old_rule.yml — superseded by improved_rule.yml
```

---

---

## 9. Sigma Rules — Practical Examples by ATT&CK Tactic

### Initial Access (T1566 — Phishing)
```yaml
title: Suspicious Office Child Process
id: 438025f9-5856-4663-83f7-52f878a70a50
status: stable
description: Detects suspicious child processes spawned by Office applications — common phishing attachment execution pattern
author: TeamStarWolf
date: 2024/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.EXE'
            - '\OUTLOOK.EXE'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\regsvr32.exe'
    condition: selection
falsepositives:
    - Legitimate Office macros used in the environment (document and suppress)
level: high
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.execution
    - attack.t1204.002
```

### Execution (T1059.001 — PowerShell)
```yaml
title: Suspicious PowerShell Encoded Command
id: ca2092a1-c273-4878-9b4b-a3f2a4f0a6b7
status: stable
description: Detects PowerShell with encoded commands — common for obfuscated malware and post-exploitation
author: TeamStarWolf
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\powershell.exe'
    selection_cli:
        CommandLine|contains:
            - ' -EncodedCommand '
            - ' -enc '
            - ' -EC '
    filter_legitimate:
        CommandLine|contains:
            - 'Get-GPOReport'   # GPMC legitimate use
    condition: selection_img and selection_cli and not filter_legitimate
falsepositives:
    - Legitimate administrative scripts using -EncodedCommand
level: medium
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
```

### Persistence (T1053.005 — Scheduled Task)
```yaml
title: Scheduled Task Created via Schtasks
id: 92a65ab3-4078-4d5b-89eb-4e01f2a28bab
status: stable
description: Detects creation of scheduled tasks via schtasks.exe — common persistence mechanism
author: TeamStarWolf
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    filter_system:
        User: 'SYSTEM'
        CommandLine|contains: '\Microsoft\Windows'
    condition: selection and not filter_system
falsepositives:
    - Legitimate software installers
    - IT automation tools (SCCM, Ansible, etc.)
level: medium
tags:
    - attack.persistence
    - attack.t1053.005
```

### Defense Evasion (T1070.001 — Clear Windows Event Logs)
```yaml
title: Windows Event Log Cleared
id: a62b31e2-d8d6-4b29-bf50-e4b4edb9c45a
status: stable
description: Detects clearing of Windows event logs — strong indicator of attacker covering tracks
author: TeamStarWolf
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID:
            - 104   # System log cleared
            - 1102  # Security log cleared
    condition: selection
falsepositives:
    - Legitimate log rotation (rare for Security log)
    - Forensic investigation procedures
level: high
tags:
    - attack.defense_evasion
    - attack.t1070.001
```

### Credential Access (T1003.001 — LSASS Memory Dump)
```yaml
title: LSASS Memory Access by Non-System Process
id: 32d0d3e2-e58d-4d41-a703-4b59b8d18901
status: stable
description: Detects non-system processes accessing LSASS memory — credential dumping indicator
author: TeamStarWolf
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x147a'
            - '0x143a'
    filter:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files\Windows Defender\'
    condition: selection and not filter
falsepositives:
    - Security software and EDR agents (add to filter list)
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

### Lateral Movement (T1021.002 — SMB/Windows Admin Shares)
```yaml
title: Remote Service Installation via Admin Shares
id: 4e0a78ef-7d53-4f4e-b1b2-8d9f5e62a1bc
status: stable
description: Detects use of PsExec-style remote service installation — lateral movement indicator
author: TeamStarWolf
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 7045   # New service installed
        ServiceFileName|contains:
            - '\ADMIN$\'
            - '\C$\'
            - '\IPC$\'
    condition: selection
falsepositives:
    - Legitimate remote administration tools
    - Software deployment via SCCM/PDQ Deploy
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.t1569.002
```

---

## 10. KQL — Microsoft Sentinel Queries

### Detect Suspicious PowerShell Network Connections
```kql
// Hunt for PowerShell making unexpected outbound connections
// Useful for detecting C2 beaconing or PowerShell download cradles
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemoteIPType != "Private"
| where RemotePort in (80, 443, 8080, 8443)
| summarize
    ConnectionCount = count(),
    DistinctIPs = dcount(RemoteIP),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| where ConnectionCount > 5
| sort by ConnectionCount desc
```

### Detect LSASS Dump via Task Manager or ProcDump
```kql
// Detect credential dumping via common tools
DeviceProcessEvents
| where FileName in~ ("procdump.exe", "procdump64.exe", "sqldumper.exe")
| where ProcessCommandLine has_any ("lsass", "-ma", "-mm")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

### Detect Kerberoasting Activity
```kql
// Kerberoasting: TGS ticket requests for SPNs with RC4 encryption
// Event 4769 — Kerberos Service Ticket Operations
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4 (weak — targeted by Kerberoasting)
| where ServiceName !endswith "$"        // Exclude machine accounts
| where ServiceName !startswith "krbtgt" // Exclude krbtgt
| summarize
    RequestCount = count(),
    TargetAccounts = make_set(ServiceName)
    by IpAddress, Account, bin(TimeGenerated, 5m)
| where RequestCount > 3
| sort by RequestCount desc
```

### Detect Azure AD Risky Sign-Ins
```kql
// Detect impossible travel or other risk signals in Entra ID
SigninLogs
| where RiskLevelDuringSignIn in ("high", "medium")
| where ResultType == 0  // Successful sign-in despite risk
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    RiskLevelDuringSignIn,
    RiskDetail,
    AppDisplayName,
    DeviceDetail
| sort by TimeGenerated desc
```

### Hunt for DNS Tunneling
```kql
// High-entropy or high-volume DNS queries indicating tunneling
DnsEvents
| extend QueryLength = strlen(Name)
| where QueryLength > 40  // Long subdomain labels common in DNS tunneling
| summarize
    QueryCount = count(),
    AvgQueryLength = avg(QueryLength),
    UniqueDomains = dcount(Name)
    by ClientIP, bin(TimeGenerated, 1h)
| where QueryCount > 200  // Unusually high DNS query rate
| sort by QueryCount desc
```

---

## 11. Splunk SPL Queries

### Detect Lateral Movement via PsExec
```spl
index=windows source="WinEventLog:Security" EventCode=7045
| where like(ServiceFileName, "%ADMIN$%") OR like(ServiceFileName, "%C$%")
| stats count by host, ServiceName, ServiceFileName, AccountName
| sort -count
```

### Detect Mimikatz via Process Name and Command Line
```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where lower(CommandLine) LIKE "%sekurlsa%" 
   OR lower(CommandLine) LIKE "%privilege::debug%"
   OR lower(CommandLine) LIKE "%lsadump::dcsync%"
   OR lower(CommandLine) LIKE "%mimikatz%"
| table _time, host, user, CommandLine, ParentProcessName
```

### Detect DNS Beaconing (Statistical Analysis)
```spl
index=network sourcetype=stream:dns query=*
| bucket _time span=1h
| stats count AS query_count, dc(query) AS unique_queries BY _time, src, dest
| eventstats avg(query_count) AS avg_qps, stdev(query_count) AS stdev_qps BY src, dest
| where query_count > avg_qps + (2 * stdev_qps)
| sort -query_count
```

### Detect Shadow Copy Deletion (Ransomware Pre-Encryption)
```spl
index=windows (EventCode=4688 OR source="*Sysmon*" EventCode=1)
| where like(lower(CommandLine), "%vssadmin%delete%shadows%")
   OR like(lower(CommandLine), "%wmic%shadowcopy%delete%")
   OR like(lower(CommandLine), "%wbadmin%delete%catalog%")
| table _time, host, user, CommandLine
| sort -_time
```

### Hunt for C2 Beaconing (Periodic Connection Pattern)
```spl
index=network sourcetype=stream:tcp dest_port IN (80, 443, 8080, 8443)
| bucket _time span=1h
| stats count AS conn_count, dc(_time) AS hours_active BY src_ip, dest_ip, dest_port
| where conn_count > 20 AND hours_active > 4
| eventstats avg(conn_count) AS avg_conns, stdev(conn_count) AS stdev_conns BY src_ip, dest_ip
| where abs(conn_count - avg_conns) < stdev_conns  // Low variance = beaconing
| sort -conn_count
```

---

## 12. Suricata Rules

### Detect Metasploit Meterpreter HTTPS Traffic (JA3)
```suricata
alert tls any any -> any any (
    msg:"MALWARE Metasploit Meterpreter HTTPS Default JA3";
    ja3.hash; content:"ae4edc6faf64d08308082ad26be60767";
    classtype:trojan-activity;
    sid:9000001;
    rev:1;
    metadata:created_at 2024_01_01, affected_product Windows;
)
```

### Detect DNS Tunneling via Long Labels
```suricata
alert dns any any -> any 53 (
    msg:"POTENTIAL DNS Tunneling - Excessively Long Query Label";
    dns.query; pcre:"/[a-zA-Z0-9\-]{50,}\./";
    threshold: type limit, track by_src, count 5, seconds 60;
    classtype:policy-violation;
    sid:9000002;
    rev:1;
)
```

### Detect ICMP Tunneling (Large Payload)
```suricata
alert icmp any any -> $HOME_NET any (
    msg:"POTENTIAL ICMP Tunneling - Oversized Echo Payload";
    itype:8;
    dsize:>64;
    threshold: type threshold, track by_src, count 10, seconds 10;
    classtype:policy-violation;
    sid:9000003;
    rev:1;
)
```

### Detect Cobalt Strike Staging URI Pattern
```suricata
alert http $HOME_NET any -> any any (
    msg:"MALWARE Cobalt Strike Default Staging URI";
    http.uri; content:"/submit.php"; endswith;
    http.method; content:"POST";
    classtype:trojan-activity;
    sid:9000004;
    rev:1;
)
```

### Detect SMB Pass-the-Hash Lateral Movement
```suricata
alert smb $HOME_NET any -> $HOME_NET 445 (
    msg:"LATERAL MOVEMENT Potential Pass-the-Hash via SMB";
    smb.ntlmssp_auth;
    threshold: type both, track by_src, count 5, seconds 30;
    classtype:policy-violation;
    sid:9000005;
    rev:1;
)
```

---

## 13. Detection Testing with Atomic Red Team

Validate your detections by executing the exact technique and confirming the rule fires.

```bash
# Install Atomic Red Team
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam

# List available tests for a technique
Invoke-AtomicTest T1003.001 -ShowDetailsBrief

# Execute LSASS dump test (run as admin in isolated lab)
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Clean up after test
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
```

**Detection validation workflow**:
1. Pick the ATT&CK technique your rule targets (e.g., T1059.001)
2. Run `Invoke-AtomicTest T1059.001 -ShowDetailsBrief` to see available tests
3. Execute the test in your lab environment
4. Confirm your SIEM/EDR fires the expected alert
5. If no alert: investigate log coverage → tune data source → update rule
6. Document: technique, test number, expected alert, confirmed firing, false positive rate

**Key Atomic Red Team resources**:
- Repository: [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
- ATT&CK technique index: [atomicredteam.io/atomics](https://atomicredteam.io/atomics)
- Windows test prerequisites: Windows Defender exclusions on lab VM required for many tests


## 8. Useful References

| Resource | URL | Description |
|----------|-----|-------------|
| SigmaHQ/sigma | https://github.com/SigmaHQ/sigma | Main Sigma rule repository |
| pySigma | https://github.com/SigmaHQ/pySigma | Modern Sigma converter library |
| Sigma Rule Specification | https://github.com/SigmaHQ/sigma-specification | Official Sigma format spec |
| YARA Documentation | https://yara.readthedocs.io | Official YARA docs and PE module reference |
| YARA-X | https://github.com/VirusTotal/yara-x | Next-generation YARA in Rust |
| yarGen | https://github.com/Neo23x0/yarGen | Auto-generate YARA rules from samples |
| Suricata Documentation | https://suricata.readthedocs.io | Official Suricata rule writing guide |
| Emerging Threats Open | https://rules.emergingthreats.net/open/ | Free community Suricata/Snort rule set |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | ATT&CK-mapped technique test cases |
| MITRE ATT&CK | https://attack.mitre.org | Adversary tactics and techniques framework |
| ATT&CK Navigator | https://mitre-attack.github.io/attack-navigator/ | Coverage visualization tool |
| Detection.fyi | https://detection.fyi | Aggregated detection rule search engine |
| SOC Prime | https://socprime.com | Commercial detection content marketplace |
| Florian Roth's Blog | https://cyb3rops.medium.com | Detection engineering articles and rules |
| CAPE Sandbox | https://github.com/kevoreilly/CAPEv2 | Malware sandbox with YARA extraction |
| Splunk Security Content | https://research.splunk.com | Splunk-maintained detection rules and analytics |
| Microsoft Sentinel GitHub | https://github.com/Azure/Azure-Sentinel | Sentinel analytics rules and hunting queries |
---

## Sigma Rule Writing Reference

### Sigma Rule Structure

```yaml
title: Suspicious PowerShell Encoded Command
id: a3a8a4a0-1234-4321-abcd-000000000001
status: experimental
description: Detects PowerShell execution with -EncodedCommand or -enc flags, commonly used for obfuscation
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: TeamStarWolf
date: 2024/01/15
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - ' -ec '
    condition: selection
falsepositives:
    - Legitimate automation scripts using encoded commands
    - Configuration management tools (SCCM, Ansible)
level: medium
```

### Sigma Condition Operators

| Operator | Meaning | Example |
|---|---|---|
| `selection` | All conditions in group must match | `condition: selection` |
| `1 of selection*` | At least one selection group matches | `condition: 1 of selection*` |
| `all of selection*` | All selection groups must match | `condition: all of selection*` |
| `selection and not filter` | Selection minus filter | `condition: selection and not filter` |
| `\|contains` | String contains value | `CommandLine\|contains: '-enc'` |
| `\|startswith` | String starts with value | `Image\|startswith: 'C:\Users'` |
| `\|endswith` | String ends with value | `Image\|endswith: '\powershell.exe'` |
| `\|re` | Regex match | `CommandLine\|re: '(?i)invoke'` |

### Sigma for T1003 — LSASS Memory Access

```yaml
title: LSASS Memory Access
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x147a'
            - '0x1fffff'
    filter_legitimate:
        SourceImage|endswith:
            - '\MsMpEng.exe'
            - '\csrss.exe'
    condition: selection and not filter_legitimate
level: high
tags:
    - attack.credential_access
    - attack.t1003.001
```

### Sigma for T1059.003 — Cmd Spawned by Office

```yaml
title: Cmd.exe Spawned by Office Application
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
            - '\outlook.exe'
            - '\mshta.exe'
            - '\wscript.exe'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.003
```

---

## KQL (Kusto Query Language) Detection Reference

### Brute Force Detection

```kql
let threshold = 10;
let timeframe = 10m;
let failedLogons = SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID == 4625
    | summarize FailedCount = count(), LastFail = max(TimeGenerated)
        by Account, IpAddress
    | where FailedCount >= threshold;
let successLogons = SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID == 4624
    | project SuccessTime = TimeGenerated, Account, IpAddress;
failedLogons
| join kind=inner successLogons on Account, IpAddress
| where SuccessTime between (LastFail .. (LastFail + timeframe))
| project Account, IpAddress, FailedCount, LastFail, SuccessTime
| extend AlertName = "Brute Force Success After Multiple Failures"
```

### Suspicious PowerShell (KQL)

```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "IEX", "Invoke-Expression",
    "DownloadString", "WebClient", "FromBase64String")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### C2 Beaconing Detection (KQL)

```kql
let lookback = 24h;
let minConnections = 10;
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
| where ActionType == "ConnectionSuccess"
| where not(RemoteIPType == "Private")
| summarize ConnectionCount = count(), ConnectionTimes = make_list(TimeGenerated, 100)
    by DeviceName, RemoteIP, RemotePort
| where ConnectionCount >= minConnections
| extend AlertName = "Potential C2 Beaconing - High Frequency External Connection"
| order by ConnectionCount desc
```

---

## Splunk SPL Detection Reference

### Ransomware Precursor Activity

```spl
index=windows sourcetype="WinEventLog:Security"
(CommandLine="*vssadmin*delete*shadows*"
 OR CommandLine="*wbadmin*delete*catalog*"
 OR CommandLine="*bcdedit*/set*recoveryenabled*no*"
 OR CommandLine="*wmic*shadowcopy*delete*")
| eval risk="HIGH - Ransomware Precursor"
| stats count by host, user, CommandLine, risk
| sort -count
```

### Pass-the-Hash Detection (Splunk)

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624
LogonType=3 AuthPackage=NTLM
| eval hour=strftime(_time, "%H")
| stats count by src_ip, user, host, hour
| where count > 5 AND (hour < 7 OR hour > 19)
| eval alert="PtH Candidate - NTLM Network Logon After Hours"
```

### Data Exfiltration via DNS (Splunk)

```spl
index=network sourcetype=dns
| eval query_length=len(query)
| where query_length > 50
| stats count, avg(query_length), values(query) as sample_queries
    by src_ip, answer
| where count > 20
| sort -count
```

### PowerShell Script Block Logging (Splunk)

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
ScriptBlockText IN ("*Net.WebClient*", "*DownloadString*", "*IEX*",
                     "*Invoke-Expression*", "*WebRequest*", "*bitsadmin*")
| rex field=ScriptBlockText "(?P<url>https?://[^\s'\"]+)"
| stats count by host, user, url, ScriptBlockText
| sort -count
```

---

## Suricata Rule Writing Reference

### Rule Format

```
action proto src_ip src_port -> dst_ip dst_port (options)
```

### Cobalt Strike Default Beacon

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Cobalt Strike Beacon Activity - Default URI";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/submit.php";
    threshold:type limit, track by_src, seconds 60, count 1;
    classtype:trojan-activity;
    sid:9000001; rev:1;
)
```

### DNS Tunneling

```suricata
alert dns any any -> any 53 (
    msg:"ET DNS Tunneling - Suspiciously Long DNS Query";
    dns.query;
    pcre:"/^[a-zA-Z0-9]{40,}\.[a-z]{2,}\.[a-z]{2,}$/i";
    threshold:type limit, track by_src, seconds 60, count 1;
    classtype:policy-violation;
    sid:9000002; rev:1;
)
```

### Log4Shell Detection

```suricata
alert http any any -> any any (
    msg:"ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)";
    flow:established,to_server;
    http.uri; content:"${jndi:"; nocase;
    threshold:type limit, track by_src, seconds 60, count 1;
    classtype:attempted-admin;
    sid:9000004; rev:1;
    reference:cve,2021-44228;
)
```

---

## Detection Engineering Quality Framework

### Pyramid of Pain (David Bianco)

| Level | Indicator Type | Adversary Cost to Change |
|---|---|---|
| Trivial | Hash values (MD5, SHA-1) | Recompile or repack |
| Easy | IP addresses | Change C2 server |
| Simple | Domain names | New domain registration |
| Annoying | Network artifacts | Modify tool configurations |
| Challenging | Host artifacts | Significant retooling |
| Tough | Tools | Develop new tooling |
| Very Hard | TTPs | Change fundamental approach |

### Alert Quality Metrics

| Metric | Formula | Target |
|---|---|---|
| True Positive Rate | TP / (TP + FN) | > 80% |
| False Positive Rate | FP / (FP + TN) | < 5% |
| Precision | TP / (TP + FP) | > 85% |
| Alert-to-Incident Rate | Incidents / Total Alerts | > 30% |
| Mean Time to Detect | Avg(Detect - Breach Time) | < 24 hours |

### Detection Lifecycle

1. **Hypothesis** — ATT&CK technique, threat intel, incident retrospective
2. **Data Sources** — Which logs capture this behavior?
3. **Logic** — Write detection using required fields
4. **Test** — Validate against attack simulation and benign data
5. **Tune** — Reduce FPs via allow-listing, thresholds
6. **Deploy** — Push to SIEM with severity and response runbook
7. **Review** — Measure FP rate, detection rate, MTTD
