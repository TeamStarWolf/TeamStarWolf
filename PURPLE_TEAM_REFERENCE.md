# PURPLE TEAM REFERENCE LIBRARY

**Version:** 1.0 | **Classification:** Internal Use | **Maintained by:** Security Engineering

---

## Table of Contents

1. [Purple Team Fundamentals](#_1-purple-team-fundamentals)
2. [MITRE ATT&CK for Purple Teams](#_2-mitre-attampck-for-purple-teams)
3. [Atomic Red Team](#_3-atomic-red-team)
4. [Adversary Emulation Platforms](#_4-adversary-emulation-platforms)
5. [Detection Validation Methodology](#_5-detection-validation-methodology)
6. [Threat Intelligence-Driven Purple Teaming](#_6-threat-intelligence-driven-purple-teaming)
7. [Purple Team Tools & Automation](#_7-purple-team-tools-amp-automation)
8. [Active Directory Purple Teaming](#_8-active-directory-purple-teaming)
9. [Cloud Purple Teaming](#_9-cloud-purple-teaming)
10. [Purple Team Reporting & Maturity](#_10-purple-team-reporting-amp-maturity)

---

## 1. Purple Team Fundamentals

### 1.1 Purple Team Defined

A purple team is a collaborative security function in which offensive (red) and defensive (blue) personnel work together in real time to improve detection and response capabilities. Unlike a traditional red team engagement — which is adversarial and designed to keep the blue team uninformed — a purple team shares attack context immediately so defenders can tune controls, build detections, and close gaps as testing progresses.

**Core distinction:**

| Dimension | Red Team | Purple Team |
|---|---|---|
| Transparency | Blue unaware | Full collaboration |
| Primary output | Breach narrative | Detection coverage improvement |
| Feedback loop | End-of-engagement report | Continuous, per-technique |
| Duration | Weeks–months | Hours–days per campaign |
| Primary audience | Executive / Board | Detection engineering / SOC |

### 1.2 Value Proposition

**Faster detection improvement cycle:** Because both teams share context in real time, a missed detection can be diagnosed and tuned on the same day it is tested — not weeks later when a red team report is delivered.

**Targeted gap analysis:** Purple teams can methodically test every technique in a threat actor's known playbook, producing a precise map of which TTPs are detected versus missed, rather than a sample of what a red teamer happened to use.

**Cost-effective vs. full red team:** Skilled red teamers are expensive. Purple teaming multiplies the return on that investment by ensuring every technique tested produces a detection improvement, not just a finding.

**Continuous security improvement culture:** Regular purple team exercises build a shared language between offense and defense, reduce organizational friction between teams, and embed security validation into normal operations.

### 1.3 Purple Team Models

**Ad-hoc collaborative:** A red team operator and a detection engineer sit together and run individual atomic tests, checking the SIEM after each execution. Low overhead, good for initial gap assessment or new log source validation.

**Structured campaigns:** Planned exercises with defined scope, threat actor emulation plan, and documented results in a tracking platform (e.g., Vectr). Run quarterly or monthly. Produces before/after ATT&CK coverage heatmaps.

**Continuous automated:** Atomic tests run on a scheduled basis (daily or weekly) via CI/CD pipeline. SIEM is queried automatically after each test. Coverage dashboard is updated programmatically. Regression alerts fire if a previously detected technique stops alerting.

### 1.4 MITRE ATT&CK as Common Language

ATT&CK provides the shared vocabulary that makes purple teaming tractable at scale.

**Technique IDs as atomic unit:** Each test maps to a specific technique (T1059.001 — PowerShell) or sub-technique. This enables unambiguous tracking: "We tested T1003.001 and it is detected" is a precise statement that any team member can act on.

**Tactic coverage measurement:** ATT&CK's 14 tactics (see Section 2) form the rows of a coverage heatmap. Teams can track what percentage of techniques under each tactic are detected, and prioritize the most-used tactics by active threat actors.

**ATT&CK Navigator heatmap:** The ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) allows teams to color-code techniques by detection status. Red = undetected, green = detected, yellow = partial/low-quality. Before-and-after layers quantify the coverage improvement from a purple team exercise.

**Common scoring scale:** Techniques are scored 0–100 in Navigator layers: 0 = no detection, 50 = telemetry only (raw log but no alert), 75 = alert fires but quality is poor, 100 = alert fires with correct context, severity, and analyst-ready enrichment.

### 1.5 Program Design

**Scope definition:** Which asset classes are in scope (endpoints, AD, cloud, OT)? Which threat actors are being emulated? What is the crown jewel data being protected?

**Cadence:** Recommended minimum: monthly automated atomic validation + quarterly structured campaign + annual full red team. Adjust to team capacity and organizational risk appetite.

**Stakeholders:** Purple team lead (coordinator), red team operator (executor), detection engineer (builder), SOC analyst (validator), threat intel analyst (scenario designer), CISO (executive sponsor).

**Rules of engagement:** Purple team RoE should document: test systems (not production unless agreed), notification chain, abort criteria, data handling for findings, and tool usage policy.

**Success metrics:** Coverage % before/after, number of new detections created, number of detections tuned, mean time to detect (MTTD) improvement, remediation rate from prior exercises.

### 1.6 Prerequisite Maturity

Before launching a purple team program, the following baseline capabilities should be in place:

- **EDR deployed** at >90% endpoint coverage with telemetry flowing to SIEM
- **SIEM operational** with retention adequate for purple team test windows (minimum 30 days)
- **Basic IR process** — the team knows how to investigate an alert and escalate
- **Logging baseline** — Windows Event Log forwarding (Security, System, Sysmon), network flow logs, DNS query logs, authentication logs
- **MITRE ATT&CK familiarity** — at least one team member can map activity to ATT&CK techniques

Without these foundations, purple team results will be dominated by infrastructure gaps rather than detection logic gaps, and the value of the exercise is significantly reduced.

---
## 2. MITRE ATT&CK for Purple Teams

### 2.1 Matrix Structure

The ATT&CK Enterprise matrix contains **14 tactics** representing phases or objectives of an adversary operation:

| # | Tactic | ID | Focus |
|---|---|---|---|
| 1 | Reconnaissance | TA0043 | Gather info before attack |
| 2 | Resource Development | TA0042 | Acquire infrastructure/tools |
| 3 | Initial Access | TA0001 | Enter the environment |
| 4 | Execution | TA0002 | Run malicious code |
| 5 | Persistence | TA0003 | Maintain foothold |
| 6 | Privilege Escalation | TA0004 | Gain higher permissions |
| 7 | Defense Evasion | TA0005 | Avoid detection |
| 8 | Credential Access | TA0006 | Steal credentials |
| 9 | Discovery | TA0007 | Learn environment |
| 10 | Lateral Movement | TA0008 | Move through network |
| 11 | Collection | TA0009 | Gather target data |
| 12 | Command and Control | TA0011 | Communicate with implants |
| 13 | Exfiltration | TA0010 | Remove data |
| 14 | Impact | TA0040 | Disrupt / destroy |

**Sub-techniques (T1xxx.xxx):** Many techniques have sub-techniques that specify the exact method. For example, T1059 (Command and Scripting Interpreter) has sub-techniques T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1059.006 (Python), etc. Purple teams should test at the sub-technique level for maximum precision.

**Procedure examples:** ATT&CK procedure examples in the knowledge base document how specific threat actors (e.g., APT29, Lazarus Group) have implemented a technique. These procedures are the raw material for realistic emulation scenarios.

### 2.2 ATT&CK Navigator

The ATT&CK Navigator is the primary visualization tool for purple team coverage tracking.

**Layer creation:**
1. Navigate to https://mitre-attack.github.io/attack-navigator/
2. Click "Create New Layer" → Select "Enterprise ATT&CK"
3. Use the technique controls panel to score/color each technique
4. Save layers as JSON for version control

**Technique scoring 0–100:**
- **0** — No detection capability, no telemetry
- **25** — Raw telemetry exists (log source) but no detection rule
- **50** — Detection rule exists but did not fire during test
- **75** — Alert fired but quality is insufficient (missing context, wrong severity)
- **100** — Alert fired with correct ATT&CK tagging, analyst-ready enrichment, and linked playbook

**Color coding:**
- Red (#ff6666) — Not detected
- Yellow (#ffff00) — Partial / telemetry only
- Green (#00cc44) — Detected with good quality

**Aggregate layers:** Navigator supports creating aggregate layers from multiple individual layers, useful for combining results across platforms (Windows + Linux + Cloud) or across different purple team campaigns.

**Export formats:**
- JSON — For version control and programmatic processing
- Excel (XLSX) — For stakeholder reporting with filtering
- SVG — For embedding in presentations and reports

**Before-after comparison:** Export a "before" layer at the start of a purple team exercise and an "after" layer at the end. Load both into Navigator to visually demonstrate coverage improvement.

### 2.3 Threat-Informed Defense

**CTID (Center for Threat-Informed Defense):** A non-profit R&D organization (operated with MITRE) that produces open-source research to advance threat-informed defense. Key outputs: adversary emulation plans, ATT&CK Workbench, mappings to security controls.

**Red Canary Top Techniques (by prevalence):** Red Canary publishes annual Threat Detection Reports ranking the most-prevalent ATT&CK techniques seen across their customer base. Prioritize purple team coverage of these high-frequency techniques:
- T1059 Command and Scripting Interpreter (consistently #1)
- T1218 System Binary Proxy Execution
- T1055 Process Injection
- T1547.001 Registry Run Keys / Startup Folder
- T1105 Ingress Tool Transfer

**Prioritizing most-used techniques by active actors:** Cross-reference ATT&CK Groups (https://attack.mitre.org/groups/) to find techniques used by threat actors targeting your industry. Weight purple team test prioritization by: (frequency of actor use) × (business impact if successful) × (current coverage gap).

### 2.4 ATT&CK Evaluations

MITRE conducts annual evaluations of security products against emulated threat actors. Results are published at https://attackevals.mitre-engenuity.org/.

**Evaluation rounds:**
- APT3 (2018) — Chinese espionage group
- APT29 (2019) — Russian SVR / Cozy Bear
- Carbanak+FIN7 (2020) — Financially motivated threat actors
- Wizard Spider+Sandworm (2021) — Ransomware + Russian GRU
- Turla (2022) — Russian FSB espionage

**Detection analytics vs. visibility scoring:**
- **Visibility** — The product captured telemetry about the action (raw data exists)
- **Detection** — The product generated an analytic alert about the action

**Vendor results interpretation for purple teams:** ATT&CK Evaluations reveal which techniques your EDR vendor detects with analytics vs. merely captures as telemetry. Use this to identify where you need to build custom SIEM rules to compensate for EDR analytic gaps.

### 2.5 D3FEND Framework

MITRE D3FEND (https://d3fend.mitre.org/) is a complementary ontology of defensive countermeasures mapped to ATT&CK offensive techniques.

**Countermeasures ontology:** D3FEND organizes defensive techniques into categories: Harden, Detect, Isolate, Deceive, Evict.

**Technique-to-countermeasure mapping:** For any ATT&CK offensive technique, D3FEND identifies the defensive countermeasures that address it. Purple teams can use this to:
1. Identify which defensive controls should have prevented/detected a tested technique
2. Prioritize defensive improvements based on what countermeasures are missing
3. Communicate defensive recommendations using a standardized ontology

---
## 3. Atomic Red Team

### 3.1 Framework Overview

Atomic Red Team (https://github.com/redcanaryco/atomic-red-team) is an open-source library of small, focused tests that each map 1:1 to a MITRE ATT&CK technique or sub-technique. Developed and maintained by Red Canary.

**Design principles:**
- **Atomic** — Each test does one thing. No complex multi-step attack chains. This enables precise detection validation.
- **Minimal prerequisites** — Tests should run with minimal setup. Prerequisites are documented and auto-installable where possible.
- **Cleanup commands** — Every test includes commands to undo its changes, ensuring test systems remain clean for repeated testing.
- **Multiple executor types** — Tests run via command_prompt, powershell, bash, manual, or python executors, matching real-world attacker tool usage.

**YAML format:** Each atomic test is defined in a YAML file organized by ATT&CK technique ID (e.g., `atomics/T1059.001/T1059.001.yaml`).

### 3.2 Invoke-AtomicRedTeam

The primary PowerShell framework for executing atomic tests on Windows.

**Installation:**
```powershell
# Install the module from PowerShell Gallery
Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force
Import-Module invoke-atomicredteam

# Install atomics folder (the test library)
Invoke-AtomicTest T1059.001 -GetPrereqs
# Or clone directly:
# git clone https://github.com/redcanaryco/atomic-red-team.git C:\AtomicRedTeam
```

**Core commands:**
```powershell
# List all tests for a technique (brief)
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Install prerequisites for a test
Invoke-AtomicTest T1059.001 -GetPrereqs

# Execute test #1
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Execute all tests for a technique
Invoke-AtomicTest T1059.001

# Execute with custom input arguments
Invoke-AtomicTest T1059.001 -TestNumbers 1 -InputArgs @{command="whoami"}

# Run cleanup after test
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup

# Execute ALL atomics (full coverage run — use on dedicated test system)
Invoke-AtomicTest All

# Execute all with prerequisites auto-installed
Invoke-AtomicTest All -GetPrereqs; Invoke-AtomicTest All
```

**Logging output:** Pipe to a log file for SIEM ingestion validation:
```powershell
Invoke-AtomicTest T1059.001 -LoggingModule "Attire-ExecutionLogger" -ExecutionLogPath "C:\Temp\atomics_log.json"
```

### 3.3 Atomic Test YAML Structure

```yaml
attack_technique: T1059.001
display_name: "Command and Scripting Interpreter: PowerShell"
atomic_tests:
  - name: "Mimikatz - Credential Dumping"
    auto_generated_guid: "f3132740-55bc-48c4-bcc0-758a459cd027"
    description: |
      Dumps credentials from LSASS using Mimikatz sekurlsa::logonpasswords
    supported_platforms:
      - windows
    input_arguments:
      mimikatz_path:
        description: Path to mimikatz executable
        type: path
        default: "PathToAtomicsFolder\..\ExternalPayloads\mimikatz\x64\mimikatz.exe"
    dependency_executor_name: powershell
    dependencies:
      - description: "Mimikatz must exist on disk at specified location"
        prereq_command: |
          if (Test-Path "#{mimikatz_path}") { exit 0 } else { exit 1 }
        get_prereq_command: |
          Invoke-WebRequest -Uri "https://github.com/..." -OutFile "#{mimikatz_path}"
    executor:
      name: command_prompt
      elevation_required: true
      command: |
        #{mimikatz_path} "sekurlsa::logonpasswords" "exit"
      cleanup_command: |
        Remove-Item "#{mimikatz_path}" -ErrorAction Ignore
```

**Key YAML fields:**
- `auto_generated_guid` — Unique identifier for each test, used in logging
- `supported_platforms` — windows / linux / macos
- `executor.name` — command_prompt / powershell / bash / manual / python
- `elevation_required` — Whether admin/root is required
- `input_arguments` — Parameterized inputs with defaults (use `#{arg_name}` syntax)
- `dependencies` — Prerequisites check/install pattern
- `cleanup_command` — Undo the test's changes

### 3.4 Creating Custom Atomic Tests

For organization-specific detections (e.g., testing a proprietary application's audit logging):

```yaml
attack_technique: T1078.002
display_name: "Valid Accounts: Domain Accounts - Custom"
atomic_tests:
  - name: "Authenticate to internal ACME app with service account"
    auto_generated_guid: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    description: |
      Tests whether authentication with the corp-svc-deploy account to
      the ACME internal portal triggers a SIEM alert for service account
      interactive login anomaly.
    supported_platforms:
      - windows
    executor:
      name: powershell
      elevation_required: false
      command: |
        # Simulate interactive login with service account credentials
        $cred = New-Object System.Management.Automation.PSCredential(
          "CORP\corp-svc-deploy",
          (ConvertTo-SecureString "#{password}" -AsPlainText -Force)
        )
        Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }
      cleanup_command: |
        Write-Host "No cleanup required"
```

### 3.5 Integration with SIEM/EDR for Validation

**Validation workflow:**
1. Execute atomic test on dedicated test endpoint
2. Wait defined SLA (e.g., 5 minutes for SIEM ingestion)
3. Query SIEM for expected alert/telemetry
4. Document result: Detected / Not Detected / False Negative
5. Run cleanup

**SIEM query after PowerShell execution (Splunk example):**
```spl
index=windows EventCode=4104 ScriptBlockText="*mimikatz*"
| table _time, ComputerName, UserID, ScriptBlockText
```

**Atomics folder organization:**
```
atomic-red-team/
  atomics/
    T1059.001/
      T1059.001.yaml         # Test definitions
      T1059.001.md           # Human-readable documentation
      src/                   # Supporting scripts/binaries
    T1003.001/
      T1003.001.yaml
    ...
  bin/                       # Invoke-AtomicRedTeam module
  docs/                      # Documentation
```

---
## 4. Adversary Emulation Platforms

### 4.1 CALDERA

CALDERA (https://github.com/mitre/caldera) is MITRE's open-source adversary emulation platform. It provides a server-agent architecture for automated adversary emulation campaigns.

**Architecture:**
- **Server** — Web UI + REST API, hosts campaigns, adversary profiles, and abilities
- **Agents** — Deployed on target systems, receive instructions from server
  - **Sandcat** — Default Go-based agent, HTTP/S C2
  - **MANX** — Reverse-shell style agent for environments blocking outbound connections
  - **Ragdoll** — Python-based agent for macOS/Linux

**Key concepts:**
- **Ability** — A single action mapped to an ATT&CK technique (equivalent to an atomic test)
- **Adversary** — A collection of abilities organized into a threat actor profile
- **Operation** — An execution of an adversary profile against one or more agents
- **Planner** — The algorithm that determines ability execution order:
  - `sequential` — Executes abilities in defined order
  - `batch` — Runs all available abilities concurrently
  - `bucketlist` — Executes abilities grouped by tactic
  - `atomic` — One ability at a time, waits for result before next

**Plugins:**
- **Stockpile** — Library of pre-built abilities and adversary profiles
- **Compass** — ATT&CK Navigator integration for coverage visualization
- **Debrief** — Post-operation reporting and analysis
- **Filestore** — File hosting for payloads
- **Response** — Automated response actions (blue team automation)

**REST API — Starting an operation:**
```bash
curl -X POST http://localhost:8888/api/v2/operations   -H "KEY: ADMIN123"   -H "Content-Type: application/json"   -d '{
    "name": "Purple Team Test - APT29",
    "adversary": {"adversary_id": "apt29-id"},
    "planner": {"id": "sequential-planner-id"},
    "group": "purple-team-endpoints",
    "auto_close": true
  }'
```

**Custom ability YAML:**
```yaml
- id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
  name: Kerberoast service accounts
  description: Request TGS tickets for SPN-registered accounts
  tactic: credential-access
  technique:
    attack_id: T1558.003
    name: "Steal or Forge Kerberos Tickets: Kerberoasting"
  platforms:
    windows:
      psh:
        command: |
          Import-Module ActiveDirectory;
          Get-ADUser -Filter {ServicePrincipalName -ne "$null"} |
          % { Add-Type -AssemblyName System.IdentityModel;
              New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.UserPrincipalName }
        cleanup: |
          Write-Host "No cleanup required"
  requirements:
    - plugins.stockpile.app.requirements.paw_provenance:
        - source: host.user.is_privileged
```

### 4.2 Stratus Red Team

Stratus Red Team (https://github.com/DataDog/stratus-red-team) is an open-source tool focused on cloud adversary emulation, developed by Datadog.

**Cloud platform coverage:** AWS, Azure, GCP, Kubernetes

**CLI usage:**
```bash
# List all available attack techniques
stratus-red-team list

# List techniques for a specific platform
stratus-red-team list --platform aws

# Warm up (create prerequisites without detonating)
stratus-red-team warmup aws.credential-access.ec2-steal-instance-credentials

# Detonate (execute the attack technique)
stratus-red-team detonate aws.credential-access.ec2-steal-instance-credentials

# Cleanup (destroy prerequisites and any artifacts)
stratus-red-team cleanup aws.credential-access.ec2-steal-instance-credentials

# Warm up, detonate, and cleanup in one command
stratus-red-team detonate aws.exfiltration.s3-backdoor-bucket-policy --auto-cleanup
```

**Key AWS techniques in Stratus:**
| Technique ID | ATT&CK Mapping | Description |
|---|---|---|
| aws.credential-access.ec2-steal-instance-credentials | T1552.005 | Steal EC2 instance metadata credentials |
| aws.exfiltration.s3-backdoor-bucket-policy | T1537 | Backdoor S3 bucket policy for exfiltration |
| aws.persistence.iam-backdoor-user | T1136.003 | Create backdoor IAM user |
| aws.discovery.ec2-enumerate-from-instance | T1580 | Enumerate EC2 resources from instance |
| aws.lateral-movement.ec2-instance-connect | T1021.004 | Lateral movement via EC2 Instance Connect |

**CloudTrail validation after detonation:**
```bash
# Query CloudTrail for the technique's expected API calls
aws cloudtrail lookup-events   --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity   --start-time $(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%SZ)   --query 'Events[].{Time:EventTime,Name:EventName,User:Username}'   --output table
```

### 4.3 Scythe (Commercial)

Scythe (https://scythe.io) is a commercial adversary emulation platform used by enterprise purple teams.

**Key capabilities:**
- **Campaign creation** — GUI-based campaign builder with drag-and-drop TTP sequencing
- **Implant deployment** — Multiple C2 protocols, staged implant delivery
- **TTP library** — Pre-built modules mapped to ATT&CK, updated for current threats
- **Reporting** — Executive and technical reports with ATT&CK heatmap export
- **Community Threats** — Shared threat actor emulation plans from the community

### 4.4 Vectr (Purple Team Tracking)

Vectr (https://vectr.io) is a purple team management platform for tracking test cases, results, and coverage over time. Available as open-source (self-hosted) or commercial SaaS.

**Hierarchy:** Organizations → Projects → Campaigns → Assessments → Test Cases

**Test case workflow:**
1. Create test case with ATT&CK technique mapping
2. Document procedure (how the test was executed)
3. Record result: Detected / Not Detected
4. Capture evidence (screenshots, SIEM alerts, logs)
5. Track remediation status

**ATT&CK heatmap:** Vectr auto-generates ATT&CK Navigator layers from recorded test results.

**REST API for programmatic test case management:**
```bash
# Create a new test case via API
curl -X POST https://vectr.io/api/v1/testcases   -H "Authorization: Bearer $VECTR_TOKEN"   -H "Content-Type: application/json"   -d '{
    "name": "T1558.003 Kerberoasting",
    "attackTechnique": "T1558.003",
    "outcome": "failed",
    "notes": "No alert generated. Missing detection rule for RC4 TGS requests."
  }'
```

---
## 5. Detection Validation Methodology

### 5.1 Detection Validation Workflow

The purple team detection validation cycle has 9 steps:

```
1. SELECT ATT&CK technique to test
        │
        ▼
2. DOCUMENT detection hypothesis
   (What alert/log should fire, in which tool, within what SLA?)
        │
        ▼
3. EXECUTE atomic test or emulation scenario
        │
        ▼
4. CHECK SIEM/EDR within defined SLA (e.g., 5 min)
        │
        ▼
5. DOCUMENT RESULT:
   ┌─────────────────────────────────────────┐
   │ Detected        │ Not Detected          │
   │ (go to step 6a) │ (go to step 6b)       │
   └─────────────────────────────────────────┘
        │
        ▼
6a. ASSESS alert quality (go to step 9)
6b. IDENTIFY gap (missing source/rule/tuning)
        │
        ▼
7. REMEDIATE (create rule / fix log source / tune)
        │
        ▼
8. RETEST (loop to step 3)
        │
        ▼
9. UPDATE Navigator coverage layer + tracking platform
```

### 5.2 Detection Hypothesis Documentation

Before executing any test, document:

```markdown
## Detection Hypothesis: T1558.003 Kerberoasting

**Technique:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
**Test:** Invoke-AtomicTest T1558.003 -TestNumbers 1

**Expected detection:**
- Tool: Splunk (Security SIEM)
- Alert name: "Possible Kerberoasting — RC4 TGS Request"
- Detection logic: Event ID 4769 with TicketEncryptionType = 0x17 (RC4) and
  TicketOptions = 0x40810000 from a non-service account
- SLA: Alert within 10 minutes of execution
- Severity: High

**Expected telemetry (minimum):**
- Windows Security Event 4769 in Splunk index=windows
- Source account, target service, encryption type visible in alert

**ATT&CK Navigator score if detected:** 100
**ATT&CK Navigator score if telemetry only:** 50
**ATT&CK Navigator score if not detected:** 0
```

### 5.3 Alert Quality Assessment

When an alert does fire, assess its quality across these dimensions:

| Dimension | Questions |
|---|---|
| **True positive accuracy** | Does the alert correctly identify the malicious action? Any false positive risk? |
| **Correct context** | Does the alert include: source host, user, target, timestamp, parent process? |
| **ATT&CK tagging** | Is the technique ID (T1558.003) tagged in the alert metadata? |
| **Severity** | Is the severity appropriate? (Kerberoasting = High, not Informational) |
| **Analyst detail** | Can an analyst understand what happened and why it's suspicious from the alert alone? |
| **Auto-enrichment** | Does the alert auto-enrich with: user risk score, asset criticality, threat intel hits? |
| **Linked playbook** | Does the alert link to an IR playbook for this technique? |

**Quality scoring:**
- All dimensions met → Score 100, mark Green in Navigator
- Most dimensions met, minor gaps → Score 75, mark Yellow
- Alert fires but poor context/enrichment → Score 50, mark Yellow
- Alert does not fire → Score 0–25, mark Red

### 5.4 Detection Gap Categories

When a technique is not detected, categorize the gap to drive the right remediation:

| Gap Category | Description | Remediation |
|---|---|---|
| **Missing log source** | The relevant data is not collected at all (e.g., Sysmon not deployed, CloudTrail disabled) | Deploy log source; validate ingestion |
| **Log present, no rule** | Data reaches SIEM but no detection rule exists | Write Sigma rule; convert to SIEM query |
| **Rule misconfigured** | Rule exists but has syntax error, wrong index, or field name mismatch | Debug and fix rule; retest |
| **EDR telemetry gap** | EDR does not generate telemetry for this technique (product limitation) | Write compensating SIEM rule from available logs |
| **Cloud API not logged** | Cloud service API calls not enabled in audit logging | Enable CloudTrail data events / Entra diagnostic settings |
| **Log volume filtered** | High-volume events being dropped by SIEM filters | Adjust filter; increase capacity or use sampling |

### 5.5 Coverage Measurement

**Technique coverage %:** (Number of techniques with detection score ≥ 75) / (Total techniques tested) × 100

**Recommended coverage targets by tactic priority:**

| Priority | Tactics | Target Coverage |
|---|---|---|
| Critical | Credential Access, Lateral Movement, Execution | ≥ 80% |
| High | Persistence, Privilege Escalation, Defense Evasion | ≥ 70% |
| Medium | Discovery, Collection, C2 | ≥ 60% |
| Lower | Recon, Resource Dev, Exfiltration, Impact | ≥ 50% |

### 5.6 Detection Engineering Feedback Loop

Purple team findings should flow directly into the detection engineering backlog:

```
Purple Team Test (Not Detected)
        │
        ▼
Create Jira/GitHub Issue:
  - Technique: T1558.003
  - Gap type: "Log present, no rule"
  - Available data: Windows Event 4769 in index=windows
  - Priority: High (active threat actor uses this)
        │
        ▼
Detection Engineer writes Sigma rule:
title: Kerberoasting RC4 TGS Request
id: 4a4e5f6a-...
status: experimental
description: Detects possible Kerberoasting via RC4 TGS ticket requests
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
        TicketOptions: '0x40810000'
    filter_computer:
        AccountName|endswith: '$'
    condition: selection and not filter_computer
falsepositives:
    - Legacy applications using RC4 Kerberos
level: high
tags:
    - attack.credential_access
    - attack.t1558.003
        │
        ▼
Convert Sigma to SIEM-native query (sigma-cli)
        │
        ▼
Deploy to SIEM → Re-run purple team test → Verify → Close issue
```

---
## 6. Threat Intelligence-Driven Purple Teaming

### 6.1 Threat Actor Identification

Effective purple teaming starts with knowing which adversaries most plausibly threaten your organization.

**Identification criteria:**

| Criterion | Questions |
|---|---|
| **Industry targeting** | Which threat groups historically target your sector (Finance, Healthcare, Energy, Tech)? |
| **Geographic focus** | Do threat actors target organizations in your region or country? |
| **Crown jewel alignment** | Do the actor's collection objectives align with your most sensitive data? |
| **Capability match** | Does the actor's sophistication level reflect your real-world threat? |

**Primary intelligence sources:**
- **Mandiant M-Trends** — Annual threat report with industry-specific TTPs
- **CrowdStrike Adversary Intelligence** — Named adversary profiles with ATT&CK mappings
- **Recorded Future** — Structured threat intelligence with ATT&CK integration
- **CISA Advisories** — Free government advisories for nation-state and criminal groups
- **ISAC reports** — Sector-specific threat intelligence sharing
- **ATT&CK Groups page** — https://attack.mitre.org/groups/ — Free ATT&CK mappings for known groups

### 6.2 APT Emulation Plans

**MITRE ATT&CK Emulation Plans (free, open-source):**

| Plan | Threat Actor | Focus |
|---|---|---|
| APT29 | Russian SVR / Cozy Bear | Espionage, credential theft, C2 |
| FIN6 | Financially motivated | POS malware, Cobalt Strike |
| menuPass | Chinese APT10 | Managed service provider targeting |

Available at: https://github.com/center-for-threat-informed-defense/adversary_emulation_library

**CTID emulation plan structure:**
1. **Intelligence Summary** — Actor background, targeting, objectives
2. **Operations Flow** — High-level attack narrative
3. **Phase breakdown** — Per-phase techniques with procedure examples
4. **ATT&CK technique list** — All mapped technique IDs
5. **Detection opportunities** — Expected log sources and events per technique
6. **Emulation execution steps** — Command-level procedures

**Mapping actor procedures to atomic tests:**
```
APT29 Procedure: Use PowerShell to download and execute remote payload
  → ATT&CK: T1059.001 (PowerShell) + T1105 (Ingress Tool Transfer)
  → Atomic: Invoke-AtomicTest T1059.001 -TestNumbers 2
             Invoke-AtomicTest T1105 -TestNumbers 1

APT29 Procedure: Steal credentials from LSASS
  → ATT&CK: T1003.001 (LSASS Memory)
  → Atomic: Invoke-AtomicTest T1003.001 -TestNumbers 1

APT29 Procedure: Kerberoast service accounts
  → ATT&CK: T1558.003
  → Atomic: Invoke-AtomicTest T1558.003 -TestNumbers 1
```

### 6.3 Intelligence-Based Scenario Design

**Scenario template — APT29 Initial Compromise to Credential Theft:**

```
SCENARIO: APT29-Inspired Credential Access Campaign

OBJECTIVE: Validate detection of Russian SVR-style credential theft following
           phishing-based initial access

THREAT ACTOR: APT29 (Cozy Bear) — Russian SVR, active against government,
              think tanks, healthcare, and tech sectors

PHASE 1 — INITIAL ACCESS
  Technique: T1566.001 Spearphishing Attachment
  Simulation: Deliver weaponized Office document to test mailbox
  Atomic: Manual delivery to sandboxed endpoint
  Detection expected: Email gateway block + EDR macro alert

PHASE 2 — EXECUTION
  Technique: T1059.001 PowerShell
  Simulation: PowerShell download cradle from C2 simulation server
  Atomic: Invoke-AtomicTest T1059.001 -TestNumbers 2
  Detection expected: PowerShell Script Block Logging Event 4104

PHASE 3 — PERSISTENCE
  Technique: T1547.001 Registry Run Key
  Atomic: Invoke-AtomicTest T1547.001 -TestNumbers 1
  Detection expected: Sysmon Event 13 registry value set

PHASE 4 — CREDENTIAL ACCESS
  Technique: T1003.001 LSASS Memory
  Atomic: Invoke-AtomicTest T1003.001 -TestNumbers 1
  Detection expected: Sysmon Event 10 LSASS access + EDR alert

PHASE 5 — LATERAL MOVEMENT
  Technique: T1550.002 Pass the Hash
  Atomic: Invoke-AtomicTest T1550.002 -TestNumbers 1
  Detection expected: Event 4624 (Logon Type 3, NTLM) + Event 4648

PHASE 6 — COLLECTION / EXFILTRATION
  Technique: T1074.001 Local Data Staging + T1048 Exfiltration Alt Protocol
  Atomic: Invoke-AtomicTest T1074.001; Invoke-AtomicTest T1048
  Detection expected: Large file creation + outbound DNS/ICMP anomaly
```

### 6.4 After-Action Threat Intelligence Updates

Purple team results should feed back into the threat intelligence function:

**Update threat model based on detection gaps:**
- If T1003.001 (LSASS dump) is undetected → elevate risk rating for credential-theft-capable actors
- If T1558.003 (Kerberoasting) is undetected → flag all APT groups known to use Kerberoasting as elevated risk

**Adjust defensive priorities based on TTP overlap with gaps:**
```
TTP overlap analysis:
  Undetected techniques: T1003.001, T1558.003, T1550.002
  Threat actors using ALL THREE: APT28, APT29, Sandworm, HAFNIUM
  Business impact of those actors: Critical
  Action: Escalate detection engineering priority for these three techniques
           to P1; brief CISO on gap-actor correlation
```

**Intelligence sharing output:** After a purple team exercise, publish an internal threat intelligence update summarizing:
- Which tested techniques were not detected
- Which threat actors use those techniques
- Recommended defensive actions (log source gaps, rule creation)
- Timeline for remediation

---
## 7. Purple Team Tools & Automation

### 7.1 Vectr — Comprehensive Platform Guide

Vectr (https://vectr.io) is the recommended purple team management platform for tracking tests, results, and coverage across campaigns.

**Hierarchy structure:**
```
Organization
  └── Project (e.g., "FY2025 Purple Team Program")
        └── Campaign (e.g., "Q1 2025 — APT29 Emulation")
              └── Assessment (e.g., "Credential Access Techniques")
                    └── Test Cases (individual ATT&CK technique tests)
```

**Test case creation fields:**
- Name (e.g., "T1558.003 — Kerberoasting via Rubeus")
- ATT&CK technique mapping (tactic + technique ID)
- Description / procedure documentation
- Operator (who ran the test)
- Test date
- Outcome: Detected / Not Detected / Partial
- Detection quality rating (1–5)
- Evidence attachment (screenshots, SIEM alert exports, logs)
- Remediation status and assigned engineer

**Executive dashboard metrics:**
- Overall detection rate (%)
- Techniques tested vs. total ATT&CK techniques
- Coverage by tactic (radar/spider chart)
- Trend over time (quarter-over-quarter improvement)
- Open remediation items by priority

**REST API for programmatic management:**
```python
import requests

VECTR_URL = "https://vectr.example.com"
TOKEN = "your-vectr-api-token"

headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

# Create a test case
test_case = {
    "name": "T1558.003 Kerberoasting",
    "attackTechnique": "T1558.003",
    "tactic": "credential-access",
    "outcome": "not_detected",
    "operatorNotes": "No SIEM alert. Event 4769 with 0x17 encryption type present in raw logs but no rule.",
    "remediationStatus": "open",
    "priority": "high"
}

r = requests.post(f"{VECTR_URL}/api/v1/testcases", headers=headers, json=test_case)
print(r.status_code, r.json()["id"])
```

### 7.2 ATT&CK Workbench

ATT&CK Workbench (https://github.com/center-for-threat-informed-defense/attack-workbench-frontend) is a self-hosted knowledge base for managing a custom ATT&CK instance.

**Use cases for purple teams:**
- **Custom techniques** — Add internal techniques not in the public ATT&CK knowledge base (e.g., techniques targeting proprietary systems)
- **Custom groups** — Track internally-identified threat actors with ATT&CK mappings
- **Procedure tracking** — Link observed procedures from your threat intel to standard techniques
- **Internal ATT&CK versioning** — Pin your team to a specific ATT&CK version while evaluating upgrades

**Deployment:**
```bash
# Clone and start via Docker Compose
git clone https://github.com/center-for-threat-informed-defense/attack-workbench-frontend
cd attack-workbench-frontend
docker-compose up -d
# Access at http://localhost
```

### 7.3 ATT&CK Flow

ATT&CK Flow (https://github.com/center-for-threat-informed-defense/attack-flow) is an open language and tool for describing sequences of adversary behaviors (multi-step attack scenarios).

**Attack Flow JSON format:**
```json
{
  "type": "bundle",
  "id": "bundle--...",
  "spec_version": "2.0",
  "objects": [
    {
      "type": "attack-flow",
      "id": "attack-flow--...",
      "name": "APT29 Credential Theft Chain",
      "description": "PowerShell download → LSASS dump → Pass the Hash"
    },
    {
      "type": "attack-action",
      "id": "attack-action--1",
      "technique_id": "T1059.001",
      "name": "PowerShell Download Cradle"
    },
    {
      "type": "attack-action",
      "id": "attack-action--2",
      "technique_id": "T1003.001",
      "name": "LSASS Memory Dump"
    }
  ]
}
```

**ATT&CK Flow Builder GUI:** Visual drag-and-drop interface at https://center-for-threat-informed-defense.github.io/attack-flow/ui/

### 7.4 TRAM — Threat Report ATT&CK Mapper

TRAM (https://github.com/center-for-threat-informed-defense/tram) uses machine learning to automatically extract ATT&CK technique mappings from threat intelligence reports.

**Workflow:** Upload threat report PDF/URL → TRAM extracts sentences mentioning techniques → Human validates suggestions → Export ATT&CK technique list for purple team test planning.

### 7.5 EDR Telemetry Assessment Tools

**PurpleSharp** (https://github.com/mvelazc0/PurpleSharp):
- Designed for Active Directory-joined Windows environments
- Simulates adversary behaviors directly in the domain context
- Generates realistic Windows Security events (logon events, process creation, network connections)
- Useful for validating detection in complex enterprise AD scenarios

**AtomicTestHarnesses** (https://github.com/redcanaryco/AtomicTestHarnesses):
- PowerShell module providing test harnesses for complex Windows behaviors
- Supplements Atomic Red Team for techniques requiring precise Windows API calls

**Prelude Operator** (https://www.prelude.org/):
- Commercial platform with automated detection validation
- Agent-based, maps to ATT&CK, supports custom TTP libraries

### 7.6 Automated Purple Team Pipelines

**CI/CD pipeline for continuous detection validation:**

```yaml
# .github/workflows/purple-team-validation.yml
name: Daily Purple Team Atomic Validation

on:
  schedule:
    - cron: '0 2 * * *'   # Run at 02:00 UTC daily
  workflow_dispatch:

jobs:
  atomic-validation:
    runs-on: [self-hosted, purple-team-endpoint]
    steps:
      - name: Run Atomic Tests — Credential Access
        shell: powershell
        run: |
          Import-Module invoke-atomicredteam
          $techniques = @("T1558.003","T1003.001","T1110.001")
          foreach ($t in $techniques) {
            Invoke-AtomicTest $t -GetPrereqs -ErrorAction SilentlyContinue
            Invoke-AtomicTest $t
            Start-Sleep -Seconds 300   # Wait for SIEM ingestion
            Invoke-AtomicTest $t -Cleanup
          }

      - name: Validate Detections via SIEM API
        env:
          SPLUNK_TOKEN: ${{ secrets.SPLUNK_TOKEN }}
        shell: python3 {0}
        run: |
          import requests, json
          from datetime import datetime, timedelta

          techniques = {
            "T1558.003": 'index=windows EventCode=4769 TicketEncryptionType=0x17',
            "T1003.001": 'index=windows EventCode=10 TargetImage="*lsass.exe"',
            "T1110.001": 'index=windows EventCode=4625 LogonType=3'
          }

          results = {}
          for technique, query in techniques.items():
            r = requests.post("https://splunk.internal:8089/services/search/jobs/export",
              auth=("admin", "${{ secrets.SPLUNK_TOKEN }}"),
              data={"search": f"search {query} earliest=-10m", "output_mode": "json"})
            results[technique] = "DETECTED" if r.text.strip() else "NOT DETECTED"

          print(json.dumps(results, indent=2))

          # Fail pipeline if regression detected
          regressions = [t for t, r in results.items() if r == "NOT DETECTED"]
          if regressions:
            raise SystemExit(f"REGRESSION: {regressions} not detected!")
```

---
## 8. Active Directory Purple Teaming

### 8.1 Core AD Attack Techniques and Detection Events

#### T1558.003 — Kerberoasting

**Attack:** Enumerate accounts with Service Principal Names (SPNs) and request TGS tickets, then crack offline.

**Execution:**
```powershell
# Enumerate SPN accounts
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
  Select-Object Name, ServicePrincipalName

# Request TGS tickets (triggers Event 4769)
Add-Type -AssemblyName System.IdentityModel
$spns = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} | Select-Object -ExpandProperty UserPrincipalName
$spns | ForEach-Object {
  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_
}
```

**Detection — Windows Security Event 4769:**
```
EventID: 4769 (A Kerberos service ticket was requested)
TicketEncryptionType: 0x17 (RC4 — weak, crackable offline)
TicketOptions: 0x40810000
ServiceName: NOT ending in $ (user account, not computer account)
```

**SPL query:**
```spl
index=windows EventCode=4769 TicketEncryptionType=0x17
  [| inputlookup service_accounts | fields AccountName]
| stats count by AccountName, ServiceName, src_ip
| where count > 3
```

#### T1558.004 — AS-REP Roasting

**Attack:** Request AS-REP for accounts with Kerberos pre-authentication disabled. No credentials required.

**Execution:**
```powershell
# Find accounts without pre-auth
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Using Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

**Detection — Windows Security Event 4768:**
```
EventID: 4768 (A Kerberos authentication ticket was requested)
PreAuthType: 0 (No pre-authentication)
AccountName: NOT ending in $ (user account)
```

#### T1003.001 — LSASS Memory Dump

**Attack:** Dump LSASS process memory to extract plaintext credentials or NTLM hashes.

**Detection events:**
- **Sysmon Event 10** (ProcessAccess): TargetImage = `C:\Windows\System32\lsass.exe`, GrantedAccess = `0x1010` or `0x1410`
- **Windows Security Event 4656**: Object Handle Requested for LSASS

**KQL (Microsoft Sentinel):**
```kql
SecurityEvent
| where EventID == 4656
| where ObjectName contains "lsass"
| where AccessMask in ("0x1010", "0x1410", "0x143a")
| project TimeGenerated, Computer, SubjectUserName, ProcessName, ObjectName, AccessMask
```

#### T1550.002 — Pass the Hash

**Attack:** Authenticate using stolen NTLM hash without knowing the plaintext password.

**Detection — combined event correlation:**
```
Event 4624 (Successful Logon):
  LogonType: 3 (Network)
  AuthenticationPackageName: NTLM
  WorkstationName: [suspicious workstation]

Event 4648 (Logon using explicit credentials):
  Correlate with above for double logon anomaly
```

**SPL query:**
```spl
index=windows EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| stats dc(Computer) as hop_count by src_user, src_ip
| where hop_count > 3
| sort -hop_count
```

#### T1484.001 — GPO Modification

**Attack:** Modify Group Policy Objects to execute malicious code across domain systems.

**Detection — Windows Security Event 5136:**
```
EventID: 5136 (A directory service object was modified)
ObjectClass: groupPolicyContainer
AttributeValue: Modified
```

#### T1207 — DCShadow

**Attack:** Register a rogue domain controller to push malicious replication changes without standard DC audit logs.

**Detection:** Look for new domain controller registration events — unusual `nTDSDSA` object creation in the Configuration partition, unexpected replication partner announcements.

### 8.2 BloodHound for Purple Team Attack Path Planning

BloodHound (https://github.com/BloodHoundAD/BloodHound) visualizes Active Directory attack paths and is invaluable for purple team planning.

**Purple team workflow with BloodHound:**

**Step 1 — SharpHound collection:**
```powershell
# Run SharpHound collector on domain-joined system
.\SharpHound.exe -c All --zipfilename purpleteam_collection.zip
# Or with specific collection methods
.\SharpHound.exe -c DCOnly,Session,ACL,ObjectProps --domain CORP.LOCAL
```

**Step 2 — BloodHound analysis:**
```cypher
-- Find all paths from any owned user to Domain Admins
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

-- Find Kerberoastable accounts with paths to DA
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN u.name, length(p) as hops
ORDER BY hops ASC LIMIT 20
```

**Step 3 — Select edges for detection testing:**
Each BloodHound edge type maps to ATT&CK techniques:

| BloodHound Edge | ATT&CK Technique | Test |
|---|---|---|
| HasSession | T1558.003 Kerberoasting | Invoke-AtomicTest T1558.003 |
| AdminTo | T1021.002 SMB/Windows Admin Shares | Invoke-AtomicTest T1021.002 |
| DCSync | T1003.006 DCSync | Invoke-AtomicTest T1003.006 |
| WriteDacl | T1222 File/Directory Permissions | Invoke-AtomicTest T1222 |
| GenericAll | T1484 Domain Policy Modification | Invoke-AtomicTest T1484.001 |

### 8.3 DCSync Detection

**Attack:** Use domain replication rights to pull password hashes from a Domain Controller without running code on the DC.

**Splunk detection query:**
```spl
index=windows EventCode=4662
  ObjectType="{19195a5b-6da0-11d0-afd3-00c04fd930c9}"
  AccessMask=0x100
  AccountName!=*$
| table _time, AccountName, Computer, ObjectName, AccessMask
| sort -_time
```

### 8.4 Golden Ticket Detection

**Attack:** Forge a Kerberos TGT using the KRBTGT hash, granting unlimited domain access.

**Detection signals:**
- Kerberos tickets with unusually long lifetimes (>10 hours default)
- TGT presented without corresponding AS-REQ (ticket sourced offline)
- Account SID mismatch between ticket and AD object

**KQL:**
```kql
SecurityEvent
| where EventID == 4769
| where TicketOptions == "0x40810010"
| where TargetUserName !endswith "$"
| where IPAddress !in (known_dc_ips)
| project TimeGenerated, TargetUserName, ServiceName, IPAddress, TicketEncryptionType
```

---
## 9. Cloud Purple Teaming

### 9.1 AWS Techniques and Detection

#### IAM Enumeration (T1087.004, T1069.003)

**Attack — enumerate IAM permissions:**
```bash
# Enumerate all IAM users
aws iam list-users --output json

# Enumerate all IAM roles
aws iam list-roles --output json

# Get full account authorization details (all policies, users, roles, groups)
aws iam get-account-authorization-details --output json > iam_dump.json
```

**Detection in CloudTrail:**
```json
{
  "eventSource": "iam.amazonaws.com",
  "eventName": "ListUsers",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "suspicious-user"
  }
}
```

**Splunk query for IAM enumeration burst:**
```spl
index=aws sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com
  eventName IN ("ListUsers","ListRoles","GetAccountAuthorizationDetails","ListPolicies")
| stats count by userIdentity.userName, sourceIPAddress
| where count > 10
| sort -count
```

#### EC2 Instance Metadata Service (IMDS) Credential Theft (T1552.005)

**Attack — steal instance credentials from IMDS:**
```bash
# IMDSv1 (no authentication required — vulnerable)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyInstanceRole

# With Stratus Red Team
stratus-red-team detonate aws.credential-access.ec2-steal-instance-credentials
```

**Detection:** VPC Flow Logs showing internal traffic to 169.254.169.254 from unexpected sources, CloudTrail events using credentials with `ec2-instance-connect` source.

**Mitigation:** Enforce IMDSv2 (requires session token, prevents SSRF-based theft):
```bash
aws ec2 modify-instance-metadata-options   --instance-id i-1234567890   --http-tokens required   --http-put-response-hop-limit 1
```

#### S3 Sensitive Data Access (T1530)

**Attack — access sensitive S3 buckets:**
```bash
# List bucket contents
aws s3 ls s3://corp-sensitive-bucket/ --recursive

# Download sensitive files
aws s3 cp s3://corp-sensitive-bucket/passwords.xlsx ./

# Stratus Red Team — backdoor bucket policy for exfiltration
stratus-red-team detonate aws.exfiltration.s3-backdoor-bucket-policy
```

**Detection — CloudTrail S3 data events (must be enabled):**
```json
{
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "requestParameters": {
    "bucketName": "corp-sensitive-bucket",
    "key": "passwords.xlsx"
  }
}
```

#### Lambda Abuse (T1648)

**Attack — create malicious Lambda for persistence or compute:**
```bash
aws lambda create-function   --function-name "LegitBackupFunction"   --runtime python3.9   --handler lambda_function.lambda_handler   --role arn:aws:iam::123456789:role/lambda-role   --zip-file fileb://malicious_payload.zip
```

**Detection:** CloudTrail `CreateFunction`, `UpdateFunctionCode` events from unusual principals or at unusual times.

### 9.2 Stratus Red Team — Cloud Detonation Workflow

**Standard workflow for any Stratus technique:**
```bash
# Step 1: List available techniques for your platform
stratus-red-team list --platform aws

# Step 2: Show technique details
stratus-red-team show aws.exfiltration.s3-backdoor-bucket-policy

# Step 3: Warm up (create prerequisites only, no attack yet)
stratus-red-team warmup aws.exfiltration.s3-backdoor-bucket-policy

# Step 4: Document current state (take CloudTrail baseline)
aws cloudtrail lookup-events --start-time $(date -u -d '2 minutes ago' +%Y-%m-%dT%H:%M:%SZ)

# Step 5: Detonate (execute the attack)
stratus-red-team detonate aws.exfiltration.s3-backdoor-bucket-policy

# Step 6: Wait for CloudTrail ingestion (up to 15 minutes)
sleep 300

# Step 7: Validate detection in SIEM
# Query Splunk/Sentinel for expected alert

# Step 8: Cleanup
stratus-red-team cleanup aws.exfiltration.s3-backdoor-bucket-policy
```

**ATT&CK Cloud matrix:** The ATT&CK framework includes a dedicated Cloud matrix covering IaaS, SaaS, Office 365, Azure AD, and Google Workspace. Navigate to https://attack.mitre.org/matrices/enterprise/cloud/ for the full matrix.

### 9.3 Azure Purple Teaming

#### Entra ID (Azure AD) Enumeration (T1087.004)

**Attack:**
```powershell
# Enumerate all users
Get-MgUser -All | Select-Object DisplayName, UserPrincipalName, Id

# Enumerate all groups
Get-MgGroup -All | Select-Object DisplayName, Id, GroupTypes

# Enumerate all service principals (application identities)
Get-MgServicePrincipal -All | Select-Object DisplayName, AppId, ServicePrincipalType
```

**Detection — Entra ID Audit Logs:**
```kql
AuditLogs
| where OperationName in ("List users", "List groups", "List service principals")
| where InitiatedBy.user.userPrincipalName !in (known_admin_upns)
| project TimeGenerated, OperationName, InitiatedBy, ResultDescription
```

#### App Consent Phishing (T1566 + T1528)

**Attack:** Trick user into granting OAuth permissions to malicious application.

**Detection — Permission grant audit log:**
```kql
AuditLogs
| where OperationName == "Consent to application"
| extend ConsentedPermissions = tostring(TargetResources[0].modifiedProperties)
| where ConsentedPermissions contains "Mail.Read" or ConsentedPermissions contains "Files.ReadWrite.All"
| project TimeGenerated, InitiatedBy, ConsentedPermissions
```

#### ARM Resource Enumeration (T1580)

**Detection — Azure Activity Log:**
```kql
AzureActivity
| where OperationName contains "list" or OperationName contains "read"
| where ActivityStatusValue == "Succeeded"
| summarize count() by Caller, OperationName
| where count_ > 100
| sort by count_ desc
```

### 9.4 Cloud Detection Validation Workflow

```
1. Select cloud technique (e.g., aws.credential-access.ec2-steal-instance-credentials)
2. Confirm CloudTrail / Entra audit logs are enabled and flowing to SIEM
3. Execute technique via Stratus Red Team or manual API calls
4. Wait for log ingestion SLA (AWS CloudTrail: up to 15 min; Entra: up to 30 min)
5. Query SIEM for expected alert
6. Document: Detected / Not Detected / Partial
7. If not detected → identify gap:
   - CloudTrail data events enabled? (S3, Lambda require explicit enablement)
   - Log source connected to SIEM?
   - Detection rule exists in SIEM?
8. Remediate → Retest → Update coverage layer
```

### 9.5 Cloud Detection Challenges

| Challenge | Description | Mitigation |
|---|---|---|
| **API calls vs. endpoint telemetry** | Cloud attacks appear as API calls in audit logs, not as process/file events. Detection logic is fundamentally different. | Build cloud-specific detection rules; don't rely on endpoint EDR for cloud technique detection |
| **IAM permission complexity** | Hundreds of IAM permissions make it hard to know which are sensitive and what "normal" looks like | Baseline IAM API call patterns; alert on unusual combinations |
| **Cross-account visibility** | Attacks traversing AWS Organizations accounts may generate events in different account CloudTrails | Centralize CloudTrail to organization-level S3 bucket + SIEM |
| **Serverless gaps** | Lambda, Azure Functions may generate minimal telemetry beyond basic CloudTrail/Activity Log events | Enable Lambda advanced logging; monitor CloudWatch Logs |
| **Log ingestion latency** | CloudTrail can have 5–15 minute delay; affects purple team SLA measurement | Account for latency in detection SLA expectations; don't fail tests at 5 minutes |

---
## 10. Purple Team Reporting & Maturity

### 10.1 Report Structure

**Executive Summary (1–2 pages):**
- Coverage % before and after the exercise
- Number of techniques tested
- Number of new detections created during exercise
- Key findings summary (top 3 detection gaps and their risk)
- Risk reduction narrative

**Methodology section:**
- Threat actor(s) emulated and justification
- Scope (asset classes, timeframe, tools used)
- ATT&CK matrix version used
- Scoring methodology (0–100 scale description)

**Findings by ATT&CK tactic (one section per tactic tested):**

| Field | Content |
|---|---|
| Technique | T1558.003 — Kerberoasting |
| Result | NOT DETECTED |
| Alert quality | N/A — no alert |
| Detection gap | Log source present (Event 4769), no detection rule |
| Remediation | Create Sigma rule for RC4 TGS requests; deploy to SIEM |
| Priority | High — used by APT28, APT29, Sandworm |
| Owner | Detection Engineering |
| Due date | 30 days |

**ATT&CK Navigator before/after heatmap:**
- Export "before" layer (pre-exercise scores)
- Export "after" layer (post-exercise scores with new detections)
- Include both in report appendix as SVG images
- Calculate and report the net coverage improvement

**Remediation roadmap:**
- Prioritized by: Risk severity × Ease of implementation
- Include: Responsible team, estimated effort, due date, validation method

### 10.2 Program Metrics

Track these metrics across every purple team exercise to demonstrate program value:

**Coverage metrics:**
```
ATT&CK Technique Coverage % =
  (Techniques with detection score ≥ 75) / (Total techniques tested) × 100

Target: Improve by ≥ 10 percentage points per quarter
```

**Detection quality score per technique:**
- Average score across all tested techniques (0–100 scale)
- Track trend quarter-over-quarter

**Mean Time to Detect (MTTD):**
```
MTTD = Average time from atomic test execution to SIEM alert generation
Measure per technique and per log source
Target: < 5 minutes for EDR-sourced detections
         < 15 minutes for SIEM rule-based detections
```

**False negative rate by log source:**
```
False Negative Rate (log source X) =
  (Techniques sourced from X that were NOT detected) /
  (Total techniques where X is the expected log source) × 100
```

**Remediation rate from prior exercises:**
```
Remediation Rate =
  (Open findings from prior exercise now remediated) /
  (Total findings from prior exercise) × 100

Target: > 80% remediation rate within 90 days
```

**Coverage improvement quarter-over-quarter:**
```
QoQ Coverage Improvement = Coverage Q(n) % - Coverage Q(n-1) %
Target: Positive trend; ≥ 5 percentage points per quarter
```

### 10.3 Purple Team Maturity Model

| Level | Name | Characteristics |
|---|---|---|
| **L1** | Ad-hoc | Occasional atomic tests run manually; results not tracked systematically; no ATT&CK mapping; no before/after comparison |
| **L2** | Structured | Regular campaigns with defined scope; results tracked in Vectr or equivalent; ATT&CK Navigator heatmaps; basic metrics (coverage %) |
| **L3** | Threat-Informed | CTI integration — campaigns driven by real threat actor TTPs; detection gap analysis tied to specific actors; remediation tracked to completion |
| **L4** | Automated | Continuous automated atomic execution (CI/CD pipeline); SIEM queried programmatically; coverage dashboard updated automatically; regression alerts |
| **L5** | Proactive | Threat modeling before actors adopt techniques (using CTI and ATT&CK research); integration with threat hunting; purple team findings drive SIEM architecture; executive KPI dashboard |

**Maturity self-assessment questions:**
- L1→L2: Are all test results tracked and mapped to ATT&CK technique IDs?
- L2→L3: Is the test plan driven by identified threat actors targeting your industry?
- L3→L4: Are tests running automatically on a schedule with programmatic detection validation?
- L4→L5: Are you testing techniques before they appear in active threat actor TTPs?

### 10.4 Continuous Program Building

**Monthly — Automated atomic validation:**
```
Schedule: 1st Monday of each month, 02:00 UTC
Scope: Full Atomic Red Team library for in-scope platforms
Method: CI/CD pipeline (see Section 7.6)
Output: Coverage dashboard update; regression alerts to Slack
```

**Quarterly — Structured campaign:**
```
Schedule: First 2 weeks of each quarter
Scope: Threat actor emulation plan (rotated quarterly)
Method: Manual purple team with red operator + detection engineer
Output: Vectr campaign results; Navigator before/after; executive report
Remediation: Findings enter Jira with 60-day SLA
```

**Annual — Full red team:**
```
Scope: Full kill chain, production environment, blind blue team
Output: Strategic report; informs next year's purple team priority list
Integration: Red team findings seed next year's purple team test backlog
```

**Integration with detection backlog:**
```
Purple Team finding (not detected)
  → Jira ticket created automatically via Vectr API integration
  → Assigned to Detection Engineering squad
  → SLA: Critical = 7 days, High = 30 days, Medium = 60 days
  → Verification: Re-run atomic test after fix, update Vectr outcome
  → SLA compliance reported to CISO monthly
```

### 10.5 Training Resources

**Formal courses:**
| Course | Provider | Level | Focus |
|---|---|---|---|
| SEC599: Defeating Advanced Adversaries | SANS Institute | Advanced | Purple team end-to-end |
| ATT&CK for Cyber Threat Intelligence | MITRE (free) | Intermediate | CTI + ATT&CK mapping |
| Purple Team Fundamentals | AttackIQ Academy (free) | Beginner | Purple team foundations |
| Certified Purple Team Analyst (CPTA) | Cyberwarfare Labs | Intermediate | Hands-on purple team |

**Hands-on labs and ranges:**
| Platform | URL | Focus |
|---|---|---|
| Blue Team Labs Online | blueteamlabs.online | Blue team / detection |
| PentesterLab | pentesterlab.com | Offensive techniques (context for purple team) |
| Range Force | rangeforce.com | Detection and IR exercises |
| MITRE ATT&CK Training | attack.mitre.org/resources/training | ATT&CK methodology |
| AttackIQ Academy | academy.attackiq.com | Free purple team + ATT&CK |

**Reference repositories:**
| Resource | URL | Use |
|---|---|---|
| Atomic Red Team | github.com/redcanaryco/atomic-red-team | Test execution |
| CALDERA | github.com/mitre/caldera | Automated emulation |
| Sigma Rules | github.com/SigmaHQ/sigma | Detection rule templates |
| MITRE ATT&CK Navigator | github.com/mitre-attack/attack-navigator | Coverage visualization |
| Adversary Emulation Library | github.com/center-for-threat-informed-defense/adversary_emulation_library | Emulation plans |
| BloodHound | github.com/BloodHoundAD/BloodHound | AD attack path mapping |
| Stratus Red Team | github.com/DataDog/stratus-red-team | Cloud emulation |
| VECTR | github.com/SecurityRiskAdvisors/VECTR | Purple team tracking |

---

*End of PURPLE_TEAM_REFERENCE.md — TeamStarWolf Security Engineering*
