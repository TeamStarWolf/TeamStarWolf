# Hunt for Living-off-the-Land Activity

> **By the end of this guide you will have baselined three dual-use system binaries in your own environment, hunted the outliers, and converted the validated logic into deployed detections.** It is written for a SOC analyst or detection engineer running their first hypothesis-driven LOTL hunt: you know your SIEM's query bar, and you want a repeatable procedure rather than theory.

## At a glance

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| 3–5 hours of hands-on work, split around a 30-day baseline window | Intermediate | SIEM or Defender XDR query access, change approval for audit policy, an isolated lab host | Per-binary usage baselines, rare-parent/rare-user hunt queries, triaged outliers, deployed Sigma detections, a written hunt report |

## Before you start

Every step below assumes this checklist is done.

- [ ] Read the [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md) — it is the doctrinal base this hunt operationalizes: the community catalogs, the telemetry foundation, and the five detection patterns (you will use Pattern 1, rare-process/rare-user baselining, and Pattern 2, parent-child anomalies).
- [ ] Skim the hunting loop and the hunt hypothesis documentation template in the [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md) — you will fill that template in as you go.
- [ ] Confirm query access to process-creation telemetry: your SIEM's process events, or [Microsoft Defender XDR advanced hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview) (the examples below use its `DeviceProcessEvents` table).
- [ ] Get change-management approval to enable audit policy on a pilot group of hosts — see [Microsoft's command-line process auditing doc](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing) for what you will be turning on.
- [ ] Have Sysmon deployed or deployable per the [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- [ ] Stand up an isolated lab host for validation — see [Homelab Setup](/HOMELAB_SETUP.md).
- [ ] Install Python 3 so you can use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) in Step 7.

## Step 1 — Pick three binaries and write the hypothesis

Pull the LOLBAS catalog's machine-readable feed — `https://lolbas-project.github.io/api/lolbas.json` (CSV at `/api/lolbas.csv`) — and cross it against your software and telemetry: which cataloged binaries actually execute in your estate? Pick three that are present, matter to your host population, and have a plausible dual use. A common first trio, verified against the live catalog:

| Binary | Expected path (per LOLBAS) | ATT&CK anchors |
|---|---|---|
| `certutil.exe` | `C:\Windows\System32\certutil.exe` | [T1105](https://attack.mitre.org/techniques/T1105/), [T1140](https://attack.mitre.org/techniques/T1140/) per its [LOLBAS entry](https://lolbas-project.github.io/lolbas/Binaries/Certutil/) |
| `regsvr32.exe` | `C:\Windows\System32\regsvr32.exe` | [T1218.010](https://attack.mitre.org/techniques/T1218/010/) per its [LOLBAS entry](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/) |
| `wmic.exe` | `C:\Windows\System32\wbem\wmic.exe` | [T1047](https://attack.mitre.org/techniques/T1047/) (WMI); its [LOLBAS entry](https://lolbas-project.github.io/lolbas/Binaries/Wmic/) adds T1218 and T1105 |

Then write the hypothesis down, one sentence per binary, in the hunt template's format. Example: *"If an adversary is using certutil.exe for ingress tool transfer (T1105), we will see certutil executions from parent processes or user accounts outside the baseline we establish in Step 3."* Give the hunt an ID, a date range, and a host scope.

**Checkpoint:** A one-page hunt charter exists: three named binaries, their technique IDs, a falsifiable hypothesis each, scope, and dates.

**Watch out:** Do not pick a binary your telemetry cannot see. If a binary lives only on servers that ship no process events, fix the telemetry first (Step 2) or pick another binary — a hunt over missing data proves nothing.

## Step 2 — Confirm the telemetry records what you need

Rare-parent and rare-user queries need process creation **with command line and parent process**. Verify each layer on your pilot hosts; the paths below are verified against Microsoft's current documentation.

1. **Event 4688 with command line.** In Group Policy, enable *Audit Process Creation* under **Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking**. Then enable **Include command line in process creation events** under **Computer Configuration > Administrative Templates > System > Audit Process Creation**. Both are off by default ([Microsoft doc](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)).
2. **Sysmon Event ID 1.** Install Sysmon with a reviewed configuration file: `sysmon64 -accepteula -i sysmonconfig.xml` (update later with `sysmon64 -c sysmonconfig.xml`). Events land in **Applications and Services Logs/Microsoft/Windows/Sysmon/Operational** ([Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)). Event ID 1 gives you command line for process **and parent**, the PE-header original file name, and a ProcessGUID that survives PID reuse.
3. **PowerShell script block logging (4104).** Enable **Turn on PowerShell Script Block Logging** under **Administrative Templates > Windows Components > Windows PowerShell**; events go to `Microsoft-Windows-PowerShell/Operational` ([about_Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)). You want this for triage even though the hunt keys on process events.
4. **Prove it end to end.** On a pilot host, run a harmless help invocation of one of your binaries — `certutil -?` only prints the parameter list ([certutil doc](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)) — then find that execution in your SIEM with the full command line and the parent process populated.

**Checkpoint:** Your test execution is visible in the SIEM within minutes, carrying command line, parent process, user, and host.

**Watch out:** Basic audit policy can silently override the advanced audit settings — Windows logs event 4719 when that happens. Set **Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings** to Enabled, per the same Microsoft doc. Also remember the doc's warning: command lines can contain passwords and other secrets, so restrict who can read the security log and the SIEM index it feeds.

## Step 3 — Baseline normal usage

Let the pilot telemetry accumulate (30 days covers most monthly admin cycles), then answer, per binary: **who runs it, on which host roles, from which parents, how often?** In Defender XDR advanced hunting:

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("certutil.exe", "regsvr32.exe", "wmic.exe")
| summarize Executions = count(),
    Users = make_set(AccountName, 50),
    Parents = make_set(InitiatingProcessFileName, 50),
    Hosts = dcount(DeviceName)
    by FileName
```

(Column names verified against the [DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table); Splunk users will find equivalent SPL aggregation patterns, including rare parent-child analysis, in the [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md).)

Run the same aggregation again split by host role (workstation, server, domain controller, build agent) — a build server's normal is a receptionist workstation's incident. Then sit down with the IT and platform teams and get every recurring pairing explained: which product, which script, which scheduled job. The [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md) is blunt about why — baselines built by security guessing from logs alone are wrong.

Record the result as a small table per binary: sanctioned parents, sanctioned users or account patterns, expected host roles, expected frequency, and who signed off.

**Checkpoint:** Three baseline tables exist, each entry explained and attributed to an owner in IT or security.

**Watch out:** Do not build one enterprise-wide baseline. Averaging across roles hides exactly the deviations you are hunting for — scope every baseline per host role and user population.

## Step 4 — Build rare-parent and rare-user queries

Now invert each baseline: everything the baseline does not explain is your review set. Key the queries on **relationships** — parent, user, host role — not on command-line strings; the joint guidance documents actors varying syntax specifically to break string matching.

**Rare parent** (Pattern 2 in the [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md) — enumerate legitimate spawn relationships, alert outside them):

```kusto
let baseline_parents = dynamic(["explorer.exe", "cmd.exe"]);  // replace with YOUR Step 3 set
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "certutil.exe"
| where InitiatingProcessFileName !in~ (baseline_parents)
| project Timestamp, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine
```

Give Office-application parents their own high-severity variant: the joint guidance calls a productivity app spawning a script interpreter or shell "a red flag, as it is uncommon."

**Rare user** (Pattern 1 — a binary used outside its established user population):

```kusto
let baseline_users = dynamic(["svc_pki", "adm-jdoe"]);  // replace with YOUR Step 3 set
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("certutil.exe", "regsvr32.exe", "wmic.exe")
| where AccountName !in~ (baseline_users)
| summarize Hits = count(), CommandLines = make_set(ProcessCommandLine, 20)
    by AccountName, FileName, DeviceName
```

**Renamed binary** (the guidance's masquerading check — on-disk name disagrees with the PE-header original file name):

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessVersionInfoOriginalFileName in~ ("certutil.exe", "regsvr32.exe", "wmic.exe")
| where FileName !~ ProcessVersionInfoOriginalFileName
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
```

Also compare `FolderPath` against the expected paths from the LOLBAS entries in Step 1 — a catalog binary running from a user-writable directory is its own outlier.

**Checkpoint:** Each binary has at least a rare-parent and a rare-user query that, run over the baseline window, returns only rows the baseline does not explain — a reviewable count, not thousands.

**Watch out:** If a query returns pages of results, the baseline is incomplete — go back to Step 3 and get those pairings explained. Do not "fix" it by pinning the query to exact command-line strings; that is the brittleness these patterns exist to avoid.

## Step 5 — Review the outliers

Work every row to a disposition, using the hypothesis template's findings section from the [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md):

- **Benign, explained** — a legitimate use the baseline missed. Add it to the baseline table with a justification and an owner.
- **Benign, unexplained** — nobody can say why it runs. That is a hygiene finding (shadow tooling, a stale scheduled task, an over-broad admin habit); route it to IT with a ticket.
- **Suspicious** — no legitimate explanation and the context is wrong (odd hours, odd host, odd account). Escalate through your incident process — see [IR Playbooks](/IR_PLAYBOOKS.md) — and preserve the evidence before touching the host.

Corroborate before you conclude. Pivot each suspicious hit to the surrounding session: the logon event, what the account did before and after, PowerShell 4104 content, and network events for the same process. The [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md) warns that actors manipulate process ancestry, so never let a parent-child pair carry the whole verdict alone.

**Checkpoint:** Zero undispositioned outliers; suspicious items escalated; hunt log updated with queries run, counts, and findings.

**Watch out:** Baseline rot. Every "benign, explained" addition needs a named owner and a review date, or your baseline quietly becomes the blanket allowlist the joint guidance warns about.

## Step 6 — Validate the logic in a lab

Before trusting the queries, prove they fire. Atomic Red Team publishes small, technique-mapped tests — for this hunt the relevant technique IDs are T1105 (certutil), T1218.010 (regsvr32), and T1047 (wmic). Using the [Invoke-AtomicRedTeam documentation](https://github.com/redcanaryco/invoke-atomicredteam/wiki), list what is available with `Invoke-AtomicTest T1218.010 -ShowDetailsBrief` and check dependencies with `-CheckPrereqs`; follow the project's own execution and cleanup instructions for the tests you select.

Run tests **only on the isolated lab host from your checklist, with written authorization** — this is detection validation, not an exercise in tradecraft, so stay at the level of the tool's documented workflow. After each test, run your Step 4 queries against the lab telemetry and confirm the execution appears with parent, user, and command line intact.

**Checkpoint:** Every query catches its corresponding lab test, and you can walk the full event chain (process creation, parent, script content where applicable) end to end.

**Watch out:** Never run atomics on production systems or without sign-off. If a query misses the lab test, treat it as a telemetry bug first — check Sysmon filtering rules and event forwarding before rewriting the logic.

## Step 7 — Convert validated logic into detections

Freeze each validated query as a Sigma rule so it outlives your SIEM choice — authoring conventions and worked examples are in the [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md). A minimal shape:

```yaml
title: Certutil Executed by Non-Baseline Parent
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
  filter_baseline_parents:
    ParentImage|endswith:
      - '\explorer.exe'   # replace with your Step 3 baseline set
  condition: selection and not filter_baseline_parents
tags:
  - attack.t1105
falsepositives:
  - Certificate administration by PKI staff
level: medium
```

Convert it for your platform with sigma-cli ([official repo](https://github.com/SigmaHQ/sigma-cli)):

```bash
python -m pip install sigma-cli
sigma plugin install splunk
sigma convert -t splunk -p sysmon rule.yml
```

Deploy, keep `status: experimental` until the rule survives production traffic, tag it with the ATT&CK technique ID, and track its precision. Close the loop the way the [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md) prescribes: each of your three binaries now has a recorded usage decision plus a mapped detection, which is one increment of the "catalog detection coverage" metric — and each hunt finding that becomes a rule is the hunt-to-detection feedback loop working.

**Checkpoint:** Three or more rules deployed, ATT&CK-tagged, alerting into your triage queue, with precision tracked per rule.

**Watch out:** Broad `CommandLine|contains` matches drown the SOC — prefer image-plus-relationship logic and negated filter blocks, per the best practices in the [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md). And schedule a re-pull of the LOLBAS feed: catalog entries drift, and a fossilized lookup table is a silent coverage gap.

## What good looks like

- Each of the three binaries has a per-role baseline table with named owners, not a single enterprise-wide average.
- Rare-parent and rare-user queries return a handful of reviewable rows per week, and every row gets a disposition.
- Each deployed rule fired on its lab validation test before it ever fired in production.
- The hunt report answers the hypothesis explicitly — confirmed, refuted, or blocked by a telemetry gap — and telemetry gaps became tickets.
- At least one finding left the hunt as something durable: a new detection, a baseline entry with an owner, or a hardening ticket.
- Rerunning the whole procedure on three new catalog binaries would take you half the time — the process, not the queries, is the deliverable.

## Go deeper

**In this library:**

- [LOTL Detection Reference](/LOTL_DETECTION_REFERENCE.md) — the full program: catalogs, telemetry, all five detection patterns, hardening, metrics
- [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md) — hunting loop, maturity model, KQL/SPL pattern library, hypothesis template
- [Threat Hunting Playbooks](/THREAT_HUNTING_PLAYBOOKS.md) — ready-made hunts to run after this one
- [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md) — Sigma authoring, conversion tooling, validation workflow
- [SIEM Detection Content](/SIEM_DETECTION_CONTENT.md) — deploying and managing the rules you just wrote
- [Detection Strategies by Tactic](/detections/strategies/README.md) — per-tactic strategy pages to extend coverage beyond these three binaries

**External:**

- [Joint Guidance: Identifying and Mitigating Living Off the Land Techniques](https://www.cisa.gov/resources-tools/resources/identifying-and-mitigating-living-land-techniques) — the canonical cross-agency playbook this hunt implements
- [LOLBAS Project](https://lolbas-project.github.io/) — the Windows catalog and its JSON/CSV API
- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — event reference and configuration schema
- [Invoke-AtomicRedTeam wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki) — official usage documentation for the validation step

---

*Guides are procedures, not references: commands, menu paths, and tool syntax change — verify them against the current official documentation before production use.*
