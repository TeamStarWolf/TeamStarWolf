# Build and Deploy Your First Detection

> **By the end of this guide you will have written a real Sigma rule for a high-prevalence ATT&CK technique, converted it to Splunk SPL and Microsoft KQL with sigma-cli, run it in audit mode against your own environment, and tuned it into a production detection with a documented noise baseline.** This is for SOC analysts and aspiring detection engineers who have access to a SIEM and at least one Windows endpoint they administer, and who want to ship their first rule the way a detection engineering team would — not just paste a query from the internet.

## At a glance

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| Half a day hands-on, plus a 1-2 week audit soak | Beginner-to-intermediate | A Windows endpoint you administer, Splunk or Microsoft Sentinel, Python 3.10+, local admin rights | A tuned, ATT&CK-tagged Sigma rule deployed as SPL and KQL, with a written false-positive baseline |

The workflow you practice here — pick, research, write, convert, audit, baseline, tune, promote — is the same lifecycle you will reuse for every detection after this one. Only the technique changes.

## Before you start

- [ ] You know what Sigma is and roughly how a rule is shaped — skim the Sigma section of the [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md), the doctrinal base for this guide.
- [ ] You know which log sources your SIEM already ingests from your Windows endpoints. If none, run [Onboard a Log Source](/guides/ONBOARD_A_LOG_SOURCE.md) first — a detection without telemetry is a text file.
- [ ] You have admin rights on one **non-production** Windows test endpoint that forwards logs to your SIEM. No lab yet? [Build a Detection Homelab](/guides/BUILD_A_DETECTION_HOMELAB.md).
- [ ] Python 3.10 or later is installed for [sigma-cli](https://github.com/SigmaHQ/sigma-cli), plus permission to create saved searches (Splunk) or analytics rules (Sentinel — requires the Microsoft Sentinel Contributor role per [Microsoft's rule-creation docs](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules)).
- [ ] You can open the official [Sigma rule documentation](https://sigmahq.io/docs/basics/rules.html) — you will follow its current field spec, not memory.

## Step 1 — Pick a technique with cheap telemetry

Your first detection should ride on telemetry that is nearly free: low-volume events your endpoints can already produce without new agents, new licenses, or a flood of noise. Windows process-creation events and task-registration audit events are the classic examples; kernel ETW tracing or full network capture are the opposite.

This guide uses **T1053.005 — Scheduled Task**: adversaries register a Windows scheduled task to persist or execute payloads. It is ideal for a first rule because the signal is two cheap events — Security Event **4698** (a scheduled task was created) and a process-creation event for `schtasks.exe` — and because legitimate task creation is rare enough on workstations to baseline in days, not months.

Choosing your own technique instead? Shop the [Detection Strategies index](/detections/strategies/README.md) with the [Data Components & Log Sources reference](/ATTACK_DATA_COMPONENTS.md) open beside it, and prefer techniques whose analytics need only `WinEventLog:Security` or Sysmon Event 1.

**Checkpoint:** You have one technique ID written down, plus the one or two event types that will carry the detection.

**Watch out:** Do not start with a technique whose strategy page lists five correlated log sources across process, registry, and network. Multi-event chains are real detections — they are just a terrible first rule.

## Step 2 — Read the detection strategy page for the technique

Before writing a line of YAML, read what MITRE says the behavior actually looks like. Open the strategy for [T1053.005 in the Execution strategies page](/detections/strategies/execution.md#t1053005) — strategy `DET0441`, analytic `AN1221`. Pull out three things:

1. **Log sources:** `WinEventLog:Security` 4698/4702 and Sysmon EventCode 1 (plus 11, 13, 14 for the file/registry side you can add later).
2. **The behavior chain:** task creation via `schtasks.exe`, PowerShell, WMI, or API, followed by execution under `svchost.exe`/`taskeng.exe` — your first rule covers the creation half.
3. **The tunable elements:** `UserContext`, `TaskNamePattern`, `TimeWindow`, and command-line entropy. These are exactly the knobs you will turn in Step 7, so copy them into your notes now.

Then look at the [Technique Detection Library entry for T1053.005](/detections/TECHNIQUE_DETECTION_LIBRARY.md#t1053005) to see how the same logic looks as ready-made SPL, KQL, and other dialects — that is where your converted rule should land, logically.

**Checkpoint:** A short note listing the technique's log sources, the behavior your rule will match, and the strategy's tunable parameters.

**Watch out:** The strategy page describes *ideal* telemetry. Your rule can only match fields your SIEM actually receives — which is what Step 3 proves.

## Step 3 — Turn on the telemetry and prove it flows

On the test endpoint, enable task-creation auditing. Event 4698 is generated by the **Audit Other Object Access Events** subcategory ([Microsoft's 4698 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698)). From an elevated prompt, per the [auditpol set reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set):

```cmd
auditpol /set /subcategory:"Other Object Access Events" /success:enable
auditpol /get /subcategory:"Other Object Access Events"
```

If you use Sysmon for process creation (recommended — Event ID 1 captures the full command line and parent), install it with a config file per the [official Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon):

```cmd
sysmon64 -accepteula -i sysmonconfig.xml
```

Now generate one **benign** signal. Create a harmless task with the documented [schtasks create syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create), then remove it:

```cmd
schtasks /create /tn "TSW-DetectionTest" /tr "C:\Windows\System32\notepad.exe" /sc once /st 23:55
schtasks /delete /tn "TSW-DetectionTest" /f
```

In Event Viewer, confirm 4698 in the **Security** log (note the `TaskName` and `TaskContent` XML fields) and Sysmon Event 1 under **Applications and Services Logs > Microsoft > Windows > Sysmon > Operational**. Then run the equivalent search in your SIEM and confirm both events arrived with the command line intact.

**Checkpoint:** Your benign task appears in your SIEM as a 4698 event and a `schtasks.exe` process-creation event, with `CommandLine` populated.

**Watch out:** If `CommandLine` is empty in 4688 events, native command-line auditing is off — that is a Group Policy setting, and without it half of all Sigma process rules match nothing. Fix ingestion gaps now using [Onboard a Log Source](/guides/ONBOARD_A_LOG_SOURCE.md); tuning cannot repair missing fields.

## Step 4 — Write the Sigma rule

Write the rule in a plain text file, `t1053_005_schtasks_staging_path.yml`, following the current [SigmaHQ rule spec](https://sigmahq.io/docs/basics/rules.html): dates are ISO 8601 (`YYYY-MM-DD`), the `id` is a random UUIDv4 (generate one with PowerShell's `New-Guid`), and new rules start as `status: experimental`. This rule narrows "a task was created" to "a task was created whose action runs out of a user-writable staging path" — the same pattern as Rule 3 in the [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md):

```yaml
title: Scheduled Task Created With Action in User-Writable Staging Path
id: 00000000-0000-4000-8000-000000000000   # replace with your own New-Guid output
status: experimental
description: |
  Detects schtasks.exe registering a task whose /tr action points into Temp,
  Public, or ProgramData - directories any user can write to, and a common
  staging location for persistence payloads (T1053.005).
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: Your Name
date: 2026-09-25
tags:
  - attack.execution
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\schtasks.exe'
  selection_create:
    CommandLine|contains|all:
      - '/create'
      - '/tr'
  selection_stagingpath:
    CommandLine|contains:
      - '\AppData\Local\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
      - '%TEMP%'
      - '%TMP%'
  condition: selection_img and selection_create and selection_stagingpath
falsepositives:
  - Software installers registering update tasks from Temp
  - Endpoint management and deployment agents
level: medium
```

Read the `detection` block out loud: the image must be `schtasks.exe`, **and** the command line must contain both `/create` and `/tr`, **and** it must reference at least one staging path. Inside a selection, a dictionary means AND and a list means OR — that asymmetry is the heart of Sigma.

**Checkpoint:** A saved `.yml` file with your own UUID, today's date, ATT&CK tags, and a condition you can explain in one sentence.

**Watch out:** Broad single-selection rules (`CommandLine|contains: 'schtasks'`) are how alert fatigue starts. Every rule needs a behavior anchor (the image + flags) plus a suspicion anchor (the staging path) — one without the other is either noise or nothing.

## Step 5 — Validate the rule and convert it with sigma-cli

Install [sigma-cli](https://github.com/SigmaHQ/sigma-cli) and the backends for your SIEMs (commands per its official README):

```bash
python -m pip install sigma-cli
sigma plugin install splunk
sigma plugin install sysmon
sigma plugin install kusto
```

Check the rule parses and passes the built-in validators, then convert it:

```bash
sigma check t1053_005_schtasks_staging_path.yml

# Splunk SPL, with the Sysmon field/event mapping pipeline
sigma convert -t splunk -p sysmon t1053_005_schtasks_staging_path.yml

# Microsoft KQL (Defender XDR advanced-hunting tables, e.g. DeviceProcessEvents),
# per the pySigma-backend-kusto README
sigma convert -t kusto -p microsoft_xdr t1053_005_schtasks_staging_path.yml
```

The `microsoft_xdr` pipeline emits KQL against the advanced-hunting tables that Microsoft Sentinel also receives through the Defender XDR connector; the backend's `sentinel_asim` pipeline (Sentinel ASIM tables) exists but is flagged beta in the [backend's documentation](https://github.com/AttackIQ/pySigma-backend-kusto). Run `sigma list pipelines` and `sigma list formats splunk` to see every identifier your install supports, and add `-o <file>` to write the query to disk.

**Checkpoint:** Two clean conversions — an SPL query and a KQL query — each visibly containing your image, flag, and path logic.

**Watch out:** Converting without a pipeline produces queries with generic Sigma field names that may match nothing in your index. The pipeline (`-p sysmon`, `-p microsoft_xdr`) is what maps fields to your real schema — if results look wrong later, the pipeline choice is the first suspect.

## Step 6 — Deploy in audit mode

Deploy the rule so it *records* matches without paging anyone. Detection engineering teams call this an audit or silent deployment; it protects the on-call from your untuned rule.

**Splunk** (per [Create scheduled alerts](https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.2/create-alerts/create-scheduled-alerts)): paste the converted SPL into Search, confirm it runs, then **Save As > Alert**. Set the alert type to scheduled (hourly is fine, or select **Run on Cron Schedule**), the trigger condition to number of results greater than 0, and choose only the alert action that lists matches on the Triggered Alerts page — no email, no ticket, no webhook yet.

**Microsoft Sentinel** (per [Create scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules)): go to **Microsoft Sentinel > Configuration > Analytics**, select **+Create > Scheduled query rule**. Paste the KQL as the rule query, set **Severity** to Informational, tag the MITRE technique (T1053.005), set **Run query every** 1 hour with **Lookup data from the last** 1 hour, and use **Test with current data** in Results simulation before saving. In **Incident settings**, set incident creation to Disabled for the audit period — unless your workspace is onboarded to the Defender portal, where Microsoft says to leave it enabled; there, keep severity Informational and triage from the Incidents queue instead.

Finally, re-run the benign `schtasks /create` from Step 3, but point `/tr` at an executable path under `C:\Users\Public\` so it crosses your rule's staging-path condition — then delete the task.

**Checkpoint:** The rule is live, and your benign staging-path task appears as a recorded match (Triggered Alerts in Splunk, an alert in Sentinel) within one schedule interval.

**Watch out:** A rule that never fires in audit is not "clean" until you have proven it *can* fire. No match on your test task means a broken field mapping or an ingestion gap — go back to Step 5 before trusting two silent weeks.

## Step 7 — Baseline the noise

First, look backward: run the converted query manually over your last 14-30 days of data, per the "test against known-good" practice in the [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md). Then let the audit deployment soak for one to two weeks. Triage every match into three buckets:

| Bucket | Example | Action |
|---|---|---|
| True positive | Red-team or your own test activity | Count it — the rule works |
| Expected-benign | A software updater registering its task from Temp | Candidate for a filter in Step 8 |
| Unexplained | A task creation nobody recognizes | Investigate before you filter it away |

For each expected-benign source, record the *stable* identifying field — the exact task name, target path, or creating account — using the strategy's tunables from Step 2 (`UserContext`, `TaskNamePattern`) as your checklist. The 4698 event's `TaskContent` XML is gold here: it names the author, the action, and the logon type.

**Checkpoint:** A short written baseline: total matches, the three-bucket split, and the specific field values that identify each recurring benign source.

**Watch out:** Never filter on a value an attacker controls freely and defenders cannot verify, like a task *description*. Filter on the narrowest stable combination you can — a full target path plus the creating account beats either alone.

## Step 8 — Tune, re-test, and promote

Fold the baseline back into the Sigma rule — not into the SIEM query directly, or your YAML and your deployed logic drift apart. Add a negated filter block for each verified-benign source, following the filter-block practice in the [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md):

```yaml
  filter_known_installer:
    CommandLine|contains: '\ProgramData\ExampleVendor\updater.exe'
  condition: selection_img and selection_create and selection_stagingpath and not filter_known_installer
```

Document each exclusion in `falsepositives`, add a `modified: <today's date>` field, re-run `sigma check` and both `sigma convert` commands, and redeploy. Then validate the tuned rule still catches the bad pattern: re-run your benign staging-path task, and when you are ready for adversary-shaped input, run the published Atomic Red Team tests for this technique — Test #1 *Scheduled Task Startup Script* and Test #2 *Scheduled task Local* from the [T1053.005 atomics](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1053.005) — on the test endpoint only, following the current [official Atomic Red Team documentation](https://www.atomicredteam.io/) for execution and cleanup, exactly as practiced in [Run a Purple-Team Exercise](/guides/RUN_A_PURPLE_TEAM_EXERCISE.md).

When a full week runs clean — every alert actionable, every test caught — promote: set `status: stable`, review `level`, switch Splunk actions to real notifications or enable Sentinel incident creation, and commit the YAML to version control. Compare your finished rule with the community's take in [SigmaHQ's process_creation rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation) (see `proc_creation_win_schtasks_creation_temp_folder.yml`) — convergent logic is a good sign.

**Checkpoint:** A version-controlled, `stable` Sigma rule; matching deployed SPL and KQL; and a validation note showing the atomic tests fired it after tuning.

**Watch out:** Promotion is per-environment. A rule that is quiet on workstations can be a siren on RDS servers where installers run constantly — re-baseline (Step 7, shortened) whenever the rule reaches a new population of hosts.

## What good looks like

- The rule detects a *behavior* (task registration from user-writable staging paths), not a tool name or a hash, and carries the correct ATT&CK tags.
- One YAML file is the single source of truth; the SPL and KQL in production were generated from it, and every tuning change went through the YAML first.
- You can hand a teammate the written baseline and they can predict what the rule will and will not fire on.
- The benign test task and the named atomic tests all produced alerts after tuning — proof the filters removed noise without removing the detection.
- You wrote it expecting to reuse the lifecycle: the next technique on your list already has its strategy page bookmarked.

## Go deeper

- [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md) — the doctrinal base: Sigma structure, modifiers, conversion workflows, and detection engineering best practices.
- [Detection Strategies index](/detections/strategies/README.md) — MITRE's per-technique detection strategies and analytics; your shopping list for rule number two.
- [Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md) — ready-to-run queries per technique across five SIEM dialects, with validation pointers.
- [Data Components & Log Sources](/ATTACK_DATA_COMPONENTS.md) — which telemetry feeds which technique, for judging what "cheap" means in your environment.
- [SIEM Detection Content](/SIEM_DETECTION_CONTENT.md) — broader query content to adapt once the lifecycle feels routine.
- [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md) — prioritizing which techniques deserve detections, by real adversary prevalence.
- [SigmaHQ rule documentation](https://sigmahq.io/docs/basics/rules.html) — the authoritative, current Sigma specification.
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli) — official conversion tooling; the README is the source of truth for commands used here.
- [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma) — thousands of community rules to study, compare against, and adapt.
- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/) — the technique's official page, including its detection and mitigation notes.

*Guides are procedures, not gospel. Verify every command, flag, and menu path against the current official documentation before using it in production.*
