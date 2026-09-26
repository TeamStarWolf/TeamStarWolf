# Run Your First Purple-Team Exercise

> **By the end of this guide you will have run a controlled, five-technique detection-validation exercise, scored each result as detected, logged-only, or missed, and turned every miss into a tracked detection backlog item.** This is for detection engineers, SOC analysts, and security leads who have a working SIEM and EDR and want to prove — not assume — what their controls actually catch.

## At a glance

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| Half a day to plan, 2-3 hours to run | Intermediate | A dedicated non-production test host, SIEM + EDR access, a blue-team partner, an approved test window | A scored results table, an ATT&CK Navigator before/after layer, and a ranked detection backlog |

This is a **detection-validation** exercise, not a red-team engagement. You pick techniques you *expect* to detect, run them transparently, and measure the gap between belief and reality. Both teams watch the same screen at the same time — that shared context is the whole point.

## Before you start

Confirm each of these before you schedule anything. If any box is unchecked, close that gap first — otherwise your results will measure infrastructure gaps, not detection logic.

- [ ] You meet the baseline maturity in the [Purple Team Reference — Prerequisite Maturity](/PURPLE_TEAM_REFERENCE.md): EDR at >90% endpoint coverage, SIEM with at least 30 days retention, a basic IR process, and Windows/Sysmon/auth log forwarding.
- [ ] You have a **dedicated test endpoint** that is not a production system, is enrolled in your EDR, and forwards logs to your SIEM the same way production does.
- [ ] At least one team member can map activity to ATT&CK techniques — see the [ATT&CK Technique Atlas](/ATTACK_TECHNIQUE_ATLAS.md).
- [ ] You can read the official [Atomic Red Team documentation](https://www.atomicredteam.io/) and the [Invoke-AtomicRedTeam execution wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki) — you will follow their current syntax, not this guide's from memory.
- [ ] You have written, signed rules of engagement covering test systems, notification chain, and abort criteria (template in the [Purple Team Reference — Program Design](/PURPLE_TEAM_REFERENCE.md)).

## Step 1 — Pick five techniques you believe you detect

Do not start with your weak spots. The exercise is a *validation* — you are testing the confidence gap on controls you already assume work. Choose five ATT&CK (sub-)techniques where you would bet money that an alert fires.

Good first candidates, because they are high-prevalence and each maps cleanly to one Atomic test set:

| Technique | Name | Expected primary signal |
|---|---|---|
| T1059.001 | PowerShell | Script Block Logging, Event ID 4104 |
| T1003.001 | LSASS Memory | Sysmon Event 10 (ProcessAccess to lsass.exe) |
| T1547.001 | Registry Run Keys / Startup Folder | Sysmon Event 13 (registry value set) |
| T1105 | Ingress Tool Transfer | EDR download telemetry / proxy logs |
| T1558.003 | Kerberoasting | Windows Security Event 4769, RC4 (0x17) |

One caveat on that table: **T1558.003 (Kerberoasting) only makes sense in a domain environment.** It assumes a domain-joined test host, an Active Directory domain with SPN-registered service accounts, and domain-controller Security logs (Event 4769) forwarded to your SIEM — none of which the "Before you start" checklist requires. If you do not have all three, swap it for another technique you would bet on. (`-CheckPrereqs` in Step 5 will also surface this, but it is cheaper to catch now.)

Write the five IDs into a simple table with one column left blank for the score. Ground your choices in the prevalence guidance in the [Purple Team Reference — Threat-Informed Defense](/PURPLE_TEAM_REFERENCE.md) and the actor mappings in [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md).

**Checkpoint:** You have exactly five technique IDs and, for each, the single alert or log source you expect to see.

**Watch out:** Testing techniques you *know* you miss teaches you nothing new and burns stakeholder goodwill. Save known gaps for a later round.

## Step 2 — Schedule the exercise with your stakeholders

Purple teaming is collaborative by definition — the blue team must be *present and informed*, unlike a red-team test. Book a single live block (2-3 hours) and confirm the roster from the [Purple Team Reference — Program Design](/PURPLE_TEAM_REFERENCE.md): a coordinator, whoever executes the tests, a detection engineer, and a SOC analyst watching the SIEM.

Send a calendar invite that states: the test window, the exact host name in scope, the five technique IDs, the abort contact, and a line confirming this is an authorized detection-validation exercise. Get an explicit written approval reply before the window opens.

**Checkpoint:** A confirmed time block, a named person in each role, and written approval on record.

**Watch out:** Never run tests outside the approved window or against a host not named in the invite. Scope creep is the fastest way to lose the program.

## Step 3 — Stand up the test host and install Atomic Red Team

On the dedicated Windows test host, open a PowerShell session — installation itself does not require elevation (only *running* some tests does; see Watch out below) — and install the execution framework **and** the atomics test library together with the official install script. These are the current commands from the [Invoke-AtomicRedTeam installation wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam) — verify them there before you run:

```powershell
# Framework + test definitions (atomics), installed to C:\AtomicRedTeam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

Use the script path above: every later step in this guide needs the atomics folder. The alternative PowerShell Gallery route (`Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser`) installs the **framework only** — per the wiki you would still have to download the atomics folder separately, and skipping that leaves every `Invoke-AtomicTest` call failing with a missing-atomics error.

The install script imports the module into your current session, so you can run tests immediately. In any **new** PowerShell session, import it by its manifest path first — the script installs under `C:\AtomicRedTeam`, not the default modules folder, so a plain `Import-Module invoke-atomicredteam` will not find it. Then preview one test set so you know what each test will do before it runs:

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```

**Checkpoint:** `Invoke-AtomicTest T1059.001 -ShowDetailsBrief` prints the list of tests for that technique with no module-not-found error.

**Watch out:** Install and run only on the isolated test host. Some atomics need elevation — an unelevated session prints `Elevation required but not provided` in red and the test will not do what you expect. Open an elevated session for those tests only.

## Step 4 — Write a detection hypothesis for each technique

Before a single test fires, write down what *should* happen. This is what makes the result objective rather than a debate afterward. Use the hypothesis format from the [Purple Team Reference — Detection Validation Methodology](/PURPLE_TEAM_REFERENCE.md): for each technique record the tool, the expected alert name, the detection logic, the SLA (for example, alert within 10 minutes), and the expected severity.

Pull the exact expected event IDs from the [SIEM Detection Content](/SIEM_DETECTION_CONTENT.md) and [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md) so the blue team knows the precise query to run when the test fires.

**Checkpoint:** Five written hypotheses, each naming the tool, the expected alert, the log source, and the SLA.

**Watch out:** A vague hypothesis ("something should alert") makes every result arguable. Name the field values you expect to see.

## Step 5 — Execute the atomic tests by ID in controlled scope

With the blue team watching, run one technique at a time. First check prerequisites, satisfy them, execute, then clean up. These are the documented commands from the [Check/Get Prerequisites](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Check-or-Get-Prerequisites-for-Atomic-Tests) and [Execute Atomic Tests](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Execute-Atomic-Tests-(Local)) wiki pages:

```powershell
# Confirm the test's dependencies are met
Invoke-AtomicTest T1059.001 -CheckPrereqs

# Attempt to satisfy any missing prerequisites
Invoke-AtomicTest T1059.001 -GetPrereqs

# Run a single, specific test by number
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Undo the test's changes when you are done scoring it
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

Run **one test number at a time**, note the wall-clock execution time, then pause so the SIEM can ingest before you score. Repeat for all five techniques. Keep everything at the level of naming and running published test IDs — this exercise validates detection, it is not a tradecraft workshop.

**Checkpoint:** All five techniques executed, each with its execution timestamp recorded, and each followed by a successful `-Cleanup`.

**Watch out:** Skipping `-Cleanup` leaves artifacts (registry keys, files, processes) that pollute the next test's baseline and can trip other controls. Clean up before moving on.

## Step 6 — Watch the SIEM live with the blue team and score each result

This is the collaboration that gives purple teaming its name. As each test fires, the SOC analyst runs the query from the matching hypothesis and everyone watches the result together. Wait the full ingestion SLA before declaring a miss — endpoint telemetry is usually fast, but SIEM rule evaluation can take minutes.

Score each technique into one of three buckets. The numbers come from the common scoring scale in section 1.4 (MITRE ATT&CK as Common Language) of the [Purple Team Reference](/PURPLE_TEAM_REFERENCE.md): 0 = no detection, 50 = telemetry only, 75 = alert fires but quality is poor, 100 = alert fires with correct context, severity, and analyst-ready enrichment.

| Bucket | Meaning | Navigator score |
|---|---|---|
| **Detected** | An alert fired | 100 if the alert is analyst-ready; 75 if it fired but quality is poor |
| **Logged-only** | Raw telemetry is present but no alert fired | 50 |
| **Missed** | No telemetry and no alert | 0 |

For a **Detected** result, decide between 100 and 75 using the quality dimensions from the reference's Alert Quality Assessment (section 5.3): correct context, ATT&CK tagging, appropriate severity, and analyst-ready enrichment. An alert that fires but is unusable is a 75, not a 100. One honest caveat: section 5.3's own quality-scoring table assigns different numbers to some of the same outcomes than section 1.4 does (for example, it puts poor-context alerts at 50). This guide follows the 1.4 scale — whichever scale your program adopts, write it down and use the same one every round so your before/after layers stay comparable.

**Checkpoint:** Every one of the five techniques has a bucket and, for detections, a quality note.

**Watch out:** Failing a test at 5 minutes when your SIEM's real ingestion latency is 15 minutes produces false misses. Score against the SLA you wrote in Step 4.

## Step 7 — Turn every miss into a detection backlog item

A miss or a logged-only result is the deliverable, not a failure. For each one, categorize the gap using the [Purple Team Reference — Detection Gap Categories](/PURPLE_TEAM_REFERENCE.md). For an endpoint exercise like this one you will almost always land in one of four: missing log source, log present but no rule, rule misconfigured, or an EDR telemetry gap. (The reference defines six categories in total — the other two are cloud- and volume-related.) The category determines the fix.

Create a tracked ticket per gap with: the technique ID, the gap category, the available data (for example, "Event 4769 present, no rule"), and a priority weighted by which active actors use the technique. Where the fix is a new rule, start from the templates in [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md) and the queries in [SIEM Detection Content](/SIEM_DETECTION_CONTENT.md), then re-run the same atomic test to verify before you close the ticket.

**Checkpoint:** One backlog ticket per non-detection, each with a gap category, an owner, and a due date.

**Watch out:** "Buy a better EDR" is not a backlog item. Every ticket must name a concrete, testable fix that a re-run of the same test ID can validate.

## Step 8 — Update the coverage layer and brief stakeholders

Capture the outcome so the next round can measure improvement. Build (or update) an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer: score the five techniques, export a "before" layer at the state you found, and an "after" layer once fixes land. Save both as JSON in version control.

Write a short readout using the report structure in the [Purple Team Reference — Reporting & Maturity](/PURPLE_TEAM_REFERENCE.md): coverage before/after, techniques tested, new detections created, and the top gaps with their risk. Track the program metrics in [Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md) so quarter-over-quarter improvement is visible.

**Checkpoint:** A saved before/after Navigator layer and a one-page readout delivered to the stakeholders from Step 2.

**Watch out:** Results that live only in someone's head or a chat thread cannot show a trend. If it is not in the layer and the metric sheet, it did not happen.

## What good looks like

- All five techniques were executed in the approved window, on the approved host, and cleaned up afterward.
- Every technique has an objective score tied to a written hypothesis — no "I think it alerted" judgments.
- Each miss and logged-only result became a backlog ticket with a gap category, an owner, and a concrete, re-testable fix.
- You can show a before/after Navigator layer that quantifies the coverage change, and the metrics feed a quarter-over-quarter trend.
- The blue team learned something they did not know before they walked in — that is the real return on the exercise.

## Go deeper

- [Purple Team Reference](/PURPLE_TEAM_REFERENCE.md) — the doctrinal base for this guide: methodology, scoring, gap categories, and maturity model.
- [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md) — prioritize which techniques to validate by real adversary behavior.
- [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md) — Sigma and rule templates for turning misses into detections.
- [SIEM Detection Content](/SIEM_DETECTION_CONTENT.md) — ready-to-adapt SIEM queries and expected event IDs per technique.
- [ATT&CK Technique Atlas](/ATTACK_TECHNIQUE_ATLAS.md) — technique-by-technique reference for mapping and hypothesis writing.
- [Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md) — coverage, MTTD, and remediation-rate metrics to track the program over time.
- [Atomic Red Team documentation](https://www.atomicredteam.io/) — the official test library and per-technique test documentation.
- [Invoke-AtomicRedTeam execution wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki) — current, authoritative command syntax for running and cleaning up tests.
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — build the before/after coverage layers.
- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/) — the source of truth for technique IDs and detections.

*Guides are procedures, not gospel. Verify every command and flag against the current official documentation before running it in any production-adjacent environment.*
