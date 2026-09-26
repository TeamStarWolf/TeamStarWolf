# Onboard a Log Source the Right Way

> **By the end of this guide you will have one new log source flowing into your SIEM or data lake — justified by a named ATT&CK data component, normalized to your schema, quality-gated, health-monitored, registered in your source inventory, and proven by a detection that actually fired.** This is for the SOC engineer, detection engineer, or sysadmin who has been handed "get the logs in" and wants to do it once, correctly, instead of three times badly.

## At a glance

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| 4–8 hours hands-on, plus a shadow-run of at least one business cycle | Intermediate | Admin access to the source and your pipeline/SIEM, a version-controlled config repo, one authorized test host | An onboarded source with a mapping doc, quality gates, health alerts, an inventory row, and one end-to-end validated detection |

Most pipeline debt is created on day one of a source, in a hurry. The order below front-loads the decisions that are expensive to change later — it operationalizes the onboarding runbook in the [Security Data Engineering Reference](/SECURITY_DATA_ENGINEERING_REFERENCE.md), which you should skim before starting.

## Before you start

- [ ] Skim the [Security Data Engineering Reference](/SECURITY_DATA_ENGINEERING_REFERENCE.md) — the doctrine this guide executes, especially the onboarding runbook and the silent-failure catalog.
- [ ] Open [ATT&CK Data Components & Log Sources](/ATTACK_DATA_COMPONENTS.md) — the telemetry-to-technique map you will justify the source against.
- [ ] Know your 1–3 priority techniques. If you don't, derive them from [Threat-Informed Defense](/THREAT_INFORMED_DEFENSE_REFERENCE.md) and your [ATT&CK priority gaps](/scores/attack_priority_gaps.md).
- [ ] Confirm write access to the repo that holds your pipeline configuration. If your pipeline config is not in version control, fix that first — a filter change is a detection change.
- [ ] Have a SIEM or lake destination you can query; platform specifics live in the [SIEM Reference](/SIEM_REFERENCE.md).
- [ ] Have one authorized, non-production test host for validation, and written permission to run benign tests on it — see the [Atomic Red Team wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki) for what those tests do.

## Step 1 — Define the detection use case first

Do not start with the source. Start with what you need to see.

1. Take one priority technique — this guide uses **T1053.005 Scheduled Task** as the running example.
2. Walk the chain: technique → [Detection Strategy](/detections/strategies/README.md) → analytics → **data components**. For T1053.005 the component is **Scheduled Job Creation**.
3. Look the component up in [ATT&CK Data Components & Log Sources](/ATTACK_DATA_COMPONENTS.md). It names the concrete sources: `WinEventLog:Security` (event 4698), `WinEventLog:TaskScheduler`, `linux:cron` via syslog.
4. Write one sentence: *"This source exists to populate Scheduled Job Creation (and Process Creation) for T1053.005 and T1053.003."* That sentence is the source's reason to exist, and it goes in the inventory row in Step 7.

**Checkpoint:** You have a one-line justification naming the data components and technique IDs this source serves. If you cannot write that sentence, stop — "the appliance can send syslog" is not a use case.

**Watch out:** ATT&CK v18 rebuilt the detection model (Detection Strategies and Analytics replaced technique-level detection text, and data components were restructured). Version-stamp any component list you operationalize — the one in this library is stamped v18.1.

## Step 2 — Capture a real event corpus

Vendor sample logs are not your logs. Capture real events from your own estate before you write a single parser line.

1. Trigger or collect examples of every variant: success, failure, edge cases, and the multiline stack trace the vendor swears never happens. For the running example: create a scheduled task on a test host and capture the 4698 event it produces.
2. Save the raw events as a test corpus **in the same repo, next to the parser config** they will test.
3. Commit it. The corpus is what every future parser change regression-tests against.

**Checkpoint:** A committed corpus file containing real, representative events — including at least one failure-path and one edge-case event.

**Watch out:** Locale, product version, and audit-policy differences change field layouts. A corpus captured from one hardened gold image will not represent the unpatched fleet; sample more than one host class.

## Step 3 — Choose the collection path

Decide how events travel: **agent → broker → pipeline tier → destinations**. Thin agents at the edge that collect, tag, and ship; routing and logic centralized where you can change and observe them.

- Use the vendor-native agent where the ecosystem demands it (Splunk Universal Forwarder, Elastic Agent, EDR sensors); use Fluent Bit or the OpenTelemetry Collector where footprint and neutrality matter. Feed them all into the broker rather than letting each own its own path to storage.
- For the Windows running example, turn the telemetry on at the source first — both are off by default:
  - Enable **Audit Process Creation** under `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking`, and **Include command line in process creation events** under `Administrative Templates\System\Audit Process Creation` (per [Microsoft's command-line auditing doc](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)).
  - Or install Sysmon with a tuned config, per the [official Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon):

```cmd
sysmon64 -accepteula -i sysmonconfig.xml
sysmon64 -c
```

  The second command dumps the active configuration so you can prove what is actually deployed. Events land in Event Viewer under `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`. Tuning guidance lives in the [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md).

**Checkpoint:** Events from your test host are visible at the collection point (broker topic, forwarder queue, or collector output) — not yet in the SIEM, just demonstrably leaving the source.

**Watch out:** Never filter at the agent what you could route at the pipeline tier. Edge-dropped data is gone forever; pipeline-routed data comes back with a config change.

## Step 4 — Normalize to your schema and keep the raw

Map the source to your house schema **once, in the pipeline tier** — not per destination.

1. Pick the target event class: OCSF class, ASIM schema, CIM data model, or ECS field set, whichever your stack uses (decision table in the [Security Data Engineering Reference](/SECURITY_DATA_ENGINEERING_REFERENCE.md)). Browse OCSF classes at [schema.ocsf.io](https://schema.ocsf.io/). The 4698 example maps to scheduled-job/process activity classes plus your entity fields.
2. Map the fields your detections consume. Send everything that does not map to a designated overflow/unmapped structure — never to /dev/null, and never renamed "helpfully" outside the schema.
3. Preserve the **raw event** (or a durable pointer to it) alongside the normalized record. Normalization is lossy by design; incident response eventually wants the original bytes.
4. Build it as reviewed, version-controlled config in a branch. If your pipeline tier is the OpenTelemetry Collector, check the config before it ships ([Collector docs](https://opentelemetry.io/docs/collector/configuration/)):

```shell
otelcol validate --config=customconfig.yaml
```

5. Run the corpus from Step 2 through the branch build until the parse rate is ≈100% and every mapped field populates.

**Checkpoint:** A config PR plus a versioned mapping document that lists mapped fields, overflowed fields, and the schema version — and a corpus run showing ≈100% parse success.

**Watch out:** There is no official crosswalk between OCSF, ECS, CIM, and ASIM. Any equivalence table you build is an internal engineering artifact: label it, version it, and expect it to drift. And never fabricate defaults to satisfy a required field — use explicit unknown markers.

## Step 5 — Validate timestamps and entities

These two quality dimensions break more detections than rule logic does.

**Timestamps:**

- Carry two timestamps per event: event time (from the source) and ingest time. Normalize event time to UTC at the first pipeline hop.
- Verify clock health on Windows sources with the [Windows Time service tools](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings):

```cmd
w32tm /query /status
w32tm /stripchart /computer:<your-ntp-source> /samples:5 /dataonly
```

- Measure ingest lag (event time → ingest time) for the new source over the corpus and shadow traffic.

**Entities:**

- Enrich every event with your canonical host and user identifiers in the pipeline tier. Short hostname, FQDN, and NetBIOS name must resolve to one asset, not three.
- Measure the resolution rate: percentage of events with a resolved canonical host and user.

Gate the source on the four conformance checks from the reference: parse success, mandatory fields present (event time, primary entity, action/outcome), value validity, and stable per-field population. Below threshold, the source is **not onboarded**, whatever the volume dashboard says.

**Checkpoint:** A pass/fail quality report covering parse rate, mandatory-field population, timestamp sanity (UTC, plausible range, measured lag), and entity resolution rate.

**Watch out:** A rule with a 5-minute lookback on a source with 20-minute ingest lag detects nothing, forever, without erroring once. Record the measured lag where rule authors will see it.

## Step 6 — Set tiering and retention

Route by value; drop almost nothing.

1. Decide which tier each stream of this source needs — hot for real-time correlation, warm (data lake) for hunts and scoping, cold for compliance — based on query pattern, not habit. The full economics and a worked Windows-channel routing example are in the [Security Data Engineering Reference](/SECURITY_DATA_ENGINEERING_REFERENCE.md).
2. Send the full-fidelity copy to cheap object storage; send the SIEM only what live rules consume. Deletion is a last resort for data you can prove nothing consumes.
3. Write the retention row for this data class: hot/warm/cold windows, the regulation or need driving each, and the disposal method. Add it to your retention schedule and automate it as lifecycle policy.

**Checkpoint:** Route and lifecycle config merged; a written retention row naming windows and the driver for each (detection window, IR dwell-time assumption, or a specific regulatory text).

**Watch out:** Never sample security events — the attacker's event is the one you sampled out. And do not let the SIEM license period silently become the organization's retention policy.

## Step 7 — Wire health monitoring, then register the source

Wire failure alarms **before** go-live, not after the first gap. Pipelines fail silently; make this one fail loudly.

1. Baseline volume during the shadow-run (at least one normal business cycle), then alert on both directions — **silence is an alert condition**, not a quiet day.
2. Add the remaining health signals per source: ingest lag p95, parse-failure rate (with failures routed to a dead-letter queue, never dropped), entity-resolution rate, and enrichment coverage.
3. Register the source in your source-of-truth inventory. The row carries: owner and contact, the Step 1 justification (data components and techniques served), schema and mapping version, collection path, route and tiers, retention row, and a review date.

**Checkpoint:** Dashboards and alerts live for all five signals; an inventory row exists that a stranger could use to understand, audit, or decommission this source.

**Watch out:** Adversaries deliberately impair telemetry ([T1562.001](https://attack.mitre.org/techniques/T1562/001/)). A pipeline that cannot distinguish "config change" from "someone killed the forwarder" cannot support that detection at all — which is why the silence alert is not optional.

## Step 8 — Prove a detection fires end to end

A source is not onboarded until a detection has consumed it in anger. Coverage claims are pipeline claims — the rule is one link of six.

1. Enable the rules that motivated the source in Step 1. If they exist as Sigma rules, convert them with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```shell
python -m pipx install sigma-cli
sigma plugin install splunk
sigma convert -t splunk -p sysmon rules/windows/process_creation
```

   Swap the backend and pipeline for your platform; rule-format details are in the [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md).
2. On your **authorized test host only**, generate a benign true positive with Atomic Red Team ([official install docs](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam)):

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics
Invoke-AtomicTest T1053.005 -CheckPrereqs
Invoke-AtomicTest T1053.005 -TestNumbers 1
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

3. Watch the whole chain: the event appears at the source, survives the pipeline, lands normalized, and the alert fires — with the correct canonical host and user, an event time that matches when you ran the test, and within the lag budget you measured in Step 5.
4. Record the run: test ID, timestamp, alert ID, and end-to-end latency. This is your benign-true-positive baseline; re-run it after any parser, filter, or schema change.

**Checkpoint:** One alert, fired by a real event you generated, carrying correct entities and timestamps — and a recorded baseline of event-to-alert latency.

**Watch out:** Atomic tests are benign by design but will trip EDR and antivirus — run them only on the authorized test host, with the owning team informed, and always run the `-Cleanup` pass. Review what a test does (`-ShowDetails` in the [wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki)) before executing it.

## What good looks like

- The inventory row's one-line justification traces to named data components and technique IDs — not to "we had the logs."
- The corpus, parser, mapping doc, and every filter live in version control; a stranger could rebuild the pipeline path from the repo alone.
- Parse rate ≈100%, mandatory fields populated, entities resolve, and the measured ingest lag is documented where rule authors see it.
- You have tested the silence alert by stopping the forwarder on a test host — and it paged.
- The benign true positive fired end to end, and re-running it is a documented, repeatable check.
- You can answer, in one minute, "what detections break if this source goes dark?" — because the dependency is written down, not remembered.

## Go deeper

**In this library:**

- [Security Data Engineering Reference](/SECURITY_DATA_ENGINEERING_REFERENCE.md) — the full doctrine: schemas, pipeline architecture, cost-driven routing, quality, retention, and the 90-day program bootstrap.
- [ATT&CK Data Components & Log Sources](/ATTACK_DATA_COMPONENTS.md) — every data component with its concrete sources and technique counts.
- [Detection Strategies](/detections/strategies/README.md) and the [Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md) — what to point the new telemetry at.
- [SIEM Reference](/SIEM_REFERENCE.md) — platform-specific ingestion, query languages, and deployment.
- [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md) — Sysmon configuration, Windows audit policy, and EDR sensor tuning.
- [Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md) — reporting onboarding coverage and pipeline health upward.

**External:**

- [Sysmon official documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — Microsoft Learn.
- [OCSF schema browser](https://schema.ocsf.io/) — the live, versioned class and attribute reference.
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli) — converting Sigma rules to your SIEM's query language.
- [Invoke-AtomicRedTeam wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki) — official usage documentation for benign detection validation.

*Guides are procedures, not gospel: verify every command and menu path against the current official documentation before you rely on it in production.*
