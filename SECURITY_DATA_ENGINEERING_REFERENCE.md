# Security Data Engineering Reference

> **Detection engineering is downstream of data engineering.** Every query in [SIEM Reference](SIEM_REFERENCE.md), every rule in [SIEM Detection Content](SIEM_DETECTION_CONTENT.md), and every hunt in this library silently assumes telemetry that arrived on time, parsed correctly, carried a trustworthy timestamp, and named the right host and user. That assumption is manufactured by a layer most SOC documentation skips: schemas and normalization models — [OCSF](https://ocsf.io/) (a Linux Foundation project), Elastic ECS, Splunk CIM, Microsoft ASIM — plus collection agents, brokers, pipeline tools, storage tiers, and security data lakes. This reference covers that layer: what the schemas are and where you meet them, how pipelines are built, how to cut cost without blinding detections, and how ATT&CK data components turn "what do we need to see?" into pipeline decisions.

A missed detection is rarely a bad rule. It is far more often a log source that was never onboarded, a filter that dropped the load-bearing field, a parser that broke on a vendor upgrade, a timestamp recorded in local time, or a hostname that resolved to three different assets. Pipelines fail silently; rules fail loudly. This document is about the silent half.

**Related:** [ATT&CK Data Components & Log Sources](ATTACK_DATA_COMPONENTS.md) · [SIEM Reference](SIEM_REFERENCE.md) · [SIEM Detection Content](SIEM_DETECTION_CONTENT.md) · [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) · [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [Endpoint Security](ENDPOINT_SECURITY_REFERENCE.md)

---

## Scope & how to use this reference

| You need | Go to |
|---|---|
| **SIEM platforms, query languages, deployment** | [SIEM Reference](SIEM_REFERENCE.md) |
| **Ready-made detection content per platform** | [SIEM Detection Content](SIEM_DETECTION_CONTENT.md) · [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) |
| **Rule formats (Sigma/YARA/Suricata) and conversion** | [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) |
| **Which telemetry detects which ATT&CK technique** | [ATT&CK Data Components](ATTACK_DATA_COMPONENTS.md) · [Detection Strategies](detections/strategies/README.md) |
| **Endpoint sensor configuration** (Sysmon, audit policy, EDR) | [Endpoint Security Reference](ENDPOINT_SECURITY_REFERENCE.md) |
| **The pipeline underneath all of it** — schemas, routing, tiering, quality, retention | **This document** |

The recurring theme: every pipeline decision is a detection decision. Filtering, normalization, tiering, and retention each silently change what a detection engineer can and cannot write. Treat the pipeline team and the detection team as one team with two backlogs.

---

## Why the data layer decides what you can detect

Rules fail loudly — they error, they page, someone notices. Pipelines fail silently: the SIEM keeps answering queries, dashboards stay green, and the events that would have caught the intrusion simply are not there. Post-incident reviews land on the data layer with depressing regularity, and the failure usually predates the incident by months.

The silent-failure catalog — each row is a recurring, real-world pattern; the guard column is the engineering control that makes the failure loud:

| Silent failure | What the SOC experiences | The guard |
|---|---|---|
| **Source never onboarded** | "Coverage" claimed from a rule that has no input; the rule has simply never fired | Reconcile sources against [ATT&CK data components](#mapping-telemetry-needs-with-attampck-data-components); periodically test rules with benign true positives |
| **Agent or forwarder stopped** | One host — or a thousand — goes dark; nothing errors | Per-source volume baselines with **silence alerts**: absence of logs is an alert condition, not a quiet day |
| **Parser drift after a vendor upgrade** | Fields move or rename; rules match nothing while events keep flowing | Parse-failure-rate alerting per source; schema validation at the pipeline contract point |
| **Filter dropped a load-bearing field** | Rules keep firing on what remains; the misses are invisible | Every filter change diffed against the detection dependency inventory ([below](#cost-driven-routing-and-filtering-without-blinding-detections)) |
| **Clock skew or ingest lag** | Correlation windows miss; incident timelines assemble in the wrong order | Ingest-lag monitoring per source; NTP enforcement ([below](#data-quality-for-detections)) |
| **Entity split** | Pivoting on a host or user finds half its activity; the other half lives under a different name | Canonical entity IDs enriched in the pipeline; resolution-rate metric per source |
| **Retention expired mid-investigation** | Incident scoping stops at the archive wall, or at the deletion date | Retention designed per data class against dwell-time assumptions, not license defaults |
| **Schema upgrade broke history** | Hunts over old data silently return partial results | Version-pinning per event; a rehearsed schema-migration procedure |

Two consequences worth internalizing:

- **Telemetry integrity is a security property, not an ops nicety.** Adversaries actively impair telemetry ([T1562.001](https://attack.mitre.org/techniques/T1562.001/) Disable or Modify Tools); a pipeline that cannot tell "source went quiet because of a config change" from "source went quiet because someone killed the forwarder" cannot support that detection at all.
- **Coverage claims are pipeline claims.** A statement like "we detect [T1003](https://attack.mitre.org/techniques/T1003/) credential dumping" decomposes into: the endpoint sensor emits the events, the agent ships them, the parser preserves the fields, the filter passes them, they arrive within the rule's window, and the entity fields resolve. The rule is one link of six. Coverage reviews ([ATT&CK Priority Gaps](scores/attack_priority_gaps.md)) that only audit rules audit one-sixth of the chain.

---

## Security data schemas: the normalization landscape

Four normalization models dominate enterprise security data. They solve the same problem — hundreds of log formats, one analyst — at different points in the data's life, under different owners.

| | **OCSF** | **Elastic ECS** | **Splunk CIM** | **Microsoft ASIM** |
|---|---|---|---|---|
| **Owner** | Linux Foundation project (open, multi-vendor) | Elastic (converging with OpenTelemetry) | Splunk (Cisco) | Microsoft (Sentinel) |
| **Version (Sep 2026)** | v1.9.0 (Aug 3, 2026) | v9.5.0 (Aug 4, 2026) | Add-on v8.7.0 (Sep 2, 2026) | 12 event schemas, each GA at v1.0.0 |
| **Unit of normalization** | Event class (in 8 categories) | Field set | Data model (26 documented, 2 deprecated) | Event schema + KQL parser |
| **Normalization point** | Producer or pipeline (schema-on-write) | Ingest (schema-on-write) | Search time (schema-on-read, accelerated) | Query time, plus optional ingest-time tables |
| **Where you meet it** | Amazon Security Lake, security data lakes, vendor export formats | Elastic Security, Elastic Agent integrations | Splunk Enterprise Security | Microsoft Sentinel |

> **There is no official crosswalk between these schemas.** No published, authoritative field-level mapping exists between OCSF, ECS, CIM, and ASIM. Microsoft documents ASIM as aligning with [OSSEM](https://github.com/OTRF/OSSEM) — not with OCSF. Any equivalence table you build (including the illustrative ones later in this document) is an internal engineering artifact: label it that way, version it, and expect it to drift.

### OCSF — Open Cybersecurity Schema Framework

The industry's bid for a vendor-neutral, schema-on-write standard. Launched at Black Hat USA 2022 — conceived and initiated by AWS and Splunk, building on the ICD Schema work done at Symantec (Broadcom), with 15 additional initial members including Cloudflare, CrowdStrike, IBM Security, Okta, Palo Alto Networks, Rapid7, Salesforce, Securonix, Sumo Logic, Tanium, Trend Micro, and Zscaler. OCSF joined the **Linux Foundation on November 19, 2024**, reporting at that point over 900 contributors and 200 participating organizations (date-stamped figures — re-check before quoting as current).

| | |
|---|---|
| **Current release** | v1.9.0 (August 3, 2026). v1.0.0 GA was September 29, 2023; cadence since has been roughly 2–3 releases per year (1.1.0 Jan 2024 → 1.8.0 Mar 2026 → 1.9.0 Aug 2026) |
| **Structure** | 8 **categories** → **event classes** → typed **attributes** built from reusable **objects**; **profiles** overlay optional attribute sets; **extensions** add vendor/domain classes without forking core |
| **The mapping unit** | A log source maps to an event class — e.g., resolver logs to *DNS Activity*, SSH daemon logs to *SSH Activity*, logon events to *Authentication* |
| **Browse it** | [schema.ocsf.io](https://schema.ocsf.io/) — the live, versioned class/object browser; source at [github.com/ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema) |

The 8 event categories in v1.9.0 (per the version-pinned `categories.json`):

| uid | Category | Covers |
|---|---|---|
| **1** | System Activity | File, process, kernel, memory, module activity on hosts |
| **2** | Findings | Detection findings, compliance findings, vulnerability findings |
| **3** | Identity & Access Management | Authentication, account changes, group management |
| **4** | Network Activity | Traffic, DNS, HTTP, SSH, email, tunnel activity |
| **5** | Discovery | Inventory and state queries against devices and software |
| **6** | Application Activity | API, web-resource, datastore, scan activity |
| **7** | Remediation | Response and remediation actions on files, processes, networks |
| **8** | Unmanned Systems | Drone/UAS flight and telemetry events |

Categories 7 and 8 — and the steady addition of new classes and profiles in recent releases — show the schema expanding well beyond classic SOC telemetry; read the [release notes](https://github.com/ocsf/ocsf-schema/releases) for exact class names per version rather than relying on secondhand lists. Class counts change per release; count from the version tag you deploy rather than quoting a number.

**Why detection engineers care:** OCSF is schema-on-write with explicit versioning discipline. Amazon Security Lake, the most prominent OCSF-native managed service ([below](#amazon-security-lake-the-ocsf-data-lake-worked-example)), pins every stored event to a class and schema version via `metadata.version` and `class_name` — which is exactly what lets a detection survive a schema upgrade.

### Elastic ECS and the OpenTelemetry convergence

Elastic Common Schema is the field dictionary underneath Elastic Security: a set of field definitions (`source.ip`, `process.command_line`, `user.name`, `event.category`, …) applied at ingest so that detections and dashboards query one vocabulary.

The frequently misreported part: in **April 2023 Elastic contributed ECS to the OpenTelemetry project**, jointly announcing intent to converge ECS and the OTel **Semantic Conventions** into one schema maintained by OpenTelemetry — with SemConv adopting ECS in its full scope as the stated goal. Three years on, the accurate description is:

- **Convergence is directional, not done.** Elastic's own ECS-and-OpenTelemetry reference describes the donation as a directional decision for both standards, not a completed merger, and classifies field relationships on a spectrum from *match* to *conflict*.
- **ECS is still actively released** — v9.5.0 shipped August 4, 2026. It is not frozen and not in maintenance mode.
- **OTel SemConv moves in parallel** — v1.44.0 also shipped August 4, 2026.

**Do not write or architect as if "ECS merged into OTel."** If you emit OTel-native telemetry and ECS-native telemetry into the same store, treat field alignment as your integration problem today, using Elastic's published ECS↔OTel reference as the map of what matches and what conflicts.

### Splunk CIM — Common Information Model

CIM is Splunk's schema-on-read normalization layer: a library of **data models** (Authentication, Network Traffic, Endpoint, Malware, Web, DNS as Network Resolution, …) shipped as JSON in the `Splunk_SA_CIM` add-on (Splunkbase app 1621; **v8.7.0 as of September 2026** — the version number moved fast in 2026, expect drift). Splunk Enterprise Security is packaged with and built on it.

| | |
|---|---|
| **Model count** | The CIM 8.7 data-model reference documents 26 data models, of which 2 are deprecated (Application State, Change Analysis) |
| **How normalization happens** | Raw events are indexed as-is; source add-ons apply field aliases, calculated fields, and tags at search time to make events CIM-compliant |
| **How it stays fast** | Data-model acceleration pre-computes the normalized view, queried via `tstats` — a schema-on-read model that pays a write-side cost for speed |
| **The failure mode** | An add-on upgrade or a custom source without CIM tags silently drops events out of a data model — ES correlation searches keep running and simply see less |

**Why detection engineers care:** CIM demonstrates that "schema-on-read" does not mean "no pipeline work." The normalization logic lives in add-ons that must be tested like code, and acceleration is a standing compute bill. Audit data-model population (which sourcetypes actually fill Authentication?) on a schedule, not on faith.

### Microsoft Sentinel ASIM — Advanced Security Information Model

ASIM is Sentinel's normalization layer and the best public worked example of the schema-on-read/schema-on-write tradeoff, because it ships both modes in one product ([below](#schema-on-write-vs-schema-on-read-for-detection-engineering)).

| | |
|---|---|
| **Schemas** | **12 event schemas**, all GA at schema version 1.0.0: Agent Event, Alert Event, Audit Event, Authentication, DHCP Activity, DNS Activity, File Activity, Network Session, Process Event, Registry Event, User Management, Web Session — plus **1 entity schema** (Asset Entity). (Per Microsoft's schema page as updated September 16, 2026 — older third-party writeups list fewer; cite Microsoft, not blogs.) |
| **Primary mode** | Query-time: **KQL parser functions** — source-specific parsers combined under unifying parsers (query `_Im_Dns` and every DNS source answers) |
| **Secondary mode** | Ingest-time normalization into **10 native tables**: `ASimAuditEventLogs`, `ASimAuthenticationEventLogs`, `ASimDhcpEventLogs`, `ASimDnsActivityLogs`, `ASimFileEventLogs`, `ASimNetworkSessionLogs`, `ASimProcessEventLogs`, `ASimRegistryEventLogs`, `ASimUserManagementActivityLogs`, `ASimWebSessionLogs` |
| **Field discipline** | Field classes: **Mandatory / Recommended / Optional / Conditional / Alias** |
| **Entity discipline** | Entity prefixes (**Actor**, **TargetUser**, **Src**, **Dvc**, …) with typed identifier fields (e.g., `UserIdType` says whether the ID is a SID, a UPN, an AAD object ID…) — directly reusable thinking for [entity resolution](#data-quality-for-detections) |
| **Lineage** | Microsoft documents ASIM as aligned with **OSSEM** — there is no official ASIM↔OCSF mapping |

ASIM's docs cite the robustness principle as the design pattern for normalization — "be strict in what you send, be flexible in what you accept" — which is the correct posture for any pipeline: tolerate source chaos on input, emit one disciplined schema on output.

### Choosing a schema (or, realistically, living with several)

| Situation | Practical answer |
|---|---|
| **Single-SIEM shop** | Use the SIEM's native model (CIM for Splunk ES, ASIM for Sentinel, ECS for Elastic) — fighting the platform's schema forfeits its content library |
| **Building a security data lake** | OCSF is the only multi-vendor, openly governed schema-on-write option with a flagship managed implementation |
| **Multi-SIEM / migration** | Normalize once in the pipeline tier to a house schema (OCSF is the sane default), then adapt per destination; never maintain N×M source-to-SIEM parsers |
| **OTel-instrumented estates** | Expect application/infra telemetry in SemConv and security telemetry in ECS/OCSF; plan the join keys (host, user, time) deliberately |

### Normalization anti-patterns

Whichever schema wins locally, the same mistakes recur:

**Do**
- Preserve the **raw event** (or a durable pointer to it) alongside the normalized record — normalization is lossy by design, and IR eventually needs the original bytes.
- Send unmappable fields to a designated **overflow/unmapped structure** rather than dropping them; today's unmapped field is next quarter's detection.
- Treat parsers and mappings **like code**: versioned, tested against a kept corpus of real events, releasable and rollback-able.
- Record **which mapping version** produced each stored event (OCSF's per-event `metadata.version` is the pattern to copy even outside OCSF).

**Don't**
- Rename vendor fields "helpfully" outside any schema — a fifth in-house naming convention is not a normalization strategy, it is a fifth problem.
- Fabricate defaults to satisfy a required field ("no severity? call it Medium") — invented values poison both statistics and detections; use explicit unknown markers.
- Normalize the same source independently in two tools and assume the outputs agree — they won't, and the disagreement will surface mid-incident.
- Chase 100% field mapping before onboarding — map the fields detections consume, overflow the rest, iterate.

---

## Log pipeline architecture

The reference shape — whatever the vendor names on the boxes:

```
 SOURCES                 COLLECTION              BUFFER / BROKER          PIPELINE TIER               DESTINATIONS
 (produce)               (agents)                (decouple, absorb)       (parse, filter, route)      (consume)

 Endpoints, EDR    ┐    ┌────────────────┐      ┌────────────────┐       ┌────────────────────┐  ┌─► SIEM / analytics
 Identity, SaaS,   ├───►│ Fluent Bit,     ├─────►│ Kafka topics    ├──────►│ OTel Collector      ├──┼─► Security data lake
 network, cloud,   │    │ OTel Collector, │      │ (durable,       │       │ gateway, Vector,    │  │   (OCSF + Parquet)
 appliances, apps  ┘    │ vendor agents   │      │ replayable)     │       │ Logstash, or a      │  └─► Cold archive /
                        └────────────────┘      └────────────────┘       │ commercial pipeline │      compliance store
                              agent mode:                                 └────────────────────┘
                              collect + ship,                              normalize HERE, once —
                              minimal logic                                not per destination
```

### Collection agents

| Agent | What it is | Where it fits |
|---|---|---|
| **Fluent Bit** | Lightweight CNCF-hosted log/telemetry agent written in C | Containers, Kubernetes nodes, edge devices — anywhere footprint matters |
| **OpenTelemetry Collector** | The OTel project's vendor-neutral collector for logs, metrics, and traces (OTel is a CNCF project); runs as per-host **agent** or centralized **gateway** | The default when you want one agent for security and observability |
| **Vector** | Open-source Rust telemetry pipeline agent developed by Datadog; runs as agent or aggregator | High-throughput transformation close to the source |
| **Vendor-native agents** | Splunk Universal Forwarder, Elastic Agent, Azure Monitor Agent, EDR sensors | Non-negotiable for their own ecosystems; feed them to the broker rather than letting each own its own path to storage |

**The pattern that survives contact with production:** thin agents at the edge (collect, tag, ship), aggregation/routing centralized in a gateway tier. Logic pushed to thousands of endpoints is logic you cannot change quickly or observe failing.

### Broker tier

A durable broker — **Apache Kafka** is the reference implementation; cloud equivalents (Kinesis-class, Event Hubs-class services) play the same role — between producers and consumers buys four things:

1. **Backpressure absorption** — a SIEM outage or ingest slowdown no longer drops logs at the source.
2. **Replay** — reprocess a time window through a fixed parser or a new destination without touching sources.
3. **Fan-out** — SIEM, data lake, and archive each consume the same topic independently.
4. **A contract point** — the topic is where you enforce "everything past this line is schema X, version Y."

### Pipeline / routing tier

An emerging product category — often called telemetry pipelines or observability pipelines — sits between collection and destinations: **OTel Collector in gateway mode, Vector, Logstash, Fluent Bit's processing mode**, and commercial offerings such as **Cribl Stream**. Category capabilities, whichever tool: parse and normalize once; enrich; filter and sample; route by content and value; convert schema per destination; and spill full-fidelity copies to cheap object storage. This tier is where [cost-driven routing](#cost-driven-routing-and-filtering-without-blinding-detections) is implemented — and where it goes wrong.

**Do**
- Keep pipeline configuration **in version control with code review** — a pipeline filter is detection-affecting change, gate it like a detection change ([checklist](#pipeline-decisions-checklist)).
- Emit **pipeline health telemetry** (events in/out per route, parse failures, drop counts, lag) into the SIEM itself — the pipeline is a tier-0 security system and an attractive tamper target.
- Normalize **once**, in this tier, and adapt outward per destination.

**Don't**
- Let each destination team run its own parser fleet against raw sources — N×M parsers is how the same event gets three different usernames.
- Grant the pipeline tier write access it doesn't need; it touches every log you have.

Whatever product lands in this tier, hold it to the same requirements:

| Demand | Because |
|---|---|
| **Configuration as code** — exportable, diffable, CI-testable | Filter changes are detection changes; they need review, history, and rollback |
| **Per-route metrics exposed** (in/out counts, drops, errors, lag) | You cannot govern routing you cannot observe |
| **Replay support** (from broker or landing zone) | Filter regret is a *when*; recovery must be a config change, not a data-loss report |
| **Schema-aware validation at the output** | Drift gets caught at the contract point, not in a failed hunt months later |
| **Documented backpressure behavior** — block, buffer, or drop, per route | What happens when a destination stalls decides what you lose in an outage |
| **No undisclosed egress** | This tier touches every log you produce; its own trust boundary is part of your threat model |

### Storage tiering: hot / warm / cold

| Tier | Typical window | Backing | What it must support |
|---|---|---|---|
| **Hot** | Days to ~1 month | SIEM index / fast SSD-backed store | Sub-second interactive queries; real-time correlation |
| **Warm** | Months | Object storage in open columnar formats (Parquet) — the security data lake | Scheduled hunts, batch analytics, incident scoping at SQL speed |
| **Cold** | Years | Compressed object storage / archive classes | Compliance retrieval and replay — hours-to-days latency acceptable |

Economics drive the split: hot storage commonly costs an order of magnitude (or more) per GB over object storage. The design question is never "hot or cheap?" — it is **which query patterns need which latency**. Real-time correlation needs hot; a hunt over 6 months of DNS does not.

### Security data lakes

A security data lake is warm/cold telemetry in **open formats on object storage** (Parquet files, open table metadata), queryable in place by SQL engines, owned by you rather than licensed per-GB by a SIEM. It complements the SIEM rather than replacing it: detections that need seconds stay hot; scale-hungry retro-hunting, UEBA-style baselining, and IR scoping move to the lake. The schema question is the whole game — a lake of unnormalized JSON is a swamp with a marketing name — which is why OCSF and the lake pattern rose together.

What earns the name "lake" rather than "bucket of logs":

| Property | Why it matters for security data |
|---|---|
| **Open columnar format** (Parquet) | Any engine can query it, forever — no vendor exit tax on your own evidence |
| **Enforced schema at write** | Hunts written once run across sources; see the Security Lake OCSF+Parquet requirement below |
| **Partitioning by time and source** | An IR scoping query over one day of one source reads megabytes, not the whole lake |
| **Access control and audit on the lake itself** | Telemetry is sensitive data *about* everything else — it inherits tier-0 handling |

### Amazon Security Lake: the OCSF data lake, worked example

The most prominent OCSF-native managed service (generally available **May 30, 2023**, previewed at re:Invent 2022) and worth studying even if you never run AWS, because its design choices are the pattern in miniature:

| Design choice | What Security Lake does |
|---|---|
| **Schema-on-write, enforced** | Converts natively supported AWS sources to OCSF and stores them as Apache Parquet in one S3 bucket per Region; **custom sources must submit data already in OCSF + Parquet** — the lake refuses to become a swamp |
| **Native sources** | CloudTrail management events, S3 data events, Lambda data events, Route 53 Resolver query logs, VPC Flow Logs, Security Hub findings, EKS audit logs, AWS WAFv2 logs |
| **Version pinning** | Every stored event carries `metadata.version`, `class_name`, and product metadata (`metadata.product.name`, `metadata.product.vendor_name`) — consumers always know which OCSF version and class they are reading |
| **Version lag, documented** | Source version 2 emits **OCSF 1.1.0** (source version 1 used 1.0.0-rc.2) while upstream OCSF is at 1.9.0 — a live lesson that schema consumers and the schema project move at different speeds; write detections against the version in the data, not the version on the website |
| **Retention as lifecycle** | Retention is configured per Region as S3 lifecycle transitions plus expiration **through the Security Lake console/API** — hand-editing the underlying S3 lifecycle rules can break its metadata; default is S3 Standard, stored indefinitely |
| **Compliance edges** | S3 Object Lock is **not supported** (no WORM legal hold in place — plan an external copy if you need it); **rollup Regions** consolidate contributing Regions' data for residency and compliance |
| **Consumption** | Subscribers consume from the lake (data access, or query-in-place through Athena-class engines) rather than each vendor re-collecting the same sources |

### Onboarding a new log source: the runbook

Most pipeline debt is created on day one of a source, in a hurry. The sequence below front-loads the decisions that are expensive to change later:

| Step | Do | Output |
|---|---|---|
| **1. Name the need** | Identify which detections, hunts, or [data components](#mapping-telemetry-needs-with-attampck-data-components) asked for this source — "the appliance can send syslog" is not a need | Justification linked to techniques/use cases |
| **2. Sample reality** | Capture real events covering the variants: success, failure, edge cases, the multiline stack trace the vendor swears never happens | A representative test corpus, kept next to the parser config |
| **3. Map the schema** | Choose the target event classes/schemas; map fields; write down what does **not** map (it goes to a raw/unmapped field, not to /dev/null) | A versioned mapping document |
| **4. Decide routing & retention** | Which tier(s), what windows, per the [retention schedule](#retention-design-vs-compliance) | Route + lifecycle config |
| **5. Build in a branch** | Parse, normalize, enrich in the pipeline tier — as reviewed, version-controlled config | A config PR, not a console click |
| **6. Gate on quality** | Against the corpus: parse rate ≈100%, timestamps UTC and sane, entities resolve, enrichment joins hit | A pass/fail quality report |
| **7. Shadow-run** | Run in production in parallel; compare volumes and field population against expectations for at least a normal business cycle | A volume/quality baseline |
| **8. Wire health first** | Volume baseline + silence alert, ingest lag, parse-failure rate — **before** go-live, not after the first gap | Dashboards and alerts |
| **9. Light up detections** | Enable the rules that motivated the source; validate with a benign true positive | Detections demonstrably consuming the source |
| **10. Register it** | Source inventory entry: owner, contact, schema version, route, retention, review date | The row the next audit will thank you for |

---

## Cost-driven routing and filtering without blinding detections

SIEM ingest pricing turns every noisy log source into a budget line, and the pipeline tier makes dropping data trivially easy. The discipline is making cost decisions **with the detection dependency graph in hand**, not with a volume report.

**The core rule: route by value, drop almost nothing.** The cheap-and-safe move is almost never deletion — it is sending full fidelity to object storage (pennies) while sending the SIEM only what live correlation needs. Deletion is a last resort reserved for data you can prove nothing consumes.

| Technique | What it does | Detection-safety check before applying |
|---|---|---|
| **Tier routing** | Full copy to lake/archive, reduced stream to SIEM | Confirm the SIEM stream still carries every field your live rules reference |
| **Field pruning** | Drop padding, duplicated envelopes, debug fields | Diff pruned fields against the fields used by detections *and* by IR runbooks — responders read fields rules don't |
| **Event filtering** | Drop event types wholesale (e.g., allowed-traffic logs from a chatty appliance) | Map the event type to [ATT&CK data components](#mapping-telemetry-needs-with-attampck-data-components) first; "allowed traffic" is exactly what C2 looks like |
| **Aggregation** | Collapse N flow records into one summarized record | Keep the fields that anchor detections (bytes, direction, endpoints, duration); accept losing per-event forensics on that source in hot |
| **Sampling** | Keep 1-in-N | Acceptable for performance/ops metrics; **almost never acceptable for security events** — the attacker's event is the one you sampled out |
| **Deduplication** | Drop identical repeats within a window | Preserve first/last-seen and a count; a repeat count is itself signal (brute force is [T1110](https://attack.mitre.org/techniques/T1110/)) |

**Do**
- Maintain a **detection dependency inventory**: which rules and hunts consume which source, event type, and field ([Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) is the per-technique starting point). No filter ships without a diff against it.
- Run new filters in **shadow mode** first: tag would-be-dropped events for a week and measure which detections would have lost input.
- Keep a **replayable raw copy** (broker retention or lake landing zone) long enough to survive discovering a filter mistake — filter regret is a matter of *when*.
- Re-test affected detections after each filter change, and record the change in the same system as detection changes.
- Revisit filters when the threat model moves — a source that was safely summarized last year may anchor this year's [Detection Strategy](detections/strategies/README.md).

**Don't**
- Let the **loudest source** get cut first by default — volume and value are uncorrelated; authentication logs are enormous *and* irreplaceable ([T1078](https://attack.mitre.org/techniques/T1078/) lives there).
- Filter at the **agent** what you could route at the pipeline tier — edge-dropped data is gone; pipeline-routed data is a config change away from coming back.
- Trust a vendor's "noise" preset — its author never saw your detections.
- Treat "we can rehydrate from archive" as equivalent to "it's in the SIEM" — rehydration measured in hours changes what a correlation rule can do in seconds. It covers forensics, not real-time detection.

**A worked example — routing Windows endpoint channels by value:**

| Stream | Route | Rationale |
|---|---|---|
| **Security 4624/4625 (logons), 4688 with command line (process creation), 4698/7045 (scheduled tasks / service installs)** | Hot + warm + cold | The anchor events for authentication and execution detections; expensive to lose, cheap relative to their value |
| **PowerShell Operational 4104 (ScriptBlock)** | Hot + warm + cold | Among the highest detection density per GB on a Windows fleet |
| **Sysmon (tuned configuration)** | Hot + warm | Its entire purpose is detection — tune the Sysmon config itself ([Endpoint Security Reference](ENDPOINT_SECURITY_REFERENCE.md)) rather than collecting broadly and filtering downstream |
| **Object-access success-audit storms (4663-class volume)** | Aggregate to hot, full fidelity to warm | File-share auditing at scale swamps hot storage; summaries carry the alerting need, the lake carries the forensics |

---

## Schema-on-write vs schema-on-read for detection engineering

| | **Schema-on-write** (normalize at ingest) | **Schema-on-read** (normalize at query) |
|---|---|---|
| **Query cost & latency** | Low — data is already shaped; real-time rules run cheap | Higher — every query re-pays the parse/normalize cost (unless pre-accelerated) |
| **Ingest cost & latency** | Higher — transform compute on the hot path | Minimal — land raw, move on |
| **Onboarding a new source** | Slower — mapping work before data is usable | Fast — land now, parse later |
| **Parser bug discovered** | Bad normalization is **baked into stored data**; fix forward, re-ingest, or live with a scar tissue window | Fix the parser, and history is instantly reinterpreted — the killer feature |
| **Source format drift** | Breaks visibly at ingest (if you monitor parse failures — do) | Breaks silently at query time; rules "work" against malformed data |
| **Raw evidence** | Lost unless you deliberately keep a raw copy (keep one) | Native — the raw event *is* the stored record |
| **Best for** | High-value, stable, real-time-correlated sources | Long-tail sources, exploratory hunting, fast-moving formats |

**The live worked example is ASIM**, which ships both modes in one product: query-time KQL parsers as the primary mode (flexible, retroactively fixable, per-query cost) and 10 native ingest-time `ASim*` tables as the performance path (pre-normalized, cheap to query, but fixed at write time). Splunk CIM is the same tradeoff from the read side — search-time normalization made fast by paying an acceleration (write-side) cost. OCSF-native lakes like Security Lake are the write side taken to its conclusion: normalization enforced before storage, version-pinned per event.

**Practical synthesis for a detection program:**

1. **Write-normalize the backbone** — the sources feeding real-time correlation (authentication, endpoint process/EDR, DNS, network sessions, cloud control plane).
2. **Read-normalize the long tail** — niche appliances, one-off SaaS exports, anything still changing format monthly.
3. **Always keep raw somewhere cheap** regardless of mode — normalization is lossy by design, and IR wants the original bytes.
4. **Version-pin normalized data** (OCSF's `metadata.version` is the model) so a schema upgrade is a migration you plan, not an incident you discover.
5. **Alert on parse-failure rate per source** — in either mode, this is the single highest-value pipeline health signal a SOC can wire.

**Do**
- Decide the mode **per source**, on query pattern and format stability — not per ideology.
- Budget acceleration and pre-compute honestly: read-side speed (CIM acceleration, ASIM ingest-time tables) is a standing cost, not a free lunch.
- Re-run query-time parsers against the kept event corpus after every parser change — retroactive reinterpretation cuts both ways; a parser regression retroactively breaks history too.

**Don't**
- Assume detections port across SIEM migrations — the schema, not the query language, is the real migration ([Detection Rules Reference](DETECTION_RULES_REFERENCE.md) covers rule conversion; field mapping is on you).
- Let "land it raw now, normalize later" quietly become *never* — schedule the normalization debt like any other debt, with the [data-component priority list](#mapping-telemetry-needs-with-attampck-data-components) setting the order.

---

## Data quality for detections

Three quality dimensions break more detections than rule logic does. None of them has a standards body; all of them have engineering discipline.

### Timestamp discipline

Correlation is time-based joining; wrong time means wrong (or no) joins.

**Do**
- Carry **at least two timestamps** per event: when it happened (event time, from the source) and when you received it (ingest time). Every schema in this document separates them — use both.
- Normalize to **UTC with explicit offsets** at the first pipeline hop; local-time logs from a fleet spanning time zones are unjoinable.
- Enforce **NTP** across the estate — a drifting domain controller quietly reorders your attack timeline.
- **Monitor ingest lag** (event time → ingest time, p95 per source) and alert on it: a source that falls hours behind is invisible to real-time rules *right now*, and lag spikes can also mean someone stopped a forwarder.
- Watch the classic mangling cases: syslog variants that omit year or zone, devices that reboot to epoch defaults, agents that substitute arrival time when parse fails — each produces confidently-wrong event times.

**Don't**
- Sort investigations by ingest time — batch-forwarded and replayed events interleave out of order.
- Let a rule's lookback window silently assume zero lag; a 5-minute window on a source with 20-minute lag detects nothing, forever, without erroring once.

### Host and user entity resolution

Detections and investigations pivot on "this host" and "this user" — but raw telemetry offers a soup of short hostnames, FQDNs, IPs that DHCP reassigned an hour later, SIDs, UPNs, email addresses, and cloud instance IDs.

**Do**
- Pick **one canonical identifier** per entity type (asset ID for hosts, a directory-anchored ID for users) and enrich every event with it in the pipeline tier.
- Keep identity resolution **time-aware**: an IP→host mapping is only valid for the DHCP lease window in which the event occurred; resolve against the mapping *as of event time*.
- Steal ASIM's design: **role-prefixed entities** (Actor vs TargetUser, Src vs Dvc) so "which user?" is unambiguous in a two-user event, and **typed identifiers** (a `UserIdType`-style field) so a SID never gets string-compared to a UPN.
- Treat ephemeral compute (VDI, containers, autoscaled instances) explicitly — a recycled hostname is two different assets on the same day.
- **Measure resolution rate** (% of events with a resolved canonical host/user) per source, and treat drops as pipeline incidents.

**Don't**
- Join on bare hostname across sources — short name vs FQDN vs NetBIOS silently splits one machine into three entities (or merges three into one).
- Assume username uniqueness across identity systems — `jsmith` local, `jsmith@corp`, and a directory account are three principals until proven otherwise.

### Enrichment joins

Enrichment turns a syntactically valid event into a decidable one: asset criticality, user department and privilege tier, geo/ASN, threat-intel verdicts, cloud tags.

| Enrich at | Use for | Because |
|---|---|---|
| **Pipeline time** (baked into the event) | Slow-changing, high-fan-out context: asset criticality, ownership, environment (prod/dev), user tier | Paid once per event; queryable and filterable everywhere downstream |
| **Query time** (lookup at search) | Volatile context: threat-intel indicators, current incident tags, watchlists | Yesterday's verdict baked into stored events is misinformation with a timestamp |

**Do**
- Record **enrichment provenance** — which source, which snapshot time — so a wrong join is auditable.
- Rebuild lookup tables from authoritative systems (CMDB, directory, cloud APIs) on a schedule, and alert when a rebuild fails or shrinks abnormally: a stale asset inventory silently degrades every enriched detection at once.
- Design for the **miss**: every enrichment field needs a defined unknown value, and "% enriched" per source belongs on the same dashboard as ingest lag.

**Don't**
- Bake threat-intel verdicts into stored events (retro-hunting then re-litigates history with stale intel).
- Let enrichment double events on a bad join key — a one-to-many CMDB match turns one logon into five.

### Schema conformance and completeness

The schemas already define requirement levels — ASIM's **Mandatory / Recommended / Optional / Conditional** field classes are the explicit public example — and the pipeline is where those levels get enforced rather than admired:

| Check | Signal to watch | On failure |
|---|---|---|
| **Parse success** | % of events per source entering the normalized path | Alert; route failures to a **dead-letter queue** for triage — never silently drop |
| **Mandatory fields present** | % of events carrying the schema's required core (event time, primary entity, action/outcome) | Gate: below threshold the source is *not onboarded*, whatever the volume dashboard says |
| **Value validity** | Enum fields hold documented values; IPs parse as IPs; timestamps land in a plausible range | Fix the mapping, not the data — coerced values are the fabricated-defaults anti-pattern in disguise |
| **Population drift** | Week-over-week change in per-field population rates per source | Investigate immediately — drift is the classic early symptom of an unannounced vendor format change |

These four checks, run per source and trended, are the difference between "we ingest that source" and "that source can carry a detection."

---

## Retention design vs compliance

Retention is three different requirements wearing one setting, and they pull in different directions:

| Driver | Pulls toward | Notes |
|---|---|---|
| **Detection & hunting** | ~90 days queryable-fast | Retro-hunting after a new advisory or IOC needs warm, not hot |
| **Investigation & IR** | 1 year+ reachable | Documented intrusion dwell times routinely exceed short retention windows; scoping an incident against expired logs is guesswork |
| **Regulatory floors** | 1 year to multi-year, per regime | Payment-card, healthcare, and government regimes (e.g., US OMB M-21-31 for federal agencies) each set their own log-retention floors — design to the specific text you are assessed against, not folklore |
| **Legal hold** | Indefinite, on demand | Needs a mechanism (WORM/object lock or an exported hold copy), not a policy PDF |
| **Privacy & minimization** | *Shorter* | Data-protection law pushes deletion of personal data; retention maximalism is itself a compliance risk |

**Design pattern:** retention **per data class, per tier** — not one global number. Authentication and cloud control-plane events earn years in cold; verbose debug streams may earn 30 days. Write the schedule down as data-class → hot/warm/cold windows → disposal method, and automate it as lifecycle policy.

An illustrative starting schedule — engineering guidance to be adjusted against your regulatory regimes and dwell-time assumptions, not a standard:

| Data class | Hot | Warm (lake) | Cold / archive | Why |
|---|---|---|---|---|
| **Authentication & identity** | 30 d | 12 mo | 3 y+ | Highest pivot value in every investigation; valid-account abuse ([T1078](https://attack.mitre.org/techniques/T1078/)) is discovered late |
| **Cloud control plane** | 30 d | 12 mo | 3 y+ | Change forensics and compliance both want it; low volume relative to value |
| **Endpoint process / EDR** | 14–30 d | 6–12 mo | 1–3 y | Forensic backbone; volume argues for aggressive tiering, value argues against deletion |
| **DNS & network sessions** | 7–30 d | 6–12 mo | 1 y+ | The retro-hunting workhorse when a new advisory lands with old indicators |
| **Web proxy / WAF** | 7–14 d | 6 mo | 1 y | Volume-heavy; summarize in hot, keep fidelity in warm |
| **Verbose app / debug streams** | 3–7 d | — | — | Not security telemetry; do not pay security-retention prices for it |

Security Lake's documented lifecycle model is the worked example: retention expressed as storage-class transitions plus expiration, configured **through the service's own console/API** (bypassing to raw S3 lifecycle rules can break its metadata), defaulting to indefinite S3 Standard, with **no S3 Object Lock support** — so a legal-hold requirement needs a copy outside the lake — and **rollup Regions** for residency consolidation. Every lake you build will face the same four decisions: who owns lifecycle, what the default is, where WORM lives, and where data is allowed to reside.

**Do**
- Test **retrieval**, not just retention: pull a 13-month-old day of logs quarterly and time it — an archive you've never restored from is a hypothesis (the same logic as backup restore testing).
- Delete on schedule when the schedule says so — provably, with disposal logged; "we keep everything forever" fails privacy review and balloons cost.

**Don't**
- Let the SIEM license period silently become the organization's retention policy.
- Conflate "retained" with "queryable" in commitments to auditors or IR — state tier and retrieval time.

---

## Mapping telemetry needs with ATT&CK data components

The question "which logs do we actually need?" has an authoritative, vendor-neutral answer layer: **ATT&CK data components**. This repo carries the full map in [ATT&CK Data Components & Log Sources](ATTACK_DATA_COMPONENTS.md) — telemetry categories cross-referenced to the techniques they detect, with concrete log sources and channels.

**Version discipline first.** ATT&CK **v18** (October 28, 2025) rebuilt the detection model: technique-level detection text was replaced by two new object types — **Detection Strategies** (691 Enterprise / 124 Mobile / 83 ICS per the v18 release notes) and **Analytics** (1,739 Enterprise / 211 Mobile / 82 ICS) — all **Data Source objects were deprecated** (retained but inactive), and **Data Components** were restructured to v2.0: 106 Enterprise, 17 Mobile, 36 ICS (v18 release-notes figures). **v19** (current since April 28, 2026; the versions page lists v19.2 as the current minor) split Defense Evasion into Stealth and Defense Impairment, brought sub-techniques to ICS, started Mobile Detection Strategies, added 12 new Mobile data components, and bumped several components to v3.0. Consequence: **version-stamp any data-component list you operationalize**, including the one in this repo.

The chain, and where the pipeline enters it:

```
 Technique (what the adversary does)
    └─► Detection Strategy (defender's approach)
          └─► Analytics (platform-specific logic)          ◄── detection engineering owns
                └─► Data Components (telemetry required)
                      └─► Log sources / channels            ◄── DATA ENGINEERING OWNS
                            └─► Pipeline decisions: onboard, normalize,
                                route, retain — per component
```

Worked usage — turning priority techniques into pipeline requirements:

| Step | Action | Using |
|---|---|---|
| **1** | Pick priority techniques (threat-informed, not alphabetic) | [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [ATT&CK Priority Gaps](scores/attack_priority_gaps.md) |
| **2** | Read their Detection Strategies and Analytics | [Detection Strategies](detections/strategies/README.md) |
| **3** | List the Data Components those analytics require | [ATT&CK Data Components](ATTACK_DATA_COMPONENTS.md) |
| **4** | Map each component to a concrete source in *your* estate, and check it against pipeline reality: onboarded? parsed? which tier? which retention? which fields survived filtering? | This document's checklists |
| **5** | Gap-list becomes the pipeline backlog, ranked by technique priority | [Security Metrics](SECURITY_METRICS_REFERENCE.md) for reporting |

Illustrative examples of step 4 — **conceptual mappings, not official ones** (neither MITRE nor the schema owners publish a data-component↔schema crosswalk):

| Data component (v18 model) | Example concrete sources | Example schema home (illustrative) |
|---|---|---|
| Process creation telemetry | Windows Security 4688 (with command line), Sysmon Event 1, EDR process events | OCSF System Activity category · ASIM Process Event · CIM Endpoint · ECS `process.*` |
| Authentication/logon telemetry | Windows Security 4624/4625, IdP sign-in logs, cloud control-plane auth | OCSF *Authentication* class · ASIM Authentication · CIM Authentication |
| DNS query telemetry | Resolver query logs (e.g., Route 53 Resolver), DNS server analytic logs, Zeek `dns.log` | OCSF *DNS Activity* class · ASIM DNS Activity · CIM Network Resolution |
| Network flow/session telemetry | VPC Flow Logs, firewall session logs, Zeek `conn.log`, NetFlow/IPFIX | OCSF Network Activity category · ASIM Network Session · CIM Network Traffic |

The payoff runs both directions: data components tell the pipeline what to onboard, and the pipeline's reality (what is actually collected, at what quality, for how long) tells detection engineering which [Detection Strategies](detections/strategies/README.md) are *actually* implementable today — which is exactly the coverage honesty this library's [coverage gap analysis](scores/coverage_gaps.md) depends on.

---

## Pipeline decisions checklist

Program-level questions, in the order they bite. Each row is a decision someone will otherwise make by accident.

| # | Decision | Good answer looks like |
|---|---|---|
| **1** | **Source inventory vs telemetry needs** | Source list reconciled against the data components your priority techniques require ([above](#mapping-telemetry-needs-with-attampck-data-components)); gaps are tickets with owners |
| **2** | **Normalization point & schema** | One house schema chosen deliberately (platform-native or OCSF); normalized once in the pipeline tier; version-pinned per event |
| **3** | **Raw copy** | Full-fidelity, replayable copy in cheap storage for every security-relevant source, regardless of normalization mode |
| **4** | **Filter governance** | Pipeline config in version control; every filter/pruning change diffed against the detection dependency inventory; shadow mode before enforcement |
| **5** | **Tier routing** | Per-source routing to hot/warm/cold justified by query pattern, not habit; rehydration path tested |
| **6** | **Quality telemetry** | Per-source dashboards + alerts: ingest lag p95, parse-failure rate, volume anomalies (both directions — silence is an incident), entity-resolution rate, enrichment coverage |
| **7** | **Retention schedule** | Per data class, per tier, mapped to the named regulation or need driving it; disposal automated and logged; legal-hold mechanism identified |
| **8** | **Pipeline as attack surface** | Pipeline/broker infrastructure treated as tier-0: hardened, least-privilege, its own logs monitored — an adversary who can drop your telemetry owns [T1562.001](https://attack.mitre.org/techniques/T1562.001/)-class outcomes at fleet scale without touching an endpoint |
| **9** | **Schema upgrade path** | A written procedure for moving schema versions (parallel-run window, detection regression tests), rehearsed before OCSF/CIM/ASIM/ECS ship their next release |
| **10** | **Ownership** | A named owner for the pipeline as a product, sharing a backlog and on-call reality with detection engineering |

**Metrics worth reporting upward** (formulas and patterns in [Security Metrics](SECURITY_METRICS_REFERENCE.md)): % of priority-technique data components with an onboarded, quality-passing source; ingest lag p95 per critical source; parse-failure rate trend; % events with resolved canonical entities; cost per GB per tier and per detection outcome; time-to-onboard a new source; detection regressions caused by pipeline changes (target: zero, counted honestly).

---

## A 90-day program bootstrap

For a SOC that has a SIEM and "some forwarders" but has never treated the pipeline as a product — same logic as the [CTEM 90-day plan](CTEM_REFERENCE.md): narrow scope, measure reality, fix the cheapest link first.

| Phase | Weeks | Do this |
|---|---|---|
| **Baseline** | 1–2 | Inventory every source end to end: source → agent → route → tier → retention → consuming detections. Pull the data components for your priority techniques from [ATT&CK Data Components](ATTACK_DATA_COMPONENTS.md) and diff against the inventory. Write down the schema and version each destination actually holds. |
| **Make failure loud** | 3–5 | Wire the five quality signals on every critical source: volume baseline with silence alert, ingest lag p95, parse-failure rate, entity-resolution rate, enrichment coverage. This costs almost nothing and it will find real, live gaps in week one. |
| **Fix the backbone** | 5–8 | Onboard or repair the sources behind your highest-priority data components using the [runbook](#onboarding-a-new-log-source-the-runbook). Normalize once, at the pipeline tier; version-pin the output. |
| **Cut cost safely** | 8–10 | Build the detection dependency inventory; move all filter/routing config into version control with review; shadow-test one big routing win (full copy to object storage, reduced stream to the SIEM) on your noisiest source and bank the savings. |
| **Write it down** | 10–12 | Retention schedule per data class signed off (with the compliance owner in the room); schema-upgrade procedure drafted; the pipeline named as a product with a named owner and a shared backlog with detection engineering. |
| **Iterate** | 13+ | Re-run the data-component diff on every ATT&CK release; treat new advisories and new detections as pipeline intake, not just rule intake. |

> **Failure modes to avoid:** buying a pipeline tool before inventorying detection dependencies; normalizing the same source differently in three destinations; filtering at the agent what you could route at the pipeline; declaring coverage from rules whose sources were never onboarded; letting the SIEM license term become the retention policy; and running the whole layer with no owner because it "belongs to everyone".

---

## Sources

- OCSF project: <https://ocsf.io/> · schema browser: <https://schema.ocsf.io/> · source: <https://github.com/ocsf/ocsf-schema>
- OCSF releases (v1.9.0, Aug 3, 2026; v1.0.0 GA Sep 29, 2023): <https://github.com/ocsf/ocsf-schema/releases> · v1.9.0 categories: <https://raw.githubusercontent.com/ocsf/ocsf-schema/v1.9.0/categories.json>
- Splunk — OCSF launch press release (Black Hat USA 2022, founding members): <https://www.splunk.com/en_us/newsroom/press-releases/2022/cybersecurity-and-technology-industry-leaders-launch-open-source-project-to-help-organizations-detect-and-stop-cyberattacks-faster-and-more-effectively.html>
- Linux Foundation — OCSF joins the Linux Foundation (Nov 19, 2024): <https://www.linuxfoundation.org/press/open-cybersecurity-schema-framework-ocsf-joins-the-linux-foundation-to-optimize-critical-security-data>
- AWS — Amazon Security Lake general availability (May 30, 2023): <https://aws.amazon.com/blogs/security/amazon-security-lake-is-now-generally-available/>
- AWS — Security Lake and OCSF (source versions, native sources, metadata pinning): <https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html> · lifecycle management: <https://docs.aws.amazon.com/security-lake/latest/userguide/lifecycle-management.html>
- Elastic — ECS donation to OpenTelemetry (Apr 2023): <https://www.elastic.co/blog/ecs-elastic-common-schema-otel-opentelemetry-announcement> · OpenTelemetry's announcement: <https://opentelemetry.io/blog/2023/ecs-otel-semconv-convergence/>
- Elastic — ECS and OpenTelemetry reference (convergence status): <https://www.elastic.co/docs/reference/ecs/ecs-opentelemetry> · ECS releases (v9.5.0, Aug 4, 2026): <https://github.com/elastic/ecs/releases>
- OpenTelemetry — Semantic Conventions releases (v1.44.0, Aug 4, 2026): <https://github.com/open-telemetry/semantic-conventions/releases> · Collector docs: <https://opentelemetry.io/docs/collector/>
- Splunk — Common Information Model add-on (v8.7.0, Sep 2, 2026): <https://splunkbase.splunk.com/app/1621> · CIM data-model reference: <https://help.splunk.com/en/splunk-enterprise/common-information-model/8.7/data-models/how-to-use-the-cim-data-model-reference-tables>
- Microsoft — ASIM normalization overview (parsers, ingest-time tables, OSSEM alignment): <https://learn.microsoft.com/en-us/azure/sentinel/normalization> · ASIM schemas (12 event schemas, field classes, entities): <https://learn.microsoft.com/en-us/azure/sentinel/normalization-about-schemas>
- MITRE ATT&CK — versions: <https://attack.mitre.org/resources/versions/> · v18 release notes (Detection Strategies, Analytics, Data Components v2.0): <https://attack.mitre.org/resources/updates/updates-october-2025/> · v19 release notes: <https://attack.mitre.org/resources/updates/updates-april-2026/>
- Fluent Bit: <https://fluentbit.io/> · Vector: <https://vector.dev/>

---

*This reference summarizes third-party projects and vendor documentation — OCSF (a Linux Foundation project), Elastic ECS, OpenTelemetry, the Splunk Common Information Model, Microsoft Sentinel ASIM, Amazon Security Lake, and MITRE ATT&CK® — as an independent practitioner summary; it is not affiliated with or endorsed by those organizations. Schema versions, model counts, and service capabilities cited here are date-stamped as of September 2026 and change frequently; consult the linked originals before relying on any specific figure. No official cross-schema field mapping exists between OCSF, ECS, CIM, and ASIM; all cross-schema tables in this document are illustrative.*
