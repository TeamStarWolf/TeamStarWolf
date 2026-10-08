# Splunk Enterprise Security

*Cisco (Splunk, a Cisco company) · SIEM / security analytics + SOAR (security orchestration, automation & response) — unified SOC / threat detection, investigation & response (TDIR) platform*

Splunk Enterprise Security (ES) is an analytics-driven SIEM built on the Splunk data platform: it ingests logs, metrics and events at scale, normalizes them to the Common Information Model (CIM), and runs correlation searches, risk-based alerting and ML to detect and investigate threats. Splunk SOAR (formerly Phantom) adds playbook-driven orchestration, automation and case management. Together they solve the SOC's core problem — turning high-volume, heterogeneous machine data into prioritized, investigable findings and then automating the response. As of ES 8.x the analyst experience (the former Mission Control) and SOAR automation are converged into a single investigation surface.

## Capabilities & architecture

**Core capabilities**
- Analytics-driven SIEM: correlation searches, 1700+ out-of-the-box detections via the Enterprise Security Content Update (ESCU) app, SPL (Search Processing Language) ad-hoc search and threat hunting
- Risk-Based Alerting (RBA): assigns risk scores to assets/identities, aggregates low-fidelity 'intermediate findings' over time into a single risk index, and fires a finding/alert only when a risk threshold is crossed — reduces alert fatigue and surfaces slow, multi-stage attacks
- Unified analyst workspace (Mission Control, now native in ES 8): findings/alert queue, investigations, response plans, standardized terminology, and embedded SOAR actions in one UI
- Splunk SOAR: visual drag-and-drop playbook editor plus custom Python logic, 300+ app/connector integrations, automated enrichment/containment, case management; now delivered as a native capability within Enterprise Security (hybrid: ES Cloud can connect to one on-prem SOAR instance)
- Threat Intelligence Management: ingestion/normalization of threat feeds and indicators; Cisco Talos intelligence integration across ES, SOAR and Attack Analyzer
- User & entity behavior analytics via Splunk UBA (UEBA) — ML-based anomaly and insider-threat detection
- Framework mapping and visualization: MITRE ATT&CK tactic/technique coverage, plus NIST, CIS Critical Security Controls and Lockheed Martin Cyber Kill Chain
- Federated Analytics / federated search: analyze data in place (e.g., Amazon Security Lake) and selectively bring data into Splunk for frequent detection
- AI Assistant in ES (8.2+): natural-language SPL generation, finding summarization, and auto-generated investigation reports (admin-enabled; choice of Frontier or Splunk-hosted models)
- Splunk Attack Analyzer: automated analysis/detonation of suspected malware and credential-phishing threats
- Dashboards, Glass Tables, notable-event framework, asset & identity framework, and compliance reporting

**Architecture & deployment.** Delivered as Splunk Cloud Platform (SaaS, the strategic default) or self-managed Splunk Enterprise (on-prem/private-cloud software), with hybrid options. Architecture is a distributed tier: universal/heavy forwarders and HTTP Event Collector (HEC) ship data to indexers (storage + indexing), search heads run ES/SPL, and ES is a premium app layered on the Splunk platform. It is agent-capable (forwarders) but primarily log/telemetry-ingest and API-based rather than inline; it sits downstream of the environment as the analytics/correlation and response hub, not in the data path. SOAR deploys as cloud or on-prem and executes playbooks against integrated tools via APIs.

**Editions & licensing.** Licensing is moving to Workload Pricing measured in Splunk Virtual Compute (SVC) units (compute/memory/IO driven by search volume/complexity and daily indexing), alongside legacy ingest-based (GB/day) and entity-based options; packages or individual products. Security editions include Splunk Enterprise Security and Splunk Enterprise Security Premier — Premier is a separately priced, workload-based edition that bundles the AI SOC / advanced capabilities (e.g., AI Assistant, Attack Analyzer, native SOAR). Splunk SOAR and Splunk UBA are separately licensed. List SVC pricing is not published — ES/Premier require a Splunk or partner quote (reported third-party figures ~$55k–$75k per SVC/yr, unverified). Verify exact edition packaging and SVC counts in a current quote.

**Key integrations.** Cisco security portfolio post-acquisition: Cisco Talos threat intelligence, and tightening integration with Cisco XDR / Secure Firewall / Duo; Cloud: AWS (incl. Amazon Security Lake via Federated Analytics), Azure, GCP; Kubernetes/container telemetry; Identity: Active Directory/Entra ID, Okta, and other IdPs feeding the asset & identity framework; ITSM/ticketing: ServiceNow, Jira, PagerDuty (via SOAR playbooks/connectors); EDR/NDR/firewall/email/cloud-security tools: CrowdStrike, Microsoft Defender, Palo Alto, and 300+ SOAR apps for enrichment and containment; Vulnerability scanners: Tenable, Qualys, Rapid7 (ingested as data sources / CIM Vulnerabilities data model); Splunk ecosystem: Splunk SOAR, Splunk UBA, Splunk Attack Analyzer, Splunk Observability/ITSI.

**Differentiators**
- Unmatched data-platform flexibility: SPL and schema-on-read ingest virtually any data source, making ES extensible to custom detections and non-standard telemetry that rigid SIEMs can't model
- Risk-Based Alerting is a mature, widely-emulated model for cutting alert volume and detecting multi-stage/low-and-slow attacks
- Deep, tightly-coupled SIEM+SOAR+UEBA+Attack Analyzer stack under one vendor, now converged into a single ES 8 analyst experience
- Large detection content library (ESCU) and strong community/app ecosystem (Splunkbase)
- Cisco ownership adds first-party Talos intelligence and a path to network-to-endpoint-to-SIEM telemetry correlation

**Limitations & considerations**
- Cost and cost-predictability are the perennial complaint; even under workload/SVC pricing, heavy search or ingest drives expense, and ES/Premier pricing is opaque and enterprise-scale
- Operational complexity: getting value requires skilled Splunk engineers, careful CIM data onboarding/normalization, and ongoing detection tuning — it is not turnkey
- SOAR's position is now 'native capability within ES' rather than a flagship standalone; buyers should confirm roadmap/support commitments (a point competitors exploit in migration pitches)
- ES is an analytics/response layer, not a scanner — it has no native vulnerability discovery and depends on ingesting scanner data for VM context
- AI Assistant is admin/account-gated and not on by default; Talos-integration GA timing and some ES 8.x capabilities should be verified against current docs
- Version churn: ES 7.3 reaches end of support Feb 28, 2026 — migration to 8.x (new converged UI) is a non-trivial project

## Vulnerability-mitigation role

Splunk is a detection, monitoring and virtual-patching-orchestration control rather than a patching tool. When a vulnerability cannot be patched immediately, ES mitigates exposure by (1) ingesting scanner output (Tenable/Qualys/Rapid7) into the CIM Vulnerabilities data model and correlating it with live asset/identity risk and exploit telemetry to prioritize what truly matters; (2) building correlation searches / RBA detections for exploitation attempts against the specific CVE (e.g., matching IDS/WAF/firewall/EDR signatures to the affected assets) so an unpatched system is watched intensively; and (3) using SOAR playbooks to execute compensating controls automatically — push WAF/firewall block rules, isolate a host via EDR, disable an account, open a ticket, and notify — effectively orchestrating a virtual patch during the window before the fix lands. It closes the loop by validating that the compensating control stopped the exploit attempts and that remediation occurred.

**VM lifecycle:** Prioritize · Mitigate · Validate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: Detect (primary), Respond, Identify (asset/vuln context), Govern/Protect (reporting, orchestrated controls); CIS Controls v8: 8 (Audit Log Management — core), 13 (Network Monitoring & Defense), 17 (Incident Response Management), 16 (Application Software Security monitoring), 7 (Continuous Vulnerability Management — via ingested scan data), 6 (Access Control monitoring); MITRE ATT&CK: platform maps detections to ATT&CK techniques for coverage analysis; as compensating-control orchestration it supports mitigations such as M1031 (Network Intrusion Prevention), M1037 (Filter Network Traffic), M1030 (Network Segmentation), M1018 (User Account Management), M1049 (Antivirus/Antimalware) executed via SOAR; MITRE Engage/detection-focused and Lockheed Martin Cyber Kill Chain mapping also supported in ES framework insights

**In a critical-CVE scenario.** First 24-72h after a critical CVE in an internet-facing app and a cloud workload: (0-4h) Run SPL/threat-hunt searches across ingested logs for IOCs and exploitation patterns; query the Vulnerability data model to identify which internet-facing and cloud assets are affected and their risk/identity context. (4-24h) Stand up a targeted RBA/correlation detection for the CVE's exploitation signature (WAF, IDS, EDR, cloud audit logs), map it to the relevant MITRE ATT&CK techniques, and raise its risk weighting; enrich with Talos/threat-intel indicators. (24-72h) Trigger SOAR playbooks to deploy compensating controls — WAF/edge block rules, security-group/NACL tightening on the cloud workload, host isolation, credential resets — create and track the remediation case in Mission Control, alert stakeholders, and continuously monitor for bypass while patching proceeds; validate closure once patched.

## Validation & telemetry

**Log sources**
- Forwarder-ingested device/app logs normalized by source-specific CIM Technology Add-ons (e.g. Splunk_TA_paloalto, Splunk_TA_zscaler, TA-microsoft-mdatp/defender, Splunk_TA_nix/windows, Splunk_TA_aws)
- HTTP Event Collector (HEC) JSON — common for cloud/WAF/EDR webhook delivery
- Syslog via Splunk Connect for Syslog (SC4S) for CEF/LEEF (firewalls, IPS, WAF)
- Modular/scripted REST inputs polling vendor APIs (e.g. MDE, AWS CloudTrail/Config, Entra sign-in logs)
- CIM-accelerated data models stored as tsidx summaries under Splunk_SA_CIM (queried with tstats / `| from datamodel`)
- ES-generated indexes: 'notable' (findings), 'risk' (RBA intermediate findings), and the risk/threat/asset-identity KV stores and lookups

**Telemetry format / transport.** Ingested as raw events via Universal/Heavy Forwarders (S2S on TCP 9997), HTTP Event Collector (HEC, JSON over HTTPS 8088), syslog (UDP/TCP 514 or CEF/LEEF via a syslog-ng/SC4S collector), file/dir monitors, and scripted/modular inputs (REST/API pollers). On top of raw data, Splunk normalizes through the Common Information Model (CIM): Technology Add-ons (TAs) do field extraction + aliasing + eventtypes/tags at search time so disparate sources map to the same CIM field names. Enterprise Security consumes CIM-accelerated data models (tsidx acceleration summaries) and emits its own artifacts: notable events to the 'notable' index and risk events to the 'risk' index. Splunk is a normalization/detection and validation layer, not an inline enforcement control itself — it observes the evidence other controls produce. Note: in ES 8.x the UI terminology changed — 'correlation searches' are now 'detections' and 'notable events' are 'findings'; the underlying savedsearch objects, 'notable' index and risk framework are unchanged, so older SPL/macros still work.

**Control-presence check (present & configured?).** Confirm the control's telemetry is actually arriving and CIM-mapped, and that the ES detection is enabled: (1) Data-model acceleration + feed health — `| rest /services/data/models splunk_server=local | search acceleration=1 | table title acceleration acceleration.earliest_time`, and freshness per CIM node via `| tstats max(_time) as last from datamodel=<Model>.<Dataset> by <dvc/vendor_product>`. (2) Detection/correlation-search enablement — `| rest /servicesNS/-/SplunkEnterpriseSecuritySuite/saved/searches | search action.correlationsearch.enabled=1 disabled=0 | table title cron_schedule action.notable action.risk`. (3) Forwarder/agent heartbeat — `| metadata type=hosts index=<idx> | eval age=now()-lastTime` or the DMC/forwarder-management 'missing forwarders' view; `index=_internal source=*metrics.log group=tcpin_connections` for S2S liveness. (4) CIM compliance of a given source — run the TA's 'eventtypes'/'tags' and confirm the source populates the expected CIM fields (e.g. `| tstats count from datamodel=Intrusion_Detection.IDS_Attacks by IDS_Attacks.vendor_product` shows the IPS is mapped). On the host side, Splunk itself doesn't read registry/agent state — that evidence comes from the Windows/Defender/endpoint TA events it ingests (e.g. the Inventory/Updates/Vulnerabilities data models).

**Validation signals (actually working?)**
- 'Configured' vs 'actually enforced' is distinguished by the action field value: Intrusion_Detection.IDS_Attacks action IN (blocked, denied, dropped, prevented) — as opposed to action=allowed/alerted — proves the IPS/IDS Prevented rather than only logged
- Web data model action value indicating a proxy/WAF deny (vendor-specific: Zscaler action=blocked, Palo Alto URL action=block-url/deny, AWS WAF action=BLOCK) tied to the signature/rule for the CVE
- Malware data model action=blocked/quarantined/deleted with a signature, proving AV/EDR actively stopped (not just detected) a sample
- Vulnerabilities data model: the CVE NO LONGER appearing on a host after a scan post-patch = reachability/vulnerable-surface removed (remediation validated); presence of the cve still reporting = not remediated
- Change data model events (action=modified/created/deleted) proving a config-hardening or patch change was actually applied
- Authentication data model action transitions proving an MFA/conditional-access or credential-rotation control took effect (e.g. failures stop, or a new src/auth method appears)
- ES artifact existence: a notable in index=notable with the detection's rule_name/search_name, or risk events in index=risk with risk_object + risk_score + annotations.mitre_attack, proving the detection fired on the evidence

**Key events / fields / tables / APIs**
- CIM data models (query via tstats/`from datamodel`): Intrusion_Detection.IDS_Attacks (fields: action, signature, signature_id, src, dest, dest_port, category, severity, vendor_product, dvc)
- Web / Web.Proxy (action, url, http_method, status, src, dest, user, bytes_in/out, category, vendor_product)
- Vulnerabilities.Vulnerabilities (cve, signature, signature_id, severity, cvss, dest, dvc, vendor_product); 'cve' = CVE id, 'severity' prescribed values critical/high/medium/low/informational/unknown
- Malware.Malware_Attacks / Malware_Operations (action, signature, file_name, file_hash, dest, vendor_product)
- Change / Change.All_Changes (action, change_type, object, object_category, command, user, dvc) — replaces deprecated Change_Analysis (deprecated as of CIM 4.12.0)
- Authentication.Authentication (action [success/failure/unknown], app, src, dest, user, authentication_method, authentication_service; 'reason' added in CIM 4.16.0)
- Updates.Update and Inventory data models for patch/installed-software presence
- ES/REST objects: /services/data/models (acceleration state), /servicesNS/-/SplunkEnterpriseSecuritySuite/saved/searches (action.correlationsearch.enabled, action.notable, action.risk), /services/configs/conf-savedsearches
- ES indexes/fields: index=notable (search_name, rule_name, urgency, status, owner), index=risk (risk_object, risk_object_type, risk_score, source, annotations.mitre_attack, threat_object)
- Internal health: index=_internal source=*metrics.log group=tcpin_connections; `| rest /services/admin/inputstatus`; DMC acceleration dashboards; `| tstats` against Splunk_SA_CIM summaries

**Example queries**

*Presence check: confirm each IPS/IDS sensor is CIM-mapped and emitting events within the last hour (control exists and is reporting)* (spl)

```spl
| tstats summariesonly=false count, max(_time) as last_event from datamodel=Intrusion_Detection.IDS_Attacks by IDS_Attacks.dvc, IDS_Attacks.vendor_product | rename IDS_Attacks.* as * | eval age_min=round((now()-last_event)/60,1) | where age_min < 60 | sort - count
```

*Validation (actively enforcing, not just configured): prove the IPS BLOCKED exploitation of a specific CVE rather than only alerting* (spl)

```spl
| tstats summariesonly=true count, values(IDS_Attacks.action) as actions from datamodel=Intrusion_Detection.IDS_Attacks where IDS_Attacks.signature="*CVE-2024-3400*" by IDS_Attacks.dest, IDS_Attacks.signature, IDS_Attacks.vendor_product | rename IDS_Attacks.* as * | eval enforced=if(match(mvjoin(actions,","),"blocked|denied|dropped|prevent"),"PREVENTED","ALERT-ONLY") | table dest signature vendor_product actions enforced count
```

*Mitigation-closure validation: confirm a host no longer reports the CVE after patching (vulnerable surface removed), with age since last seen* (spl)

```spl
| tstats summariesonly=false latest(Vulnerabilities.severity) as severity, latest(Vulnerabilities.cvss) as cvss, latest(_time) as last_seen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2024-3400" by Vulnerabilities.dest, Vulnerabilities.signature | rename Vulnerabilities.* as * | eval days_since_last_report=round((now()-last_seen)/86400,1) | eval status=if(days_since_last_report>7,"LIKELY REMEDIATED","STILL VULNERABLE") | table dest signature severity cvss days_since_last_report status
```

*Governance check: list enabled ES detections/correlation searches and whether they create a notable and/or write risk (confirms the detection-as-control is actually on)* (spl)

```spl
| rest /servicesNS/-/SplunkEnterpriseSecuritySuite/saved/searches splunk_server=local | search action.correlationsearch.enabled=1 disabled=0 | rename action.correlationsearch.label as detection | eval writes_notable=if('action.notable'=1,"yes","no"), writes_risk=if('action.risk'=1,"yes","no") | table detection cron_schedule writes_notable writes_risk search
```

**How it mitigates (mechanism).** Splunk does not block inline; it is the evidence/normalization and detection-as-control layer — CIM normalization lets one query assert the same thing across every vendor, and tstats over accelerated data models reads the observable proof (action=blocked/denied, cve no longer present, action=quarantined) that an upstream control enforced. Enforcement/response it can drive is through adaptive-response / ES actions and SOAR playbooks (create notable, write risk score, trigger a ticket, or call a block action), so the mitigation signal and any automated reaction are both tied to the normalized field that proved enforcement.

**Logging gotchas**
- tstats with summariesonly=true only reads the acceleration summary — if a data model's acceleration lags or a backfill hasn't completed, recent blocks/events are silently missing; always check acceleration freshness (`| rest /services/data/models`) before trusting a 'nothing found' result as 'not happening'
- CIM compliance is entirely dependent on the source TA: if the vendor TA isn't installed/current or a custom source isn't tagged, events exist in the index but never appear in the data model — your validation query returns zero while the control is working fine
- The 'action' field is NOT standardized across vendors — one source uses blocked/denied/dropped, another uses deny/reset-both/block-url; you must know each vendor's verb set or an 'enforced' filter will undercount. Splunk CIM prescribes allowed values for some fields (Authentication.action, Vulnerabilities.severity) but Web.action values are vendor-dependent
- A notable existing proves the detection fired, not that a mitigation worked — distinguish 'detection matched suspicious activity' from 'control blocked it' by inspecting the underlying action field, not the notable's presence
- Verbose per-request/allow logging (e.g. full proxy allow events, firewall permits) is frequently dropped at the source or filtered at ingest for license/volume reasons, so absence of allow events is not evidence; block events may also be sampled
- Index retention + data-model acceleration retention are separate and often shorter than raw retention — historical mitigation validation beyond the acceleration window requires summariesonly=false (slower) or raw search
- ES 8.x renamed correlation searches to 'detections' and notables to 'findings'; macros/dashboards written against the old names still work but documentation/UI references diverge by version — confirm which ES version the tenant runs
- Host-presence checks (registry keys, agent config, patch level) are only as good as the ingested endpoint TA (Updates/Inventory/Vulnerabilities data models) — Splunk has no agent-side introspection of its own; a stale scanner feed will show a control/patch as absent when it is present, and vice versa

## Documentation & repositories

_Official documentation & manuals_
- [Splunk Enterprise Security docs (latest)](https://docs.splunk.com/Documentation/ES/latest)
- [ES Install and Upgrade Manual](https://docs.splunk.com/Documentation/ES/latest/Install/Overview)
- [Use Splunk Enterprise Security (analyst workflow)](https://docs.splunk.com/Documentation/ES/latest/User)
- [Administer Splunk Enterprise Security](https://docs.splunk.com/Documentation/ES/latest/Admin)
- [Splunk Help Center (new docs portal)](https://help.splunk.com/en/splunk-enterprise-security)
- [Splunk Enterprise Security product page](https://www.splunk.com/en_us/products/enterprise-security.html)
- [Splunk Enterprise core docs (platform)](https://docs.splunk.com/Documentation/Splunk/latest)

_API & developer docs_
- [Splunk Developer Portal (dev.splunk.com)](https://dev.splunk.com)
- [Splunk Enterprise REST API reference](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog)
- [REST API tutorial](https://docs.splunk.com/Documentation/Splunk/latest/RESTTUT/RESTbasicuse)
- [Splunk Cloud Platform REST API reference](https://help.splunk.com/en/splunk-cloud-platform/rest-api-reference)
- [Splunk SDK documentation index](https://docs.splunk.com/Documentation/SDK)
- [Splunk SDK for Python docs](https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python)
- [Terraform Splunk provider (registry)](https://registry.terraform.io/providers/splunk/splunk/latest/docs)

_GitHub (official)_
- [Splunk official GitHub org](https://github.com/splunk)
- [splunk/security_content (Splunk Threat Research detections / ESCU)](https://github.com/splunk/security_content)
- [splunk/attack_range (attack simulation lab)](https://github.com/splunk/attack_range)
- [splunk/splunk-sdk-python](https://github.com/splunk/splunk-sdk-python)
- [splunk/docker-splunk (official container images)](https://github.com/splunk/docker-splunk)
- [splunk/terraform-provider-splunk](https://github.com/splunk/terraform-provider-splunk)

_Community / integration / detection repos_
- [SigmaHQ/sigma (generic detection rules, converts to SPL)](https://github.com/SigmaHQ/sigma)
- [redcanaryco/atomic-red-team (ATT&CK-mapped tests for detection validation)](https://github.com/redcanaryco/atomic-red-team)
- [splunk/attack_data (datasets to test detections)](https://github.com/splunk/attack_data)
- [splunk/contentctl (build/test/package detection content)](https://github.com/splunk/contentctl)
- [splunk-soar-connectors (SOAR/Phantom playbook integrations)](https://github.com/splunk-soar-connectors)

_Learning & reference_
- [Splunk Research / detection content browser (ESCU)](https://research.splunk.com)
- [Splunk Education & Training](https://www.splunk.com/en_us/training.html)
- [Splunk Lantern (use cases & getting-started guidance)](https://lantern.splunk.com)
- [Splunk Security Blog](https://www.splunk.com/en_us/blog/security.html)
- [Splunk Community (Q&A, Splunk Dev)](https://community.splunk.com)
- [Splunkbase (apps & add-ons marketplace, incl. ES add-ons)](https://splunkbase.splunk.com)

> Note: Splunk was acquired by Cisco (2024); product branding is transitioning but docs/repos remain under Splunk. Documentation is actively migrating from docs.splunk.com to the newer help.splunk.com Help Center — both are live; docs.splunk.com still hosts versioned ES manuals and the version selector. Current ES major line is 8.x (search also surfaced legacy 3.x–4.x/7.x pages — ignore for current deployments). Enterprise Security ships the ESCU (DA-ESS-ContentUpdate) content pack built from splunk/security_content; research.splunk.com is updated daily. REST API runs over HTTPS on splunkd management port 8089; Cloud Platform exposes a subset of Enterprise endpoints. Splunkbase and some training/education resources require a (free) Splunk account login.

## Current state (2025-26)

Cisco completed its $28B acquisition of Splunk on March 18, 2024; Splunk is now a Cisco company and the products carry Cisco Talos threat-intelligence integration. Splunk Enterprise Security 8.x is the current line: 8.0 GA Sept 2024 (folded the former Mission Control into ES as the unified analyst experience), 8.1 (June 2025, detection version comparison), 8.2/8.2.1 (Sept 2025, added the ES AI Assistant for NL SPL generation, finding/investigation summarization, and a hybrid ES-Cloud-to-on-prem-SOAR pairing); Splunk's own documentation now publishes user guides through ES 8.6/8.7, indicating further 2026 releases past 8.2 — verify the exact latest point release. Splunk SOAR (ex-Phantom) is still named Splunk SOAR but is now positioned as a native capability within Enterprise Security; AI SOC features are delivered through the separately-priced, workload-based Enterprise Security Premier edition. ES 7.3 end of support is Feb 28, 2026. Workload (SVC) pricing is the strategic model; published SVC/Premier list prices are not available — verify via quote. Talos-integration GA timing across ES/SOAR/Attack Analyzer should be verified against current Splunk docs.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
