# Akamai App & API Protector

*Akamai Technologies · Cloud/edge WAAP (Web Application and API Protection) delivered on a global CDN*

App & API Protector (AAP) is Akamai's flagship WAAP, launched November 2021 as the consolidation and successor to the older Kona Site Defender (KSD) and Web Application Protector (WAP) lines. It bundles a web application firewall, L7 DDoS protection, bot management, and API security into one product running inline on Akamai's globally distributed edge network, so malicious requests are inspected and dropped at thousands of edge PoPs before they ever reach the origin. It solves the problem of protecting internet-facing web apps and APIs against the OWASP Top 10, volumetric and application-layer DDoS, automated bot abuse, and API-specific attacks without the customer operating any appliances.

## Capabilities & architecture

**Core capabilities**
- Adaptive Security Engine: ML-driven, self-tuning rule engine that combines a signature/heuristic negative model with anomaly scoring to cut false positives and auto-adapt protections
- Web application firewall covering OWASP Top 10 (SQLi, XSS, RFI/LFI, command injection, etc.) with Akamai-curated managed rule groups and custom rules
- Layer 7 (application-layer) DDoS defense plus rate controls, slow-POST protection, and client reputation (IP intelligence) scoring
- API discovery (automatic detection of shadow/undocumented APIs from live traffic) and positive-security API request validation against an OpenAPI/schema model at the edge
- Built-in bot detection with a directory of 1,500+ known bots; escalates to the separately licensed Bot Manager for advanced/adversarial bots and browser-impersonation detection
- Edge malware/file scanning to inspect uploads before they reach the origin
- AI-powered security dashboards that surface anomalies, threats, and suggested configuration improvements
- Rapid Rules / Akamai-managed updates: Akamai threat team pushes new CVE-specific protections automatically
- App & API Protector Hybrid to extend policy enforcement off the Akamai platform (on-prem, hybrid cloud, multi-CDN)

**Architecture & deployment.** SaaS delivered inline as a reverse proxy on Akamai's global edge CDN. Customer points DNS at Akamai; all HTTP/HTTPS (and TLS-terminated) traffic transits edge servers where WAF/bot/DDoS/API policy is evaluated before forwarding clean traffic to origin. No customer appliances or agents. Managed via Akamai Control Center and Akamai APIs/Terraform; config pushes propagate network-wide (user reviews cite ~20 minutes to activate/roll back). App & API Protector Hybrid extends enforcement to non-Akamai-fronted assets. Separate add-on deployment for the dedicated API Security product (reinforced by the 2024 Noname Security acquisition).

**Editions & licensing.** Positioned as the mid/high tier of Akamai's WAAP family: Web Application Protector (entry, simplified) below it, and Kona Site Defender (highly customizable, enterprise negative-security control) as the more configurable sibling still sold for advanced use cases. Licensing is subscription/consumption-based, typically tied to clean traffic volume (bandwidth/requests) plus number of protected properties; Bot Manager, API Security (Noname-based), and Hybrid are priced as add-ons. Enterprise contract pricing; reviewers consistently note it is expensive. No public per-unit list price.

**Key integrations.** SIEM/SOAR via Akamai SIEM integration (Splunk, Microsoft Sentinel, QRadar, Chronicle) and the DataStream log feed; Akamai ecosystem: Bot Manager, API Security (Noname), Client-Side Protection & Compliance, Guardicore microsegmentation, Prolexic (network-layer DDoS); Terraform provider and Akamai OPEN APIs for CI/CD and config-as-code; Webhook/syslog export to ticketing and incident tooling; identity enforced upstream at origin/IdP (AAP is not an IdP).

**Differentiators**
- Runs on one of the largest global edge networks, absorbing massive DDoS close to the attacker and reducing origin exposure
- Adaptive Security Engine self-tuning reduces manual rule maintenance and false positives
- Single bundle unifying WAF, L7 DDoS, bot, and API security, with automatic API discovery at the edge
- Akamai-managed Rapid Rules mean new CVE protections arrive without customer action
- Deep API-security bench reinforced by the 2024 Noname Security acquisition

**Limitations & considerations**
- Premium/enterprise pricing; smallest customers may find KSD/AAP cost-prohibitive
- Config change propagation and rollback can take ~20 minutes (reviewer-reported), slowing rapid tuning during an incident
- Protects only traffic routed through Akamai's edge (or Hybrid); assets bypassing the CDN or reached over uninspected protocols are not covered
- Some reviewers rate its pure app-layer attack efficacy and documentation below best-in-class competitors (e.g., Cloudflare)
- Advanced bot defense and full API security require additional licensed modules, raising true cost
- ML self-tuning reduces but does not remove the need for expert tuning on complex apps

## Vulnerability-mitigation role

Acts as a virtual-patching / compensating control at the network edge: when a critical CVE drops in an internet-facing app, Akamai (or the customer) deploys a CVE-specific signature or custom rule that blocks exploit-shaped requests before they reach the vulnerable origin, closing the exposure window while the real code/library patch is scheduled and tested. Rapid Rules let Akamai push protection automatically. It does not fix the vulnerable code — it reduces exploitability and blast radius temporarily, and should be tracked with an owner and retirement date tied to the remediation ticket.

**VM lifecycle:** Discover · Mitigate · Monitor/Detect · Validate

**Framework mapping:** NIST CSF 2.0: PROTECT (PR.PS, PR.IR), DETECT (DE.CM), RESPOND (RS.MI); IDENTIFY (ID.AM) via API discovery; CIS Controls v8: 13.10 (application-layer filtering/WAF), 7 (continuous vulnerability management - compensating control), 16 (application software security), 8 (audit log management); MITRE ATT&CK mitigations: M1050 Exploit Protection, M1037 Filter Network Traffic, M1031 Network Intrusion Prevention, M1036 Account Use Policies (bot/credential-stuffing controls)

**In a critical-CVE scenario.** First 24-72h on a critical internet-facing CVE: (1) Confirm which properties/paths are exposed; (2) enable the Akamai-published Rapid Rule for the CVE or author a custom WAF rule targeting the exploit pattern, deployed first in alert/log-only mode; (3) validate attack traffic is blocked while legitimate flows pass, then switch to deny and push network-wide; (4) raise rate controls/client-reputation blocking and watch the AI dashboard and SIEM feed for exploitation attempts; (5) for the cloud workload, front it with AAP or Hybrid so the same virtual patch applies; keep the rule as a tracked temporary control until the code/library is patched and verified.

## Validation & telemetry

**Log sources**
- SIEM Integration API (pull): GET https://{akab-host}.luna.akamaihost.net/siem/v1/configs/{configId} with EdgeGrid auth; offset mode (offset/limit) or time-based mode (from/to). Returns NDJSON. Credential must have the SIEM API service enabled with READ-WRITE; operator needs the 'Manage SIEM' role in Control Center.
- DataStream 2 (push): the Security data set / 'security data format', delivered to S3/Splunk/Datadog/HTTPS endpoints. Separate from access/performance DataStream logs.
- Connectors that pull the SIEM API: Splunk 'Akamai SIEM Integration' add-on (sourcetype akamai:siem / Akamai:SIEM), Sumo Logic Akamai SIEM API C2C source, Elastic Akamai integration, Google SecOps/Chronicle AKAMAI_SIEM_CONNECTOR + Akamai WAF parsers, Dynatrace, Microsoft Sentinel (via connector into a custom Log Analytics table).
- Akamai Control Center Security Center / Web Security Analytics (console view) and the Application Security (appsec) API for the policy/config state itself.

**Telemetry format / transport.** JSON security events. Two emission paths: (1) SIEM Integration API pull — newline-delimited JSON (NDJSON), one record per security event, EdgeGrid-authenticated GET. (2) DataStream 2 push — the 'Security' data set delivered over HTTPS/raw to S3, Splunk, Datadog, etc. Downstream connectors commonly re-emit as CEF (act = appliedAction) or vendor-normalized JSON (Elastic ECS, Chronicle UDM, Sentinel custom table).

**Control-presence check (present & configured?).** Confirm the security configuration is active and in BLOCK (deny), not alert-only: (a) Control Center > Security Configurations shows the config version activated on the Production network. (b) Application Security API: GET /appsec/v1/configs/{configId}/versions/{version}/security-policies/{policyId} and the per-protection action resources (e.g. .../attack-group-actions, .../rules — each protection returns an action of 'alert' or 'deny'); 'deny' means enforcing, 'alert' means detect-only. (c) Confirm telemetry egress exists: SIEM API credential has SIEM service READ-WRITE and a client is polling /siem/v1/configs/{configId}; or a DataStream 2 stream with the Security data set is in 'Activated' state. Rapid Rules / Adaptive Security Engine attack groups default to alert when newly added, so check their action explicitly.

**Validation signals (actually working?)**
- attackData.appliedAction = "deny" on a real event = the request was actually blocked (this is the aggregate/final action applied to the request, sits at attackData level).
- attackData.ruleActions (URL-encoded, base64, semicolon-separated per matched rule, e.g. decodes to alert;alert;deny) containing 'deny' — the per-rule verdict; must be base64-decoded before evaluating.
- attackData.ruleTags identifying the matched protection (e.g. OWASP_CRS/WEB_ATTACK/... or AKAMAI/POLICY/...) tying the block to the CVE/signature; attackData.ruleMessages carries the human-readable rule name; attackData.ruleData shows the matched payload / anomaly score.
- For anomaly-scored virtual patches: a policy-level rule (e.g. *-ANOMALY) with ruleAction deny whose ruleData shows vector score >= deny threshold — proves the aggregate scoring crossed the enforcement line, not just an individual alert.
- Distinguish configured vs effective: appsec API protection action = 'deny' proves it is CONFIGURED to block; an event with appliedAction=deny + httpMessage.status (e.g. 403) proves it ACTUALLY blocked a request.

**Key events / fields / tables / APIs**
- attackData.configId, attackData.policyId, attackData.clientIP, attackData.appliedAction, attackData.ruleActions, attackData.rules, attackData.ruleVersions, attackData.ruleMessages, attackData.ruleTags, attackData.ruleData, attackData.ruleSelectors, attackData.clientReputation, attackData.apiId/apiKey, attackData.slowPostAction/slowPostRate
- httpMessage.* (requestId, start, protocol, method, host, path, requestHeaders, status, bytes, responseHeaders) and geo.* (country, region, city, asn)
- SIEM API: GET /siem/v1/configs/{configId} (offset=.. & limit=.. OR from=.. & to=..); 5s intentional latency, ordered by storage time
- Splunk add-on sourcetype akamai:siem; Chronicle parsers AKAMAI_SIEM_CONNECTOR / AKAMAI_WAF (maps attackData.ruleActions deny -> security_result.action BLOCK, alert -> ALLOW); CEF mapping act = appliedAction

**Example queries**

*Pull recent security events for a config and confirm live blocking telemetry exists* (bash/curl (SIEM API, EdgeGrid))

```
http --auth-type edgegrid -a default: GET ":/siem/v1/configs/{configId}?from=$(date -d '-15 min' +%s)&to=$(date +%s)"   # NDJSON; grep/jq for \"appliedAction\":\"deny\"
```

*Validate the control is actually blocking and attribute blocks to the CVE/signature rule tag* (Splunk SPL)

```
index=akamai sourcetype="akamai:siem" "attackData.appliedAction"=deny | spath input="attackData.ruleTags" | stats count by attackData.policyId, attackData.ruleTags, attackData.ruleMessages | sort - count
```

*Separate enforced (deny) from detect-only (alert) over time per policy* (KQL (Sentinel custom table))

```
Akamai_SIEM_CL | extend applied = tostring(attackData_appliedAction_s) | summarize deny=countif(applied=='deny'), alert=countif(applied=='alert') by bin(TimeGenerated,1h), tostring(attackData_policyId_s)
```

**How it mitigates (mechanism).** Inline block at the Akamai edge (reverse proxy): a request matching a managed/custom WAF rule or crossing the adaptive anomaly deny-threshold is terminated at the edge (deny, typically 403) before reaching origin — a true virtual patch. The observable proof is attackData.appliedAction=deny with the matching ruleTags/ruleMessages.

**Logging gotchas**
- Default/newly-added protections and Rapid Rules often ship in 'alert' (monitor) mode — they generate events but do NOT block; alert-mode traffic is passed to origin.
- Normalizers treat alert as ALLOW (e.g. Chronicle maps only 'deny' -> BLOCK), so alert-only rules never appear as blocks in the normalized view — always check the raw appliedAction/ruleActions.
- attackData.ruleActions is URL-encoded base64 and semicolon-separated; un-decoded it looks like opaque junk. Decode before filtering.
- SIEM API has a built-in ~5s latency and orders by storage (not event) time; offset mode can surface late-stored events out of order; design detections to tolerate reordering, and use time-based mode to replay up to the last 12h after an outage.
- A single request matching multiple rules may be split into one event per rule by some connectors (Sumo Logic), duplicating attackData — dedupe on httpMessage.requestId before counting.
- DataStream 2 access logs are NOT the security feed; App & API Protector events come from the SIEM API or the DataStream Security data set specifically.

## Documentation & repositories

_Official documentation & manuals_
- [App & API Protector (TechDocs home)](https://techdocs.akamai.com/cloud-security/docs/app-api-protector)
- [App & API Protector product page](https://www.akamai.com/products/app-and-api-protector)
- [Web Application Protector (simplified WAF variant)](https://www.akamai.com/products/web-application-protector)
- [Akamai TechDocs (full documentation portal)](https://techdocs.akamai.com/home)

_API & developer docs_
- [Application Security API reference (configures AAP/WAP: policies, WAF modes, rate/custom rules)](https://techdocs.akamai.com/application-security/reference/api)
- [Akamai Terraform provider — overview & akamai_appsec_* resources](https://techdocs.akamai.com/terraform/docs/overview)
- [Akamai Terraform provider (Terraform Registry)](https://registry.terraform.io/providers/akamai/akamai/latest/docs)
- [EdgeGrid authentication (required for all Akamai APIs)](https://techdocs.akamai.com/developer/docs/authenticate-with-edgegrid)
- [Akamai CLI for Application Security (cli-appsec) docs](https://techdocs.akamai.com/cli/docs/appsec)

_GitHub (official)_
- [Akamai GitHub org](https://github.com/akamai)
- [akamai/cli (Akamai CLI)](https://github.com/akamai/cli)
- [akamai/cli-appsec (CLI plugin for Application Security)](https://github.com/akamai/cli-appsec)
- [akamai/terraform-provider-akamai](https://github.com/akamai/terraform-provider-akamai)
- [akamai/AkamaiOPEN-edgegrid-golang (Go EdgeGrid auth lib used by provider/CLI)](https://github.com/akamai/AkamaiOPEN-edgegrid-golang)
- [akamai/AkamaiOPEN-edgegrid-python](https://github.com/akamai/AkamaiOPEN-edgegrid-python)

_Community / integration / detection repos_
- [Pulumi Akamai provider (AppSec resources: security policies, custom/rate rules, WAF mode)](https://github.com/pulumi/pulumi-akamai)
- [akamai/cli-terraform (export existing AAP config to Terraform HCL)](https://github.com/akamai/cli-terraform)
- [akamai/PowerShell (PowerShell module over Akamai APIs)](https://github.com/akamai/PowerShell)

_Learning & reference_
- [Akamai TechDocs Developer hub](https://techdocs.akamai.com/developer/docs)
- [Akamai Community](https://community.akamai.com)
- [Akamai Security blog](https://www.akamai.com/blog/security)
- [App & API Protector getting-started / best practices](https://techdocs.akamai.com/cloud-security/docs/welcome-to-app-api-protector)

> Note: App & API Protector (AAP) is the current flagship WAF/WAAP; Web Application Protector (WAP) is the lighter self-service variant and Kona Site Defender is the legacy enterprise WAF — all three share the same Application Security API and akamai_appsec_* Terraform resources. There is no separate 'App & API Protector API' — it is configured through the Application Security API. All APIs require EdgeGrid token auth (.eddgerc client credentials) and an API client granted AppSec access. edgegrid-golang is now v7+ on main (v1 is a legacy branch; package split into edgegrid/config and edgegrid/signer).

## Current state (2025-26)

App & API Protector is the current flagship name; Kona Site Defender and Web Application Protector still exist as the customizable-enterprise and entry tiers respectively. Akamai acquired API-security vendor Noname Security for ~$450M (announced May 7, 2024, expected close Q2 2024) and folded it into Akamai API Security. Akamai also acquired browser-security vendor LayerX (2025, per Akamai newsroom) and previously Guardicore (microsegmentation). 2025 AAP updates emphasized WAAP simplicity/automation, AI-powered dashboards, edge malware scanning, and App & API Protector Hybrid for off-platform enforcement. Exact edition packaging and current datasheet specifics: verify against Akamai documentation.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
