# Zscaler Zero Trust Exchange

*Zscaler, Inc. · Security Service Edge (SSE) / Zero Trust Network Access & cloud-delivered security*

The Zscaler Zero Trust Exchange is a cloud-native SSE platform delivered as a globally distributed inline proxy. Its core services are ZIA (Zscaler Internet Access - secure web/internet gateway, cloud firewall, sandbox, DLP, CASB) and ZPA (Zscaler Private Access - identity-based ZTNA to private apps), with ZDX for digital-experience monitoring. It brokers every user-to-app and app-to-app connection based on identity and policy, never placing users on the network. Its defining vulnerability-mitigation value is attack-surface elimination: ZPA makes private apps dark to the internet so unpatched internal services can't be reached, and ZIA inline inspection blocks exploit and C2 traffic.

## Capabilities & architecture

**Core capabilities**
- ZIA: cloud secure web gateway, Cloud Firewall/IPS, DNS security, inline sandbox (Cloud Sandbox), Data Protection (DLP + inline/out-of-band CASB), Browser Isolation, SSL/TLS inspection at scale
- ZPA: identity- and context-aware Zero Trust Network Access to private apps via inside-out broker connections (App Connectors), app segmentation, app discovery, private-app protection, and privileged remote access
- ZDX (Digital Experience): end-to-end performance/latency monitoring across device, network, and app
- Zscaler for Workloads / Posture Control: cloud workload protection and CNAPP/DSPM for cloud-to-cloud and workload-to-internet segmentation
- Exposure Management suite: Asset Exposure Management (CAASM), Unified Vulnerability Management (UVM), External Attack Surface Management (EASM), and Risk360 risk quantification - all built on the Avalor data fabric
- Zero Trust SD-WAN / Zero Trust Branch and agentless segmentation for IoT/OT (from the Airgap Networks acquisition); Deception; Breach Predictor
- Agentic SecOps: Red Canary MDR/threat detection and response, AI Guardrails for GenAI app usage

**Architecture & deployment.** 100% cloud-native, delivered from a large global network of data centers; no inbound appliances. Users connect via the lightweight Zscaler Client Connector agent (or branch/GRE/IPsec tunnels or PAC files); traffic is forwarded to the nearest Zscaler edge where it is decrypted and inspected inline, then sent to its destination. ZPA uses outbound-only App Connectors deployed next to private apps that stitch to the broker, so apps have no public listener and no inbound firewall holes. It sits as an inline proxy chokepoint between every user/device and every destination (internet or private app), agent-based on the client side and agentless for IoT/OT segmentation.

**Editions & licensing.** Per-user (per-identity) annual subscription, sold in tiered bundle editions for ZIA and ZPA (historically Professional / Business / Transformation tiers) that add modules such as sandbox, DLP, CASB, and isolation as you move up. Workload, exposure-management, and SecOps products are licensed separately (per workload / per asset / consumption). Enterprise buyers typically negotiate platform-wide ELAs. Public per-seat list pricing is not disclosed.

**Key integrations.** Identity: Okta, Microsoft Entra ID, Ping, and SAML/SCIM IdPs for policy and device posture; SIEM/SOAR: Splunk, Microsoft Sentinel, Google Chronicle via Nanolog Streaming Service (NSS) / cloud log streaming; ITSM/ticketing: ServiceNow (CMDB sync from Asset Exposure Management), Jira; EDR/posture: CrowdStrike, Microsoft Defender, SentinelOne for device-posture and risk signals; Cloud: AWS, Azure, GCP for workload protection and log ingestion; Vulnerability data: ingests Tenable, Qualys, Rapid7 and other scanner findings into Unified Vulnerability Management for correlation and de-duplication.

**Differentiators**
- Attack-surface elimination: ZPA hides private apps entirely (no inbound exposure), which mitigates exploitation of unpatched internal apps by removing reachability rather than just filtering
- Massive inline TLS-inspection capacity in a proxy architecture built for full decryption at scale - something appliance stacks struggle with
- No hardware, auto-scaling, and consistent policy for any user anywhere (true SSE/SASE delivery); recognized SSE Magic Quadrant Leader (verify current-year placement)
- UVM can automatically down-rank vulnerability severity when a Zscaler zero-trust control already mitigates the exposure, cutting remediation noise
- Breadth now spanning users, workloads, IoT/OT, exposure management, and (via Red Canary) managed SecOps on one data fabric

**Limitations & considerations**
- It is a proxy for traffic that transits Zscaler; it does not inspect purely local or east-west traffic that never leaves a segment unless that traffic is explicitly routed/segmented through Zscaler
- Full value requires routing all traffic through the cloud - creates a dependency on Zscaler availability and can add latency for poorly peered locations; outages are high-impact
- TLS inspection at scale raises privacy, certificate-pinning, and app-breakage challenges that need careful exception management
- Rich but complex policy model and many SKUs/editions; cost grows quickly as modules and user counts scale
- Exposure-management and SecOps capabilities are newer and partly acquisition-stitched (Avalor, Airgap, Red Canary); maturity and integration depth should be validated, not assumed
- Its IPS/threat blocking is signature/reputation inline control, not a substitute for host patching of the vulnerable service itself

## Vulnerability-mitigation role

Two complementary mitigation modes. (1) Attack-surface reduction: ZPA removes internet reachability of private apps so an unpatched internal service simply cannot be reached from the outside - the strongest compensating control, mitigating the vuln regardless of patch state. (2) Inline interception: ZIA's Cloud Firewall/IPS, sandbox, and DNS security block exploit delivery, malicious downloads, and C2 for internet-facing flows, acting as a virtual patch against drive-by and web-exploit vectors. Unified Vulnerability Management then correlates scanner findings and automatically lowers the severity of items already mitigated by these zero-trust controls, focusing real patching effort where exposure remains.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: IDENTIFY (ID.AM asset/exposure via AEM/EASM), PROTECT (PR.AA access control, PR.IR network protection), DETECT (DE.CM), RESPOND (via Red Canary SecOps); CIS Controls v8: 3 (Data Protection), 6 (Access Control Management), 9 (Email & Web Browser Protections), 12 (Network Infrastructure Management), 13 (Network Monitoring & Defense); MITRE ATT&CK mitigations: M1030 Network Segmentation, M1035 Limit Access to Resource Over Network, M1037 Filter Network Traffic, M1031 Network Intrusion Prevention, M1021 Restrict Web-Based Content

**In a critical-CVE scenario.** Within 24-72h of a critical CVE in an internet-facing app and a cloud workload: (1) use Asset Exposure Management/EASM to find every instance of the affected service and confirm which are internet-reachable; (2) for internal/private instances, move them behind ZPA so they are no longer internet-exposed - immediate attack-surface removal; (3) in ZIA, enable/verify the relevant Cloud IPS and advanced threat-protection signatures, tighten URL/DNS and firewall rules to the exploited destinations, and route inbound content through Cloud Sandbox; (4) for the cloud workload, use Zscaler for Workloads/Posture Control to segment it so only required app-to-app flows are brokered and block egress C2; (5) in Unified Vulnerability Management, down-rank findings now mitigated by these controls and hand the still-exposed assets to the owners via ServiceNow for the real patch, keeping the compensating controls until remediation is validated.

## Validation & telemetry

**Log sources**
- ZIA Web/Firewall/DNS/DLP transactions are logged in the Zscaler cloud (Nanolog) and streamed out by an NSS server (on-prem VM) or Cloud NSS (SaaS) to syslog/SIEM. Feed is defined in ZIA Admin Portal: Administration > Nanolog Streaming Service > NSS Feeds (Web, Firewall, DNS, Tunnel, etc.).
- ZPA access/policy events (User Activity, User Status, App Connector Status, Private Service Edge Status, Browser Access, AppProtection) are streamed by LSS, configured in ZPA Admin Portal > Administration > Log Streaming Service, each with a Log Type + Log Stream Content template + a Log Receiver (IP:port).
- Collection targets: Microsoft Sentinel (Zscaler connector -> CommonSecurityLog or Zscaler-specific *_CL tables), Splunk (Zscaler Technical Add-ons -> Web/Proxy, Intrusion_Detection, Network_Traffic CIM), Cribl/Chronicle/Sumo/Coralogix parsers.
- Field names are chosen by the admin in the Feed Output Format, so the schema is tenant-defined; the macro vocabulary is fixed by Zscaler.

**Telemetry format / transport.** ZIA: Nanolog Streaming Service (NSS) emits transactions as syslog with a fully admin-defined Feed Output Format (tab-delimited, key=value, or JSON) using %-macros; Cloud NSS streams the same to cloud SIEMs without an on-prem VM. ZPA: Log Streaming Service (LSS) streams JSON/CSV over TCP/TLS to a receiver. Both are then parsed into SIEM schemas (Sentinel CommonSecurityLog or dedicated Zscaler tables, Splunk CIM Web/Network_Traffic, OCSF).

**Control-presence check (present & configured?).** ZIA: In the Admin Portal confirm the NSS feed exists and is healthy - Administration > NSS Feeds shows feed state/connectivity; NSS server health is visible under NSS server status (and the NSS VM's own admin). Confirm the enforcing policy is actually set to block: URL Filtering / Malware Protection / Advanced Threat Protection policy rule Action = Block, and - critically - that SSL Inspection is enabled, since threat/URL fields are only populated for decrypted traffic. Via API: ZIA API (e.g. GET /api/v1/webDlpRules, /api/v1/firewallFilteringRules, /api/v1/sandboxSettings, and Cloud NSS feed management endpoints) can read policy/feed state programmatically. ZPA: confirm an LSS config exists and the Log Receiver is reachable (ZPA Admin Portal > Log Streaming Service shows config; App Connector health under App Connectors must be 'Enabled'/green and reporting). Confirm the Access Policy rule governing the app exists and its action is set appropriately. Via ZPA API (config.private.zscaler.com): GET /mgmtconfig/v1/admin/customers/{customerId}/lssConfig and /accessPolicy to read state.

**Validation signals (actually working?)**
- ZIA web: action = Blocked (field %s{action}) together with a non-None %s{threatname}/%s{malwarecat} proves a threat was ACTUALLY blocked; action=Allowed with a non-None threatname/elevated %d{riskscore} is the 'detected but allowed' highest-risk case. %s{reason} gives the policy/engine reason. Tie-to-vuln: %s{rulelabel} / %s{ruletype} names the policy rule that fired.
- ZIA firewall: %s{action}=Allow/Block/Drop on a session, with %s{ipsrulelabel} / %s{threatcat} / %s{threatname} showing an IPS/threat match at the firewall layer.
- ZPA User Activity: ConnectionStatus (e.g. 'close'/active) + InternalReason (e.g. APP_NOT_REACHABLE, ZPN_STATUS_AUTH_FAILED) + Policy (the access policy rule) show whether a brokered connection was allowed, blocked, or failed policy - the Zero Trust 'reachability removed' evidence.
- CONFIGURED vs EFFECTIVE: a policy rule set to Block in the portal/API = configured; an NSS/LSS record with action=Blocked (ZIA) or a denied/failed ConnectionStatus+InternalReason (ZPA) = actually enforced.
- Mitigation-by-unreachability (ZPA): absence of any User Activity 'allowed' record for an app from an unauthorized user, plus policy-block counts in the User Activity dashboard (Access Policy Blocks / Timeout Policy Blocks), evidences that the app was never exposed.

**Key events / fields / tables / APIs**
- ZIA Web log macros (verified field set): time, login, action, reason, appname, appclass, urlcat, urlsupercat, malwarecat, threatname, riskscore, dlpeng, dlpdict, location, dept, cip, sip, reqmethod, respcode, ruletype, rulelabel, contenttype, deviceowner, devicehostname (macros written %s{action}, %s{threatname}, %d{riskscore}, hex-encoded variants %s{elogin}/%s{eua}).
- ZIA Firewall log fields (verified): action, rulelabel, ipsrulelabel, threatcat, threatname, nwsvc, nwapp, ipproto, csip/cdip/ssip/sdip, cdport/sdport, aggregate, numsessions, inbytes/outbytes, destcountry.
- ZPA User Activity fields (verified, LSS JSON template keys): LogTimestamp, Username, Policy, ConnectionStatus, InternalReason, Application, AppGroup, Host, Server, ServerIP, ServerPort, ClientPublicIP, SessionID, ConnectionID, Idp, Customer, IPProtocol, TimestampConnectionStart/End. ZPA App Connector Status: SessionStatus, CPUUtilization, MemUtilization, Connector, Version.
- LSS template placeholder syntax: strings %j{Field}, ints %d{Field}, floats %f{Field}, epoch timestamps %J{Field:epoch}. NSS macro syntax: %s{} string, %d{} numeric, prefix e = hex-encoded, prefix o = obfuscated.
- SIEM landing: Sentinel CommonSecurityLog (CEF) or Zscaler data connector tables; Splunk CIM Web (action, url, http_user_agent) and Intrusion_Detection (signature=threatname). No native Windows Event IDs - all events are cloud transaction records.

**Example queries**

*ZIA: confirm malware was actually blocked (effective enforcement), keying on action + threat fields* (Splunk SPL)

```
index=zscaler sourcetype=zscalernss-web action=Blocked threatname!=None
| stats count by threatname malwarecat rulelabel action user url
| sort - count
```

*ZIA: 'configured-but-not-effective' hunt - threat detected on traffic that was still Allowed* (KQL (Microsoft Sentinel))

```
CommonSecurityLog
| where DeviceVendor == "Zscaler"
| where isnotempty(FileType) or AdditionalExtensions has "threatname"
| extend threat = extract(@"threatname=([^;]+)", 1, AdditionalExtensions)
| where isnotempty(threat) and threat != "None" and DeviceAction == "Allowed"
| project TimeGenerated, SourceUserName, RequestURL, threat, DeviceAction
```

*ZPA: validate Zero Trust reachability enforcement - access brokered vs blocked per policy* (ZPA LSS / Splunk SPL)

```
index=zscaler sourcetype=zscalerlss-zpa
| stats count by Policy ConnectionStatus InternalReason Application Username
| where InternalReason="ZPN_STATUS_AUTH_FAILED" OR ConnectionStatus!="active"
```

**How it mitigates (mechanism).** ZIA inline-proxies and (when SSL inspection is on) decrypts traffic, applying URL/malware/ATP/DLP policy and dropping the transaction at the cloud edge (observable as action=Blocked); ZPA brokers application access per-session and only stitches an authorized user to an app, so unauthorized access is never reachable (observable as a denied/failed ConnectionStatus+InternalReason or the simple absence of an allowed User Activity record).

**Logging gotchas**
- ZIA threat/URL/DLP fields (threatname, malwarecat, dlpdict) are only populated for SSL-INSPECTED traffic; if SSL inspection is off for a site, a real threat can show threatname=None - 'None' is not proof of safety.
- NSS feed only forwards what the admin put in the Feed Output Format and what the policy chose to log; fields you didn't add to the template simply won't exist in the SIEM - verify the live feed string, not a vendor sample.
- Aggregate firewall logs group sessions over a 15-min window (aggregate=1); per-session detail is lost unless Full Session Logging is enabled - affects count/attribution.
- Case & casing drift: sample logs show action='Allowed'/'Blocked' (web) and 'Allow' (firewall) capitalized, but many community detections match action=blocked lowercase - confirm casing in your tenant before case-sensitive filters.
- ZPA client-side bypass traffic (apps/domains configured to bypass the connector) is NOT brokered and therefore NOT in User Activity logs - absence of a log is expected for bypassed apps, not an enforcement failure.
- NSS/Cloud NSS is a streamer, not a store - the Zscaler-side retention of raw Nanolog is limited (and NSS VMs buffer only briefly); if the receiver is down you lose events. Monitor NSS/LSS feed health, not just policy state.
- Official Zscaler NSS Web/Firewall and ZPA LSS field-reference pages are JavaScript-rendered and hard to scrape; the macro/field names above were cross-verified from Zscaler's feed-format guidance plus multiple SIEM parser docs - for a given tenant, confirm against help.zscaler.com NSS Feed Output Format pages for your exact firmware.
- Some field macro names differ by prefix for encoding (login vs elogin vs ologin); a parser built for one prefix silently drops the other.

## Documentation & repositories

_Official documentation & manuals_
- [Zscaler Help Portal (central docs home for all services)](https://help.zscaler.com)
- [ZIA (Internet Access) documentation](https://help.zscaler.com/zia)
- [ZPA (Private Access) documentation](https://help.zscaler.com/zpa)
- [ZDX (Digital Experience) documentation](https://help.zscaler.com/zdx)
- [ZIdentity / OneAPI unified platform docs](https://help.zscaler.com/zidentity)
- [Zero Trust Exchange platform overview](https://www.zscaler.com/platform/zero-trust-exchange)

_API & developer docs_
- [ZIA API — Getting Started (OAuth 2.0 / legacy key)](https://help.zscaler.com/zia/api-getting-started)
- [Understanding OneAPI Authentication (ZIdentity OAuth2)](https://help.zscaler.com/unified/understanding-oneapi-authentication)
- [ZPA API reference](https://help.zscaler.com/zpa/api-reference)
- [Zscaler Python SDK docs (OneAPI client)](https://zscaler-sdk-python.readthedocs.io/)
- [Zscaler Go SDK docs](https://pkg.go.dev/github.com/zscaler/zscaler-sdk-go/v3)
- [Zscaler ZPA Terraform provider (registry docs)](https://registry.terraform.io/providers/zscaler/zpa/latest/docs)
- [Zscaler ZIA Terraform provider (registry docs)](https://registry.terraform.io/providers/zscaler/zia/latest/docs)

_GitHub (official)_
- [zscaler (official Zscaler GitHub org)](https://github.com/zscaler)
- [zscaler-terraformer (generates Terraform from existing ZIA/ZPA config)](https://github.com/zscaler/zscaler-terraformer)
- [terraform-provider-zpa](https://github.com/zscaler/terraform-provider-zpa)
- [terraform-provider-zia](https://github.com/zscaler/terraform-provider-zia)
- [zscaler-sdk-python / zscaler-sdk-go](https://github.com/zscaler/zscaler-sdk-python)

_Community / integration / detection repos_
- [zpacloud-ansible (ZPA Ansible collection)](https://github.com/zscaler/zpacloud-ansible)
- [ziacloud-ansible (ZIA Ansible collection)](https://github.com/zscaler/ziacloud-ansible)
- [zscaler-mcp-server (community MCP server exposing 300+ Zscaler tools; NOT an official product)](https://github.com/zscaler/zscaler-mcp-server)
- [Zscaler App / Technology Add-on for Splunk (ZIA/ZPA log ingestion)](https://splunkbase.splunk.com/app/3865)
- [Zscaler terraform modules (ZIA/ZPA reusable modules)](https://registry.terraform.io/namespaces/zscaler)

_Learning & reference_
- [Zscaler Training & Certification (Zscaler Academy, ZCCA/ZCCP)](https://www.zscaler.com/resources/training-certification)
- [Zscaler Community (forums, knowledge, user groups)](https://community.zscaler.com)
- [Zscaler ThreatLabz (threat research blog)](https://www.zscaler.com/blogs/security-research)
- [Zscaler Tools (free internet exposure / security posture tools)](https://www.zscaler.com/tools)
- [Zscaler Zenith Live / resource library](https://www.zscaler.com/resources)

> Note: Zscaler is a cloud SASE/SSE suite, not one product: ZIA (secure internet/SaaS access), ZPA (zero-trust private app access), ZDX (digital experience), plus ZCC client connector. Docs are unified under help.zscaler.com with per-service subpaths. Zscaler is migrating APIs to 'OneAPI' with ZIdentity as the OAuth 2.0 authorization server (client-credentials grant); legacy per-service API keys still exist for ZDX/ZTW. Most of the help portal and API credential creation require an authenticated admin tenant. GitHub org handle is 'zscaler'; Terraform Registry namespace is 'zscaler' (providers zscaler/zpa and zscaler/zia). The zscaler-mcp-server is maintained in the official org but labeled unofficial/not supported.

## Current state (2025-26)

Core platform remains the Zero Trust Exchange with ZIA, ZPA, and ZDX. Confirmed recent acquisitions: Avalor (closed March 2024, ~$350M, data fabric now powering Risk360 and Unified Vulnerability Management); Airgap Networks (2024, agentless segmentation / Zero Trust SD-WAN for IoT/OT); Red Canary (completed August 1 2025, ~$675M, MDR/SecOps now operating as 'Red Canary, a Zscaler company' for agentic AI-driven security operations). 2025-2026 direction set at Zenith Live 2025: 'Zero Trust Everywhere' across users, branches, workloads, and IoT/OT, plus an Agentic SecOps/exposure-management push - Asset Exposure Management (CAASM) launched to combine with UVM, EASM, and Risk360. Reported as an SSE Magic Quadrant Leader (verify current-year placement with Gartner directly). Specific module names/edition contents and ITDR/Zscaler Cellular/Breach Predictor details: verify against Zscaler's current product pages.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
