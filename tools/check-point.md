# Check Point Quantum & Infinity

*Check Point Software Technologies Ltd. · Network firewall, IPS & consolidated security platform*

Check Point Quantum is the network-security pillar of Check Point's Infinity Platform: a line of next-generation firewalls (now branded Quantum Force) that combine stateful firewalling, VPN, and a software-blade stack including IPS, Application Control, URL Filtering, Anti-Bot, Antivirus, and Threat Emulation/Extraction (sandboxing), all driven by the ThreatCloud AI intelligence layer. The problem it solves is consolidated, prevention-first perimeter and data-center defense with centralized policy management. In vulnerability-management terms it is a textbook virtual-patching control: its IPS blade blocks exploit traffic for known CVEs at the wire before the host is patched.

## Capabilities & architecture

**Core capabilities**
- Quantum Force NGFW appliances: AI-powered gateways spanning branch/SMB to hyperscale data center (flagship Quantum Force 19200 ~800 Gbps firewall / ~36.9 Gbps threat-prevention throughput); plus Quantum Spark for SMB/branch and Maestro hyperscale orchestration to cluster many gateways into one logical system
- IPS software blade: signature- and anomaly-based intrusion prevention with CVE-mapped protections, automatic signature updates from ThreatCloud AI, and virtual-patching for unpatched hosts
- Threat-prevention blade stack: Application Control, URL Filtering, Anti-Bot (post-infection C2 detection), Antivirus, DNS security, and Threat Emulation + Threat Extraction (zero-day sandboxing and content disarm, formerly SandBlast)
- Identity Awareness, Remote Access VPN, IoT security, and SD-WAN delivered on the same gateway
- Centralized management via Quantum Management (SmartConsole / Smart-1) and the cloud-delivered Infinity Portal with unified policy, logging, and the Infinity AI Copilot
- ThreatCloud AI: shared global threat-intel and ML engine feeding real-time IPS/AV/anti-bot protections across all enforcement points
- Infinity Core Services: Infinity XDR/XPR, Infinity Playblocks (automated, cross-product response; GenAI playbook creation; ServiceNow/Jira integration), Infinity Events, and managed prevention & response (MPR)

**Architecture & deployment.** Primarily on-premises physical or virtual appliances (Quantum gateways) deployed inline at the perimeter, data-center core, internal segments, and branch. Also available as CloudGuard Network Security virtual gateways in AWS/Azure/GCP and as Maestro scaled clusters. Management is either on-prem (Smart-1 / Security Management Server) or cloud-hosted (Infinity Portal SaaS). Traffic flows through the gateway where blades inspect it in a single pass (SecureXL/CoreXL acceleration); ThreatCloud AI is queried in the cloud for reputation and emulation verdicts. It sits as an inline enforcement chokepoint rather than an agent or agentless scanner.

**Editions & licensing.** Per-gateway hardware/VM purchase plus annual software-blade subscriptions. Common pre-packaged bundles: NGFW (firewall, IPS, App Control) and NGTP/NGTX (adds Anti-Bot, AV, and Threat Emulation/Extraction sandboxing). Enterprise consolidation is sold via the Infinity Platform Agreement / Infinity ELA: a single multi-year SKU granting access to the full Quantum + Harmony + CloudGuard + Core Services portfolio with commitment-based discounting. Public list pricing is not published; quotes are per user/device and term.

**Key integrations.** SIEM/SOAR: Splunk, Microsoft Sentinel, QRadar, and generic syslog/LEA log export; ITSM/ticketing: ServiceNow and Jira (natively via Infinity Playblocks); Identity: Microsoft Entra ID/AD, Okta, and other IdPs via Identity Awareness; Cloud: AWS, Azure, GCP (CloudGuard), plus Kubernetes/container environments; Vulnerability & exposure: Veriti (acquired 2025) for multi-vendor pre-emptive exposure mitigation and safe config remediation; third-party scanners feed context; MITRE ATT&CK mapping surfaced in logs/XDR and ThreatCloud research.

**Differentiators**
- Prevention-first philosophy: inline blocking (not just detection) with consistently high third-party block rates, making it a strong compensating control
- Single unified management plane and policy across network, cloud, endpoint, and email via the Infinity Platform, reducing tool sprawl
- ThreatCloud AI shared intelligence turns one detection anywhere into prevention everywhere, with automatic IPS signature delivery
- Maestro hyperscale orchestration lets throughput scale elastically without forklift upgrades
- Mature, granular IPS with per-CVE protections and the ability to run in Detect vs Prevent mode per signature for safe rollout

**Limitations & considerations**
- Operational complexity: software-blade licensing, policy layers, and the Infinity/Harmony/CloudGuard naming can be confusing; steep learning curve for SmartConsole
- Enabling the full blade stack (especially Threat Emulation) reduces real-world throughput well below datasheet firewall numbers, requiring careful sizing
- IPS signature quality can lag or carry false positives on niche application stacks; some reviewers report gaps/tuning burden on specific vendor signatures
- It mitigates exploit traffic traversing the gateway but does nothing for lateral or host-local exploitation of an unpatched asset that an attacker already reaches internally unless that traffic is also segmented through a gateway
- Premium price point and a licensing model that rewards long multi-year commitments; harder to right-size for smaller shops

## Vulnerability-mitigation role

Classic network-based virtual patching / compensating control. When a CVE is disclosed, Check Point publishes an IPS protection (often within hours) that fingerprints the exploit; enabling it in Prevent mode blocks exploitation of the vulnerable service at the gateway even though the host remains unpatched, buying time in the window before (or if) a patch is deployed. Anti-Bot and Threat Emulation blunt post-exploitation (C2, dropper payloads). Network segmentation on the gateway shrinks the reachable attack surface for internal unpatched assets. The 2025 Veriti acquisition extends this into pre-emptive, multi-vendor exposure mitigation and safe configuration rollout.

**VM lifecycle:** Assess/Scan · Prioritize · Mitigate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: PROTECT (PR.PS, PR.IR network protections), DETECT (DE.CM), RESPOND (RS via Playblocks), with some IDENTIFY (asset/network visibility); CIS Controls v8: 4 (Secure Configuration), 9 (Email & Web Browser Protections), 12 (Network Infrastructure Management), 13 (Network Monitoring & Defense); MITRE ATT&CK mitigations: M1050 Exploit Protection, M1031 Network Intrusion Prevention, M1037 Filter Network Traffic, M1030 Network Segmentation, M1021 Restrict Web-Based Content

**In a critical-CVE scenario.** Within 24-72h of a critical CVE in an internet-facing app: (1) confirm Check Point has released an IPS protection mapped to the CVE (ThreatCloud auto-update) and search logs for prior exploit attempts; (2) move the relevant IPS signature(s) from Detect to Prevent on the perimeter/data-center gateways fronting the exposed app, applying virtual patching immediately; (3) tighten the policy layer to restrict source geographies/identities and enable Threat Emulation on inbound content; (4) for a cloud workload, enforce the same protections via the CloudGuard Network virtual gateway and segment the workload so only required flows reach it; (5) use Infinity Playblocks to auto-quarantine any host showing Anti-Bot/C2 hits and open a ServiceNow ticket for the real patch, then keep the virtual patch until remediation is validated.

## Validation & telemetry

**Log sources**
- Security Gateway / IPS (SmartDefense) blade generates the protection hit; log is sent to the Management Server / Log Server (SmartCenter) or Smart-1 / Smart-1 Cloud.
- Log Exporter (cp_log_export) on the Management/Log Server streams logs out. Config lives under $EXPORTERDIR/conf/ (targetConfiguration.xml, CefFieldsMapping.xml / LeefFieldsMapping.xml). exportAllFields=true forces every raw field into CEF as extensions.
- ThreatCloud: cloud reputation/signature service the gateway queries; its verdicts are reflected inside the gateway's Threat Prevention logs (not a separate exportable log store for the customer).
- SIEM ingestion: Microsoft Sentinel via CEF -> CommonSecurityLog table (AMA/CEF connector); Splunk via the Splunk Add-on for Check Point (Log Exporter) mapping to the Intrusion_Detection / Network_Traffic CIM data models; QRadar via Check Point DSM.
- Infinity / Harmony SOC and Smart-1 Cloud provide a hosted log view and API for the same records.

**Telemetry format / transport.** Raw Check Point log records exported by Log Exporter, most commonly as Syslog in CEF (ArcSight Common Event Format) or Splunk/generic key=value; LEEF and JSON are also selectable. Transport is syslog over UDP/TCP/TLS to a SIEM or forwarder. The CEF header fields (DeviceVendor=Check Point, DeviceProduct, DeviceEventClassID, Name, Severity) are populated from raw Check Point fields; for IPS events DeviceProduct='SmartDefense' and DeviceEventClassID='IPS'.

**Control-presence check (present & configured?).** Confirm the IPS blade is enabled and in Prevent mode, and that Log Exporter is running. On the gateway CLI: `ips stat` returns IPS Status (Enabled/Disabled), IPS Update Version, Global Detect (On/Off) and Bypass Under Load (On/Off); `enabled_blades` lists active blades (look for 'ips'); `fw stat` and `cpstat ips` show blade/policy state. Remotely via Management API: `mgmt_cli -r true run-script script-name 'ips' script 'ips stat' targets.1 '<gw>'` then decode the base64 responseMessage from `show-task`. Confirm the Threat Prevention profile's IPS activation is set to Prevent (not Detect) in SmartConsole (profile -> IPS -> Activation). Confirm Log Exporter target is up: `cp_log_export status` (and `cp_log_export show`) on the Mgmt/Log Server. Mapping file to inspect for field names: `$EXPORTERDIR/conf/CefFieldsMapping.xml`.

**Validation signals (actually working?)**
- CONFIGURED vs EFFECTIVE: 'ips stat'=Enabled + profile Activation=Prevent proves the control is CONFIGURED. An actual exported log record with the raw `action`=Prevent (CEF `act`/DeviceAction='Prevent') on a specific protection proves it ACTUALLY BLOCKED something.
- act / DeviceAction = 'Prevent' (blocked) vs 'Detect'/'Accept' (logged only) on an IPS record = the enforcement decision.
- cs3 (cs3Label 'Protection Type') = 'IPS' identifies the record as an IPS protection hit; cs4 (cs4Label 'Protection Name') = the signature/attack name that fired; cs2 (cs2Label 'Protection ID') = internal protection id.
- Tying to a vulnerability: the protection's CVE/industry reference appears in the protection metadata; a Prevent hit on a protection whose Protection Name / reference maps to the target CVE is the evidence that the signature actively mitigated that vulnerability inline.
- flexNumber2 (label 'Performance Impact', 1-3) and cp_severity (Very-High/High/Medium/Low) indicate the protection's weight/severity; flexString2 (label 'Attack Information') carries attack detail.

**Key events / fields / tables / APIs**
- Raw->CEF mappings (from Log Exporter CefFieldsMapping.xml / sample IPS record): action->act (DeviceAction); protection_id->cs2 (cs2Label 'Protection ID'); protection_type->cs3 (cs3Label 'Protection Type', value 'IPS'); protection_name->cs4 (cs4Label 'Protection Name'); attack_info->flexString2 (label 'Attack Information'); performance_impact->flexNumber2 (label 'Performance Impact'); cp_severity (extension key, e.g. Very-High).
- CEF header identifiers for IPS: DeviceVendor='Check Point', DeviceProduct='SmartDefense', DeviceEventClassID='IPS'; Name header is drawn from protection_name.
- Microsoft Sentinel CommonSecurityLog columns: DeviceAction (act), DeviceCustomString2/DeviceCustomString2Label (cs2), DeviceCustomString3 (cs3=ProtectionType), DeviceCustomString4 (cs4=ProtectionName), FlexString2, with non-standard keys (e.g. cp_severity, attack) landing in AdditionalExtensions.
- Check Point does not use Windows Event IDs; events are identified by DeviceProduct/DeviceEventClassID, not numeric IDs.
- Splunk Add-on maps these to CIM Intrusion_Detection (signature, src, dest, severity, action).

**Example queries**

*Validate IPS actually blocked a given vulnerability's protection (effective, not just configured), via CommonSecurityLog* (KQL (Microsoft Sentinel))

```
CommonSecurityLog
| where DeviceVendor == "Check Point" and DeviceProduct == "SmartDefense"
| where DeviceEventClassID == "IPS" or DeviceCustomString3 == "IPS"
| where DeviceAction in ("Prevent","Drop","Reject")
| where DeviceCustomString4 has "Apache" or AdditionalExtensions has "CVE-"
| project TimeGenerated, SourceIP, DestinationIP, ProtectionName=DeviceCustomString4, ProtectionID=DeviceCustomString2, Action=DeviceAction, AdditionalExtensions
| sort by TimeGenerated desc
```

*Confirm the IPS control is present AND enforcing for a protection (count Prevent vs Detect over time)* (Splunk SPL)

```
index=checkpoint (DeviceProduct=SmartDefense OR product=SmartDefense) (protection_type=IPS OR cs3=IPS)
| eval decision=coalesce(act,action)
| stats count by cs4 protection_name decision
| where decision IN ("Prevent","Detect")
```

*Presence + mode check: prove the IPS blade is Enabled and Log Exporter is running* (Check Point Mgmt API / CLI)

```
ips stat ; enabled_blades ; cp_log_export status
```

**How it mitigates (mechanism).** The IPS engine pattern-matches / protocol-anomaly-inspects traffic inline on the gateway and, when a protection in Prevent mode matches, drops/rejects the packet or connection before it reaches the vulnerable host, which is why the observable evidence is an IPS log record carrying act=Prevent with the matching Protection Name (and its CVE reference).

**Logging gotchas**
- Community-reported bug: on some versions IPS records with action=Prevent have been observed MISSING the protection_name/Attack Name field (present on Reject/Drop) - verify on your R-version by comparing a test Prevent vs Drop CEF line before building detections that key on cs4.
- Forensics/'Advanced Forensics' detail fields frequently arrive empty for IPS events forwarded as CEF (reported on R81.10) - the richer forensic payload may not export; don't assume it is there.
- CEF field mapping is version-dependent (community mappings are based on R80.20); the authoritative source is CefFieldsMapping.xml on YOUR Log Exporter host - grep it rather than trusting a blog.
- 'ips stat'=Enabled with profile Activation=Detect means the control is present but only logging, NOT blocking - this is the classic 'configured but not effective' trap; the only proof of enforcement is a log with act=Prevent.
- Non-standard extension keys (cp_severity, attack, protection details) land in AdditionalExtensions in Sentinel CommonSecurityLog and are not first-class columns - parse them out before filtering.
- ThreatCloud is a backend reputation service; there is no separate customer-exportable 'ThreatCloud log' - its verdicts only surface inside the gateway's Threat Prevention logs, so absence of a separate feed is expected, not a gap.
- If the gateway is in 'Global Detect' / 'Bypass Under Load' = On, protections can silently stop preventing under high load; check those flags in 'ips stat' when a Prevent you expected is absent.

## Documentation & repositories

_Official documentation & manuals_
- [Check Point Support Center (home for all product docs, SK articles, downloads)](https://support.checkpoint.com)
- [Check Point Documentation / admin guides hub (per-product guides, PDFs/HTML)](https://sc1.checkpoint.com/documents/)
- [Infinity Portal Administration Guide](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/Infinity-Portal-Admin-Guide/Content/Topics-Infinity-Portal/Introduction-to-Infinity-Portal.htm)
- [Quantum product page / resources](https://www.checkpoint.com/quantum/)
- [Check Point Infinity Platform overview](https://www.checkpoint.com/infinity/)

_API & developer docs_
- [Check Point Management API Reference (R8x/latest, web services + CLI)](https://sc1.checkpoint.com/documents/latest/APIs/)
- [Check Point Developer / API portal (Management, Identity Awareness, GAiA REST)](https://sc1.checkpoint.com/documents/latest/APIs/index.html)
- [Harmony Endpoint Management API & SDK docs (via GitHub SDK READMEs)](https://github.com/CheckPointSW/harmony-endpoint-management-py-sdk)
- [CloudGuard / Infinity Next Terraform provider docs](https://registry.terraform.io/providers/CheckPointSW/checkpoint/latest/docs)

_GitHub (official)_
- [CheckPointSW (official Check Point Software org)](https://github.com/CheckPointSW)
- [CloudGuardIaaS (solution + Terraform templates, deployment scripts)](https://github.com/CheckPointSW/CloudGuardIaaS)
- [terraform-provider-checkpoint (official management Terraform provider)](https://github.com/CheckPointSW/terraform-provider-checkpoint)
- [harmony-endpoint-management-py-sdk](https://github.com/CheckPointSW/harmony-endpoint-management-py-sdk)
- [mcp-servers (official Check Point MCP servers for management via LLM tool calls)](https://github.com/CheckPointSW/mcp-servers)

_Community / integration / detection repos_
- [terraform-aws-cloudguard-network-security (AWS deployment module)](https://github.com/CheckPointSW/terraform-aws-cloudguard-network-security)
- [terraform-azure-cloudguard-network-security (Azure deployment module)](https://github.com/CheckPointSW/terraform-azure-cloudguard-network-security)
- [Evasions (Check Point Research malware-evasion encyclopedia)](https://github.com/CheckPointSW/Evasions)
- [InviZzzible (VM/sandbox detection & evasion assessment tool)](https://github.com/CheckPointSW/InviZzzible)
- [Check Point App/Add-on for Splunk (log analytics)](https://splunkbase.splunk.com/app/2843)

_Learning & reference_
- [Check Point Training & Certification (CCSA/CCSE, courseware)](https://training-certifications.checkpoint.com/)
- [CheckMates community (TechTalks, config guides, user forum)](https://community.checkpoint.com)
- [Check Point MIND / learning & cyber education hub](https://www.checkpoint.com/mind/)
- [Check Point Research (threat intel blog)](https://research.checkpoint.com/)

> Note: Product docs are split across two domains: the Support Center (support.checkpoint.com, for SK knowledge-base articles and downloads) and the documents hub (sc1.checkpoint.com/documents, for the HTML/PDF admin guides). 'Infinity' is the overarching platform brand and 'Infinity Portal' is the SaaS management console; 'Quantum' is the network-security line (gateways, SmartConsole, Maestro). Some login-gated SKs require a free UserCenter/PartnerMap account. The CloudGuardIaaS repo's AWS/Azure subfolders are deprecated in favor of the dedicated terraform-*-cloudguard-network-security repos. GitHub org handle is CheckPointSW; Terraform Registry namespace is CheckPointSW.

## Current state (2025-26)

CEO Nadav Zafrir (ex-Unit 8200/Team8) took over in December 2024; founder Gil Shwed is Executive Chairman. Current firewall generation is Quantum Force (AI-powered; ~10 new gateways launched, flagship 19200; AI-powered Quantum Force Branch Office gateways announced May 2025, with a 15-25% automatic threat-prevention throughput boost to existing perimeter/DC gateways). Infinity Platform is the umbrella brand with four pillars: Quantum (network), Harmony (workspace/SASE/endpoint/email), CloudGuard (cloud/CNAPP), and Infinity Core Services (XDR/XPR, Playblocks, Events, AI Copilot, MPR, ThreatCloud AI). Recent acquisitions: Perimeter 81 (2023, SASE/ZTNA ~ $490-503M), Cyberint (2024, external risk management), Veriti (announced May 2025, automated multi-vendor pre-emptive exposure & mitigation), Lakera (closed Oct 22 2025, AI-native/agentic-AI security), and Cyata + Cyclops + Rotate (announced with Q4/FY2025 results, ~$150M total, ~$85M for Cyclops). Infinity Playblocks was formerly branded Horizon Playblocks. Exact current blade-bundle contents and ELA pricing: verify with a Check Point quote.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
