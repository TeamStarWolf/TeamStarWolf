# Tool Manuals and Repositories

> **Tools Research** · Verified directory of official manuals, API references, release notes, marketplace listings, GitHub organizations, repositories and GitHub Pages sites for a CTEM stack. Every link was checked on 2026-10-08.

Back to [Tools Research](/tools-research/README.md)

This directory covers **ServiceNow**, **Armis** and the **MITRE threat-informed defense ecosystem**. For Tenable, Wiz, Snyk, Invicti, Zafran and Splunk, see [Security Tool Documentation](/SECURITY_TOOL_DOCUMENTATION.md).

## How to use this page

Each table gives a resource, what it is for, and the result of the 2026-10-08 check. The Status column uses these values:

| Status | Meaning |
|---|---|
| OK | Returned HTTP 200 and the page title or content matched what was expected. |
| OK (redirect) | Returned 200 after a redirect. The link given is the stable entry point. |
| Gated (login) | Redirects to a vendor login or SSO page. The link is official, but the content needs an account. |
| Bot-blocked (verify in a browser) | An automated client got a 403 or 429 challenge (Cloudflare or Vercel). The URL comes from an official page, but its content could not be read by script. |
| App shell (SPA returns 200 for any path) | A single-page app that answers 200 for every path, including made-up ones. A 200 proves nothing, so confirm the page in a browser. |

Notes on reading the tables:

- **ServiceNow docs.** The public docs site (`www.servicenow.com/docs/r/...`) is an app shell. It returned 200 even for a made-up path, so a status check cannot confirm that a page exists. ServiceNow publishes the same docs as markdown in the [ServiceNow/ServiceNowDocs](https://github.com/ServiceNow/ServiceNowDocs) GitHub repo, where a missing file returns a real 404. That GitHub copy is the verified link used below. Each file's `canonical_url` frontmatter gives its public URL. On the `brazil` branch the pattern is `markdown/<publication>/<path>.md` on GitHub to `https://www.servicenow.com/docs/r/<publication>/<path>.html` on the public site.
- **ServiceNowDocs branches.** There is one branch per release family (`brazil` is current, `australia` and `zurich` are older, and `store` holds Store app release notes). The repo deletes its oldest branch when a new family goes GA, so re-pin links after each family release.
- **ServiceNow Store and Splunkbase.** Both return a real 404 for a fake listing ID, so a 200 with the app name in the title is meaningful.
- **GitHub facts.** Stars and last-push dates are as of 2026-10-08. "Verified" means the org shows GitHub's verified-domain badge. Several official orgs are not verified, and some lookalike orgs are not the vendor. Each section says which is which.
- **Dead links.** Links that returned 404, were withdrawn, or have moved are not in the section tables. They are listed in the final section, "Dead or moved links to avoid", with what to use instead.

## ServiceNow

ServiceNow product docs live in the [ServiceNow/ServiceNowDocs](https://github.com/ServiceNow/ServiceNowDocs) repo ("ServiceNow AI Platform documentation for LLM consumption"). Links below point to the `brazil` branch unless noted. In the Brazil table of contents, Unified Security Exposure Management (USEM) is the parent of Vulnerability Response, Application Vulnerability Response, Container Vulnerability Response, Configuration Compliance, Security Incident Response and Threat Intelligence.

### Security Operations and USEM modules

**Core modules**

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Security Operations](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-operations-landing-page.md) | Landing page | Entry point for all SecOps applications | OK |
| [Exploring Security Operations](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/understanding-secops.md) | Overview | How SecOps apps connect security and IT teams | OK |
| [Security Operations and the ServiceNow Store](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/secops-and-store.md) | Admin guide | Which SecOps apps and integrations ship through the Store | OK |
| [Security Operations common functionality](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/sec-ops-common-functionality.md) | Admin guide | Shared integration framework, roles and tables | OK |
| [Security Operations Integration Reference](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/secops-integ-ref.md) | Reference | Index of SecOps integration workflows | OK |
| [Unified Security Exposure Management](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/unified-security-exposure-management-landing-page.md) | Landing page | USEM, the umbrella for exposure management | OK |
| [Exploring USEM](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/exploring-unified-security-exposure-management.md) | Overview | Unified exposure and finding model, personas | OK |
| [Implementing USEM](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/configuring-security-exposure-management.md) | Admin guide | USEM configuration | OK |
| [ServiceNow Otto for USEM](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/now-assist-for-usem-landing-ties.md) | Admin guide | Generative-AI skills for USEM | OK |
| [Vulnerability Response](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/vuln-landing-page.md) | Landing page | Vulnerability Response (VR) | OK |
| [VR implementation](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/vr_implement-ovrview.md) | Admin guide | VR implementation steps | OK |
| [Install VR and supported applications](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/cj-vr-setup.md) | Admin guide | VR install and plugins | OK |
| [VR integrations](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/vuln_integrations.md) | Integration guide | Index of scanner and source integrations | OK |
| [VR reference information](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/vr-reference-info.md) | Reference | VR tables, roles and properties | OK |
| [VR Orchestration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/c_VulnRespOrchestration.md) | Admin guide | Automated remediation and patching actions | OK |
| [VR Workspaces](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response-workspaces/vr-wkspace-overview-v16.md) | Admin guide | Analyst and manager workspaces | OK |
| [Vulnerability Manager Workspace](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-manager-workspace/vulnerability-manager-workspace-landing-page.md) | Admin guide | Manager workspace | OK |
| [Vulnerability Solution Management](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/vuln-solution-mgmt.md) | Landing page | Groups vulnerabilities by vendor fix or patch | OK |
| [Set up vulnerability solution providers](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/setup-vulnerability-solution-providers.md) | Admin guide | Feeds for Solution Management | OK |
| [Vulnerability Crisis Management](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/vulnerability-crisis-management.md) | Landing page | Campaigns for emerging critical vulnerabilities | OK |
| [Exploring exposure assessment](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response-workspaces/vr-ws-exposure-assessment.md) | Overview | Assess exposure to a CVE or software across the estate | OK |
| [Exposure assessment by CVE](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response-workspaces/vr-ws-exposure-assessment-cve.md) | Admin guide | Run an exposure assessment for one CVE | OK |
| [Fix Intelligence data flow](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/fix-intel-data-flow.md) | Admin guide | VIPR-powered fix grouping in USEM | OK |
| [Install Fix Intelligence](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/install-fix-intel.md) | Admin guide | Prerequisites, including the VIPR entitlement | OK |
| [Container Vulnerability Response](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/container-vulnerability-response/cvr-landing.md) | Landing page | Container Vulnerability Response (CVR) | OK |
| [Exploring CVR](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/container-vulnerability-response/exploring-cvr.md) | Overview | Image and container vulnerable items | OK |
| [Configuration Compliance](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/configuration-compliance/vr-config-compliance-landing.md) | Landing page | Configuration Compliance (CC) | OK |
| [CC reporting](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/configuration-compliance/vuln-config-compl-overview.md) | Admin guide | CC reports and dashboards | OK |
| [Application Vulnerability Response](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/application-vulnerability-response/avr-landing.md) | Landing page | Application Vulnerability Response (AVR) | OK |
| [Security Posture Control](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/spc-landing.md) | Landing page | Security Posture Control (SPC) | OK |
| [Exploring SPC](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/spc-overview.md) | Overview | Asset inventory and security-tool coverage gaps | OK |
| [Install SPC](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/spc-install.md) | Admin guide | Install SPC and supporting apps | OK |
| [Security Incident Response](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-incident-response/sir-landing-page.md) | Landing page | Security Incident Response (SIR) | OK |
| [SIR Overview dashboard](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-incident-response/c_SIROverview.md) | Admin guide | SIR dashboard | OK |
| [SIR setup](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-incident-response/setup-sir.md) | Admin guide | SIR setup | OK |
| [SIR Workspace](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-incident-response/sir-workspace-landing-page.md) | Admin guide | SIR analyst workspace | OK |
| [SIR integrations](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-incident-response/sir_integrations.md) | Integration guide | SIEM, EDR, email and sandbox integrations | OK |
| [SIR Orchestration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-incident-response/c_SecIncRespOrchestration.md) | Admin guide | SIR playbook actions | OK |

**Threat intelligence and MITRE frameworks**

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Threat Intelligence](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/threat-intel-landing-page.md) | Landing page | IoCs, observables and MITRE data | OK |
| [Threat Intelligence administration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/r_ThreatRespAdmin.md) | Admin guide | TI administration | OK |
| [Threat Intelligence integrations](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/threat-intelligence-integrations.md) | Integration guide | TI feed and lookup integrations | OK |
| [Threat Intelligence Security Center](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/threat-intelligence-security-center/tisc-landing-page.md) | Landing page | Threat Intelligence Security Center (TISC) | OK |
| [TISC Explore](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/threat-intelligence-security-center/threat-intelligence-security-center-overview.md) | Overview | TISC concepts | OK |
| [TISC threat intelligence feeds](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/threat-intelligence-security-center/threat-intelligence-feeds.md) | Integration guide | Configure TI feeds | OK |
| [MITRE ATT&CK framework overview](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/about-mitre-attack.md) | Landing page | ATT&CK support in SecOps | OK |
| [Get started with MITRE ATT&CK](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/get-started-with-mitre.md) | Admin guide | Load and configure ATT&CK data | OK |
| [Using MITRE ATT&CK to detect and analyze threats](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/mitre-att-ck-features.md) | Admin guide | Techniques on incidents and cases | OK |
| [MITRE ATT&CK heat map and navigator](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/mitre-att-ck-heatmap-and-navigator.md) | Admin guide | Heat map and navigator views | OK |
| [Data source and detection tool mapping](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/manage-mitre-att-ck-data-sources.md) | Admin guide | Map data sources and tools to ATT&CK coverage | OK |
| [MITRE D3FEND framework](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/mitre-d3fend-framework.md) | Admin guide | D3FEND support | OK |
| [MITRE ATLAS framework](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/about-mitre-atlas.md) | Admin guide | ATLAS (AI adversarial techniques) support | OK |
| [TISC MITRE ATT&CK repository](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/threat-intelligence-security-center/tisc-mitre-att-ck-framework-overview.md) | Admin guide | ATT&CK repository inside TISC | OK |

**ServiceNow-side integration guides for the rest of the stack**

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Understanding the Tenable Vulnerability Integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/tenableIntegration.md) | Integration guide | Tenable VM, Security Center and Cloud Security into VR | OK |
| [Install the Tenable integration with Setup Assistant](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/tenableInstall.md) | Integration guide | Guided install | OK |
| [Preparing for the Tenable integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/tenable-setup-checklist.md) | Integration guide | Prerequisites checklist | OK |
| [Tenable.io integrations with VR and CC](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/tenable-io-integrations-list.md) | Integration guide | Tenable.io data streams | OK |
| [Tenable.sc integrations with VR](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/tenable-sc-integrations-list.md) | Integration guide | Tenable.sc data streams | OK |
| [Tenable integration with Configuration Compliance](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/configuration-compliance/cc-tenable-integration-overview.md) | Integration guide | Tenable compliance results into CC | OK |
| [Tenable Web App Scanning integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/application-vulnerability-response/tenable-was-integration.md) | Integration guide | Tenable WAS into AVR | OK |
| [Understanding the Wiz VR integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/vr-wiz-exploring-host-cf.md) | Integration guide | Wiz host vulnerabilities into VR | OK |
| [Activate the Wiz VR integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/vr-wiz-host-vuln-install.md) | Integration guide | Activate the app | OK |
| [Configure the Wiz VR integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/vr-config-wiz-host-vuln.md) | Integration guide | Configure the app | OK |
| [Field mapping for the Wiz VR integrations](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response/wiz-vul-resp-integration-view-findings.md) | Reference | Wiz field mapping | OK |
| [Wiz Container Vulnerability integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/container-vulnerability-response/wiz-exploring-cvr-vuln-intcf.md) | Integration guide | Wiz container findings into CVR | OK |
| [Wiz Test Results and Issues with CC](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/configuration-compliance/exploring-wiz-ctest-results-int.md) | Integration guide | Wiz cloud misconfigurations into CC | OK |
| [Wiz AI-SEM integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/configuration-compliance/wiz-ai-sem-integration.md) | Integration guide | Wiz AI security exposure findings | OK |
| [Wiz AVR integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/application-vulnerability-response/wiz-exploring-avr-sca-secrets.md) | Integration guide | Wiz SCA and secrets findings into AVR | OK |
| [Invicti Vulnerability Integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/application-vulnerability-response/invicti-vuln-integration.md) | Integration guide | Invicti findings into AVR | OK |
| [Install the Invicti integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/application-vulnerability-response/invicti-install.md) | Integration guide | Install the ServiceNow-built app | OK |
| [Configure the Invicti integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/application-vulnerability-response/invicti-configure.md) | Integration guide | Configure the app | OK |
| [Early Warning for Security Exposure Management](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/armis-early-warning-integration.md) | Integration guide | Armis early-warning exploit intel into USEM | OK |
| [Configure Early Warning](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/configure-early-warning-integration.md) | Integration guide | Armis Intelligence Center API key setup | OK |
| [SecOps add-on for Splunk overview](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-incident-response/secops-integration-with-splunk.md) | Integration guide | Splunk-side SecOps add-on | OK |
| [Splunk ES event ingestion](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-incident-response/splunk-event-ingest-overview-security.md) | Integration guide | Splunk ES notable events into SIR | OK |
| [Splunk Incident Enrichment](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-incident-response/splunk-in-enrich-landing-page.md) | Integration guide | Splunk searches from SIR | OK |
| [Event Ingestion Addon for Splunk ES setup](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/security-incident-response/splunk-es-addon.md) | Integration guide | Set up Splunkbase app 4770 | OK |
| [TISC Splunk integration](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/threat-intelligence-security-center/tisc-splunk-integration.md) | Integration guide | Sightings and observable search in Splunk | OK |

- The brazil docs have no Snyk page and no ServiceNow-side page for the Tenable or Armis Service Graph Connectors. Those are partner-published Store apps, listed in the Tenable, Armis and Snyk sections.
- Armis appears in the brazil docs only as Early Warning for Security Exposure Management and Fix Intelligence.

### ITSM, CMDB and platform

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [IT Service Management](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/it-service-management/r_ITServiceManagement.md) | Landing page | ITSM entry point | OK |
| [Exploring ITSM](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/it-service-management/exploring-itsm.md) | Overview | ITSM concepts | OK |
| [Incident Management](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/it-service-management/incident-management/c_IncidentManagement.md) | Landing page | Incident Management | OK |
| [Problem Management](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/it-service-management/problem-management/c_ProblemManagement.md) | Landing page | Problem Management | OK |
| [Change Management](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/it-service-management/change-management/c_ITILChangeManagement.md) | Landing page | Change Management | OK |
| [Configuration Management](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/configuration-management-database-cmdb/manage-cmdb.md) | Landing page | CMDB entry point | OK |
| [Configuration Management Database](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/configuration-management-database-cmdb/c_ITILConfigurationManagement.md) | Overview | CMDB concepts | OK |
| [Identification and Reconciliation Engine](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/configuration-management-database-cmdb/ire.md) | Admin guide | IRE overview | OK |
| [Configuring identification and reconciliation](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/configuration-management-database-cmdb/configuring-ire.md) | Admin guide | IRE rules | OK |
| [Integrating third-party data into CMDB](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/configuration-management-database-cmdb/cmdb-third-party-integrations.md) | Integration guide | Service Graph Connectors and IntegrationHub ETL | OK |
| [Common Service Data Model](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/common-service-data-model-csdm/csdm-landing-page.md) | Landing page | CSDM | OK |
| [Service Graph Connectors](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/service-graph-connectors/cmdb-sgc-available.md) | Landing page | Index of documented connectors | OK |
| [Service Graph Connector for Wiz](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/service-graph-connectors/sgc-cmdb-integration-wiz.md) | Integration guide | Wiz cloud assets into CMDB | OK |
| [Set up the Wiz environment](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/service-graph-connectors/sgc-cmdb-wiz-setup.md) | Integration guide | Wiz-side setup for the connector | OK |
| [Service Graph Connector for Splunk](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/service-graph-connectors/sgc-splunk-integration.md) | Integration guide | CMDB ingestion from Splunk | OK |
| [SGC Central view in CMDB Workspace](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/servicenow-platform/configuration-management-database-cmdb/sg-workspace-ingestion-view.md) | Admin guide | Install and monitor connectors | OK |
| [Platform Analytics](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/now-intelligence/c_performanceAnalyticsAndReporting.md) | Landing page | Performance Analytics, reporting and dashboards | OK |
| [Performance Analytics concepts](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/now-intelligence/performance-analytics/c_PerformanceAnalytics.md) | Overview | Indicators, breakdowns and scores | OK |
| [Performance Analytics indicator data sources](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/now-intelligence/performance-analytics/pa-overview.md) | Reference | Indicator data sources (last updated 2023, may be stale) | OK |

### Store listings and release notes

**ServiceNow Store listings published by ServiceNow.** Listings published by Tenable, Armis, Snyk, Wiz and Zafran are in those vendor sections.

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [ServiceNow Store](https://store.servicenow.com/) | Store home | Store entry point (listing search needs a login) | OK (redirect) |
| [Vulnerability Response](https://store.servicenow.com/store/app/21d8a32e1be06a50a85b16db234bcb7e) | Store app, v30.8.7 | Core VR application | OK |
| [Unified Security Exposure Management](https://store.servicenow.com/store/app/89440738537d765472c95a01a0490e93) | Store app, v31.3.1 | USEM core | OK |
| [Security Exposure Management Workspace](https://store.servicenow.com/store/app/f04407744779361439e06507e26d43a4) | Store app, v30.7.9 | USEM analyst workspace | OK |
| [Risk Scoring for Security Exposure Management](https://store.servicenow.com/store/app/cd7247fc93f1f254a0f2fc1d6cba102a) | Store app, v30.1.9 | USEM risk-scoring engine | OK |
| [Remediation for Security Exposure Management](https://store.servicenow.com/store/app/90f143b897353a503fa8b84bf253af1f) | Store app, v31.0.12 | USEM remediation | OK |
| [Exception Management for USEM](https://store.servicenow.com/store/app/39f18f7c9775b298f25ab9e0f053af5e) | Store app, v30.7.5 | Exceptions and risk acceptance | OK |
| [Vulnerability Response Integration Framework](https://store.servicenow.com/store/app/a6a426781bd96ed47d31ed7a234bcba9) | Store app, v1.6.4 | Shared framework for scanner integrations | OK |
| [Central Vulnerability Database](https://store.servicenow.com/store/app/f561041b47804f90040ae738436d43c7) | Store app, v1.2.5 | Central CVE data store | OK |
| [Security Operations Setup Assistant](https://store.servicenow.com/store/app/929babaa1b246a50a85b16db234bcb23) | Store app, v10.4.41 | Guided setup used by integrations | OK |
| [Vulnerability Response Integration with Tenable](https://store.servicenow.com/store/app/861aa3e21b246a50a85b16db234bcb7c) | Store app, v30.5.3 | Tenable VM, Security Center and Cloud Security into VR and CC | OK |
| [Vulnerability Response Integration with Wiz](https://store.servicenow.com/store/app/c0211a8e1b87aad02ca2a643604bcb1f) | Store app, v32.8.4 | Wiz host, container, app and configuration findings | OK |
| [Invicti Application Vulnerability Integration](https://store.servicenow.com/store/app/44eaa3e61b246a50a85b16db234bcb26) | Store app, v1.2.1 | Invicti DAST and IAST findings into AVR | OK |
| [Service Graph Connector for Wiz](https://store.servicenow.com/store/app/434a27261b246a50a85b16db234bcb82) | Store app, v1.6.1 | Wiz cloud inventory into CMDB | OK |
| [Security Incident Response](https://store.servicenow.com/store/app/85ab6faa1b246a50a85b16db234bcb74) | Store app, v14.4.0 | Core SIR application | OK |
| [Security Incident Response Workspace](https://store.servicenow.com/store/app/b229ef6e1be06a50a85b16db234bcb44) | Store app, v1.10.1 | SIR analyst workspace | OK |
| [Threat Intelligence Support Common](https://store.servicenow.com/store/app/96196b6e1be06a50a85b16db234bcb83) | Store app, v13.8.0 | Shared TI tables and components | OK |
| [Splunk ES Integration for Security Operations](https://store.servicenow.com/store/app/ec3963ae1be06a50a85b16db234bcb89) | Store app, v12.5.3 | Splunk ES notable events into SIR | OK |
| [Splunk Enterprise Event Ingestion for Security Operations](https://store.servicenow.com/store/app/57baa7a61b246a50a85b16db234bcbc2) | Store app, v11.6.7 | Splunk alerts into SIR | OK |
| [Splunk Search Integration for Security Operations](https://store.servicenow.com/store/app/f79da3661b646a50a85b16db234bcb9e) | Store app, v10.5.0 | Splunk searches and sightings from SIR and TI | OK |
| [SGC Central](https://store.servicenow.com/store/app/e2ba67a61b246a50a85b16db234bcbd5) | Store app, v2.7.5 | Install and manage Service Graph Connectors | OK |
| [Integration Commons for CMDB](https://store.servicenow.com/store/app/f809636e1be06a50a85b16db234bcbc9) | Store app, v2.26.0 | Shared dependency for connectors | OK |
| [IntegrationHub ETL](https://store.servicenow.com/store/app/7e0aefa21b246a50a85b16db234bcb42) | Store app, v3.6.0 | ETL mapping into CMDB through IRE | OK |
| [CMDB Workspace](https://store.servicenow.com/store/app/77ca2fa61b246a50a85b16db234bcb56) | Store app, v9.6.0 | Hosts the SGC Central view | OK |

- The Invicti listing shows v1.2.1 while its Store release notes show v30.4.2 (September 2026). Check the listing before upgrading.
- USEM-track apps use a 30.x to 32.x version line. Some integrations still publish a parallel lower line, so pick the line that matches whether USEM is licensed.
- Listings for CC, CVR, AVR, TI, TISC and SPC could not be located because Store search needs a login. Their release notes are below.

**Brazil family release notes**

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Security Operations release notes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/security-operations-rn-landing.md) | Release notes | Brazil SecOps landing | OK |
| [Vulnerability Response release notes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/secops-vuln-resp-rn.md) | Release notes | VR, Brazil | OK |
| [USEM release notes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/secops-sem-rn.md) | Release notes | USEM, Brazil | OK |
| [CVR release notes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/secops-cvr-rn.md) | Release notes | CVR, Brazil | OK |
| [SIR release notes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/secops-sir-rn.md) | Release notes | SIR, Brazil | OK |
| [TISC release notes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/secops-tisc-rn.md) | Release notes | TISC, Brazil | OK |
| [Brazil security and notable fixes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/brazil-security-notables.md) | Release notes | Security and notable fixes | OK |
| [CMDB release notes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/cmdb-rn.md) | Release notes | CMDB, Brazil | OK |
| [Incident Management release notes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/incident-management-rn.md) | Release notes | Incident, Brazil | OK |
| [Change Management release notes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/change-management-rn.md) | Release notes | Change, Brazil | OK |
| [Performance Analytics release notes](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/release-notes/performance-analytics-rn.md) | Release notes | Performance Analytics, Brazil | OK |
| [AVR upgrade notes, Zurich to Brazil](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/delta-zurich-brazil/brazil-zurich-applicationvulnerabilityresponse-release-notes.md) | Release notes | Combined AVR upgrade delta | OK |
| [CC upgrade notes, Zurich to Brazil](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/delta-zurich-brazil/brazil-zurich-configurationcompliance-release-notes.md) | Release notes | Combined CC upgrade delta | OK |
| [CVR upgrade notes, Zurich to Brazil](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/delta-zurich-brazil/brazil-zurich-containervulnerabilityresponse-release-notes.md) | Release notes | Combined CVR upgrade delta | OK |

**Store app version histories** (from the `store` branch; each row shows the newest entry)

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Store release notes index](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/index.md) | Release notes index | All Store app version histories | OK |
| [Security Operations version histories](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/sn-store-rn-secops.md) | Release notes index | SecOps app index | OK |
| [USEM](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-unified-security-exposure-mgmt.md) | Release notes | Latest 31.3.1, September 2026 | OK |
| [Vulnerability Response](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-vulnerability-response.md) | Release notes | Latest 30.8.5, September 2026 | OK |
| [VR and CC for Containers](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-vr-cc-containers.md) | Release notes | Latest 30.8.5, September 2026 | OK |
| [Configuration Compliance](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-config-compl.md) | Release notes | Latest 30.6.15, September 2026 | OK |
| [Vulnerability Solution Management](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-solution-manangement.md) | Release notes | Latest 10.4.1, December 2022 | OK |
| [Vulnerability Crisis Management](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-vr-vulnerability-crisis-mgmt.md) | Release notes | Latest 1.0.1, August 2024 | OK |
| [Vulnerability Exposure Assessment](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-vr-vulnerability-exposure-assessment.md) | Release notes | Latest 30.9.1, September 2026 | OK |
| [Security Posture Control core](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-vr-posture-control-core.md) | Release notes | Latest 7.2.3, September 2026 | OK |
| [VR Integration with Tenable](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-vr-integration-with-tenable.md) | Release notes | Latest 30.5.3, September 2026 | OK |
| [VR Integration with Wiz](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-vr-int-wiz.md) | Release notes | Latest 32.8.4, September 2026 | OK |
| [Invicti Application Vulnerability Integration](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-invicti-app-vuln-integration.md) | Release notes | Latest 30.4.2, September 2026 | OK |
| [Security Incident Response](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-sir.md) | Release notes | Latest 14.4.0, September 2026 | OK |
| [Threat Intelligence](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-threat-intel.md) | Release notes | Latest 13.5.0, September 2026 | OK |
| [TISC for Security Operations](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-threat-intel-sec-center-secops.md) | Release notes | Latest 4.8.1, September 2026 | OK |
| [Splunk ES Integration for Security Operations](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-sir-splunk-es-int-sec-ops.md) | Release notes | Latest 12.5.3, September 2026 | OK |
| [Splunk Enterprise Event Ingestion](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-splunk-ingestion.md) | Release notes | Latest 11.6.7, September 2026 | OK |
| [Splunk Search integration](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-splunk-search.md) | Release notes | Latest 10.5.0, August 2025 | OK |
| [Splunk Enterprise Security integration (older app)](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-splunk-es.md) | Release notes | Latest 12.0.12, April 2024 | OK |
| [Service Graph Connector for Wiz](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-platcap-rn-service-graph-connector-wiz.md) | Release notes | Latest 1.6.0, July 2026 | OK |
| [Service Graph Connector for Splunk](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-platcap-rn-service-graph-connector-splunk.md) | Release notes | Latest 4.2.0, June 2026 | OK |
| [CMDB version histories](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-cmdb-landing.md) | Release notes index | CMDB app index | OK |
| [Performance Analytics for CC](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-vr-performance-analytics-configuration-compliance.md) | Release notes | Latest 1.5.2, December 2025 | OK |
| [Performance Analytics for SIR](https://github.com/ServiceNow/ServiceNowDocs/blob/store/markdown/store-release-notes/store-secops-rn-pa-sir.md) | Release notes | Latest 10.5.2, May 2025 | OK |

### Third-party integration apps on the ServiceNow Store

Vendor-published or vendor-specific ServiceNow Store apps for tools whose own documentation is indexed in [Security Tool Documentation](/SECURITY_TOOL_DOCUMENTATION.md).

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Service Graph Connector for Tenable](https://store.servicenow.com/store/app/d102bfea1ba46a50a85b16db234bcbf7) | ServiceNow Store app, published by Tenable, v6.3.0 | Tenable assets into CMDB through IRE; prerequisite for Tenable-built apps | OK |
| [Wiz Integration for Security Operations](https://store.servicenow.com/store/app/d069e3ee1be06a50a85b16db234bcb1d) | ServiceNow Store app | Wiz SecOps app | OK |
| [Wiz Integration for Container Vulnerability Response](https://store.servicenow.com/store/app/225b676a1b246a50a85b16db234bcb18) | ServiceNow Store app | Container VR integration, linked from Wiz | OK |
| [Snyk Security for Application Vulnerability Response](https://store.servicenow.com/store/app/bc2ae7e21b246a50a85b16db234bcb88) | ServiceNow Store app | Snyk Open Source and Code findings into AVR | OK |
| [Snyk API and Web for Application Vulnerability Response](https://store.servicenow.com/store/app/0a5317329797ea103fa8b84bf253afe4) | ServiceNow Store app, published by Snyk Ltd, v1.1.0 | API and Web (DAST) findings into AVR | OK |
| [Zafran Threat Exposure Management Platform](https://store.servicenow.com/store/app/ccebefea1b246a50a85b16db234bcb21) | ServiceNow Store app, published by Zafran Security | VR integration with Zafran risk score and mitigating factors | OK |

### Splunk apps that connect to ServiceNow

| App | Built by | Latest version | What it is for | Status |
|---|---|---|---|---|
| [Splunk Add-on for ServiceNow (1928)](https://splunkbase.splunk.com/app/1928) | Splunk | 11.2.0 (2026-09-21) | Pull ServiceNow CMDB and incidents; create incidents from Splunk | OK |
| [ServiceNow SecOps Event Ingestion Addon for Splunk ES (4770)](https://splunkbase.splunk.com/app/4770) | ServiceNow | 1.4.2 (2025-10-16) | Forward ES notable events to SIR | OK |
| [ServiceNow Security Operations Addon (3921)](https://splunkbase.splunk.com/app/3921) | ServiceNow | 1.40.4 (2025-10-16) | ServiceNow SecOps app for Splunk | OK |
| [ServiceNow SOAR connector (5932)](https://splunkbase.splunk.com/app/5932) | Splunk | 2.6.10 (2026-08-07) | SOAR actions against ServiceNow | OK |

### Developer APIs

The REST API reference is in the `australia` and `zurich` branches of ServiceNowDocs. The `api-reference` folder was not in the `brazil` branch as of 2026-09-28, so check again later.

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [API implementation and reference index](https://github.com/ServiceNow/ServiceNowDocs/blob/australia/markdown/api-reference/index.md) | API reference | Contents of the REST, server and client API docs | OK |
| [REST APIs overview](https://github.com/ServiceNow/ServiceNowDocs/blob/australia/markdown/api-reference/rest-api-explorer/c_RESTAPI.md) | API reference | REST concepts and the REST API Explorer | OK |
| [Table API](https://github.com/ServiceNow/ServiceNowDocs/blob/australia/markdown/api-reference/rest-apis/c_TableAPI.md) | API reference | CRUD on any table, such as VR vulnerable items or incidents | OK |
| [Import Set API](https://github.com/ServiceNow/ServiceNowDocs/blob/australia/markdown/api-reference/rest-apis/c_ImportSetAPI.md) | API reference | Push records into staging tables and transform maps | OK |
| [Identification and Reconciliation API](https://github.com/ServiceNow/ServiceNowDocs/blob/australia/markdown/api-reference/rest-apis/c_IdentifyReconcileAPI.md) | API reference | Dedupe-safe CMDB writes through IRE | OK |
| [CMDB Instance API](https://github.com/ServiceNow/ServiceNowDocs/blob/australia/markdown/api-reference/rest-apis/cmdb-instance-api.md) | API reference | CRUD on CIs and relationships | OK |
| [Change Management API](https://github.com/ServiceNow/ServiceNowDocs/blob/australia/markdown/api-reference/rest-apis/change-management-api.md) | API reference | Create and manage change requests | OK |
| [Scorecards API](https://github.com/ServiceNow/ServiceNowDocs/blob/australia/markdown/api-reference/rest-apis/c_PerformanceAnalyticsAPI.md) | API reference | Read Performance Analytics scorecards for metrics export | OK |
| [Attachment API](https://github.com/ServiceNow/ServiceNowDocs/blob/australia/markdown/api-reference/rest-apis/c_AttachmentAPI.md) | API reference | Upload and download attachments | OK |
| [Create a scripted REST API](https://github.com/ServiceNow/ServiceNowDocs/blob/australia/markdown/api-reference/rest-api-explorer/t_CreateAScriptedRESTService.md) | How-to | Build custom inbound endpoints | OK |
| [CVE Exposure Assessment REST API](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/security-management/vulnerability-response-workspaces/vr-va-ws-cve-exposure-assessment-api.md) | API reference | Exposure assessment by CVE; the only security-specific REST API in the brazil docs | OK |
| [ServiceNow SDK](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/application-development/servicenow-sdk/servicenow-sdk-landing.md) | Developer docs | Fluent SDK, apps as code | OK |
| [Fluent Table API](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/application-development/servicenow-sdk/table-api-now-ts.md) | API reference | Define tables as code | OK |
| [Fluent Scripted REST API](https://github.com/ServiceNow/ServiceNowDocs/blob/brazil/markdown/application-development/servicenow-sdk/scripted-rest-api-api-now-ts.md) | API reference | Define scripted REST as code | OK |
| [ServiceNow Developer portal](https://developer.servicenow.com/dev.do) | Developer portal | Personal developer instances, API reference UI, learning | App shell (SPA returns 200 for any path) |

### GitHub organizations and repositories

Official orgs: [ServiceNow](https://github.com/ServiceNow) (286 public repos), [ServiceNowDevProgram](https://github.com/ServiceNowDevProgram) (89) and [ServiceNowNextExperience](https://github.com/ServiceNowNextExperience) (22). None of them holds VR, SIR or TI application source. Those apps ship only through the Store.

| Repository | Purpose | Stars | Last push | Notes |
|---|---|---|---|---|
| [ServiceNow/ServiceNowDocs](https://github.com/ServiceNow/ServiceNowDocs) | Official product docs as markdown, one branch per release family | 525 | 2026-09-28 | Default branch `brazil`; license NOASSERTION; see `llms.txt` for agent use |
| [ServiceNow/sdk](https://github.com/ServiceNow/sdk) | Fluent SDK (now-sdk) | 129 | 2026-09-28 | Release v4.13.0 (2026-09-23); no license reported, check terms before reuse |
| [ServiceNow/sdk-examples](https://github.com/ServiceNow/sdk-examples) | SDK examples | 93 | 2026-09-14 | MIT |
| [ServiceNow/servicenow-cli](https://github.com/ServiceNow/servicenow-cli) | Alternative download for the ServiceNow CLI | 38 | 2025-11-20 | No license reported |
| [ServiceNow/PySNC](https://github.com/ServiceNow/PySNC) | Python client for ServiceNow (GlideRecord style) | 125 | 2026-05-19 | MIT |
| [ServiceNow/vulnerability-response](https://github.com/ServiceNow/vulnerability-response) | GitHub Action for SBOM Workspace | 1 | 2024-10-09 | Not VR product source or docs |
| [ServiceNow/sbom-upload](https://github.com/ServiceNow/sbom-upload) | GitHub Action to upload SBOMs | 1 | 2024-12-03 | MIT |
| [ServiceNow/sbom-status](https://github.com/ServiceNow/sbom-status) | GitHub Action to check SBOM upload status | 1 | 2025-02-11 | |
| [ServiceNow/servicenow-devops-security-result](https://github.com/ServiceNow/servicenow-devops-security-result) | Security-scan results into ServiceNow DevOps | 6 | 2026-09-10 | MIT; no description, purpose inferred |
| [ServiceNow/servicenow-devops-change](https://github.com/ServiceNow/servicenow-devops-change) | Change gating from pipelines | 34 | 2026-09-10 | MIT |
| [ServiceNow/servicenow-devops-get-change](https://github.com/ServiceNow/servicenow-devops-get-change) | Read change status from pipelines | 5 | 2026-09-10 | MIT; sibling `servicenow-devops-update-change` |
| [ServiceNow/servicenow-devops-sonar](https://github.com/ServiceNow/servicenow-devops-sonar) | SonarQube results into DevOps | 3 | 2026-09-10 | MIT |
| [ServiceNow/sncicd-instance-scan](https://github.com/ServiceNow/sncicd-instance-scan) | CI/CD Instance Scan action | 14 | 2023-07-19 | MIT; stale |
| [ServiceNow/example-restclient-myworkapp-nodejs](https://github.com/ServiceNow/example-restclient-myworkapp-nodejs) | Example Node.js REST client app | 102 | 2022-01-21 | Stale |
| [ServiceNow/DoomArena](https://github.com/ServiceNow/DoomArena) | Framework for testing AI agents against security threats | 64 | 2025-09-12 | Apache-2.0; research |
| [ServiceNowDevProgram/code-snippets](https://github.com/ServiceNowDevProgram/code-snippets) | Community code snippets | 440 | 2025-10-31 | Managed by the Developer Program |
| [ServiceNowDevProgram/example-instancescan-checks](https://github.com/ServiceNowDevProgram/example-instancescan-checks) | Instance Scan example checks | 70 | 2025-09-30 | GPL-2.0 |
| [ServiceNowDevProgram/ServiceNow-SDK-CC-Starter](https://github.com/ServiceNowDevProgram/ServiceNow-SDK-CC-Starter) | AI coding-assistant starter commands for SDK work | 4 | 2026-05-30 | |
| [ServiceNowDevProgram/Hacktoberfest](https://github.com/ServiceNowDevProgram/Hacktoberfest) | Developer community hub repo | 182 | 2026-09-08 | |

**GitHub Pages sites**

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [servicenow.github.io/sdk](https://servicenow.github.io/sdk/) | GitHub Pages | Fluent SDK docs | OK |
| [servicenow.github.io/PySNC](https://servicenow.github.io/PySNC/) | GitHub Pages | PySNC docs | OK |
| [servicenow.github.io/DoomArena](https://servicenow.github.io/DoomArena/) | GitHub Pages | DoomArena research site | OK |
| [servicenowdevprogram.github.io/code-snippets](https://servicenowdevprogram.github.io/code-snippets/) | GitHub Pages | Browsable code snippets | OK |
| [servicenownextexperience.github.io](https://servicenownextexperience.github.io/) | GitHub Pages | Next Experience (UI Builder) developer site | OK |

### Community and training

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Security Operations community hub](https://www.servicenow.com/community/secops/ct-p/security-operations) | Community | VR, SIR, TI and CC discussions | OK |
| [Security Operations forum](https://www.servicenow.com/community/secops-forum/bd-p/security-operations-forum) | Forum | SecOps questions and answers | OK |
| [ITSM community hub](https://www.servicenow.com/community/itsm/ct-p/it-service-management) | Community | Incident, Problem and Change | OK |
| [ServiceNow AI Platform forum](https://www.servicenow.com/community/servicenow-ai-platform-forum/bd-p/now-platform-forum) | Forum | Platform, CMDB and analytics questions | OK (redirect) |
| [Developer community hub](https://www.servicenow.com/community/developer/ct-p/Developer) | Community | Developer hub | OK |
| [Developer forum](https://www.servicenow.com/community/developer-forum/bd-p/developer-forum) | Forum | Scripting and API questions | OK |
| [Now Learning](https://learning.servicenow.com/) | Training | Official courses and certifications | Gated (login) |
| [Now Learning (legacy host)](https://nowlearning.servicenow.com/) | Training | Same portal | Gated (login) |
| [Developer learning paths](https://developer.servicenow.com/dev.do#!/learn) | Training | Developer learning and personal instances | App shell (SPA returns 200 for any path) |

- Specific Now Learning SecOps paths and certification pages sit behind SSO and could not be verified.
- ServiceNow marketing product pages timed out during the check and are left out.

## Armis Centrix and VIPR

Armis customer manuals are behind logins, but the REST API reference at dev.armis.com is public. VIPR Pro (formerly Silk Security) has no separate public docs; its documentation is in the gated Armis portal. ServiceNow has completed its acquisition of Armis, so listing publishers may change.

**Product pages**

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Armis Centrix platform](https://www.armis.com/platform/armis-centrix/) | Product page | Platform overview | OK (redirect) |
| [Armis Centrix for VIPR Pro](https://www.armis.com/platform/armis-centrix-for-vipr-pro-prioritization-and-remediation/) | Product page | Finding consolidation, dedup, prioritization, ownership and remediation | OK |
| [VIPR Pro launch blog](https://www.armis.com/blog/introducing-armis-centrix-for-vipr-pro-prioritization-and-remediation/) | Blog | Module launch after the Silk acquisition | OK |
| [VIPR Pro brochure (PDF)](https://media.armis.com/pdfs/br-armis-centrix-for-vipr-pro-en.pdf) | Datasheet | Product brochure | OK |
| [VIPR Pro integrations](https://www.armis.com/integration-product/armis-centrix-for-vipr-pro-prioritization-and-remediation/) | Catalog | Integrations that feed VIPR Pro | OK |
| [Armis Centrix for Early Warning](https://www.armis.com/platform/armis-centrix-for-early-warning/) | Product page | Pre-CVE and active-exploitation intel | OK |
| [Armis Centrix for VMDR](https://www.armis.com/platform/armis-centrix-for-vulnerability-management-detection-and-response/) | Product page | Vulnerability management detection and response | OK |
| [Asset Management and Security](https://www.armis.com/platform/armis-centrix-for-asset-management-and-security/) | Product page | Core asset inventory | OK |
| [Asset Intelligence Engine](https://www.armis.com/platform/armis-asset-intelligence-engine) | Product page | Crowdsourced device knowledge base | OK (redirect) |
| [Integrations and Adapters](https://www.armis.com/integrations-adapters/) | Catalog | Master list of Armis adapters | OK (redirect) |
| [Vulnerability-management integrations](https://www.armis.com/technology-integrations-category/vulnerability-management/) | Catalog | Scanner and VM integrations | OK |
| [Armis and Splunk](https://www.armis.com/splunk/) | Partner page | Links to Splunkbase 4872 and 4873 | OK |
| [Armis and ServiceNow](https://www.armis.com/servicenow/) | Partner page | ServiceNow integration overview | OK |
| [Armis and ServiceNow partner brief (PDF)](https://media.armis.com/pdfs/pb-armis-and-servicenow-partnership-en.pdf) | Partner brief | Connector and VR integration summary | OK |
| [Armis Marketplace](https://www.armis.com/platform/armis-marketplace/) | Vendor marketplace | Armis add-on marketplace | OK |
| [Resources center](https://www.armis.com/resources/) | Library | Whitepapers, briefs and webinars | OK |
| [ServiceNow acquisition-close blog](https://www.armis.com/blog/welcoming-the-next-chapter-servicenow-completes-armis-acquisition/) | Blog | Armis is now part of ServiceNow | OK |

**Docs, support and API**

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Armis docs portal](https://docs.armis.com/) | Product manuals | Customer documentation | Gated (login) |
| [Armis Support](https://support.armis.com/) | Support portal | Cases and knowledge base, including integration guides | Gated (login) |
| [Service Graph Connector KB](https://support.armis.com/s/article/Service-Graph-Connector) | KB article | Install and configure the ServiceNow connector | Gated (login) |
| [ServiceNow VR integration KB](https://support.armis.com/s/article/ServiceNow-vulnerability-response) | KB article | Configure the VR integration | Gated (login) |
| [API Management KB](https://support.armis.com/s/article/Content-Armis-User-Guide-API) | KB article | API key and secret management | Gated (login) |
| [Armis Developers](https://developers.armis.com/) | Developer portal | Entry to API docs and the partner program | OK (needs a full browser user agent) |
| [Armis API reference](https://dev.armis.com/reference) | API reference | Public REST reference: OAuth token, assets, alerts, collectors, sites, integrations, policies | OK |
| [Armis API getting-started guide](https://dev.armis.com/docs/your-guide-to-building-with-armis-apis) | API guide | Building with Armis APIs | OK |
| [Armis developer community](https://dev.armis.com/discuss) | Forum | API questions | OK |
| [Developer portal tech paper (PDF)](https://media.armis.com/image/upload/v1772640904/tp-armis-developer-portal-en.pdf) | PDF | Developer portal overview | OK |
| [Armis Python SDK docs](https://armis-python-sdk.readthedocs.io/en/stable/) | SDK docs | Docs for `armis-sdk` on PyPI (v1.2.3) | OK |
| [Armis Intelligence Center](https://ic.armis.com/) | Console | API key source for the Early Warning feed | Bot-blocked (verify in a browser) |
| [Armis Trust Center](https://trust.armis.com/) | Trust and compliance | Security and compliance documents | Bot-blocked (verify in a browser) |
| [Armis Partner Portal](https://partnerportal.armis.com/English/) | Partner program | Partner resources (login inside) | OK |

**Marketplace listings and community**

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Vulnerability Response Integration with Armis](https://store.servicenow.com/store/app/6d4bef2a1b246a50a85b16db234bcb6c) | ServiceNow Store app, published by Armis Inc, v2.0.4 | Armis device vulnerabilities into VR, including OT | OK |
| [Service Graph Connector for Armis](https://store.servicenow.com/store/app/e43a2fe21b246a50a85b16db234bcb55) | ServiceNow Store app, published by Armis Inc, v2.2.0 | Managed, unmanaged, IoT and OT assets into CMDB | OK |
| [Early Warning for Security Exposure Management](https://store.servicenow.com/store/app/1a9d3020c3868f10bc9a989f050131e8) | ServiceNow Store app, published by ServiceNow | Armis exploited-CVE intel inside USEM and VR | OK |
| [Armis connector troubleshooting](https://www.servicenow.com/community/service-graph-connectors-forum/armis-service-graph-connector-for-servicenow-basic/m-p/3594160) | Community post | Basic connector troubleshooting; links to the Armis KB | OK |
| [Armis from ServiceNow community](https://www.servicenow.com/community/armis-from-servicenow/ct-p/armis) | Community | Post-acquisition Armis community | OK |
| [Armis on AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-zhbfuevcbnjfw) | AWS Marketplace | Armis Centrix SaaS through AWS billing | OK |
| [Armis Centrix FedRAMP private offer](https://aws.amazon.com/marketplace/pp/prodview-rvovutwqs4qfe) | AWS Marketplace | FedRAMP authorized offer | OK |
| [Armis AWS Marketplace page](https://www.armis.com/aws-marketplace) | Vendor page | Procurement through AWS | OK |
| [Armis on Microsoft Marketplace](https://marketplace.microsoft.com/en-us/product/armisinc1668090987837.armis-solution?tab=Overview) | Microsoft Marketplace | Azure listing | OK (redirect) |
| [Tenable Exposure Management: Armis Connector](https://docs.tenable.com/exposure-management/Content/connectors/armis-connector.htm) | Third-party connector docs | Pulls Armis assets into Tenable | OK |

- Splunkbase apps 4872 (add-on) and 4873 (app) are in the Splunk section. There is no Armis connector in the Splunk SOAR connectors org.
- Armis publishes no public API changelog.

**GitHub.** The official org is [ArmisSecurity](https://github.com/ArmisSecurity) ("Armis, Inc.", verified, 31 repos, no GitHub Pages). The legacy [silk-security](https://github.com/silk-security) org ("Silk Security (by Armis)", not verified) has 3 repos, all archived. A separate `armis-security` org is a one-off 2019 event org, not the product org.

| Repository | Purpose | Stars | Last push | Notes |
|---|---|---|---|---|
| [ArmisSecurity/armis-sdk-python](https://github.com/ArmisSecurity/armis-sdk-python) | Python SDK for common Armis platform use cases | 5 | 2026-08-18 | MIT; PyPI `armis-sdk` 1.2.3 |
| [ArmisSecurity/armis-cli](https://github.com/ArmisSecurity/armis-cli) | Go CLI (Armis AppSec branding) | 9 | 2026-10-07 | SLSA-3 signed releases and SBOMs |
| [ArmisSecurity/armis-appsec-mcp](https://github.com/ArmisSecurity/armis-appsec-mcp) | AI-powered security scanning MCP plugin | 6 | 2026-10-07 | Apache-2.0 |
| [ArmisSecurity/armis-knowledge-mcp](https://github.com/ArmisSecurity/armis-knowledge-mcp) | Knowledge MCP server for customers | 1 | 2026-07-30 | |
| [ArmisSecurity/homebrew-tap](https://github.com/ArmisSecurity/homebrew-tap) | Homebrew tap | 0 | 2026-10-07 | |
| [ArmisSecurity/silk-tf-modules](https://github.com/ArmisSecurity/silk-tf-modules) | Public Terraform modules from Silk Security | 0 | 2023-06-14 | Silk legacy |
| [ArmisSecurity/blueborne](https://github.com/ArmisSecurity/blueborne) | BlueBorne vulnerability research PoC | 619 | 2021 | Historical |
| [ArmisSecurity/urgent11-detector](https://github.com/ArmisSecurity/urgent11-detector) | URGENT/11 detector | 64 | 2019 | Historical |

**Splunkbase**

| App | Built by | Latest version | What it is for | Status |
|---|---|---|---|---|
| [Armis Add-On for Splunk (4872)](https://splunkbase.splunk.com/app/4872) | Armis employee account | 1.9.4 (2026-07-08) | Armis data ingestion | OK |
| [Armis App for Splunk (4873)](https://splunkbase.splunk.com/app/4873) | Armis employee account | 1.5.2 (2025-04-17) | Armis dashboards | OK |

## Tenable, Wiz, Snyk, Invicti, Zafran and Splunk

Manuals, API references, SDKs, GitHub repositories and training for these six tools are maintained in the library's [Security Tool Documentation](/SECURITY_TOOL_DOCUMENTATION.md) index, one page per tool. This page does not repeat them. Their ServiceNow Store integration apps are listed in the ServiceNow section above.

| Tool | Documentation page |
|---|---|
| Tenable | [Tenable documentation and repositories](/tools/tenable.md) |
| Wiz | [Wiz documentation and repositories](/tools/wiz.md) |
| Snyk | [Snyk documentation and repositories](/tools/snyk.md) |
| Invicti | [Invicti documentation and repositories](/tools/invicti.md) |
| Zafran Security | [Zafran Security documentation and repositories](/tools/zafran.md) |
| Splunk | [Splunk documentation and repositories](/tools/splunk.md) |

## MITRE and threat-informed defense ecosystem

The current ATT&CK release is v19.2 (published 2026-08-05; v19 was released on April 28, 2026). The STIX data, mitre/cti and TAXII collections are all at v19.2.

### ATT&CK knowledge base

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [MITRE ATT&CK](https://attack.mitre.org/) | Docs | ATT&CK knowledge base, v19.2 | OK |
| [Enterprise matrix](https://attack.mitre.org/matrices/enterprise/) | Docs | Enterprise tactics and techniques | OK |
| [ICS matrix](https://attack.mitre.org/matrices/ics/) | Docs | ICS matrix | OK |
| [Mobile matrix](https://attack.mitre.org/matrices/mobile/) | Docs | Mobile matrix | OK |
| [Enterprise mitigations](https://attack.mitre.org/mitigations/enterprise/) | Docs | M-IDs, control intent per technique | OK |
| [ICS mitigations](https://attack.mitre.org/mitigations/ics/) | Docs | ICS mitigations | OK |
| [Mobile mitigations](https://attack.mitre.org/mitigations/mobile/) | Docs | Mobile mitigations | OK |
| [Detection strategies](https://attack.mitre.org/detectionstrategies/) | Docs | DET-IDs in the v18 and later detection model | OK |
| [Analytics](https://attack.mitre.org/analytics/) | Docs | Analytics referenced by detection strategies | OK |
| [Data sources](https://attack.mitre.org/datasources/) | Docs | Data sources | OK |
| [Data components](https://attack.mitre.org/datacomponents/) | Docs | Log-level telemetry | OK |
| [Resources](https://attack.mitre.org/resources/) | Docs | Index of guidance | OK |
| [ATT&CK data and tools](https://attack.mitre.org/resources/attack-data-and-tools/) | Docs | Official list of STIX, Excel and TAXII formats and tools | OK |
| [Working with ATT&CK](https://attack.mitre.org/resources/working-with-attack/) | Docs | How to consume ATT&CK data | OK |
| [Versions](https://attack.mitre.org/resources/versions/) | Docs | Version history and permalinks | OK |
| [v19 permalink](https://attack.mitre.org/versions/v19/) | Docs | Frozen v19 site | OK |
| [Updates index](https://attack.mitre.org/resources/updates/) | Release notes | All release notes | OK |
| [Updates, August 2026 (v19.2)](https://attack.mitre.org/resources/updates/updates-august-2026/) | Release notes | v19.2 groups and software update | OK |
| [Updates, April 2026 (v19)](https://attack.mitre.org/resources/updates/updates-april-2026/) | Release notes | v19 | OK |
| [Updates, October 2025 (v18)](https://attack.mitre.org/resources/updates/updates-october-2025/) | Release notes | v18, which introduced detection strategies | OK |
| [Changelog](https://attack.mitre.org/resources/changelog.html) | Release notes | Object-level change log | OK |
| [Contribute](https://attack.mitre.org/resources/contribute/) | Docs | Contribution guidance | OK |
| [Terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) | Docs | License and branding terms | OK |

- Tools still keyed on the old data-source model or the `x_mitre_detection` text field are out of date for v18 and later. Use detection strategies, analytics and data components.

### ATT&CK data, Navigator, Workbench, TAXII and mitreattack-python

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [attack-stix-data index.json](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json) | Feed | Collection index; latest files are the 19.2 Enterprise, Mobile and ICS bundles | OK |
| [ATT&CK TAXII 2.1 discovery](https://attack-taxii.mitre.org/taxii2/) | API | TAXII 2.1 server for ATT&CK STIX 2.1 | OK only with the TAXII Accept header |
| [ATT&CK TAXII collections](https://attack-taxii.mitre.org/api/v21/collections/) | API | Enterprise, Mobile and ICS collections | OK only with the TAXII Accept header |
| [ATT&CK Navigator (hosted)](https://mitre-attack.github.io/attack-navigator/) | GitHub Pages | Hosted Navigator | OK |
| [Navigator usage guide](https://github.com/mitre-attack/attack-navigator/blob/master/USAGE.md) | Docs | Layer format and usage | OK |
| [mitreattack-python docs](https://mitreattack-python.readthedocs.io/en/latest/) | Docs | Library docs | OK |
| [ATT&CK Data Model docs](https://mitre-attack.github.io/attack-data-model/) | GitHub Pages | TypeScript library and schema docs | OK |
| [Cyber Analytics Repository](https://car.mitre.org/) | Docs | Analytics mapped to ATT&CK | OK |

- **TAXII needs the Accept header.** Send `Accept: application/taxii+json;version=2.1`. Without it the server returns 400 on `/taxii2/` and `/api/v21/`, and 404 on `/`. That is normal TAXII behavior, not an outage. Versioned API roots start at `/api/v21/attack-1.0`.
- **Workbench moved.** The ATT&CK Workbench repos now live in the `mitre-attack` org. The old `center-for-threat-informed-defense/attack-workbench-*` URLs redirect there. Workbench has no GitHub Pages site.
- For a pipeline pinned to v19.2, use attack-stix-data (versioned file names) or TAXII. mitre/cti is STIX 2.0 legacy; use it for CAPEC links or backward compatibility.

| Repository | Purpose | Stars | Last push | Notes |
|---|---|---|---|---|
| [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) | Official STIX 2.1 bundles, versioned | 689 | n/a | Release v19.2 (2026-08-05) |
| [mitre/cti](https://github.com/mitre/cti) | Legacy STIX 2.0 ATT&CK plus CAPEC | 2,154 | n/a | Release ATT&CK-v19.2 (2026-08-05); still maintained |
| [mitre-attack/attack-navigator](https://github.com/mitre-attack/attack-navigator) | Matrix annotation and layer web app | 2,475 | 2026-10-01 | v5.3.2 (2026-04-21); Apache-2.0 |
| [mitre-attack/attack-workbench-frontend](https://github.com/mitre-attack/attack-workbench-frontend) | Explore, extend and annotate ATT&CK locally | 445 | 2026-10-06 | v4.6.10 (2026-06-25) |
| [mitre-attack/attack-workbench-rest-api](https://github.com/mitre-attack/attack-workbench-rest-api) | Workbench backend REST API | n/a | 2026-10-07 | v4.17.3 (2026-07-06) |
| [mitre-attack/attack-workbench-taxii-server](https://github.com/mitre-attack/attack-workbench-taxii-server) | TAXII 2.1 server for Workbench collections | n/a | n/a | v2.0.1 (2026-06-17) |
| [mitre-attack/attack-workbench-deployment](https://github.com/mitre-attack/attack-workbench-deployment) | Docker Compose deployment for Workbench | n/a | 2026-10-04 | No releases |
| [mitre-attack/mitreattack-python](https://github.com/mitre-attack/mitreattack-python) | STIX access, Navigator layers, Excel export, diffs | 749 | n/a | v6.2.1 (2026-09-30) |
| [mitre-attack/attack-data-model](https://github.com/mitre-attack/attack-data-model) | TypeScript library and schema for ATT&CK objects | n/a | n/a | v4.10.1 (2026-05-06) |
| [mitre-attack/attack-website](https://github.com/mitre-attack/attack-website) | Source of attack.mitre.org | n/a | 2026-10-07 | |
| [mitre-attack/car](https://github.com/mitre-attack/car) | Cyber Analytics Repository data | n/a | 2025-05-16 | No releases |
| [mitre-attack/bzar](https://github.com/mitre-attack/bzar) | Zeek scripts that detect ATT&CK techniques | n/a | 2024-06-26 | |
| [mitre-attack/attack-arsenal](https://github.com/mitre-attack/attack-arsenal) | Red-team and emulation resources | n/a | 2021-04-20 | Stale |
| [mitre-attack/attack-scripts](https://github.com/mitre-attack/attack-scripts) | Old utility scripts | n/a | n/a | Archived; use mitreattack-python |
| [center-for-threat-informed-defense/attack-workbench-collection-manager](https://github.com/center-for-threat-informed-defense/attack-workbench-collection-manager) | Old Workbench component | n/a | n/a | Archived 2023, deprecated |

- Other archived repos in the mitre-attack org: attack-archives, attack-datasources, attack-datasources-stix-beta, attack-evals, evals_caldera, joystick and tram.

### CTID projects

Projects from the MITRE Center for Threat-Informed Defense (CTID). Several mapping repos are archived and their content has moved into Mappings Explorer.

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [CTID home](https://ctid.mitre.org/) | Docs | Center home | OK |
| [CTID projects](https://ctid.mitre.org/projects/) | Docs | Project catalog | OK |
| [Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) | GitHub Pages | ATT&CK mappings for NIST 800-53, CVE and KEV, VERIS and cloud controls | OK |
| [Mappings Explorer project page](https://ctid.mitre.org/projects/mappings-explorer/) | Docs | Project overview | OK |
| [Mappings Editor](https://center-for-threat-informed-defense.github.io/mappings-editor/) | GitHub Pages | Web tool for writing mappings | OK |
| [Top ATT&CK Techniques](https://center-for-threat-informed-defense.github.io/top-attack-techniques/) | GitHub Pages | Prioritize techniques by prevalence, choke points and actionability | OK |
| [Top ATT&CK Techniques project page](https://ctid.mitre.org/projects/top-attack-techniques/) | Docs | Project overview | OK |
| [Sightings Ecosystem](https://center-for-threat-informed-defense.github.io/sightings_ecosystem/) | GitHub Pages | Technique sightings seen in the wild | OK |
| [Sightings Ecosystem project page](https://ctid.mitre.org/projects/sightings-ecosystem/) | Docs | Project overview | OK |
| [Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/) | GitHub Pages | STIX extension for sequencing techniques | OK |
| [Attack Flow builder](https://center-for-threat-informed-defense.github.io/attack-flow/ui/) | GitHub Pages | Browser-based flow builder | OK |
| [Technique Inference Engine](https://center-for-threat-informed-defense.github.io/technique-inference-engine/) | GitHub Pages | Model that infers likely co-occurring techniques | OK |
| [Summiting the Pyramid](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/) | GitHub Pages | Method for robust analytics | OK |
| [Sensor Mappings to ATT&CK](https://center-for-threat-informed-defense.github.io/sensor-mappings-to-attack/) | GitHub Pages | Sensor telemetry mapped to data components | OK |
| [ATT&CK Sync](https://center-for-threat-informed-defense.github.io/attack-sync/) | GitHub Pages | Track ATT&CK version changes for mapping upkeep | OK |
| [CTI Blueprints](https://center-for-threat-informed-defense.github.io/cti-blueprints/) | GitHub Pages | CTI report templates | OK |
| [Threat-informed defense maturity (M3TID successor page)](https://ctid.mitre.org/inform) | Docs | Where the ctid.io/m3tid shortlink now lands | OK |

| Repository | Purpose | Stars | Last push | Notes |
|---|---|---|---|---|
| [mappings-explorer](https://github.com/center-for-threat-informed-defense/mappings-explorer) | Mappings Explorer source and data | n/a | 2026-10-05 | Last tag v1.1.0 (2024-04-15) |
| [mappings-editor](https://github.com/center-for-threat-informed-defense/mappings-editor) | Mappings Editor | n/a | n/a | v2.0.0 (2026-05-15) |
| [top-attack-techniques](https://github.com/center-for-threat-informed-defense/top-attack-techniques) | Top ATT&CK Techniques | n/a | 2026-10-07 | v2.0.0 (2024-07-17) |
| [sightings_ecosystem](https://github.com/center-for-threat-informed-defense/sightings_ecosystem) | Sightings data | n/a | 2025-05-28 | v2.0.0 (2024-03-12) |
| [attack-flow](https://github.com/center-for-threat-informed-defense/attack-flow) | Attack Flow | 781 | 2026-10-07 | v3.2.0 (2026-05-15) |
| [adversary_emulation_library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) | Full emulation plans such as APT29 and FIN6 | 2,171 | 2025-05-28 | v5.0.2 (2023); no Pages site |
| [technique-inference-engine](https://github.com/center-for-threat-informed-defense/technique-inference-engine) | Technique Inference Engine | n/a | 2026-09-04 | v1.0.0 (2024) |
| [summiting-the-pyramid](https://github.com/center-for-threat-informed-defense/summiting-the-pyramid) | Summiting the Pyramid | n/a | 2026-09-29 | v2.0.0 (2024-12-13) |
| [sensor-mappings-to-attack](https://github.com/center-for-threat-informed-defense/sensor-mappings-to-attack) | Sensor mappings | n/a | n/a | v1.0.0 (2023) |
| [attack-sync](https://github.com/center-for-threat-informed-defense/attack-sync) | ATT&CK Sync | n/a | 2026-05-19 | No releases |
| [attack-powered-suit](https://github.com/center-for-threat-informed-defense/attack-powered-suit) | Browser extension for ATT&CK lookups | n/a | 2026-04-29 | No releases |
| [tram](https://github.com/center-for-threat-informed-defense/tram) | ML mapping of CTI reports to ATT&CK | n/a | 2025-05-06 | v1.3.0 (2023) |
| [cti-blueprints](https://github.com/center-for-threat-informed-defense/cti-blueprints) | CTI report templates | n/a | n/a | v1.0.0 (2023) |
| [attack_to_cve](https://github.com/center-for-threat-informed-defense/attack_to_cve) | CVE to ATT&CK methodology | n/a | n/a | Archived; moved to Mappings Explorer |
| [security-stack-mappings](https://github.com/center-for-threat-informed-defense/security-stack-mappings) | Cloud-native controls to ATT&CK | n/a | n/a | Archived; moved to Mappings Explorer |
| [attack-control-framework-mappings](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings) | NIST 800-53 to ATT&CK | n/a | n/a | Archived; moved to Mappings Explorer |
| [attack_to_veris](https://github.com/center-for-threat-informed-defense/attack_to_veris) | VERIS to ATT&CK | n/a | n/a | Archived |
| [m3tid](https://github.com/center-for-threat-informed-defense/m3tid) | Threat-informed defense maturity model | n/a | n/a | Archived 2025-06-25 |

- Last tagged releases of Mappings Explorer, Top ATT&CK Techniques and Sightings Ecosystem (2024) predate ATT&CK v18 and v19. Check the ATT&CK version embedded in each dataset before treating it as v19.2-compatible.
- Other active CTID repos: defending-iaas-with-attack, defending-ot-with-attack, threat-modeling-with-attack, insider-threat-ttp-kb, cloud-analytics, cwe-calculator, fight-fraud-framework and public-resources.

### D3FEND, ATLAS, Engage, CAPEC and CWE

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [D3FEND](https://d3fend.mitre.org/) | Docs | Knowledge graph of defensive countermeasures, ontology 1.6.0 | OK |
| [D3FEND API docs](https://d3fend.mitre.org/api-docs/) | API | REST API reference | OK |
| [D3FEND version endpoint](https://d3fend.mitre.org/api/version.json) | API | Returns 1.6.0, released 2026-08-31 | OK |
| [D3FEND matrix JSON](https://d3fend.mitre.org/api/matrix.json) | Feed | Matrix as JSON | OK |
| [D3FEND ontology JSON-LD](https://d3fend.mitre.org/ontologies/d3fend.json) | Feed | Full ontology | OK |
| [D3FEND resources](https://d3fend.mitre.org/resources/) | Docs | Downloads and resources | OK |
| [D3FEND offensive techniques](https://d3fend.mitre.org/offensive-technique/) | Docs | ATT&CK to D3FEND mapping | OK |
| [D3FEND digital artifact ontology](https://d3fend.mitre.org/dao/) | Docs | Digital artifacts | OK |
| [MITRE ATLAS](https://atlas.mitre.org/) | Docs | Adversarial threats to AI systems, data v2026.09 | OK |
| [ATLAS Navigator](https://mitre-atlas.github.io/atlas-navigator/) | GitHub Pages | Navigator with ATLAS data | OK |
| [MITRE Engage](https://engage.mitre.org/) | Docs | Denial, deception and adversary engagement | OK |
| [Engage matrix](https://engage.mitre.org/matrix/) | Docs | Engage matrix | OK |
| [Engage starter kit](https://engage.mitre.org/starter-kit/) | Docs | Getting started | OK |
| [Engage resources](https://engage.mitre.org/resources/) | Docs | Resources | OK |
| [CAPEC](https://capec.mitre.org/) | Docs | Attack pattern enumeration | OK |
| [CAPEC downloads](https://capec.mitre.org/data/downloads.html) | Feed | XML and CSV downloads | OK |
| [CAPEC latest XML](https://capec.mitre.org/data/xml/capec_latest.xml) | Feed | Full CAPEC XML | OK |
| [CWE](https://cwe.mitre.org/) | Docs | Weakness enumeration | OK |
| [CWE downloads](https://cwe.mitre.org/data/downloads.html) | Feed | XML and CSV downloads | OK |
| [CWE latest XML (zip)](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip) | Feed | Full CWE XML | OK |

| Repository | Purpose | Stars | Last push | Notes |
|---|---|---|---|---|
| [d3fend/d3fend-ontology](https://github.com/d3fend/d3fend-ontology) | Source for the D3FEND ontology build | n/a | 2026-10-01 | MIT; no GitHub releases |
| [d3fend/d3fend](https://github.com/d3fend/d3fend) | D3FEND website source | n/a | 2026-09-24 | |
| [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data) | ATLAS tactics, techniques and case studies (YAML) | n/a | n/a | v2026.09 (2026-09-15): 16 tactics, 120 techniques, 88 sub-techniques |
| [mitre-atlas/atlas-navigator-data](https://github.com/mitre-atlas/atlas-navigator-data) | ATLAS as STIX and Navigator layers | n/a | 2026-06-24 | v1.14.0 (2026-02-06); behind atlas-data |
| [mitre-atlas/atlas-website](https://github.com/mitre-atlas/atlas-website) | ATLAS site source | n/a | 2026-09-16 | |
| [mitre/engage](https://github.com/mitre/engage) | Engage data | n/a | 2024-04-01 | v1.0 (2022); stale |

- **ATLAS deep links.** atlas.mitre.org is a single-page app. Deep links such as `/matrices/ATLAS`, `/techniques/` and `/studies/` return 404 to curl but serve the app shell and render in a browser. Link checkers should allow atlas.mitre.org routes or check for the app shell instead of the status code.
- atlas-navigator-data lags atlas-data, so ATLAS Navigator layers may miss the newest techniques.

### Vulnerability feeds: CVE, NVD, CISA KEV, Vulnrichment, SSVC and EPSS

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [CVE.org](https://www.cve.org/) | Docs | CVE Program site | OK |
| [CVE downloads](https://www.cve.org/Downloads) | Feed | Bulk downloads | OK |
| [CVE Services](https://www.cve.org/AllResources/CveServices) | Docs | CVE Services information | OK |
| [CVE Services API docs](https://cveawg.mitre.org/api-docs/) | API | Official CVE JSON 5 record API | OK |
| [CVE record example](https://cveawg.mitre.org/api/cve/CVE-2021-44228) | API | Example record call | OK |
| [CVE schema docs](https://cveproject.github.io/cve-schema/) | GitHub Pages | CVE JSON record schema | OK |
| [CVE Project docs](https://cveproject.github.io/) | GitHub Pages | CVE Project documentation | OK |
| [NVD](https://nvd.nist.gov/) | Docs | National Vulnerability Database | OK |
| [NVD developers](https://nvd.nist.gov/developers) | Docs | API 2.0 docs hub | OK |
| [NVD start here](https://nvd.nist.gov/developers/start-here) | Docs | API keys and rate limits | OK |
| [NVD vulnerability API docs](https://nvd.nist.gov/developers/vulnerabilities) | API | CVE API 2.0 reference | OK |
| [NVD API workflows](https://nvd.nist.gov/developers/api-workflows) | Docs | Recommended sync workflows | OK |
| [NVD products API docs](https://nvd.nist.gov/developers/products) | API | CPE API | OK |
| [NVD data sources](https://nvd.nist.gov/developers/data-sources) | Docs | Data sources | OK |
| [NVD CVE API 2.0 example](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228) | API | CVSS, CPE and CWE enrichment | OK |
| [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Docs | KEV catalog (short link cisa.gov/kev) | OK |
| [KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Feed | Catalog version 2026.10.04, 1,734 entries | OK |
| [KEV CSV feed](https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv) | Feed | Same data as CSV | OK |
| [KEV JSON schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json) | Feed | Schema | OK |
| [KEV catalog resource page](https://www.cisa.gov/resources-tools/resources/kev-catalog) | Docs | Resource listing | OK |
| [KEV data on GitHub Pages](https://cisagov.github.io/kev-data/) | GitHub Pages | Mirror of the KEV files | OK |
| [CISA SSVC guidance](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) | Docs | CISA SSVC decision tree | OK (redirect) |
| [CISA SSVC calculator](https://www.cisa.gov/ssvc-calculator) | Tool | Web calculator | OK |
| [SSVC docs](https://certcc.github.io/SSVC/) | GitHub Pages | SSVC documentation | OK |
| [SSVC calculator (CERT/CC)](https://certcc.github.io/SSVC/ssvc-calc/) | GitHub Pages | Calculator | OK |
| [FIRST EPSS](https://www.first.org/epss/) | Docs | EPSS model overview | OK |
| [EPSS data](https://www.first.org/epss/data) | Docs | Data overview | OK |
| [EPSS FAQ](https://www.first.org/epss/faq) | Docs | FAQ | OK |
| [EPSS API docs](https://api.first.org/epss/) | API | API reference | OK |
| [EPSS API example](https://api.first.org/data/v1/epss?cve=CVE-2021-44228) | API | Score and percentile per CVE | OK |

| Repository | Purpose | Stars | Last push | Notes |
|---|---|---|---|---|
| [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | Official CVE List in CVE JSON 5 | 3,034 | n/a | Rolling releases, latest cve_2026-10-08_0500Z |
| [CVEProject/cve-schema](https://github.com/CVEProject/cve-schema) | CVE JSON schema | n/a | n/a | v5.2.0 (2025-10-29) |
| [CVEProject/cve-services](https://github.com/CVEProject/cve-services) | CVE Services API source | n/a | n/a | v2.8.6 (2026-09-17) |
| [cisagov/kev-data](https://github.com/cisagov/kev-data) | Official GitHub mirror of the KEV files | n/a | 2026-10-04 | |
| [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) | CISA ADP enrichment of CVEs: SSVC decision points, CVSS, CWE, CPE | 866 | 2026-10-08 | CC0-1.0; branch `develop`; no releases |
| [cisagov/decider](https://github.com/cisagov/decider) | Web app that guides ATT&CK mapping | n/a | 2026-02-20 | v3.0.0 (2023); no Pages site |
| [CERTCC/SSVC](https://github.com/CERTCC/SSVC) | SSVC framework, decision points and Python | n/a | 2026-10-07 | Release 2026.7.0 |
| [empiricalsec/epss_scores](https://github.com/empiricalsec/epss_scores) | Historical EPSS scores | n/a | 2026-10-07 | |

- **EPSS host move.** The daily CSV moved from `epss.cyentia.com` to `epss.empiricalsecurity.com`. The old `epss_scores-current.csv.gz` URL still redirects to a dated file on the new host (for example `epss_scores-2026-10-07.csv.gz`), but update hard-coded URLs. Only the redirect was checked, not the new host root.
- Vulnrichment's SSVC fields (Exploitation, Automatable, Technical Impact) are now inputs that BOD 26-04 relies on, not optional enrichment.

### Emulation and validation: Atomic Red Team, Caldera (Apache) and DeTTECT

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [Apache Caldera](https://caldera.apache.org/) | Docs | Caldera project home | OK |
| [caldera.mitre.org](https://caldera.mitre.org/) | Docs | Announcement page pointing to caldera.apache.org | OK |
| [Caldera docs](https://caldera.readthedocs.io/en/latest/) | Docs | User and developer docs | OK |
| [Atomic Red Team site](https://www.atomicredteam.io/atomic-red-team) | Docs | Project site | OK |
| [Atomic Red Team at Red Canary](https://redcanary.com/atomic-red-team/) | Docs | Where atomicredteam.io now redirects | OK (redirect) |
| [Atomic Red Team wiki](https://github.com/redcanaryco/atomic-red-team/wiki) | Docs | Wiki | OK |
| [Invoke-AtomicRedTeam wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki) | Docs | Execution framework wiki | OK |
| [DeTT&CT wiki](https://github.com/rabobank-cdc/DeTTECT/wiki) | Docs | DeTT&CT docs | OK |

| Repository | Purpose | Stars | Last push | Notes |
|---|---|---|---|---|
| [apache/caldera](https://github.com/apache/caldera) | Automated adversary emulation platform | 7,324 | 2026-08-27 | Latest release 5.3.0 (2025-04-24) |
| [mitre/stockpile](https://github.com/mitre/stockpile) | Caldera abilities and adversaries plugin | n/a | 2026-04-30 | Homepage now caldera.apache.org; sibling plugins emu, atomic, caldera-ot, access, debrief, fieldmanual, builder, gameboard |
| [center-for-threat-informed-defense/caldera_pathfinder](https://github.com/center-for-threat-informed-defense/caldera_pathfinder) | Maps scanned vulnerabilities to attack paths | n/a | n/a | Archived 2025-04-03 |
| [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) | Atomic tests mapped to ATT&CK (YAML) | 12,617 | 2026-10-06 | MIT; no GitHub releases |
| [redcanaryco/invoke-atomicredteam](https://github.com/redcanaryco/invoke-atomicredteam) | PowerShell framework that runs atomic tests | n/a | 2025-09-08 | v2.3.0 (2025-02-28) |
| [rabobank-cdc/DeTTECT](https://github.com/rabobank-cdc/DeTTECT) | Score data-source, visibility and detection coverage; outputs Navigator layers | 2,346 | 2026-09-14 | v2.2.0 (2026-01-21); GPL-3.0 |
| [rabobank-cdc/dettect-editor](https://github.com/rabobank-cdc/dettect-editor) | DeTT&CT YAML editor | n/a | 2026-08-06 | |

- **Caldera moved to Apache.** MITRE contributed Caldera to the Apache Software Foundation incubator. github.com/mitre/caldera redirects to apache/caldera, and caldera.mitre.org is now an announcement page. Update old links to apache/caldera and caldera.apache.org.
- DeTT&CT v2.2.0 predates ATT&CK v19. Check its data-source model against the v18 and later detection-strategy model before relying on it for v19.2 layers.

### Policy: CISA BOD 26-04 and NIST SP 800-40r4

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [CISA BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) | Policy | Prioritizing Security Updates Based on Risk (June 10, 2026): risk-tiered remediation using KEV status, exploit automation, technical impact and asset exposure | OK |
| [BOD 26-04 implementation guidance](https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk) | Policy | Implementation guidance | OK |
| [BOD 22-01 (revoked)](https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities) | Policy | Previous KEV directive; redirects to a revoked page | OK (redirect) |
| [NIST SP 800-40r4](https://csrc.nist.gov/pubs/sp/800/40/r4/final) | Policy | Guide to enterprise patch management planning | OK |
| [NIST SP 800-40r4 (PDF)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-40r4.pdf) | Policy | Full text | OK |

- BOD 26-04 supersedes and revokes BOD 19-02 and BOD 22-01. It names KEV and CISA Vulnrichment as sources for KEV status, exploit automation and technical impact.
- Secondary coverage reports remediation deadlines (three days for vulnerabilities that meet all four criteria). Read the deadlines from the directive's own Table 1 before citing them.

## Related community resources

| Resource | Type | What it is for | Status |
|---|---|---|---|
| [TeamStarWolf library (repo)](https://github.com/TeamStarWolf/TeamStarWolf) | Repository | Open, threat-informed cybersecurity reference library; MIT | OK |
| [TeamStarWolf library (site)](https://teamstarwolf.github.io/TeamStarWolf/) | GitHub Pages | Rendered library, including this Tools Research section | OK |
| [ATTACK-Navi (repo)](https://github.com/TeamStarWolf/ATTACK-Navi) | Repository | Browser-based ATT&CK analyst workbench; v0.10.0 (2026-08-17); MIT | OK |
| [ATTACK-Navi (hosted)](https://teamstarwolf.github.io/ATTACK-Navi/) | GitHub Pages | Hosted app | OK |
| [cybersecurity-resources](https://github.com/TeamStarWolf/cybersecurity-resources) | Repository | Curated resources for vulnerability management and threat intelligence | OK |

## Dead or moved links to avoid

These URLs returned 404, were withdrawn, or have moved. They are shown as plain text so they are not clicked by mistake.

| Tool | Old URL | What happened | Use instead |
|---|---|---|---|
| ServiceNow | `store.servicenow.com/store/app/c8635e664717aa1002872f46736d43b0` | 404 (second Invicti listing ID from search) | [Invicti Application Vulnerability Integration](https://store.servicenow.com/store/app/44eaa3e61b246a50a85b16db234bcb26) |
| ServiceNow | `store.servicenow.com/sn_appstore_store.do#!/store/application/99251a9b9b923110f0b35f54d93fa174` | Old hash-style Invicti link; 404 under the current URL scheme | [Invicti Application Vulnerability Integration](https://store.servicenow.com/store/app/44eaa3e61b246a50a85b16db234bcb26) |
| ServiceNow | `store.servicenow.com/store/app/2c7cf7921b291810993e0feddc4bcb79` | 404 (Armis connector ID cited in a community post) | [Service Graph Connector for Armis](https://store.servicenow.com/store/app/e43a2fe21b246a50a85b16db234bcb55) |
| ServiceNow | `store.servicenow.com/store/app/ce8e6186476f6e10392d3369126d43c2` | 404 (Tenable ID from search results) | [VR Integration with Tenable](https://store.servicenow.com/store/app/861aa3e21b246a50a85b16db234bcb7c) |
| ServiceNow | `store.servicenow.com/store/app/05cd5c221b1bf010c8f185d0604bcbdc` | 404 (old link on a Wiz page) | [VR Integration with Wiz](https://store.servicenow.com/store/app/c0211a8e1b87aad02ca2a643604bcb1f) |
| ServiceNow | `servicenow.com/community/secops-forum/bd-p/secops-forum` | 404 | [Security Operations forum](https://www.servicenow.com/community/secops-forum/bd-p/security-operations-forum) |
| ServiceNow | `servicenow.com/community/cmdb-forum/bd-p/cmdb-forum`, `/itsm-forum/bd-p/itsm-forum`, `/itom-forum/bd-p/itom-forum`, `/performance-analytics-forum/bd-p/performance-analytics-forum` | 404 | [ServiceNow AI Platform forum](https://www.servicenow.com/community/servicenow-ai-platform-forum/bd-p/now-platform-forum) or [ITSM hub](https://www.servicenow.com/community/itsm/ct-p/it-service-management) |
| Armis | `www.armis.com/platform/armis-centrix-for-vipr-pro/` | 404 | [Armis Centrix for VIPR Pro](https://www.armis.com/platform/armis-centrix-for-vipr-pro-prioritization-and-remediation/) |
| Armis | `www.armis.com/platform/avm/` | Moved; redirects | [Armis Centrix for VIPR Pro](https://www.armis.com/platform/armis-centrix-for-vipr-pro-prioritization-and-remediation/) |
| Armis | `dev.armis.com/changelog` | 404, no public API changelog | [Armis API reference](https://dev.armis.com/reference) |
| Armis | `silk.security` | 404, domain no longer serves a site | [Armis Centrix for VIPR Pro](https://www.armis.com/platform/armis-centrix-for-vipr-pro-prioritization-and-remediation/) |
| Armis | `www.armis.com/integrations/tenable/` (also `/servicenow/`, `/splunk/`, `/wiz/`, `/snyk/`) | Moved; redirects to the adapters catalog | [Integrations and Adapters](https://www.armis.com/integrations-adapters/) |
| MITRE | `attack.mitre.org/detectionstrategies/enterprise/` | 404, no per-domain index | [Detection strategies](https://attack.mitre.org/detectionstrategies/) |
| MITRE | `attack.mitre.org/versions/v19.2/` | 404 | [v19 permalink](https://attack.mitre.org/versions/v19/) or the live site |
| MITRE | `attack.mitre.org/docs/attack-taxii/` | 404 | [ATT&CK data and tools](https://attack.mitre.org/resources/attack-data-and-tools/) |
| MITRE | `github.com/center-for-threat-informed-defense/attack-workbench-frontend` (and other `attack-workbench-*`) | Moved; redirects | [mitre-attack/attack-workbench-frontend](https://github.com/mitre-attack/attack-workbench-frontend) |
| MITRE | `mitre-attack.github.io/attack-workbench-frontend/` | 404, Workbench has no Pages site | [mitre-attack/attack-workbench-frontend](https://github.com/mitre-attack/attack-workbench-frontend) |
| MITRE | `top-attack-techniques.mitre-engenuity.org` and the `ctid.io/top-attack-techniques` shortlink that points to it | 403, old host | [Top ATT&CK Techniques](https://center-for-threat-informed-defense.github.io/top-attack-techniques/) |
| MITRE | `ctid.io/sightings-ecosystem` | 404 | [Sightings Ecosystem](https://center-for-threat-informed-defense.github.io/sightings_ecosystem/) |
| MITRE | `ctid.io/adversary-emulation` and `center-for-threat-informed-defense.github.io/adversary_emulation_library/` | 404 | [adversary_emulation_library repo](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) |
| MITRE | `center-for-threat-informed-defense.github.io/mappings-explorer/external/cve/` and `/external/kev/` | 404, site restructured | [Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) |
| MITRE | `github.com/mitre-engage` | No such org | [mitre/engage](https://github.com/mitre/engage) |
| MITRE | `github.com/mitre/caldera` and `caldera.mitre.org` | Moved to Apache | [apache/caldera](https://github.com/apache/caldera) and [caldera.apache.org](https://caldera.apache.org/) |
| Red Canary | `www.atomicredteam.io/invoke-atomicredteam` | 404 | [Invoke-AtomicRedTeam wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki) |
| FIRST | `www.first.org/epss/api` | 404, API docs moved | [EPSS API docs](https://api.first.org/epss/) |
| FIRST | `epss.cyentia.com/epss_scores-current.csv.gz` | Moved; redirects to the new host | `epss.empiricalsecurity.com` |
| CISA | `www.cisa.gov/news-events/directives/bod-26-04` | 404, short slug does not exist | [CISA BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) |
| CISA | `cisagov.github.io/decider/` | 404, no Pages site | [cisagov/decider](https://github.com/cisagov/decider) |


## Maintenance

Re-verify every link on this page quarterly, and after any major release (a new ServiceNow family, ATT&CK version or ES version). Check status codes and page titles, and treat app-shell hosts as unconfirmed until opened in a browser. Move anything that stops resolving into "Dead or moved links to avoid".

Last verified: 2026-10-08.
