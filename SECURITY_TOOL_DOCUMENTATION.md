# Security Tool Documentation & Repositories

> Reference index of official documentation, developer/API docs, GitHub organizations and repositories, notable community/integration repos, and learning resources for a representative enterprise security stack of 21 platforms. Curated to support a vulnerability-mitigation and detection-engineering program.

> **Verify before relying.** URLs and repo paths were collected by automated, web-assisted research and reflect vendor state as of 2025-2026; some deep links were not live-re-verified. Treat this as a starting index and confirm the current canonical URL before bookmarking widely. Vendor products are referenced descriptively, not endorsed.

## Contents

- Endpoint & EDR
- WAF & Edge
- Network & SSE
- Cloud & Supply Chain
- Vulnerability Management & AppSec
- Identity & Privileged Access
- SIEM

## Endpoint & EDR

### Tanium

_Official documentation & manuals_
- [Tanium Documentation Portal (current product docs)](https://docs.tanium.com)
- [Tanium Patch module guide](https://docs.tanium.com/patch/patch/index.html)
- [Tanium Knowledge Base (legacy; being decommissioned ~2026, content moving to docs.tanium.com)](https://kb.tanium.com)

_API & developer docs_
- [Tanium Developer Hub](https://developer.tanium.com)
- [Tanium API Reference (GraphQL API Gateway + Platform REST API)](https://developer.tanium.com/site/global/docs/api_reference)

_GitHub (official)_
- [Tanium GitHub organization —  (NOTE: org existence not confirmable via search this run; verify the org is Tanium-verified before trusting)](https://github.com/Tanium)

_Community / integration / detection repos_
- [PyTan — community Python wrapper for the Tanium SOAP/REST API](https://github.com/tanium/pytan)
- [pytan3 (newer Python client, docs on Read the Docs)](https://pytan3.readthedocs.io)

_Learning & reference_
- [Tanium blog and Tech Talks series](https://www.tanium.com/blog)
- [Tanium company / product overview](https://www.tanium.com/about)

> Note: Docs consolidated onto docs.tanium.com; the old kb.tanium.com Knowledge Base is slated for retirement around 2026 and redirects to the Resource Center. Tanium now positions the GraphQL API Gateway as the preferred integration path over the older Platform REST API; module-specific REST docs are reached via help links inside the Tanium Console (auth required). Console and most API docs require a customer login. GitHub org and the PyTan repo paths rely on established knowledge — web-search budget for this run was exhausted before they could be re-verified live; confirm before publishing.


### Microsoft Defender for Endpoint / Defender Vulnerability Management

_Official documentation & manuals_
- [Microsoft Defender for Endpoint documentation (Microsoft Learn hub)](https://learn.microsoft.com/en-us/defender-endpoint/)
- [Microsoft Defender Vulnerability Management documentation](https://learn.microsoft.com/en-us/defender-vulnerability-management/)
- [Microsoft Defender XDR documentation (parent suite)](https://learn.microsoft.com/en-us/defender-xdr/)

_API & developer docs_
- [Defender for Endpoint management & APIs overview](https://learn.microsoft.com/en-us/defender-endpoint/management-apis)
- [Defender for Endpoint API reference (apis-intro)](https://learn.microsoft.com/en-us/defender-endpoint/api/apis-intro)
- [Microsoft Graph Security API (strategic API surface for Defender)](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview)

_GitHub (official)_
- [Microsoft GitHub organization](https://github.com/microsoft)
- [mdatp-xplat — official cross-platform (Linux/macOS) Defender deployment & config samples](https://github.com/microsoft/mdatp-xplat)
- [mdatp-devicecontrol — official device-control policy samples](https://github.com/microsoft/mdatp-devicecontrol)

_Community / integration / detection repos_
- [Microsoft 365 Defender Hunting Queries (KQL, archived but widely referenced)](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
- [Sigma detection rules](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team (ATT&CK test content)](https://github.com/redcanaryco/atomic-red-team)
- [MITRE CALDERA (adversary emulation)](https://github.com/mitre/caldera)

_Learning & reference_
- [Microsoft Learn training catalog (Secure your organization with Defender for Endpoint)](https://learn.microsoft.com/en-us/training/)
- [Microsoft Defender for Endpoint Ninja training (Tech Community)](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/bg-p/MicrosoftDefenderATPBlog)

> Note: Product is part of Microsoft Defender XDR; the operations portal is security.microsoft.com (was securitycenter.microsoft.com). Advanced hunting uses KQL. The legacy Defender for Endpoint REST API is being superseded by the unified Microsoft Graph Security API — build new automation against Graph. Localized Learn URLs exist (/en-us/ is canonical). The /defender-endpoint/api/apis-intro path reflects a recent restructure of the API docs section; verify the exact leaf page if deep-linking. API-reference and DVM URLs rely on established knowledge — search budget was exhausted before live re-verification this run.


### CrowdStrike Falcon

_Official documentation & manuals_
- [CrowdStrike Falcon product documentation (in-console, auth required)](https://falcon.crowdstrike.com/documentation)
- [CrowdStrike resources / tech center](https://www.crowdstrike.com/resources/)

_API & developer docs_
- [CrowdStrike Developer Center (public API/SDK reference)](https://developer.crowdstrike.com)
- [FalconPy official project documentation](https://www.falconpy.io)

_GitHub (official)_
- [CrowdStrike GitHub organization](https://github.com/CrowdStrike)
- [FalconPy — official Python SDK](https://github.com/CrowdStrike/falconpy)
- [PSFalcon — official PowerShell SDK](https://github.com/CrowdStrike/psfalcon)
- [gofalcon — official Go SDK](https://github.com/CrowdStrike/gofalcon)
- [falcon-scripts — official sensor install/uninstall scripts](https://github.com/CrowdStrike/falcon-scripts)

_Community / integration / detection repos_
- [rusty-falcon — Rust SDK](https://github.com/CrowdStrike/rusty-falcon)
- [falcon-helm — Kubernetes Helm charts for Falcon sensors](https://github.com/CrowdStrike/falcon-helm)
- [falcon-operator — Kubernetes operator](https://github.com/CrowdStrike/falcon-operator)
- [CrowdStrike community samples](https://github.com/CrowdStrike/community)
- [helpful-links — curated index of CrowdStrike open-source projects & resources](https://github.com/CrowdStrike/helpful-links)
- [Sigma detection rules](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team (ATT&CK test content)](https://github.com/redcanaryco/atomic-red-team)

_Learning & reference_
- [CrowdStrike University (training/certification)](https://www.crowdstrike.com/services/crowdstrike-university/)
- [FalconPy documentation site & wiki](https://www.falconpy.io)
- [CrowdStrike blog](https://www.crowdstrike.com/blog/)

> Note: CrowdStrike has a strong, verified official GitHub presence at github.com/CrowdStrike (falconpy, psfalcon, gofalcon, rusty-falcon, falcon-scripts, falcon-operator, falcon-helm, community, helpful-links all confirmed). The SDKs are open-source and community-supported, not formal CrowdStrike products. In-console docs at falcon.crowdstrike.com require authentication; developer.crowdstrike.com is the public API reference. Falcon API uses OAuth2 with regional base URLs. A Terraform provider (CrowdStrike/terraform-provider-crowdstrike) also exists for IaC but was not re-verified live this run. crowdstrike-falconpy is the PyPI package name. developer.crowdstrike.com, falconpy.io, falcon.crowdstrike.com, CrowdStrike University and blog URLs rely on established knowledge — search budget was exhausted before live re-verification.


## WAF & Edge

### Akamai App & API Protector

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


### AWS WAF

_Official documentation & manuals_
- [AWS WAF Developer Guide](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)
- [AWS WAF Developer Guide (what is AWS WAF)](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html)
- [AWS WAF product page](https://aws.amazon.com/waf/)
- [AWS WAF endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/waf.html)

_API & developer docs_
- [AWS WAFV2 API Reference](https://docs.aws.amazon.com/waf/latest/APIReferenceV2/Welcome.html)
- [AWS CLI wafv2 command reference](https://docs.aws.amazon.com/cli/latest/reference/wafv2/index.html)
- [Boto3 WAFV2 client (Python SDK)](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/wafv2.html)
- [Terraform aws_wafv2_web_acl resource (HashiCorp AWS provider)](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl)
- [CloudFormation AWS::WAFv2::WebACL reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html)

_GitHub (official)_
- [AWS GitHub org](https://github.com/aws)
- [aws-samples org (example repos & blog code)](https://github.com/aws-samples)
- [awslabs org](https://github.com/awslabs)
- [hashicorp/terraform-provider-aws (contains all aws_wafv2_* resources)](https://github.com/hashicorp/terraform-provider-aws)

_Community / integration / detection repos_
- [aws-solutions/aws-waf-security-automations (managed WAF rule set + IP reputation/flood/scanner protection)](https://github.com/aws-solutions/aws-waf-security-automations)
- [aws-samples/aws-waf-sample (sample WAF conditions/rules)](https://github.com/aws-samples/aws-waf-sample)
- [awslabs/aws-waf-security-automations-partner-dashboard / AWS WAF dashboards](https://github.com/aws-samples/aws-cloudwatch-dashboard-for-aws-waf)

_Learning & reference_
- [AWS Security blog — WAF category](https://aws.amazon.com/blogs/security/category/security-identity-compliance/aws-waf/)
- [AWS WAF Workshop (Workshop Studio)](https://catalog.workshops.aws/aws-waf/en-US)
- [AWS Skill Builder (free training)](https://skillbuilder.aws/)
- [AWS WAF Managed Rules & AWS Marketplace rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups.html)

> Note: Use WAFV2 (the current API, single set of endpoints for regional + CloudFront/global). AWS WAF Classic (waf/wafregional, waf.amazonaws.com endpoint) is legacy — do not use for new work. The aws-solutions/aws-waf-security-automations solution is scheduled to retire December 2026; AWS now recommends native AWS Managed Rules + rate-based rules instead. Verify the Terraform aws_wafv2_web_acl page in-browser (Terraform Registry is JS-rendered and did not return text to WebFetch, but the resource is a long-standing part of the hashicorp/aws provider).


### Citrix NetScaler Web App Firewall

_Official documentation & manuals_
- [NetScaler Web App Firewall (current release docs)](https://docs.netscaler.com/en-us/citrix-adc/current-release/application-firewall.html)
- [Introduction to NetScaler Web App Firewall](https://docs.netscaler.com/en-us/citrix-adc/current-release/application-firewall/introduction-to-citrix-web-app-firewall.html)
- [Configuring the Web App Firewall](https://docs.netscaler.com/en-us/citrix-adc/current-release/application-firewall/configuring-application-firewall.html)
- [NetScaler product documentation portal](https://docs.netscaler.com/)

_API & developer docs_
- [NetScaler NITRO API / developer docs](https://developer-docs.netscaler.com/)
- [terraform-provider-citrixadc (Terraform Registry)](https://registry.terraform.io/providers/citrix/citrixadc/latest/docs)
- [netscaler/adc-nitro-go (NITRO API Go SDK)](https://github.com/netscaler/adc-nitro-go)
- [ansible-collection-netscaleradc (Ansible Galaxy)](https://galaxy.ansible.com/ui/repo/published/netscaler/adc/)
- [NetScaler config reference (appfw NITRO config objects)](https://developer-docs.netscaler.com/en-us/adc-nitro-api/current-release/configuration/application-firewall.html)

_GitHub (official)_
- [NetScaler GitHub org](https://github.com/netscaler)
- [citrix/terraform-provider-citrixadc (official Terraform provider)](https://github.com/citrix/terraform-provider-citrixadc)
- [netscaler/adc-nitro-go (NITRO API SDK for Go)](https://github.com/netscaler/adc-nitro-go)
- [netscaler/ansible-collection-netscaleradc](https://github.com/netscaler/ansible-collection-netscaleradc)
- [netscaler/automation-toolkit](https://github.com/netscaler/automation-toolkit)

_Community / integration / detection repos_
- [netscaler/netscaler-adc-metrics-exporter (Prometheus metrics, incl. WAF/AppFw)](https://github.com/netscaler/netscaler-adc-metrics-exporter)
- [netscaler/netscaler-observability-exporter (logs/metrics to observability stacks)](https://github.com/netscaler/netscaler-observability-exporter)
- [netscaler/netscaler-terraform-modules](https://github.com/netscaler/netscaler-terraform-modules)
- [netscaler/netscaler-k8s-ingress-controller (WAF via CRDs for Kubernetes)](https://github.com/netscaler/netscaler-k8s-ingress-controller)

_Learning & reference_
- [NetScaler Education & training](https://www.netscaler.com/services-support/education)
- [NetScaler blogs](https://www.netscaler.com/blog)
- [NetScaler Web App Firewall deployment/best-practice guide](https://docs.netscaler.com/en-us/citrix-adc/current-release/application-firewall/appfw-deployment-guide.html)
- [NetScaler developer hub (NITRO, automation samples)](https://developer-docs.netscaler.com/)

> Note: Product was renamed: Citrix ADC -> NetScaler ADC after the 2022 Cloud Software Group acquisition; the WAF feature has been called Citrix Web App Firewall / NetScaler AppFirewall (NITRO objects are still 'appfw'). Documentation moved from docs.citrix.com to docs.netscaler.com (the citrix-adc URL path is retained). GitHub content is actively migrating from the citrix org to the netscaler org — the Terraform provider (terraform-provider-citrixadc) and some repos still live under github.com/citrix, published to the Terraform Registry under the citrix namespace, while NITRO SDK/Ansible/toolkit repos are under github.com/netscaler.


## Network & SSE

### Check Point Quantum / Infinity

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


### Zscaler Zero Trust Exchange

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


## Cloud & Supply Chain

### AWS native security (Inspector / GuardDuty / Security Hub / Config)

_Official documentation & manuals_
- [Amazon Inspector User Guide](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html)
- [Amazon GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [AWS Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- [AWS Config Developer Guide](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html)
- [AWS Prescriptive Guidance: Configure AWS security services (vulnerability management)](https://docs.aws.amazon.com/prescriptive-guidance/latest/vulnerability-management/configure-aws-security-services.html)

_API & developer docs_
- [Amazon Inspector2 API Reference](https://docs.aws.amazon.com/inspector/v2/APIReference/Welcome.html)
- [Amazon GuardDuty API Reference](https://docs.aws.amazon.com/guardduty/latest/APIReference/Welcome.html)
- [AWS Security Hub API Reference](https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html)
- [AWS Config API Reference](https://docs.aws.amazon.com/config/latest/APIReference/Welcome.html)
- [AWS provider (hashicorp/aws) Terraform docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [AWS SDK for Python (Boto3) documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)

_GitHub (official)_
- [aws-samples org](https://github.com/aws-samples)
- [amazon-guardduty-multiaccount-scripts](https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts)
- [Automated Security Response on AWS (Security Hub remediation solution)](https://github.com/aws-solutions/automated-security-response-on-aws)
- [AWS Config Rules (awslabs)](https://github.com/awslabs/aws-config-rules)
- [aws org (official)](https://github.com/aws)

_Community / integration / detection repos_
- [Prowler (AWS/multi-cloud security assessment, maps to Security Hub)](https://github.com/prowler-cloud/prowler)
- [ScoutSuite (NCC Group multi-cloud auditing)](https://github.com/nccgroup/ScoutSuite)
- [Steampipe AWS Compliance mod](https://github.com/turbot/steampipe-mod-aws-compliance)
- [Cloud Custodian (policy-as-code / Config-style rules)](https://github.com/cloud-custodian/cloud-custodian)

_Learning & reference_
- [AWS Workshop Studio catalog (Security Hub/GuardDuty workshops)](https://catalog.workshops.aws/)
- [AWS Skill Builder](https://skillbuilder.aws/)
- [AWS Security Blog](https://aws.amazon.com/blogs/security/)
- [AWS Security Maturity Model](https://maturitymodel.security.aws.dev/)

> Note: Doc landing URLs are the long-stable AWS entry points (Inspector = Inspector2/v2; Config lives under the Developer Guide). IMPORTANT: Security Hub now has two variants — classic Security Hub CSPM (ASFF format, APIReference 1.0) and the newer Security Hub (OCSF); confirm which your account uses before wiring automation. The aws-samples GuardDuty multi-account repo and aws-solutions ASR repo are the canonical official examples. Search-session budget was exhausted before every GitHub path could be re-confirmed live this run; AWS doc hostnames (docs.aws.amazon.com) are authoritative and stable.


### Microsoft Defender for Cloud

_Official documentation & manuals_
- [Microsoft Defender for Cloud documentation hub](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
- [What is Microsoft Defender for Cloud?](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction)
- [Defender CSPM (cloud security posture management)](https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management)
- [Defender for Cloud deployment / enable plans](https://learn.microsoft.com/en-us/azure/defender-for-cloud/get-started)

_API & developer docs_
- [Microsoft Defender for Cloud REST API reference](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/)
- [Security Center REST API (legacy namespace, still referenced)](https://learn.microsoft.com/en-us/rest/api/securitycenter/)
- [Azure Resource Manager Microsoft.Security provider (api-version query)](https://learn.microsoft.com/en-us/azure/templates/microsoft.security/)
- [azurerm Terraform provider (security_center_* resources)](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
- [Azure SDK for Python / .NET developer docs](https://learn.microsoft.com/en-us/azure/developer/)

_GitHub (official)_
- [Microsoft Defender for Cloud community repo (official, Microsoft/Azure)](https://github.com/Azure/Microsoft-Defender-for-Cloud)
- [Azure org](https://github.com/Azure)
- [Microsoft org](https://github.com/microsoft)

_Community / integration / detection repos_
- [Microsoft Sentinel / Defender detection content & hunting queries](https://github.com/Azure/Azure-Sentinel)
- [Defender for Cloud workbooks, Logic App playbooks, policies (inside Azure/Microsoft-Defender-for-Cloud)](https://github.com/Azure/Microsoft-Defender-for-Cloud)
- [Azure Landing Zones / policy baselines (Enterprise-Scale)](https://github.com/Azure/Enterprise-Scale)

_Learning & reference_
- [Microsoft Learn training catalog](https://learn.microsoft.com/en-us/training/)
- [Defender for Cloud Ninja training (Microsoft Tech Community)](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/become-a-microsoft-defender-for-cloud-ninja/ba-p/1608761)
- [Microsoft Defender for Cloud blog (Tech Community)](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/bg-p/MicrosoftDefenderCloudBlog)

> Note: Product was renamed from Azure Security Center / Azure Defender to Microsoft Defender for Cloud; older REST docs still live under the 'securitycenter' namespace and the ARM Microsoft.Security provider. REST reference pages on Microsoft Learn may show a sign-in/authorization banner. Do NOT confuse with 'Microsoft Defender for Cloud Apps' (MCAS) — a separate product with its own tenant-scoped REST API. The Azure/Microsoft-Defender-for-Cloud GitHub repo is the official home for workbooks, automation playbooks, and sample policies.


### Wiz

_Official documentation & manuals_
- [Wiz Documentation portal (requires tenant login)](https://docs.wiz.io/)
- [Wiz docs / reference (win.wiz.io)](https://win.wiz.io/reference)
- [Wiz API prerequisites (service account, API/token URL, client ID/secret)](https://win.wiz.io/reference/prerequisites)

_API & developer docs_
- [Wiz GraphQL API reference (win.wiz.io/reference)](https://win.wiz.io/reference)
- [Wiz API endpoint pattern: https://api.<dc>.app.wiz.io/graphql (dc = us1/us2/eu1/eu2 etc.), token via OAuth client credentials](https://win.wiz.io/reference/prerequisites)
- [Wiz CLI (wizcli) for CI/CD & IaC/image scanning —  (Wiz CLI section)](https://docs.wiz.io/)

_GitHub (official)_
- [wiz-sec-public org (Wiz's public GitHub presence)](https://github.com/wiz-sec-public)
- [wiz-sec org](https://github.com/wiz-sec)
- [Wiz Sensor GitHub Action](https://github.com/wiz-sec-public/wiz-sensor-github-action)

_Community / integration / detection repos_
- [Roadie Backstage Wiz plugin (community, RoadieHQ)](https://github.com/RoadieHQ/roadie-backstage-plugins)
- [Harness IDP Wiz plugin docs (integration reference)](https://developer.harness.io/docs/internal-developer-portal/plugins/available-plugins/wiz)

_Learning & reference_
- [Wiz Academy (free cloud security courses)](https://www.wiz.io/academy)
- [Wiz blog (incl. PEACH tenant-isolation framework, cloud threat research)](https://www.wiz.io/blog)
- [CloudSec Academy](https://www.wiz.io/academy/cloud-security)

> Note: Wiz is largely a closed/SaaS product: the full product documentation (docs.wiz.io) and the API/GraphQL reference under win.wiz.io require an authenticated Wiz tenant, so most of it is login-gated. Wiz has a limited official open-source footprint under the wiz-sec-public GitHub org (confirmed via third-party mirror for the wiz-sensor-github-action repo); verify the org/repo list directly on github.com since the search index did not return the org page. API uses a per-data-center GraphQL endpoint + OAuth client-credentials. The Roadie Backstage plugin is community-maintained, not an official Wiz repo.


### Chainguard

_Official documentation & manuals_
- [Chainguard Academy (docs & guides)](https://edu.chainguard.dev/)
- [How to use Chainguard Images](https://edu.chainguard.dev/chainguard/containers/how-to-use-chainguard-images/)
- [Chainguard Images directory (per-image overview, pull commands, advisories)](https://images.chainguard.dev/)
- [Chainguard developer resources (docs bundle / llms.txt)](https://edu.chainguard.dev/developer-resources/)

_API & developer docs_
- [chainctl CLI reference](https://edu.chainguard.dev/chainguard/chainctl/)
- [apko documentation (declarative OCI image builder)](https://edu.chainguard.dev/open-source/build-tools/apko/)
- [melange documentation (apk package builder)](https://edu.chainguard.dev/open-source/build-tools/melange/)
- [Chainguard cosign Terraform provider](https://registry.terraform.io/providers/chainguard-dev/cosign/latest/docs)
- [Chainguard AI docs bundle / MCP server (ghcr.io/chainguard-dev/ai-docs)](https://edu.chainguard.dev/developer-resources/)

_GitHub (official)_
- [chainguard-dev org](https://github.com/chainguard-dev)
- [chainguard-images/images (build configs for hardened OCI images)](https://github.com/chainguard-images/images)
- [chainguard-dev/apko](https://github.com/chainguard-dev/apko)
- [chainguard-dev/melange](https://github.com/chainguard-dev/melange)
- [chainguard-dev/images-autodocs (generates Academy image reference docs)](https://github.com/chainguard-dev/images-autodocs)

_Community / integration / detection repos_
- [Wolfi OS (undistro Linux base behind Chainguard Images/Starter tier)](https://github.com/wolfi-dev/os)
- [Sigstore cosign (image signing/verification used by Chainguard supply-chain flow)](https://github.com/sigstore/cosign)
- [Sigstore project org](https://github.com/sigstore)

_Learning & reference_
- [Chainguard Academy (labs & courses)](https://edu.chainguard.dev/)
- [Chainguard Unchained blog](https://www.chainguard.dev/unchained)
- [Chainguard developer resources hub](https://edu.chainguard.dev/developer-resources/)

> Note: Supply-chain focused: minimal, distroless, 0-known-CVE hardened container images plus signing/provenance tooling. Note the two GitHub orgs — chainguard-dev (tools: apko, melange, chainctl, images-autodocs) and chainguard-images (image build configs). Images are distroless by default with a `-dev` variant (shell/package manager) for build stages. Free Starter tier is built on Wolfi; other images on Chainguard OS. Full catalog and private-registry (cgr.dev) pulls require an org account. All GitHub/edu URLs here were surfaced or corroborated in search; the Terraform cosign provider path follows Chainguard's standard registry namespace.


## Vulnerability Management & AppSec

### Tenable (Tenable One / Nessus)

_Official documentation & manuals_
- [Tenable Documentation Hub (all products)](https://docs.tenable.com)
- [Tenable One Exposure Management Platform docs](https://docs.tenable.com/Tenableone.htm)
- [Tenable Vulnerability Management (formerly Tenable.io) docs](https://docs.tenable.com/Tenableio.htm)
- [Tenable Nessus documentation (Essentials/Professional/Expert/Manager)](https://docs.tenable.com/nessus.htm)
- [Tenable Security Center docs](https://docs.tenable.com/security-center.htm)

_API & developer docs_
- [Tenable Developer Portal (API reference, API Explorer)](https://developer.tenable.com)
- [pyTenable Python SDK documentation](https://pytenable.readthedocs.io)
- Tenable Security Center API Docs (linked from Developer Resources on docs.tenable.com)

_GitHub (official)_
- [Tenable GitHub organization (~89 repos)](https://github.com/tenable)
- [pyTenable — Python library for Tenable platform APIs](https://github.com/tenable/pyTenable)
- [tenable-connectors — officially supported connectors for the Tenable Integration Framework](https://github.com/tenable/tenable-connectors)
- [integration-jira-cloud — Jira Cloud integration](https://github.com/tenable/integration-jira-cloud)
- [container-security-action / was-action — official GitHub Actions for Tenable container & WAS scans](https://github.com/tenable/container-security-action)

_Community / integration / detection repos_
- [Tenable App & Add-on for Splunk (SIEM integration) —  (verify exact app ID on Splunkbase)](https://splunkbase.splunk.com/app/4060)
- [Security-Hub — Tenable.io to AWS Security Hub integration](https://github.com/tenable/Security-Hub)
- Navi — community CLI/automation tool for Tenable.io (github.com/tenable/navi — confirm slug before use)

_Learning & reference_
- [Tenable University / training](https://www.tenable.com/education)
- [Tenable Research blog](https://www.tenable.com/blog)
- [Tenable Community (forums/knowledge)](https://community.tenable.com)

> Note: Nessus guides are version-specific (URLs like docs.tenable.com/nessus/<ver>/...), so use the version selector on the Nessus docs page. Tenable One is the exposure-management umbrella that includes Tenable Vulnerability Management, Web App Scanning, Cloud Security, and Lumin. The legacy Nessus/SecurityCenter XMLRPC API reference is outdated — use the Developer Portal + API Explorer for current REST APIs. GitHub org has both Tenable-supported and community-supported (open-source) integrations. WebSearch budget was exhausted this turn; the org, pyTenable, connectors, and Jira repos were directly verified, Navi and the Splunk app ID were not fully re-verified live.


### Zafran Security

_Official documentation & manuals_
- [Zafran Threat Exposure Management Platform (product overview)](https://zafran.io/platform)
- [Zafran homepage](https://zafran.io)
- [Zafran resource library (whitepapers, briefs)](https://zafran.io/resources)

_API & developer docs_
- [Zafran Security API profile (third-party index, API Evangelist) —  (no public first-party API reference located; API access is behind customer authentication)](https://providers.apievangelist.com/providers/zafran-security/)

_GitHub (official)_
- No official Zafran Security GitHub organization or public repositories were found.

_Community / integration / detection repos_
- No notable community repositories specific to Zafran were found (product is closed/SaaS with marketplace-based integrations rather than open-source tooling).

_Learning & reference_
- [Zafran blog & resources](https://zafran.io/resources)
- [AWS Marketplace listing](https://aws.amazon.com/marketplace/pp/prodview-3fcfd4kifsf7k)
- CrowdStrike Marketplace / Trend Micro partner platform listings (integration references)

> Note: Zafran is a newer (venture-backed) AI-native Continuous Threat Exposure Management (CTEM) / mitigation platform. There is NO public developer documentation site, no public API reference, and no official GitHub presence that could be verified — technical docs, API, and integration setup require a customer account and vendor engagement. Integrations (Cyera, CrowdStrike, Trend Micro, Jira, ServiceNow VR, SOAR) are configured in-product rather than via open-source repos. Treat vendor exploitability/mitigation claims (e.g. '90% of critical vulns not exploitable') as marketing until validated.


### Invicti (Invicti Platform / Acunetix / Netsparker)

_Official documentation & manuals_
- [Invicti documentation site](https://docs.invicti.com)
- [Invicti Platform docs (Invicti Platform 'ip' section)](https://docs.invicti.com/ip/)
- [Acunetix product manual (Standard & Premium)](https://www.acunetix.com/support/docs/wvs)
- [Invicti AppSec (ASPM / Acunetix integration guides)](https://docs.invicti.com/appsec/)
- [Invicti Support / Help Center](https://www.invicti.com/support)

_API & developer docs_
- [Invicti Platform API — getting started](https://docs.invicti.com/ip/category/platform-api)
- [Get your Invicti Platform API key](https://docs.invicti.com/ip/s1-get-your-api-key)
- [Access API documentation (Swagger UI from user settings)](https://docs.invicti.com/ip/access-api-documentation)
- [Acunetix API usage articles —  (examples; no formal standalone REST reference published)](https://www.acunetix.com/blog/)

_GitHub (official)_
- [Invicti Security GitHub organization](https://github.com/Invicti-Security)
- [brainstorm — LLM-assisted web fuzzing (ffuf wrapper)](https://github.com/Invicti-Security/brainstorm)
- [netsparker-custom-security-checks — custom checks for Netsparker/Invicti](https://github.com/Invicti-Security/netsparker-custom-security-checks)
- [netsparker-cloud-scan-plugin — Jenkins plugin to trigger Enterprise scans](https://github.com/Invicti-Security/netsparker-cloud-scan-plugin)
- [invicti-platform-onprem-tools — on-prem deployment tooling](https://github.com/Invicti-Security/invicti-platform-onprem-tools)

_Community / integration / detection repos_
- Acunetix/Invicti CI integrations are mostly first-party (Jenkins, Azure DevOps, GitHub) under the Invicti-Security org; few notable independent community repos exist for this commercial DAST.
- [jenkinsci/netsparker-cloud-scan-plugin (upstream Jenkins plugin index)](https://plugins.jenkins.io/netsparker-cloud-scan/)

_Learning & reference_
- [Invicti blog](https://www.invicti.com/blog/)
- [Acunetix blog](https://www.acunetix.com/blog/)
- [Invicti web security resources / learning center](https://www.invicti.com/learn/)

> Note: Invicti Security owns both Acunetix and Netsparker; 'Netsparker' was rebranded to 'Invicti'. Documentation is split: docs.invicti.com covers the modern Invicti Platform (the 'ip' path), while acunetix.com/support/docs covers the standalone Acunetix scanner. The Platform API is OpenAPI/Swagger and the full reference is only reachable after authenticating and generating an API key (Inventory, DAST, Reports API sections; regional base URLs for SaaS). Acunetix tokens are shown only once on generation; default on-prem port is 3443.


### Snyk

_Official documentation & manuals_
- [Snyk documentation hub](https://docs.snyk.io)
- [Snyk API overview (REST + V1)](https://docs.snyk.io/snyk-api)
- [Snyk CLI documentation](https://docs.snyk.io/snyk-cli)
- [Docs machine index for LLMs](https://docs.snyk.io/llms.txt)

_API & developer docs_
- [Snyk REST API (OpenAPI/JSON:API, versioned)](https://docs.snyk.io/developer-tools/snyk-api/rest-api)
- [Snyk API reference & authentication](https://docs.snyk.io/snyk-api)
- [Snyk Apps APIs (build integrations)](https://docs.snyk.io/developer-tools/snyk-api/using-specific-snyk-apis/snyk-apps-apis)
- [Terraform provider for Snyk (community/partner)](https://registry.terraform.io/providers/pavel-snyk/snyk/latest/docs)

_GitHub (official)_
- [Snyk GitHub organization (~240 repos)](https://github.com/snyk)
- [snyk/cli — Snyk CLI (TypeScript, ~5.7k stars)](https://github.com/snyk/cli)
- [snyk/actions — official GitHub Actions for CI scanning](https://github.com/snyk/actions)
- [snyk/snyk-to-html — export CLI reports to HTML](https://github.com/snyk/snyk-to-html)
- [snyk/vscode-extension & snyk/snyk-intellij-plugin — IDE plugins](https://github.com/snyk/vscode-extension)
- [snyk/driftctl — IaC drift detection](https://github.com/snyk/driftctl)

_Community / integration / detection repos_
- [snyk-labs GitHub organization (community/example tooling)](https://github.com/snyk-labs)
- [snyk-apps-demo — starter for building a Snyk App](https://github.com/snyk/snyk-apps-demo)
- [snyk-api-import — bulk import/onboard projects via API](https://github.com/snyk/snyk-api-import)
- [snyk-labs/nodejs-goof & other 'goof' vulnerable demo apps](https://github.com/snyk-labs/nodejs-goof)

_Learning & reference_
- [Snyk Learn — free interactive secure-coding lessons (NIST NICE aligned)](https://learn.snyk.io)
- [Snyk blog](https://snyk.io/blog/)
- [Snyk Vulnerability Database](https://security.snyk.io)
- [Snyk Tutorials & product training —  (learning series within docs)](https://docs.snyk.io)

> Note: Snyk REST API is OpenAPI + JSON:API and requires a date-based ?version= query parameter on every request; the older V1 API is being sunset in favor of REST. API availability can depend on plan tier (historically Business/Enterprise, with some token access on lower tiers) — check the current plans page. Core open-source tooling (CLI, actions, IDE plugins, driftctl, snyk-ls language server) lives under github.com/snyk; demos/experiments under github.com/snyk-labs.


### HackerOne

_Official documentation & manuals_
- [HackerOne Platform Documentation (Help Center)](https://docs.hackerone.com)
- [Get Started section —   (navigate from docs.hackerone.com 'Get Started')](https://docs.hackerone.com/en/collections/...)
- [Run a Program (customer/program-owner guidance) —  (Run a Program section)](https://docs.hackerone.com)
- [Integrate Tools (third-party integrations incl. GitHub/Jira) —  (Integrate Tools section)](https://docs.hackerone.com)

_API & developer docs_
- [HackerOne API documentation](https://api.hackerone.com)
- [HackerOne API getting started](https://api.hackerone.com/getting-started/)
- [HackerOne REST API reference (reports, programs, bounties, balances)](https://api.hackerone.com/customer-resources/)
- [HackerOne GraphQL API (used by the official MCP server) — see](https://github.com/Hacker0x01/hackerone-graphql-mcp-server)

_GitHub (official)_
- [Hacker0x01 — HackerOne's verified official GitHub organization (~168 repos)](https://github.com/Hacker0x01)
- [hacker101 — source for Hacker101.com free security class (~14.6k stars)](https://github.com/Hacker0x01/hacker101)
- [hackerone-graphql-mcp-server — MCP server for the HackerOne GraphQL API](https://github.com/Hacker0x01/hackerone-graphql-mcp-server)
- [react-datepicker — widely used React component maintained by HackerOne](https://github.com/Hacker0x01/react-datepicker)

_Community / integration / detection repos_
- [kryndex/hackerone-client — community Node client library (limited operations)](https://github.com/kryndex/hackerone-client)
- [nu11pointer/hackerone-cli — unofficial CLI client over the official API](https://github.com/nu11pointer/hackerone-cli)

_Learning & reference_
- [Hacker101 — free web & mobile security course](https://www.hacker101.com)
- [Hacker101 CTF — hands-on capture-the-flag labs](https://ctf.hacker101.com)
- [HackerOne blog](https://www.hackerone.com/blog)
- [Hacktivity (public disclosed reports)](https://hackerone.com/hacktivity)

> Note: The official API lives at api.hackerone.com (NOT docs.hackerone.com); the docs.hackerone.com Help Center is the product/program documentation portal (12 sections incl. Get Started, Run a Program, Integrate Tools, Pentesting, AI) but has no standalone API section. Official GitHub org is 'Hacker0x01' (verified controlling hackerone.com) — note github.com/hackerone is an UNRELATED personal user account, not HackerOne. REST API uses HTTP Basic auth (API token identifier + token value); a newer GraphQL API also exists. hackerone-client / hackerone-cli are community, not official.


## Identity & Privileged Access

### Microsoft Entra ID

_Official documentation & manuals_
- [Microsoft Entra ID documentation (Microsoft Learn)](https://learn.microsoft.com/en-us/entra/identity/)
- [Microsoft Entra documentation hub (all Entra products)](https://learn.microsoft.com/en-us/entra/)
- [What is Microsoft Entra ID? (overview)](https://learn.microsoft.com/en-us/entra/fundamentals/whatis)
- [Microsoft Entra admin center (console)](https://entra.microsoft.com/)

_API & developer docs_
- [Microsoft identity platform documentation](https://learn.microsoft.com/en-us/entra/identity-platform/)
- [Microsoft Graph API reference (overview)](https://learn.microsoft.com/en-us/graph/api/overview)
- [Microsoft Graph Azure AD / Entra resources overview](https://learn.microsoft.com/en-us/graph/api/resources/azure-ad-overview)
- [Microsoft identity platform code samples (auth libraries)](https://learn.microsoft.com/en-us/entra/identity-platform/sample-v2-code)
- [Terraform azuread provider (HashiCorp Registry)](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs)
- [HashiCorp tutorial: Manage Microsoft Entra ID users and groups](https://developer.hashicorp.com/terraform/tutorials/azure/entra-id)

_GitHub (official)_
- [AzureAD GitHub organization (MSAL + identity libraries)](https://github.com/AzureAD)
- [MSAL for JavaScript](https://github.com/AzureAD/microsoft-authentication-library-for-js)
- [MSAL for .NET](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet)
- [MSAL for Python](https://github.com/AzureAD/microsoft-authentication-library-for-python)
- [microsoft-identity-web (.NET web app auth)](https://github.com/AzureAD/microsoft-identity-web)
- [Microsoft Graph SDKs organization](https://github.com/microsoftgraph)
- [Azure-Samples (identity/auth code samples)](https://github.com/Azure-Samples)

_Community / integration / detection repos_
- [Microsoft Sentinel detection content (Entra sign-in/audit analytics)](https://github.com/Azure/Azure-Sentinel)
- [SigmaHQ detection rules (Azure/Entra sign-in & audit logs)](https://github.com/SigmaHQ/sigma)
- [Azure AD Incident Response PowerShell Module](https://github.com/AzureAD/Azure-AD-Incident-Response-PowerShell-Module)
- [ROADtools (Entra/Azure AD recon & enumeration)](https://github.com/dirkjanm/ROADtools)
- [AADInternals (Entra/Azure AD admin & offensive toolkit)](https://github.com/Gerenios/AADInternals)
- [Atomic Red Team (T1098 cloud account manipulation / Azure AD)](https://github.com/redcanaryco/atomic-red-team)

_Learning & reference_
- [Microsoft Learn training (browse Entra products)](https://learn.microsoft.com/en-us/training/browse/?products=entra)
- [Microsoft Entra blog (Tech Community)](https://techcommunity.microsoft.com/t5/microsoft-entra-blog/bg-p/Identity)
- [Microsoft Entra admin center (hands-on console)](https://entra.microsoft.com/)

> Note: LIVE-VERIFIED via WebSearch 2026-10-08. Product renamed from Azure Active Directory (Azure AD) to Microsoft Entra ID in 2023; docs moved from learn.microsoft.com/azure/active-directory to learn.microsoft.com/entra (old paths redirect). GitHub auth libraries still live under the legacy 'AzureAD' org, not an 'Entra' org. Microsoft Learn flagged the sample-v2-code page as undergoing maintenance with some possibly broken sample links — check live before relying on a specific sample repo. For the azuread Terraform provider, confirm the current major version/resource schema on the registry page.


### Cisco Duo

_Official documentation & manuals_
- [Duo documentation hub](https://duo.com/docs)
- [Duo Administration – Admin Panel Overview](https://duo.com/docs/administration)
- [Duo administrator roles](https://duo.com/docs/administration-admins)
- [Cisco Security Cloud Control provisioning for Duo](https://duo.com/docs/cisco-security-cloud-control)
- [Getting Started with Duo](https://duo.com/docs/getting-started)
- [Duo Lift-Off Guide (deployment best practices, PDF)](https://duo.com/assets/pdf/duo-liftoff-guide.pdf)

_API & developer docs_
- [Duo Admin API (users, phones, tokens, logs)](https://duo.com/docs/adminapi)
- [Duo Auth API (low-level 2FA REST API)](https://duo.com/docs/authapi)
- [Duo Accounts API (parent/child account management)](https://duo.com/docs/accountsapi)

_GitHub (official)_
- [Duo Security GitHub organization](https://github.com/duosecurity)
- [duo_client_python (Auth/Admin/Accounts API client)](https://github.com/duosecurity/duo_client_python)
- [duo_client_java](https://github.com/duosecurity/duo_client_java)
- [duo_api_csharp](https://github.com/duosecurity/duo_api_csharp)
- [duo_api_golang](https://github.com/duosecurity/duo_api_golang)
- [duo_api_nodejs](https://github.com/duosecurity/duo_api_nodejs)
- [duo_log_sync (official SIEM log ingestion tool)](https://github.com/duosecurity/duo_log_sync)

_Community / integration / detection repos_
- [SigmaHQ detection rules (Duo/MFA authentication logs)](https://github.com/SigmaHQ/sigma)
- [Elastic detection-rules (identity/MFA, incl. Duo-relevant)](https://github.com/elastic/detection-rules)
- [Duo apps & add-ons on Splunkbase (SIEM integration)](https://splunkbase.splunk.com/apps?keyword=duo)

_Learning & reference_
- [Duo Guide to Two-Factor Authentication (end-user/enrollment)](https://guide.duo.com/)
- [Duo Security blog](https://duo.com/blog)
- [Duo product/solutions knowledge base](https://duo.com/docs)

> Note: LIVE-VERIFIED via WebSearch 2026-10-08. Duo is owned by Cisco. Admin onboarding is migrating to Cisco Security Cloud Control (SCC): admins created via SCC after 2026-05-11 must sign in through SCC rather than admin.duosecurity.com directly. Admin API and Auth API are SEPARATE Duo application types with separate key pairs; Admin API requires Essentials/Advantage/Premier plan while Auth API is also available on Free/trial. Auth API clients using certificate pinning required updates before 2026-04-15 (see Duo KB 9451). thebananastand.duo.com mirrors the same doc pages — use duo.com as the canonical host.


### CyberArk

_Official documentation & manuals_
- [CyberArk documentation portal (all products)](https://docs.cyberark.com/)
- [CyberArk Privileged Access Manager – Self-Hosted docs](https://docs.cyberark.com/pam-self-hosted/)
- [CyberArk Privilege Cloud (SaaS PAM) docs](https://docs.cyberark.com/privilege-cloud-shared-services/)
- [CyberArk Identity (SSO/MFA, formerly Idaptive) docs](https://docs.cyberark.com/identity/)
- [CyberArk corporate site / product pages](https://www.cyberark.com/)

_API & developer docs_
- [CyberArk REST API reference (navigate per-product from docs hub)](https://docs.cyberark.com/)
- [Conjur open-source secrets manager documentation](https://docs.conjur.org/)
- [Conjur project site](https://www.conjur.org/)
- [Terraform CyberArk Conjur provider](https://registry.terraform.io/providers/cyberark/conjur/latest/docs)

_GitHub (official)_
- [CyberArk GitHub organization](https://github.com/cyberark)
- [Conjur (secrets management)](https://github.com/cyberark/conjur)
- [epv-api-scripts (Vault/PAS REST API automation scripts)](https://github.com/cyberark/epv-api-scripts)
- [Summon (secrets injection into env)](https://github.com/cyberark/summon)
- [Secretless Broker](https://github.com/cyberark/secretless-broker)
- [CyberArk Ansible security automation collection](https://github.com/cyberark/ansible-security-automation-collection)

_Community / integration / detection repos_
- [psPAS — community PowerShell module for the CyberArk PAS/PVWA REST API (widely used)](https://github.com/pspete/psPAS)
- [SigmaHQ detection rules (CyberArk Vault/PAS activity)](https://github.com/SigmaHQ/sigma)
- [CyberArk apps & add-ons on Splunkbase (SIEM integration)](https://splunkbase.splunk.com/apps?keyword=cyberark)

_Learning & reference_
- [CyberArk University / training catalog](https://training.cyberark.com/)
- [CyberArk Technical Community (forums, Marketplace, how-tos)](https://community.cyberark.com/)
- [Conjur tutorials & guides](https://docs.conjur.org/)

> Note: NOT LIVE-VERIFIED THIS TURN: the shared WebSearch budget (200 calls/turn, shared by all concurrent workflow agents) was exhausted after the Entra ID and Duo queries, so these CyberArk URLs are compiled from high-confidence prior knowledge and should be re-confirmed. Product structure to be aware of: CyberArk splits into PAM Self-Hosted (on-prem, formerly 'PAS') vs Privilege Cloud (SaaS); CyberArk Identity is the former Idaptive (SSO/MFA/IGA); Conjur is the open-source developer/secrets product with its own site (conjur.org). Deep doc paths under docs.cyberark.com are versioned and change per release — navigate from the hub and pick the matching version. Confirm the exact product slugs (pam-self-hosted, privilege-cloud-shared-services, identity) and the ansible-security-automation-collection repo name against the live sites before publishing into the reference library.


## SIEM

### Splunk Enterprise Security

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


---
*Generic reference. No organization or personal data. Confirm all URLs against current vendor sources.*
