# Enterprise Technology Inventory

A map of the enterprise technologies a security program inventories and protects, organized by domain, with the named products in each and a common data model for tracking them. It is framed for vulnerability management, continuous threat exposure management, and asset management: the asset universe you scan and defend, not only the security tools that do the scanning. Product names and ownership reflect the market as of 2026, so verify a product's current name, owner, support status, and version against the vendor before relying on a detail.

A full enterprise inventory distinguishes three things that all contribute to security outcomes: the security tools, the enterprise IT platforms, and the infrastructure those tools protect. For the security tools themselves see the [Security Tools Catalog](/SECURITY_TOOLS_CATALOG.md); this page covers the technologies they protect.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability management, asset management, and security teams inventorying the estate

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,378 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building an asset inventory, you are scoping what a vulnerability program must cover, or you need to map enterprise technologies to owners and vulnerability sources

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[The common inventory data model](#the-common-inventory-data-model), [Infrastructure and computing](#infrastructure-and-computing), [Using this for vulnerability management](#using-this-for-vulnerability-management)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Security Tools Catalog](SECURITY_TOOLS_CATALOG.md), [Databases](databases/README.md), [Vulnerability Management Reference](VULNERABILITY_MANAGEMENT_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Why this matters for security

You cannot manage the exposure of an asset you do not know about, so asset inventory is the first control for a reason. A vulnerability management or exposure program has to account for the operating systems, hypervisors, network devices, databases, cloud services, business applications, and operational technology that make up the estate, because each has its own advisories, discovery methods, and remediation owners. The platforms below are not primarily security products, but they are where most vulnerabilities and misconfigurations live, and securing them is the work. See [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CTEM Reference](/CTEM_REFERENCE.md), and [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md).

## The common inventory data model

Each technology can be classified with the same fields so that scanning, prioritization, and ownership all join on one record.

| Field | Example |
|---|---|
| Technology | VMware ESXi |
| Vendor | Broadcom (VMware) |
| Domain | Virtualization |
| Product family | VMware vSphere |
| Deployment | On-premises |
| Asset type | Hypervisor |
| Business criticality | High |
| Security relevance | Hypervisor vulnerabilities, management-plane exposure |
| Discovery methods | CMDB, vCenter API, authenticated scans |
| Vulnerability sources | Vendor advisories, CVE, CISA KEV |
| Remediation owner | Infrastructure Engineering |
| Lifecycle attributes | Version, support status, patch level |

This is the shape the [ServiceNow Vulnerability Response](/platforms/servicenow-vr.md) configuration-management database and the scanners reconcile against.

## Infrastructure and computing

| Category | Common solutions |
|---|---|
| Physical servers | Dell PowerEdge, HPE ProLiant, Lenovo ThinkSystem, Cisco UCS |
| Hyperconverged infrastructure | Nutanix, VMware vSAN, Dell VxRail, Azure Local |
| Virtualization | VMware vSphere and ESXi, Microsoft Hyper-V, Nutanix AHV, Proxmox VE, KVM |
| Mainframes | IBM Z, IBM LinuxONE |
| Enterprise operating systems | Windows Server, Red Hat Enterprise Linux, Ubuntu Server, SUSE Linux Enterprise, Oracle Linux |
| Container platforms | Kubernetes, Red Hat OpenShift, Rancher, VMware Tanzu |
| Infrastructure automation | Ansible, Terraform, Puppet, Chef, Salt |
| Infrastructure management | VMware vCenter, HPE OneView, Dell OpenManage, Red Hat Satellite |

The hypervisor and its management plane are high-value targets; see [Platform hardening](/hubs/platform-hardening.md) and, for the command surface, [Linux commands](/commands/linux-commands.md) and [Containers](/commands/docker.md).

## Networking and connectivity

| Category | Common solutions |
|---|---|
| Switching | Cisco Catalyst, Cisco Nexus, Aruba CX, Juniper EX, Arista EOS |
| Routing | Cisco ISR and Catalyst 8000, Juniper MX, Nokia IP routing |
| Wireless | Cisco Meraki, Aruba Central, Ruckus, Extreme Networks |
| SD-WAN | Cisco Catalyst SD-WAN, Fortinet Secure SD-WAN, VMware VeloCloud |
| Load balancing | F5 BIG-IP, Citrix NetScaler, HAProxy, NGINX Plus |
| DNS, DHCP, and IPAM | Infoblox, BlueCat, EfficientIP, Microsoft DNS and DHCP |
| Network monitoring | SolarWinds, PRTG, LogicMonitor, ThousandEyes |
| Network access control | Cisco ISE, Aruba ClearPass, Forescout |

Network devices are edge-exposed and KEV-heavy; see [Network security](/hubs/network-security.md) and [Networking commands](/commands/networking-commands.md).

## Cloud computing and platforms

| Category | Common solutions |
|---|---|
| Public cloud | AWS, Microsoft Azure, Google Cloud, Oracle Cloud Infrastructure |
| Private cloud | VMware Cloud Foundation, OpenStack, Nutanix Cloud Platform |
| Hybrid cloud | Azure Arc, AWS Outposts, Google Distributed Cloud |
| Serverless | AWS Lambda, Azure Functions, Google Cloud Run |
| Container services | Amazon EKS, Azure AKS, Google GKE |
| Cloud storage | Amazon S3, Azure Blob Storage, Google Cloud Storage |
| Cloud databases | Amazon RDS, Azure SQL, Cloud SQL, Amazon Aurora |
| Cloud governance | Azure Policy, AWS Organizations, AWS Control Tower |

See [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md) and the cloud CLIs: [AWS](/commands/aws-cli.md), [Azure](/commands/azure-cli.md), [Google Cloud](/commands/gcloud.md).

## Identity, directory, and access

| Category | Common solutions |
|---|---|
| Directory services | Microsoft Active Directory, LDAP, OpenLDAP |
| Cloud identity | Microsoft Entra ID, Okta, Ping Identity |
| Identity governance | SailPoint, Saviynt, One Identity |
| Privileged access | CyberArk, BeyondTrust, Delinea |
| Authentication protocols | Kerberos, RADIUS, SAML, OAuth 2.0, OpenID Connect |
| Certificate management | DigiCert, Sectigo, Keyfactor, Microsoft AD CS |
| Secrets management | HashiCorp Vault, Azure Key Vault, AWS Secrets Manager |
| Multi-factor authentication | Duo, Microsoft Authenticator, RSA SecurID |

See [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Microsoft Entra ID](/platforms/entra-id.md), and [Certificate Trust Incident Response](/CERTIFICATE_TRUST_INCIDENT_RESPONSE_REFERENCE.md).

## Databases and data platforms

| Category | Common solutions |
|---|---|
| Relational | Microsoft SQL Server, Oracle Database, PostgreSQL, MySQL, IBM Db2 |
| NoSQL | MongoDB, Cassandra, Couchbase, DynamoDB |
| Data warehouses | Snowflake, Amazon Redshift, Google BigQuery, Azure Synapse |
| Data lakes | Databricks, Amazon S3 data lake, Azure Data Lake Storage |
| Data integration | Informatica, Talend, Fivetran, Azure Data Factory |
| Streaming | Apache Kafka, Confluent, Amazon Kinesis |
| Business intelligence | Power BI, Tableau, Qlik Sense, Looker |
| Enterprise search | Elasticsearch, OpenSearch, Splunk |

The library covers these engines in depth in [Databases](/databases/README.md).

## Business applications

| Category | Common solutions |
|---|---|
| ERP | SAP S/4HANA, Oracle Fusion Cloud ERP, Microsoft Dynamics 365 |
| CRM | Salesforce, Microsoft Dynamics 365 Sales, SAP Sales Cloud |
| Human resources | Workday, SAP SuccessFactors, Oracle HCM Cloud, UKG |
| Financial management | SAP, Oracle Financials, NetSuite, Sage Intacct |
| Supply chain | SAP IBP, Oracle SCM, Blue Yonder, Kinaxis |
| IT service management | ServiceNow, BMC Helix, Jira Service Management |
| Enterprise content management | SharePoint, OpenText, Box, Hyland OnBase |
| Workflow automation | ServiceNow, Appian, Pega, Power Automate |

These hold the crown-jewel data, so their patching and access control are high priority even though they are not security products.

## Collaboration and productivity

| Category | Common solutions |
|---|---|
| Productivity suites | Microsoft 365, Google Workspace |
| Enterprise email | Exchange Online, Exchange Server, Gmail Enterprise |
| Collaboration and messaging | Microsoft Teams, Slack, Webex |
| File collaboration | SharePoint, OneDrive, Box, Dropbox Business |
| Knowledge management | Confluence, SharePoint, Notion Enterprise |
| Unified communications | Cisco Unified Communications Manager, Microsoft Teams Phone, RingCentral |

Email and collaboration are the main delivery path for phishing; see [Proofpoint](/platforms/proofpoint.md) and the email-security pages.

## Software development and DevOps

| Category | Common solutions |
|---|---|
| Source control | GitHub Enterprise, GitLab, Bitbucket, Azure Repos |
| CI/CD | Jenkins, GitHub Actions, GitLab CI/CD, Azure Pipelines |
| Artifact repositories | JFrog Artifactory, Sonatype Nexus |
| Container registries | Amazon ECR, Azure Container Registry, Harbor |
| Infrastructure as code | Terraform, OpenTofu, Pulumi, CloudFormation |
| Observability | Datadog, Dynatrace, New Relic, Grafana |
| API management | Apigee, Kong, MuleSoft, Azure API Management |
| Testing automation | Selenium, Playwright, Tricentis Tosca |

See [Software frameworks](/frameworks/README.md), [Git](/commands/git.md), and [Terraform](/commands/terraform.md).

## Storage, backup, and disaster recovery

| Category | Common solutions |
|---|---|
| Enterprise SAN and NAS | Dell PowerStore, NetApp ONTAP, Pure Storage FlashArray |
| Object storage | Amazon S3, MinIO, Cloudian, Dell ECS |
| Backup | Veeam, Commvault, Veritas NetBackup, Rubrik |
| Disaster recovery | Zerto, Azure Site Recovery, AWS Elastic Disaster Recovery |
| Data replication | Dell RecoverPoint, NetApp SnapMirror |
| Immutable storage | S3 Object Lock, WORM object storage |
| Archiving | OpenText, Veritas Enterprise Vault |

The library covers the backup platforms as the ransomware-recovery control in [Security platforms: backup and recovery](/platforms/README.md).

## Monitoring and IT operations

| Category | Common solutions |
|---|---|
| Infrastructure monitoring | SolarWinds, PRTG, Zabbix, Nagios |
| Application performance | Dynatrace, AppDynamics, New Relic |
| Full-stack observability | Datadog, Grafana Cloud, Elastic Observability |
| IT operations management | ServiceNow ITOM, BMC Helix |
| Configuration management database | ServiceNow CMDB, Device42 |
| IT asset management | Flexera One, ServiceNow ITAM, Lansweeper |
| Endpoint management | Microsoft Intune, Tanium, HCL BigFix, Ivanti |
| Patch management | Windows Autopatch, Automox, Tanium Patch |

The CMDB and asset-management systems are the backbone of a vulnerability program, because they supply ownership and criticality. See [ServiceNow Vulnerability Response](/platforms/servicenow-vr.md) and [Tanium](/platforms/tanium.md).

## Healthcare, industrial, and AI technology

Industry and emerging platforms that security teams increasingly inventory.

| Category | Common solutions |
|---|---|
| Electronic health records | Epic, Oracle Health (Cerner), MEDITECH |
| Healthcare integration | InterSystems HealthShare, Rhapsody, Mirth Connect |
| Industrial control systems | Siemens SIMATIC, Rockwell Automation ControlLogix |
| SCADA and DCS | AVEVA System Platform, Ignition, Honeywell Experion, Emerson DeltaV, ABB 800xA |
| Industrial historians | AVEVA PI System, Canary Historian |
| Building automation | Johnson Controls Metasys, Siemens Desigo, Schneider EcoStruxure |
| Enterprise AI platforms | Azure AI Foundry, Amazon Bedrock, Google Vertex AI |
| MLOps and serving | MLflow, Kubeflow, NVIDIA Triton, KServe |
| Vector databases | Pinecone, Weaviate, Milvus |

See [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), and [AI tooling](/ai-tooling/README.md).

## Using this for vulnerability management

Treat this map as the outline of an asset inventory. For each domain, record the technologies in use with the data model above, decide the discovery method (agent, authenticated scan, API, or CMDB feed), name the vulnerability source (vendor advisory, CVE, KEV), and assign a remediation owner. The security tooling that performs the discovery and tracking is in the [Security Tools Catalog](/SECURITY_TOOLS_CATALOG.md) and [Security platforms](/platforms/README.md); the study order for the disciplines is in the [IT Domains and Specializations](/IT_DOMAINS_REFERENCE.md) map.

## Related pages

- [Security Tools Catalog](/SECURITY_TOOLS_CATALOG.md)
- [IT Domains and Specializations](/IT_DOMAINS_REFERENCE.md)
- [Databases](/databases/README.md)
- [Security platforms](/platforms/README.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Reference Index](/INDEX.md)

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [GRC and security program](/hubs/grc-and-security-program.md)

<!-- related:end -->
