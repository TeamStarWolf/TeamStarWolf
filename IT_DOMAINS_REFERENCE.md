# IT Domains and Specializations

Information technology is far broader than help desk, networking, and security. This page maps 100 IT domains across 15 categories and points to where this library covers each, so it can serve as an orientation map for labs, research projects, and learning paths. The library is a cybersecurity reference, so the first category is covered in depth and the rest are linked where the library touches them and marked adjacent or out of scope otherwise.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Learners, lab builders, and anyone orienting across the IT and security landscape

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,138 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are planning a lab or study program, you want to decide which IT domains to learn, or you need to see where this library covers a given specialization

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[How to read this map](#how-to-read-this-map), [Cybersecurity and information security](#cybersecurity-and-information-security), [Using this map](#using-this-map)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Career Paths](CAREER_PATHS.md), [Learning paths](disciplines/README.md), [Domains index](hubs/README.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## How to read this map

Each category below is a table of its domains with where to go in this library. A link means the library has direct coverage. "Adjacent" means the library covers the security of that domain rather than the domain itself, with the nearest page named. "Out of scope" means the library does not cover it, and the domain is listed so its absence is explicit rather than assumed. For the study order within a discipline, see the [Learning paths](/disciplines/README.md); for the security domains as a whole, see the [Domains index](/hubs/README.md).

## Cybersecurity and information security

The library's core. Every domain here has direct coverage.

| Domain | Where the library covers it |
|---|---|
| Cybersecurity Operations | [Detection and response](/hubs/detection-and-response.md) |
| Security Operations Centers (SOC) | [Detection and response](/hubs/detection-and-response.md) |
| Threat Intelligence | [Threat intelligence](/hubs/threat-intelligence.md) |
| Vulnerability Management | [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) |
| Continuous Threat Exposure Management (CTEM) | [CTEM Reference](/CTEM_REFERENCE.md) |
| Penetration Testing and Ethical Hacking | [Offensive security](/hubs/offensive-security.md) |
| Red Team Operations | [Offensive security](/hubs/offensive-security.md) |
| Blue Team Operations | [Detection and response](/hubs/detection-and-response.md) |
| Digital Forensics and Incident Response (DFIR) | [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) |
| Identity and Access Management (IAM) | [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Identity and data protection](/hubs/identity-and-data-protection.md) |
| Application Security (AppSec) | [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Application and supply chain](/hubs/application-and-supply-chain.md) |
| Cloud Security | [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md) |
| Operational Technology Security (OT/ICS) | [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md) |
| Governance, Risk, and Compliance (GRC) | [GRC and security program](/hubs/grc-and-security-program.md) |
| Security Architecture | [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [Zero Trust Reference](/ZERO_TRUST_REFERENCE.md) |

## Networking and telecommunications

The library covers network defense and architecture rather than carrier engineering.

| Domain | Where the library covers it |
|---|---|
| Network Engineering | Adjacent: [Networking commands](/commands/networking-commands.md), [Network security](/hubs/network-security.md) |
| Network Architecture | [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md) |
| Software-Defined Networking (SDN) | Adjacent: [Network security](/hubs/network-security.md) |
| Wireless Networking | Adjacent: [Network security](/hubs/network-security.md) |
| Network Automation | Adjacent: [Command reference](/commands/README.md) |
| Telecommunications Engineering | Out of scope |
| Network Performance Monitoring | Adjacent: [Detection and response](/hubs/detection-and-response.md) |
| Network Security Engineering | [Network security](/hubs/network-security.md) |

## Cloud computing

The library covers cloud security and the platforms, not cloud operations in general.

| Domain | Where the library covers it |
|---|---|
| Cloud Infrastructure Engineering | Adjacent: [Cloud and infrastructure](/hubs/cloud-and-infrastructure.md) |
| Cloud Architecture | Adjacent: [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md) |
| Multi-Cloud Management | Adjacent: [Cloud and infrastructure](/hubs/cloud-and-infrastructure.md) |
| Hybrid Cloud Engineering | Adjacent: [Cloud and infrastructure](/hubs/cloud-and-infrastructure.md) |
| Cloud-Native Development | [Software frameworks](/frameworks/README.md), [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md) |
| Serverless Computing | Adjacent: [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md) |
| Cloud Cost Optimization (FinOps) | Out of scope |
| Cloud Platform Engineering | Adjacent: [AWS CLI](/commands/aws-cli.md), [Azure CLI](/commands/azure-cli.md), [gcloud](/commands/gcloud.md) |

## Infrastructure and systems administration

| Domain | Where the library covers it |
|---|---|
| Windows Server Administration | Adjacent: [Windows Command Prompt](/commands/windows-cmd.md), [PowerShell commands](/commands/powershell-commands.md), [Platform hardening](/hubs/platform-hardening.md) |
| Linux Systems Administration | Adjacent: [Linux commands](/commands/linux-commands.md), [systemd and systemctl](/commands/systemctl.md) |
| Virtualization Engineering | Adjacent: [Cloud and infrastructure](/hubs/cloud-and-infrastructure.md) |
| Data Center Operations | Out of scope |
| Storage Engineering | Adjacent: [Databases](/databases/README.md) |
| Backup and Disaster Recovery | [Security platforms: backup and recovery](/platforms/README.md) |
| Enterprise Infrastructure Architecture | Adjacent: [Cloud and infrastructure](/hubs/cloud-and-infrastructure.md) |
| High Availability and Fault Tolerance | Adjacent: [Cloud and infrastructure](/hubs/cloud-and-infrastructure.md) |

## Software engineering and development

Direct coverage through the developer-reference sections.

| Domain | Where the library covers it |
|---|---|
| Frontend Development | [Software frameworks](/frameworks/README.md), [All languages](/languages/README.md) |
| Backend Development | [Software frameworks](/frameworks/README.md), [All languages](/languages/README.md) |
| Full-Stack Development | [Software frameworks](/frameworks/README.md) |
| Mobile Application Development | [Software frameworks](/frameworks/README.md) |
| API Development and Integration | [API Security Reference](/API_SECURITY_REFERENCE.md), [Software frameworks](/frameworks/README.md) |
| Systems Programming | [All languages](/languages/README.md), [Programming paradigms](/paradigms/README.md) |
| Embedded Software Development | Adjacent: [All languages](/languages/README.md) |
| Software Quality Assurance | Adjacent: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) |

## DevOps, automation, and reliability

| Domain | Where the library covers it |
|---|---|
| DevOps Engineering | Adjacent: [Command reference](/commands/README.md) |
| DevSecOps | [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Snyk](/platforms/snyk.md) |
| Site Reliability Engineering (SRE) | Out of scope |
| Infrastructure as Code (IaC) | [Terraform](/commands/terraform.md), [Wiz](/platforms/wiz.md) |
| CI/CD Engineering | Adjacent: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Git](/commands/git.md) |
| Configuration Management | Adjacent: [Data formats and regex](/formats/README.md) |
| Containerization and Kubernetes | [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), [Docker](/commands/docker.md), [kubectl](/commands/kubectl.md) |
| Observability Engineering | Adjacent: [Splunk Enterprise Security](/platforms/splunk.md) |

## Artificial intelligence and machine learning

| Domain | Where the library covers it |
|---|---|
| Artificial Intelligence Engineering | [AI and emerging tech](/hubs/ai-and-emerging-tech.md), [AI tooling](/ai-tooling/README.md) |
| Machine Learning Engineering | Adjacent: [AI tooling](/ai-tooling/README.md) |
| Deep Learning | Adjacent: [AI tooling](/ai-tooling/README.md) |
| Natural Language Processing (NLP) | Adjacent: [AI tooling](/ai-tooling/README.md) |
| Generative AI and Large Language Models | [AI tooling](/ai-tooling/README.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md) |
| MLOps | Adjacent: [AI and emerging tech](/hubs/ai-and-emerging-tech.md) |
| AI Security and Safety | [AI Security Reference](/AI_SECURITY_REFERENCE.md) |
| Autonomous AI Agents | [AI tooling](/ai-tooling/README.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md) |

## Data engineering and analytics

| Domain | Where the library covers it |
|---|---|
| Data Engineering | [Databases](/databases/README.md) |
| Database Administration | [Databases](/databases/README.md) |
| Data Science | Adjacent: [All languages](/languages/README.md) |
| Business Intelligence | Out of scope |
| Data Warehousing | [Snowflake](/databases/snowflake.md), [Databricks and Spark SQL](/databases/databricks.md) |
| Big Data Engineering | Adjacent: [Databricks and Spark SQL](/databases/databricks.md) |
| Data Governance | Adjacent: [Identity and data protection](/hubs/identity-and-data-protection.md) |

## Enterprise IT and business technology

Mostly adjacent or out of scope for a security library.

| Domain | Where the library covers it |
|---|---|
| Enterprise Architecture | Adjacent: [GRC and security program](/hubs/grc-and-security-program.md) |
| IT Service Management (ITSM) | Adjacent: [ServiceNow Vulnerability Response](/platforms/servicenow-vr.md) |
| Enterprise Resource Planning (ERP) | Out of scope |
| Customer Relationship Management (CRM) | Out of scope |
| Business Process Automation | Adjacent: [Tines](/platforms/tines.md) |
| IT Asset Management | Adjacent: [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) |
| Enterprise Application Integration | Adjacent: [Data formats and regex](/formats/README.md) |

## Emerging and advanced technologies

| Domain | Where the library covers it |
|---|---|
| Quantum Computing | Adjacent: [Post-Quantum Migration Reference](/POST_QUANTUM_MIGRATION_REFERENCE.md) |
| Blockchain and Distributed Ledgers | Adjacent: [Solidity](/languages/solidity.md) |
| Internet of Things (IoT) | [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md) |
| Edge Computing | Adjacent: [Cloud and infrastructure](/hubs/cloud-and-infrastructure.md) |
| Robotics and Autonomous Systems | Out of scope |
| Augmented Reality and Virtual Reality | Out of scope |
| Digital Twin Technology | Out of scope |

## Industrial and critical infrastructure technology

| Domain | Where the library covers it |
|---|---|
| Industrial Control Systems (ICS) | [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md) |
| Supervisory Control and Data Acquisition (SCADA) | [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md) |
| Industrial Automation | Adjacent: [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md) |
| Critical Infrastructure Engineering | Adjacent: [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md) |

## IT governance and management

| Domain | Where the library covers it |
|---|---|
| IT Governance | [GRC and security program](/hubs/grc-and-security-program.md) |
| IT Risk Management | [GRC and security program](/hubs/grc-and-security-program.md) |
| IT Program and Portfolio Management | Out of scope |

## Digital workplace and end-user computing

| Domain | Where the library covers it |
|---|---|
| Endpoint Management | [Tanium](/platforms/tanium.md), [Platform hardening](/hubs/platform-hardening.md) |
| Unified Endpoint Management (UEM) | Adjacent: [Microsoft Defender for Endpoint](/platforms/microsoft-defender.md) |
| Desktop Engineering | Adjacent: [Platform hardening](/hubs/platform-hardening.md) |

## Privacy, compliance, and digital trust

| Domain | Where the library covers it |
|---|---|
| Data Privacy Engineering | Adjacent: [Identity and data protection](/hubs/identity-and-data-protection.md) |
| Digital Identity and Trust | [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md) |
| IT Audit and Assurance | Adjacent: [GRC and security program](/hubs/grc-and-security-program.md) |

## Specialized technology industries

Industry verticals, out of scope for this library except where their security overlaps the domains above.

| Domain | Where the library covers it |
|---|---|
| Healthcare Information Technology | Out of scope |
| Financial Technology (FinTech) | Out of scope |
| Geographic Information Systems (GIS) | Out of scope |

## Using this map

For a security career or a lab program, the cybersecurity category is the spine, and the developer-reference sections ([languages](/languages/README.md), [paradigms](/paradigms/README.md), [frameworks](/frameworks/README.md), [commands](/commands/README.md), [formats](/formats/README.md), [databases](/databases/README.md)) and the [security platforms](/platforms/README.md) give the technical breadth that the adjacent domains draw on. Pair this map with the [Learning paths](/disciplines/README.md) to turn a domain into a study order, and with the [Domains index](/hubs/README.md) to go deep on a security area.

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [GRC and security program](/hubs/grc-and-security-program.md)
- [Career Paths](/CAREER_PATHS.md)
- [Discipline Learning Paths](/disciplines/README.md)
- [Domain Hubs](/hubs/README.md)

<!-- related:end -->
