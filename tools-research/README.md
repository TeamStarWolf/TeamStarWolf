# Tools Research

In-depth studies of security products and how they integrate, written from the vendors' official documentation. Each study explains how a product actually works (its data model, defaults, automation, and licensing), how named integrations move data into it, and where the documentation is silent or contradicts itself. Studies are dated to a specific product release, because product behavior and documentation both change.

These studies are independent. TeamStarWolf is not affiliated with, sponsored by, or endorsed by any vendor named here, and all product names and trademarks belong to their owners.

## Studies

| Study | Products | What it covers | Verified against | Download |
|---|---|---|---|---|
| [ServiceNow USEM with Tenable and Wiz](/tools-research/SERVICENOW_USEM_TENABLE_WIZ.md) | ServiceNow Unified Security Exposure Management; Tenable; Wiz | What USEM is, release history, the unified data model, default risk scoring, remediation rules, licensing, the Tenable and Wiz integration paths, cross-scanner deduplication, known issues, and a critical review | ServiceNow docs repository, Brazil branch (September 2026); Tenable docs; ServiceNow release notes | [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/tools-research/pdf/ServiceNow_USEM_Tenable_Wiz.pdf) |
| [ServiceNow VR, CC and CVR with Tenable and Wiz](/tools-research/SERVICENOW_VR_CC_CVR_TENABLE_WIZ.md) | ServiceNow Vulnerability Response, Configuration Compliance, Container Vulnerability Response; Tenable; Wiz | How each of the three applications works, how Tenable and Wiz feed each one, field mappings, setup prerequisites on all three sides, and documentation contradictions | ServiceNow docs repository, Brazil branch (September 2026); Tenable docs and developer docs; ServiceNow release notes | [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/tools-research/pdf/ServiceNow_VR_CC_CVR_Tenable_Wiz.pdf) |

Read the USEM study first if you are new to ServiceNow's security applications. It explains the shared rule and scoring layer that sits above the three applications covered in the second study.

## Reference directories

| Directory | Covers |
|---|---|
| [Tool Manuals and Repositories](/tools-research/TOOL_MANUALS_AND_REPOSITORIES.md) | Verified links to official manuals, API references, release notes, ServiceNow Store and Splunkbase listings, GitHub organizations, repositories and GitHub Pages sites for ServiceNow, Armis and the MITRE threat-informed defense ecosystem, plus dead or moved links to avoid. Checked 2026-10-08 |
| [Security Tool Documentation](/SECURITY_TOOL_DOCUMENTATION.md) | The library's per-tool documentation index, including Tenable, Wiz, Snyk, Invicti, Zafran and Splunk |

## Method

Every study follows the same rules.

1. **Official documentation first.** ServiceNow facts come from ServiceNow's public documentation repository, [ServiceNow/ServiceNowDocs](https://github.com/ServiceNow/ServiceNowDocs), and are linked to the exact page. Tenable and Wiz facts come from their official documentation where it is public.
2. **Every material claim carries its source.** Claims are labeled by the kind of evidence behind them.
3. **Contradictions are recorded, not resolved by guesswork.** Where two official pages disagree, the study says so and names both.
4. **Inference is marked.** Where a study reasons from documented behavior to a likely outcome, it says so.
5. **Your instance is the final authority.** Documentation lags releases. Test anything that sets SLAs or closes findings automatically in a sub-production instance first.

| Label | Meaning |
|---|---|
| Official docs | A vendor's published product documentation, linked to the page |
| Release notes | A vendor's Store or release notes published outside the main documentation |
| Community | Vendor community posts, often written by vendor staff but not product documentation |
| Third-party | Analyst, consultancy, legal, or news sources |
| Inference | The study's own reasoning from documented behavior |

## About the figures

Figures are original diagrams drawn from the cited documentation. They do not reproduce vendor screenshots. Each figure caption lists the documentation pages it was drawn from.

## Related references

- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)
- [CTEM Reference](/CTEM_REFERENCE.md)
- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md)
- [Security Tools Reference](/TOOLS.md)
