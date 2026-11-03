# Case Studies

Evidence-graded studies of how the threat landscape is changing, written from primary sources: threat reports from AI providers and security vendors, government advisories, and the disclosures of the organizations that were hit. Each study is dated, because both the threats and the sources change.

## Studies

| Study | Period | What it covers | Sources | Download |
|---|---|---|---|---|
| [AI Threats in the Cybersecurity Industry: A 2026 Case Study](/case-studies/AI_THREATS_2026.md) | January 2024 to October 2026 | Six cases (AI-orchestrated intrusions, deepfake social engineering, AI-native malware, prompt injection and agent hijacking, the AI software supply chain, and machine-speed vulnerability discovery), a cross-case analysis, a defensive playbook with a 180-day roadmap, and the 2026 regulatory and standards picture | Anthropic, Google, OpenAI and Microsoft threat reports; Hugging Face, Sysdig, ESET and other vendor research; FBI, CISA, NIST, the State Department, the European Commission, OWASP and MITRE ATLAS; checked 7 October 2026 | [PDF](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/pdf/AI_Threats_2026_Case_Study.pdf) · [Slides (PowerPoint)](https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/slides/AI_Threats_2026_Case_Study.pptx) |
| [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md) | February to March 2024 | How a maintainer identity spent more than two years gaining release authority over XZ Utils and hid a build-time backdoor in liblzma 5.6.0 and 5.6.1 that hooked sshd authentication for pre-authentication root code execution, how Andres Freund found it through SSH login latency, which distributions shipped it (rolling and pre-release, not stable), and a per-platform remediation table | Andres Freund's oss-security disclosure, CVE-2024-3094 (NVD), the CISA alert, and Red Hat, Debian, Arch and OpenSSF advisories; checked 3 November 2026 | Markdown only |
| [The eMudhra Certificate Authority Key Compromise: A 2026 Case Study](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md) | October 2026 | How eight eMudhra (emSign) intermediate CA private keys were found recoverable from their public certificates (a key-ceremony flaw), the eight-intermediate and sixteen-certificate scope with the Sectigo cross-signatures, the browser and software-client response, and why non-browser trust stores stayed exposed longest | eMudhra, Mozilla CCADB (Bugzilla 2083449), Chrome Root Store, the Go project (CVE-2026-111943), and vendor analyses from Kudelski, Cloudflare and Qualys; checked 2 November 2026 | Markdown only |

## Method

Every study follows the same rules.

1. **Primary sources first.** Facts come from the report, advisory, or disclosure that first published them, linked to the exact page. Where only press coverage was available, the study says so.
2. **Every event carries an evidence grade.** The grade separates what has happened from what has only been shown to be possible.
3. **Hype and evidence are kept apart.** Each study says which threats are overstated and which are understated, and why.
4. **Numbers are reported as the source states them.** A study notes when a figure is a floor, an estimate, or a vendor's own count.
5. **Figures are checked against their sources.** Every figure in a study is checked against the source it cites.

| Grade | Meaning |
|---|---|
| Confirmed | An observed, attributed incident with technical detail from the victim, a government agency, or the AI provider |
| Reported | A single vendor's account of in-the-wild activity, not independently corroborated |
| Demonstrated | A research proof of concept or a fixed vulnerability with no known in-the-wild use |

## About the figures

Figures are original charts and diagrams drawn from the data each study cites. Each figure's caption names its source.

## Related references

- [AI Security Reference](/AI_SECURITY_REFERENCE.md)
- [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md)
- [MITRE ATLAS Reference](/ATLAS_REFERENCE.md)
- [Deepfake & Synthetic-Media Defense](/DEEPFAKE_DEFENSE_REFERENCE.md)
- [Threat Report Almanac](/THREAT_REPORT_ALMANAC.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [Tools Research](/tools-research/README.md)
