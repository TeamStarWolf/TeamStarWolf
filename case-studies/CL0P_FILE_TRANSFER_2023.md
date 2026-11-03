# The Cl0p MOVEit Breach and the File-Transfer Extortion Playbook: A 2023 Case Study

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Edge Device Security](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)

## Executive summary

Over the US Memorial Day weekend of 2023, the Cl0p extortion group exploited a zero-day flaw in Progress MOVEit Transfer, a managed file transfer product used by thousands of organizations to move sensitive data between parties. The flaw, CVE-2023-34362, was a SQL injection weakness that let an unauthenticated attacker reach the application database and drop a web shell that stole files wholesale. Cl0p did not encrypt anything. It copied the data, listed victims on its leak site, and demanded payment to keep the files unpublished. By August 2024 the running tally reached roughly 2,773 organizations and about 95.8 million individuals, and it is best read as a floor, because many of the organizations hit were service providers whose own customers became downstream victims.

MOVEit was not a one-off. It was the fourth and largest in a pattern: Cl0p had already run the same exploit-exfiltrate-extort play against Accellion FTA in 2020 and 2021, Fortra GoAnywhere in early 2023, and would run it again against Cleo file-transfer software in late 2024. The through-line is the target class. Managed file transfer software sits on the internet edge, concentrates other organizations' most sensitive data, and is bought by teams who treat it as plumbing rather than as a high-value attack surface. For a vulnerability management program, the lesson is that an internet-facing application that aggregates third-party data is a crown-jewel asset whose unauthenticated critical flaws are ransomware-grade events, whether or not a single file is ever encrypted.

Evidence grade: **Confirmed** overall (Progress, CISA, FBI and Microsoft for the vulnerabilities and attribution; victim-count totals are **Reported** tallies marked below).

### Key findings

- **A single unauthenticated SQL injection caused a global data breach.** CVE-2023-34362 (CVSS 9.8) let an attacker inject SQL into the MOVEit Transfer web application without credentials, read and alter the database, and install a web shell. Two further SQL injection flaws, CVE-2023-35036 and CVE-2023-35708, were found during the code review that followed and were patched in June 2023.
- **The payload was theft, not encryption.** Post-exploitation deployed a web shell commonly named `human2.aspx` (the LEMURLOOT family) that enumerated and exfiltrated stored files and could harvest the service account's cloud storage keys. Cl0p's extortion rested entirely on the stolen copies, so there was no encryption event for a backup to recover from.
- **Mass exploitation preceded disclosure.** Exploitation was observed from around 27 May 2023, days before Progress published its advisory on 31 May 2023, which is the defining feature of a zero-day: there was no patch window to be inside of.
- **The damage spread through third parties.** Many organizations were breached not through their own MOVEit server but through a vendor's, for example the payroll provider Zellis, so one compromised server exposed many unrelated downstream organizations. This is why the individual count dwarfs the organization count.
- **It was a repeat of a proven playbook.** Cl0p (also tracked as TA505, FIN11 and LACE Tempest) ran the identical exploit-steal-extort pattern against Accellion FTA (CVE-2021-27101 and related, 2020 to 2021), Fortra GoAnywhere MFT (CVE-2023-0669, early 2023, about 130 organizations claimed), and Cleo Harmony, VLTrader and LexiCom (CVE-2024-50623 and CVE-2024-55956, late 2024, about 200 victims claimed). The target class, not the specific product, is the constant.

### Top recommendations

1. Inventory every managed file transfer and edge data-exchange product, including ones a vendor operates on your behalf, and treat them as crown-jewel internet-facing assets on the shortest patch clock, not as background infrastructure.
2. Plan for the zero-day case, because the MOVEit and Cleo flaws were exploited before a patch existed. Put these products behind authenticated access or a VPN, restrict outbound connections, monitor for web shells and anomalous file access, and be ready to take the service offline.
3. Treat an unauthenticated critical flaw in a data-aggregating edge product as a ransomware-grade exposure during prioritization, even with no encryption behavior, because pure data-theft extortion causes the same business harm.
4. Map third-party and fourth-party exposure: know which of your vendors run these products with your data, because a breach of their server is a breach of you, and your incident response may depend on their disclosure timeline.
5. Minimize data at rest in transfer systems. A file that was deleted after delivery, or never staged on an internet-facing box, cannot be stolen from one.

## Scope and method

This study covers the Cl0p MOVEit campaign of 2023 as its center, with the surrounding Accellion, GoAnywhere and Cleo campaigns as context for the pattern. Sources are Progress, Fortra, Cleo, CISA, the FBI and vendor and victim reporting. Each claim carries one of three evidence grades.

| Grade | Meaning |
|---|---|
| Confirmed | The vendor, CISA or the FBI confirms the vulnerability or the exploitation |
| Reported | A single vendor, tracker or press account, not independently corroborated |
| Demonstrated | A research reproduction with no known in-the-wild use at the time |

## Part 1: the playbook, four times

Cl0p's file-transfer campaigns are best understood as one method applied to one target class across four years (**Confirmed** for each vulnerability and for Cl0p's involvement):

- **Accellion File Transfer Appliance (2020 to 2021).** The origin of the pattern. A chain of flaws in Accellion's legacy FTA (including CVE-2021-27101, a SQL injection, with command-injection and server-side request forgery flaws alongside it) let attackers deploy the DEWMODE web shell and steal files, after which Cl0p extorted the victims. The appliance was end-of-life, which is itself the lesson: an unsupported edge box holding live data is a standing liability.
- **Fortra GoAnywhere MFT (early 2023).** CVE-2023-0669, a pre-authentication flaw in the License Response Servlet caused by insecure deserialization, gave remote code execution. Cl0p claimed on the order of 130 organizations. The same month set the stage for MOVEit.
- **Progress MOVEit Transfer (May to June 2023).** CVE-2023-34362, the subject of Part 2, and the largest of the four by a wide margin.
- **Cleo Harmony, VLTrader and LexiCom (late 2024).** CVE-2024-50623, an unrestricted file upload and download flaw, was followed by CVE-2024-55956, which Rapid7 assessed as a distinct unauthenticated command-execution flaw in the Autorun feature rather than a bypass of the first. CISA added the activity to its Known Exploited Vulnerabilities catalog, and Cl0p confirmed to reporters that it was behind the exploitation. About 200 victims were listed.

Four products, four vendors, one method. The attacker did not need a new idea each time, only a new unpatched file-transfer product exposed to the internet.

## Part 2: the MOVEit zero-day

MOVEit Transfer is a product organizations run to exchange files securely with partners, often as the automated backbone of payroll, benefits, healthcare and financial data flows. That is exactly what made it valuable to steal from.

CVE-2023-34362 is a SQL injection vulnerability in the MOVEit Transfer web application (**Confirmed**: Progress, CVSS 9.8). An unauthenticated attacker sends crafted input that the application passes into a database query, which lets the attacker read and modify the contents of the MOVEit database and, in the observed attacks, stage a web shell on the server. Progress published its advisory and an emergency patch on 31 May 2023. During the hardening review that followed, two more SQL injection flaws were identified and fixed in June 2023 (**Confirmed**):

- **CVE-2023-35036**: additional SQL injection in MOVEit Transfer.
- **CVE-2023-35708**: a SQL injection and privilege-escalation flaw addressed in a follow-up fix.

The post-exploitation payload is what turned a web vulnerability into a mass breach. Attackers installed a web shell, most often a file named `human2.aspx` and tracked as the LEMURLOOT family, that let them list the files held in MOVEit, pull them out, and in cloud-backed deployments retrieve the Azure Storage account keys the service used (**Confirmed**: CISA and FBI advisory AA23-158A, and multiple vendors). The attacker's goal was the stored data, and the web shell was the pipe that drained it.

Cl0p did not deploy encrypting ransomware here. Starting around 14 June 2023 it published victim names on its leak site and told organizations to make contact before a deadline or see their files released (**Confirmed**). That choice matters for defenders: there was no encryption event, no ransom-note-on-every-host moment, and no clean backup that could undo the harm, because the harm was that the data had already left. Detection had to come from the exploitation and exfiltration itself, not from a later encryption stage.

### MOVEit remediation and detection

| Step | What to do |
|---|---|
| Patch | Apply the Progress fixes for CVE-2023-34362, CVE-2023-35036 and CVE-2023-35708 and stay current with later MOVEit advisories; confirm every instance, including any a vendor runs for you |
| Hunt | Search for `human2.aspx` and other unexpected `.aspx` files in the MOVEit `wwwroot` path, review MOVEit and IIS logs for anomalous activity around late May 2023, and look for new or unexpected administrator accounts and large outbound transfers |
| Rotate | If exploitation is suspected, rotate the MOVEit service credentials and any Azure Storage or other cloud keys the server held, because the web shell could read them |
| Reduce exposure | Put MOVEit behind authenticated access or a VPN, restrict its inbound and outbound connectivity, and be prepared to take it offline during an active campaign |
| Assume breach | If the server was internet-facing and unpatched over the exploitation window, treat the data it held as stolen and begin breach notification analysis, do not wait for a ransom note |

## Part 3: who did it, and the scale

The campaigns were run by Cl0p, a financially motivated group also tracked as TA505, FIN11, LACE Tempest (Microsoft) and Graceful Spider, and known for large-scale extortion rather than quiet espionage (**Confirmed**: Microsoft and CISA). The group's distinguishing trait across these campaigns was patience in the target choice: it repeatedly found and stockpiled file-transfer zero-days, then fired them at internet scale in a short burst to beat the patch cycle.

The scale of MOVEit specifically grew for more than a year as downstream victims filed notifications (**Reported** except where noted):

- By mid-2023, early tallies already reached roughly 1,000 organizations and about 60 million individuals.
- By August 2024, the most-cited running tally stood at about 2,773 organizations and roughly 95.8 million individuals, and the trackers that maintain it caution that the figure is a floor, since several victims were service providers whose own customers were affected.
- Victims spanned government, education, finance, healthcare, insurance and large enterprises across several continents, and many were breached through a third party's MOVEit server rather than their own, for example through the payroll provider Zellis.

The spread through third parties is the part a vulnerability management program must internalize. The number of organizations that ran MOVEit was a fraction of the number of organizations whose data was in a MOVEit server somewhere. Exposure was not bounded by your own asset inventory.

## Cross-cutting themes

- **Data-theft extortion is a ransomware-grade event without ransomware.** No encryption occurred in MOVEit, yet the business impact (breach notification, regulatory exposure, extortion pressure, reputational harm) matched a ransomware incident. A prioritization model that weights encryption behavior over data exposure misreads this class of attack. See [the Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md).
- **Managed file transfer is a crown-jewel attack surface, not plumbing.** These products are internet-facing, aggregate many parties' sensitive data, and are often operated outside the security team's close attention. That combination is why the same actor hit the same product class four times.
- **Zero-day exploitation defeats patch cadence by definition.** MOVEit and Cleo were exploited before a patch existed. Defense of this asset class therefore cannot rest on patching alone; it needs exposure reduction, egress control, web-shell detection and a rehearsed take-offline option. This mirrors the edge-device lesson in [the SharePoint ToolShell case study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md).
- **Your exposure includes your vendors' assets.** Much of the MOVEit harm reached organizations that never ran MOVEit. Fourth-party risk is real risk, and mapping which vendors hold your data in which transfer systems is part of vulnerability management, not a separate compliance exercise. See [the Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

## Sources

- Progress Software advisories for CVE-2023-34362, CVE-2023-35036 and CVE-2023-35708, and the MOVEit Transfer security notifications.
- The joint CISA and FBI advisory AA23-158A on Cl0p ransomware exploitation of MOVEit Transfer, and the CISA Known Exploited Vulnerabilities catalog entries for the MOVEit, GoAnywhere and Cleo flaws.
- Fortra advisory for CVE-2023-0669 (GoAnywhere MFT) and Cleo advisories for CVE-2024-50623 and CVE-2024-55956, with Rapid7's analysis distinguishing the two Cleo flaws.
- Microsoft Threat Intelligence attribution of the MOVEit exploitation to Lace Tempest (Cl0p), and reporting from Mandiant and Huntress on the LEMURLOOT web shell.
- Emsisoft's running MOVEit impact tally (about 2,773 organizations and about 95.8 million individuals as of August 2024) and corroborating reporting from BleepingComputer, The Record and security trackers; figures are reported totals and best treated as a floor.

## Related references

- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)
- [The SharePoint ToolShell Mass Exploitation](/case-studies/SHAREPOINT_TOOLSHELL_2025.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
