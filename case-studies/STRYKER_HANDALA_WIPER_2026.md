# The Stryker Device-Wipe Attack of March 2026: A Case Study

*A TeamStarWolf case study. Published 12 November 2026; sources checked 11 November 2026; the SEC filings reopened 12 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Threat Actors: Iran](/case-studies/THREAT_ACTORS_IRAN.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Microsoft Intune and Entra administrators, healthcare and medical-technology security teams, incident responders, threat intelligence analysts and vulnerability management leads

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 17 min (3,839 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want the dated record of the March 2026 Stryker device-wipe attack, you need to separate the Handala persona's claims from what Stryker and the US government confirmed, or you want the controls that stop a compromised administrator from wiping every managed device

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: what happened](#part-1-what-happened), [Part 5: the defender and vulnerability-management view](#part-5-the-defender-and-vulnerability-management-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Iran-Attributed Threat Actors](/case-studies/THREAT_ACTORS_IRAN.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Stryker's own staff felt it at once. In the early hours of 11 March 2026, employees in four countries reported that managed devices, including personal phones enrolled for work, had been remotely wiped through the company's device management system [22] (**Reported**); in Ireland thousands could not log in [25] (**Reported**). Hospitals felt it too: Stryker rescheduled some personalized-implant cases for the week of 16 March because of shipping delays [10] [11] (**Confirmed**), and a Maryland EMS agency told hospitals that Stryker's LifeNet ECG transmission was not working in most of the state, which Stryker disputed [26] (**Reported**).

Stryker told the SEC on 11 March of "a global disruption" to its Microsoft environment, with no indication of ransomware or malware [1]; on 23 March it reported, with Unit 42, a malicious file that ran commands to hide the actor's activity [3]; on 9 April it declared the incident material to first-quarter results [6] (**Confirmed**).

The Handala Hack persona claimed the attack [21] [22] (**Reported**). The US Department of Justice says Iran's Ministry of Intelligence and Security (MOIS) used the Handala domain to claim a destructive attack on "a U.S.-based multinational medical technologies firm", and announced the seizure of four domains on 19 March [14] (**Confirmed**; DOJ does not name Stryker). No source opened ties a CVE to the incident, and the KEV catalog has no matching entry [13] (**Demonstrated** for the KEV check; **Inferred** that no CVE applies); CISA's response was a call to harden endpoint management, not a patch [12] (**Confirmed**).

### Key facts at a glance

| Field | Value |
|---|---|
| Victim | Stryker Corporation, Portage, Michigan; medical technology manufacturer [1] |
| Systems affected | Microsoft environment [1], later the wider corporate network [3]; Unit 42 names Entra ID, servers and workstations [4] |
| Mechanism as reported | Remote wipe from a new Global Administrator account created after an administrator account was compromised [22] [23] (**Reported**) |
| Claimed scale | More than 200,000 systems wiped, 50 TB stolen, offices in 79 countries shut (persona claim, **Reported**) [21] [22]; Stryker gave no device count [1] to [11] |
| Claimed by | Handala Hack persona (**Reported**) [21] [22]; DOJ ties the persona's domains to MOIS [14] |
| ATT&CK group | [G1055 VOID MANTICORE](/mitre/groups/G1055.md), whose description names the Stryker attack [19] |
| CVE and KEV | KEV catalog 2026.11.10 has no entry naming Intune, Entra or Stryker [13] (**Demonstrated**) |
| Financial effect | Material to Q1 2026 results, not to full-year guidance [6]; idle production time hit gross margin [8] |

### Key findings

- **Reporting points to an administrative weapon, not malicious code alone.** Reporting describes a built-in device wipe issued from a compromised administrator path [22] [23] (**Reported**); CISA's alert names the attack and recommends Multi Admin Approval for device wipe [12] (**Confirmed**). Stryker's filings and customer pages do not name Intune [1] to [11] (**Inferred** from this study's reading).
- **Recovery took about three weeks and a rebuild.** From the 11 March disclosure to full operations on 1 April [1] [11], systems were rebuilt or restored from backups predating the compromise window, unrebuilt systems were isolated, and Microsoft was engaged to recover identity infrastructure [4] (**Confirmed**).
- **The device counts stay claims.** The persona claimed more than 200,000 devices, and later, per BleepingComputer, nearly 80,000 [21] [23]; TechCrunch reported "tens of thousands" [24] (**Reported**). Stryker's motion to dismiss, as reported, said its search of the compromised files found the business email addresses of two plaintiffs and no PII [28] (**Reported**).

### Top recommendations

1. Require a second administrator for device wipe and other high-impact actions, and scope Intune administrators by role [12] [15] [18] (**Inferred** from the guidance each gives).
2. Put phishing-resistant MFA and privileged identity management on Global Administrator and device-management roles, and alert on any new Global Administrator [12] [15] [23] (**Inferred**).
3. Alert on mass wipes and lock out the initiating admin [16] (**Inferred** from Unit 42's guidance).
4. Plan identity-plane recovery: pre-compromise backups, an Entra ID rebuild path and manual ordering workarounds [4] [8] [10] (**Inferred**).

## Scope and method

This brief covers the March 2026 attack on Stryker, its attribution and the response through 11 November 2026. The wider Iranian record is in [Threat Actors: Iran](/case-studies/THREAT_ACTORS_IRAN.md), which graded the DOJ release Reported because it could not be opened on 3 November 2026 [30]; it opened on 11 November 2026 [14]. [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md) summarizes the attack in one paragraph and points here as the home study [31]. Tradecraft is described at advisory level; no indicators or commands appear here.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study (filings, customer pages, government releases, vendor and ISAC guidance, ATT&CK or library data, a court filing); a vendor's attribution is Confirmed only as that vendor's assessment |
| Reported | Known through journalism, through a persona's own claims, or through a secondary account of a primary not opened |
| Demonstrated | Shown by this study's own check of data (the KEV feed) |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

## Part 1: what happened

| Date (2026) | Event | Sources | Grade |
|---|---|---|---|
| 6 to 9 Mar | Persona domains claim 851 GB stolen from a Hasidic community and post data on about 190 people tied to the IDF | [14] | Confirmed |
| 11 Mar, early hours | Managed devices wiped in the US, Ireland, Costa Rica and Australia; Entra login page shows the Handala logo | [22] | Reported |
| 11 Mar | Handala-hack domain claims a destructive attack on a US medtech firm; persona claims 200,000 devices, 50 TB and 79 countries | [14] [21] [22] | Confirmed (claim made); Reported (figures) |
| 11 Mar | Stryker 8-K Item 8.01: global disruption to its Microsoft environment; no indication of ransomware or malware; materiality undetermined | [1] | Confirmed |
| 12 Mar | 8-K: order processing, manufacturing and shipping disrupted | [2] | Confirmed |
| 18 Mar | CISA alert on endpoint management hardening names the Stryker attack | [12] | Confirmed |
| 19 Mar | DOJ announces seizure of Justicehomeland, Handala-Hack, Karmabelow80 and Handala-Redwanted domains used by MOIS; separately notes the State Department's Rewards for Justice offer of up to $10 million for information on foreign-directed cyber activity against US critical infrastructure | [14] | Confirmed |
| 23 Mar | 8-K revises the no-malware view (malicious file, "not capable of spreading") | [3] | Confirmed |
| 1 Apr | Fully operational across global manufacturing | [11] | Confirmed |
| 9 Apr | 8-K/A Item 1.05: material impact on operations and Q1 results, not on full-year guidance | [6] | Confirmed |
| 20 Apr | ATT&CK creates G1055 VOID MANTICORE; the current version (modified 31 Jul) names the Stryker attack | [19] | Confirmed |

## Part 2: the intrusion record

The primary record fixes the outline and leaves the mechanism to secondary sources. Unit 42's assurance letter, filed as an exhibit, is the most specific primary: a compromise "impacting" Entra ID, servers and workstations, with no persistent unauthorized access found, known IOCs eradicated, and no unauthorized activity identified after 11 March [4] (**Confirmed**). The 23 March 8-K adds a malicious file that ran commands to hide activity and could not spread [3] (**Confirmed**). Neither names the file, the commands or the initial access route.

The wipe mechanism comes from reporting. A source told BleepingComputer the attackers compromised an administrator account, created a new Global Administrator account and used the built-in Intune wipe command [23]; KrebsOnSecurity's source also points to an Intune remote wipe [21] (**Reported**). Whether the compromised account used MFA, Stryker's spokesperson did not say [24] (**Reported**).

The primary link between Stryker and device management is CISA's 18 March alert, which names the attack and lists least-privilege Intune RBAC, phishing-resistant MFA with privileged access hygiene, and Multi Admin Approval for high-impact actions such as device wipe [12] (**Confirmed**); it does not name Handala. Microsoft's guidance of 14 March covers the same ground and names no incident [15] (**Confirmed**). Unit 42 says Handala's recent operations reportedly used phishing-based identity exploitation and Intune administrative access [16] (**Confirmed** as Unit 42's statement; not Stryker-specific).

## Part 3: who and why

Attribution rests on four statements; Stryker speaks only of "purported threat actors" [10] (**Confirmed**).

- **DOJ (19 March).** MOIS used the four seized domains: two (Handala-hack and Handala-redwanted) for the Handala Hack persona and two (Justicehomeland and Karmabelow80) for a shell hacktivist entity. The FBI tied them together through shared leak sites, Iranian IP ranges and a common playbook of destructive attacks and "faketivist" psychological operations [14]. On 11 March the Handala-hack domain claimed the medtech attack [14] (**Confirmed** as the US government's position).
- **Check Point (12 March).** Handala Hack is a persona of the MOIS-affiliated Void Manticore, which also ran the Homeland Justice persona against Albania from mid-2022; Stryker is named as an example [17] (**Confirmed** as Check Point's assessment).
- **Unit 42 (12 March, updated).** Handala emerged in late 2023 and is "currently assessed" to be a state-directed MOIS front [16] (**Confirmed** as Unit 42's assessment).
- **ATT&CK (created 20 April, modified 31 July).** G1055 VOID MANTICORE is assessed to operate on behalf of MOIS; its aliases include Handala Hack and Homeland Justice, and its description names the Stryker attack [19] (**Confirmed**).

Not every publisher agrees. The 2026 chronicle records that ESET calls the group it spells "Hamdala" a pro-Iranian hacktivist group, not a state-aligned one [31] (**Reported**, as the chronicle grades ESET's statement).

The stated motive is retaliation: DOJ quotes the persona on the "Axis of Resistance" [14] (**Confirmed**), and Krebs reports a manifesto citing a 28 February strike on an Iranian school [21] (**Reported**). The lineage runs to the 2022 HomeLand Justice attack on Albania [20], campaign [C0038](/mitre/campaigns/C0038.md) [29] (**Confirmed**).

## Part 4: impact and response

**The victim.** Some employees could not reach IT systems, and the company used manual workarounds [8]; electronic ordering was returning on 15 March [10]; manufacturing was ramping by 23 March [5]; full operations returned on 1 April [11] (**Confirmed**). Q1 net sales still rose 2.6% to $6.0 billion, but adjusted operating margin fell 180 basis points [7], and idle production time was still cited in the Q3 10-Q [9] (**Confirmed**).

**Hospitals and patients.** Stryker says patient-related services and connected products were not affected [2] [10] (**Confirmed** as Stryker states). On LifeNet, the Maryland EMS notice and Stryker's reply that it stayed functional while some providers paused it are **Reported** [26]. Compare [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md).

**Government.** CISA issued its alert on 18 March, with Microsoft and Stryker contributing [12]; DOJ announced the domain seizures the next day [14]; Health-ISAC told members on 17 March to require a second approver for destructive Intune commands [18] (**Confirmed**). Ireland's NCSC said it was assessing impact [25] (**Reported**).

**Courts and notification.** A former employee filed a class action on 13 March [27] (**Confirmed**). Eight suits were consolidated; Stryker moved to dismiss on 22 June, and plaintiffs dismissed without prejudice on 29 June; as of 3 July Stryker had sent no breach notifications to HHS OCR or state attorneys general [28] (**Reported**).

## Part 5: the defender and vulnerability-management view

- A program that ranks work by CVE and KEV would have seen nothing: the exposure was privilege and configuration [12] [13] (**Inferred**).
- Treat Entra ID and Intune administration as tier-zero systems. Between them, the responders name role scoping [12] [15] [18], phishing-resistant MFA [12] [15], privileged identity management [15] and a second approver for wipe [12] [15] [16] [18] (**Confirmed** for each source as cited; whether Stryker had them on is not in any primary opened).
- Enrolled personal phones were reportedly wiped [22] (**Reported**); BYOD policy should say what an administrator can do to them (**Inferred**).

### What is overstated and what is understated

- *Overstated:* the device counts and the 50 TB theft are unconfirmed claims [21] [22] [23] (**Reported**); Stryker's filings and customer pages give no device count and do not confirm exfiltration [1] to [11] (**Inferred** from this study's reading); its reported motion to dismiss refers only to a search of compromised files [28] (**Reported**). Reading the attribution as settled goes beyond the government record: DOJ attributes the claim domains, not the intrusion forensics [14], and the vendor and ATT&CK attributions are assessments [16] [17] [19] (**Inferred**).
- *Understated:* Stryker's day-one "no malware" framing was revised on 23 March to a concealment-capable malicious file [1] [3], and the Unit 42 letter describes a compromise of Entra ID, servers and workstations [4] (**Confirmed**); together they show more than a device-management misuse (**Inferred**).

## MITRE mappings

This Part binds the verified record to ATT&CK v20.0 Enterprise, CAPEC and D3FEND, with names and tactics from the library's `data/attack/` files [29]. Rows that rest on ATT&CK's G1055 page say so [19]. No source describes industrial control systems, so no ATT&CK for ICS techniques apply.

### Groups, software and campaigns

| Object | ATT&CK id | Relationship to this record |
|---|---|---|
| VOID MANTICORE | [G1055](/mitre/groups/G1055.md) | Bound. ATT&CK names the Stryker attack under the Handala Hack persona [19] |
| HomeLand Justice | [C0038](/mitre/campaigns/C0038.md) | Related. The 2022 Albania campaign of a persona ATT&CK lists as a G1055 alias [19] [20] [29] |
| ZeroCleare, CHIMNEYSWEEP, ROADSWEEP | [S1151](/mitre/software/S1151.md), [S1149](/mitre/software/S1149.md), [S1150](/mitre/software/S1150.md) | Related only. 2022 Albania campaign software [20] [29]; not named in the Stryker record |

No software is bound: the record does not name the 23 March malicious file [3].

### ATT&CK Enterprise techniques

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T1583.001`](/mitre/techniques/T1583-001.md) | Domains | Resource Development | Four persona domains used by MOIS, seized 19 Mar 2026 | [14] |
| [`T1585.001`](/mitre/techniques/T1585-001.md) | Social Media Accounts | Resource Development | ATT&CK G1055 row: Handala Hack and other personas used social media accounts including Telegram, citing Check Point [17] and a Specops blog on the Stryker wipe; no Stryker-specific account is described | [17] [19] |
| [`T1566`](/mitre/techniques/T1566.md) | Phishing | Initial Access | Persona-level phishing-based identity exploitation (Unit 42, 12 Mar 2026); not Stryker-specific | [16] |
| [`T1078.004`](/mitre/techniques/T1078-004.md) | Cloud Accounts | Initial Access, Persistence, Privilege Escalation, Stealth | Administrator account compromised (BleepingComputer, 19 Mar 2026); Entra ID compromise (Unit 42 letter, 20 Mar 2026); ATT&CK G1055 row citing Stryker's 23 Mar 8-K for Entra ID account compromise and a separate Unit 42 article for Intune console access | [3] [4] [19] [23] |
| [`T1098`](/mitre/techniques/T1098.md) | Account Manipulation | Persistence, Privilege Escalation | ATT&CK G1055 row citing the Unit 42 letter (20 Mar 2026) for administrative account abuse or privilege escalation | [4] [19] |
| [`T1136.003`](/mitre/techniques/T1136-003.md) | Cloud Account | Persistence | New Global Administrator account created (BleepingComputer, 19 Mar 2026) | [23] |
| [`T1651`](/mitre/techniques/T1651.md) | Cloud Administration Command | Execution | ATT&CK G1055 row (citing a separate Unit 42 article of 16 Mar 2026, not opened here): abuse of built-in remote wipe or factory reset commands in a cloud management solution; Stryker wipe of 11 Mar 2026 as reported | [19] [22] [23] |
| [`T1072`](/mitre/techniques/T1072.md) | Software Deployment Tools | Execution, Lateral Movement | Remote wipe through a privileged Intune account (ATT&CK G1055, Stryker source); 11 Mar 2026 as reported | [19] [22] [23] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | Impact | Destructive attack claimed 11 Mar 2026; ATT&CK G1055 row citing the Stryker source | [14] [19] |
| [`T1561.001`](/mitre/techniques/T1561-001.md) | Disk Content Wipe | Impact | Devices wiped 11 Mar 2026; ATT&CK G1055 row citing the Stryker source | [19] [22] |
| [`T1491.001`](/mitre/techniques/T1491-001.md) | Internal Defacement | Impact | Entra login page shown with the Handala logo (11 Mar 2026) | [22] |

Fit notes (**Inferred**): T1072, T1561.001 and T1098 follow ATT&CK's own G1055 rows [19]. T1136.003 and T1491.001 rest only on Reported sources. The 23 March "malicious file to run commands" that hid activity [3] is too general to bind: the record names neither the interpreter nor what was hidden, so T1059 and T1070 are left out. The 50 TB exfiltration claim is not bound because no primary confirms it. T1119, T1005 and T1657, which ATT&CK's G1055 page ties to the Stryker operation's exfiltration, are not bound because no primary confirms exfiltration.

### CWE and CAPEC

No source ties a CVE to the incident, so this study binds no CWE [13]. CAPEC entries the library relates to this study's techniques [29]:

| CAPEC | Name | Via | Where it meets the record |
|---|---|---|---|
| [CAPEC-560](/mitre/capec/CAPEC-560.md) | Use of Known Domain Credentials | T1078 (parent of T1078.004) | The compromised administrator account [23] (**Inferred**, partial fit) |
| [CAPEC-98](/mitre/capec/CAPEC-98.md) | Phishing | T1566 | Persona-level phishing-based identity exploitation [16] |
| [CAPEC-148](/mitre/capec/CAPEC-148.md) | Content Spoofing | T1491 (parent of T1491.001) | The defaced login page [22] (**Inferred**) |

CAPEC-187 and CAPEC-657 (via T1072) are left out: no spoofed software update is described.

### D3FEND countermeasures

| D3FEND countermeasure | Techniques the library maps it to (from this study) | Where it meets the record |
|---|---|---|
| [User Account Permissions](/mitre/d3fend/user-account-permissions.md) (D3-UAP) | T1078.004, T1136.003 | Least-privilege Intune RBAC and scope tags [12] [15] [18] |
| [Account Locking](/mitre/d3fend/account-locking.md) (D3-AL) | T1078.004, T1136.003 | Automatic lockout of an admin who starts a mass wipe [16] |
| [Restore Software](/mitre/d3fend/restore-software.md) (D3-RS) | T1072 | Systems rebuilt or restored from pre-compromise backups [4] |

[Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (D3-MFA) covers the phishing-resistant MFA that CISA and Microsoft recommend [12] [15], though the library does not map it to this study's techniques. See the [D3FEND Reference](/D3FEND_REFERENCE.md).

### Navigator layer

The study's Navigator layer is [`navigator/library-layers/stryker-handala-wiper-2026.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/stryker-handala-wiper-2026.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/stryker-handala-wiper-2026.json)), listed on [the Navigator layers page](/navigator/index.md). It is pinned to ATT&CK v20 Enterprise; scores measure the tie to this record (100 primary, 60 ATT&CK or partial fit, 40 Reported only), and each comment names the source numbers. Score 100: T1583.001 and T1078.004. Score 60: T1585.001, T1566, T1098, T1651, T1072, T1485 and T1561.001. Score 40: T1136.003 and T1491.001.

## Cross-cutting themes

- **Administrative tools are destructive tools.** A built-in wipe needs no malware [12] [23] (**Confirmed** for CISA's framing; **Reported** for the mechanism).
- **Personas are a delivery mechanism.** DOJ calls the playbook "faketivist" [14] (**Confirmed**); treat persona numbers as claims until confirmed (**Inferred**).

## Sources

All sources were opened on 11 November 2026; the SEC filings [1] to [9] were reopened on 12 November 2026 and the 2026 chronicle [31] was read on 12 November 2026. Addresses shown as code rather than as links refuse automated link checkers (the sec.gov filings); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Stryker, Form 8-K Item 8.01, 11 Mar 2026 | `https://www.sec.gov/Archives/edgar/data/310764/000119312526102460/d76279d8k.htm` | 2026-11-11 | Confirmed |
| 2 | Stryker, Form 8-K Item 7.01, 12 Mar 2026 | `https://www.sec.gov/Archives/edgar/data/310764/000119312526104431/d101097d8k.htm` | 2026-11-11 | Confirmed |
| 3 | Stryker, Form 8-K Item 7.01, 23 Mar 2026 | `https://www.sec.gov/Archives/edgar/data/310764/000119312526118634/d94012d8k.htm` | 2026-11-11 | Confirmed |
| 4 | Unit 42 General Assurance Letter, 20 Mar 2026 (Ex. 99.1 to [3]) | `https://www.sec.gov/Archives/edgar/data/310764/000119312526118634/d94012dex991.htm` | 2026-11-11 | Confirmed |
| 5 | Stryker customer statement, 23 Mar 2026 (Ex. 99.2 to [3]) | `https://www.sec.gov/Archives/edgar/data/310764/000119312526118634/d94012dex992.htm` | 2026-11-11 | Confirmed |
| 6 | Stryker, Form 8-K/A Item 1.05, 9 Apr 2026 | `https://www.sec.gov/Archives/edgar/data/310764/000119312526149607/d112875d8ka.htm` | 2026-11-11 | Confirmed |
| 7 | Stryker, Q1 2026 earnings release, 30 Apr 2026 | `https://www.sec.gov/Archives/edgar/data/310764/000031076426000025/sykex991earningsq12026.htm` | 2026-11-11 | Confirmed |
| 8 | Stryker, Form 10-Q for Q1 2026, filed 11 May 2026 | `https://www.sec.gov/Archives/edgar/data/310764/000031076426000031/syk-20260331.htm` | 2026-11-11 | Confirmed |
| 9 | Stryker, Form 10-Q for Q3 2026, filed 30 Oct 2026 | `https://www.sec.gov/Archives/edgar/data/310764/000031076426000061/syk-20260930.htm` | 2026-11-11 | Confirmed |
| 10 | Stryker, customer updates (regional page), 11 to 23 Mar 2026 | [stryker.com/au/en/about/news/...](https://www.stryker.com/au/en/about/news/a-message-to-our-customers-03-2026.html) | 2026-11-11 | Confirmed |
| 11 | Stryker, customer updates (US page), 19 Mar to 1 Apr 2026 | [stryker.com/us/en/about/news/2026/...](https://www.stryker.com/us/en/about/news/2026/a-message-to-our-customers-03-2026.html) | 2026-11-11 | Confirmed |
| 12 | CISA, endpoint management system hardening alert, 18 Mar 2026 | [cisa.gov/news-events/alerts/2026/03/18/...](https://www.cisa.gov/news-events/alerts/2026/03/18/cisa-urges-endpoint-management-system-hardening-after-cyberattack-against-us-organization) | 2026-11-11 | Confirmed |
| 13 | CISA, KEV catalog JSON feed, version 2026.11.10 | [cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 2026-11-11 | Demonstrated |
| 14 | DOJ, Justice Department disrupts Iranian cyber-enabled psychological operations (26-251), 19 Mar 2026 | [justice.gov/opa/pr/...](https://www.justice.gov/opa/pr/justice-department-disrupts-iranian-cyber-enabled-psychological-operations) | 2026-11-11 | Confirmed |
| 15 | Microsoft Intune Customer Success, Best practices for securing Microsoft Intune, 14 Mar 2026 | [techcommunity.microsoft.com/.../4502117](https://techcommunity.microsoft.com/blog/intunecustomersuccess/best-practices-for-securing-microsoft-intune/4502117) | 2026-11-11 | Confirmed |
| 16 | Unit 42, Handala Hack wiper attacks threat brief, 12 Mar 2026, updated 13 Mar | [unit42.paloaltonetworks.com/handala-hack-wiper-attacks/](https://unit42.paloaltonetworks.com/handala-hack-wiper-attacks/) | 2026-11-11 | Confirmed (as Unit 42's assessment); Reported (INCD relay) |
| 17 | Check Point Research, Handala Hack: unveiling group's modus operandi, 12 Mar 2026 | [research.checkpoint.com/2026/...](https://research.checkpoint.com/2026/handala-hack-unveiling-groups-modus-operandi/) | 2026-11-11 | Confirmed (as Check Point's assessment) |
| 18 | Health-ISAC, configuring Intune tenant administration against unwanted wipes, 17 Mar 2026 | [health-isac.org/best-practices-...](https://health-isac.org/best-practices-configuring-microsoft-intune-tenant-administration-to-safeguard-devices-from-unwanted-wipes/) | 2026-11-11 | Confirmed |
| 19 | MITRE ATT&CK, G1055 VOID MANTICORE (created 20 Apr 2026, modified 31 Jul 2026) | [attack.mitre.org/groups/G1055/](https://attack.mitre.org/groups/G1055/) | 2026-11-11 | Confirmed |
| 20 | CISA and FBI, AA22-264A, Iranian state actors and the Government of Albania, 2022 | [cisa.gov/news-events/cybersecurity-advisories/aa22-264a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a) | 2026-11-11 | Confirmed |
| 21 | KrebsOnSecurity, Iran-backed hackers claim wiper attack on medtech firm Stryker, 11 Mar 2026 | [krebsonsecurity.com/2026/03/...](https://krebsonsecurity.com/2026/03/iran-backed-hackers-claim-wiper-attack-on-medtech-firm-stryker/) | 2026-11-11 | Reported |
| 22 | BleepingComputer, Medtech giant Stryker offline after Iran-linked wiper malware attack, 11 Mar 2026 | [bleepingcomputer.com/news/security/...](https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-offline-after-iran-linked-wiper-malware-attack/) | 2026-11-11 | Reported |
| 23 | BleepingComputer, CISA warns businesses to secure Microsoft Intune systems after Stryker breach, 19 Mar 2026 | [bleepingcomputer.com/news/security/...](https://www.bleepingcomputer.com/news/security/cisa-warns-businesses-to-secure-microsoft-intune-systems-after-stryker-breach/) | 2026-11-11 | Reported |
| 24 | TechCrunch, Stryker restoring systems after pro-Iran hackers wiped employee devices, 17 Mar 2026 | [techcrunch.com/?p=3103249](https://techcrunch.com/?p=3103249) | 2026-11-11 | Reported |
| 25 | The Irish Times, Thousands of Irish workers affected by cyberattack on Stryker, 11 Mar 2026 | [irishtimes.com/ireland/2026/03/11/...](https://www.irishtimes.com/ireland/2026/03/11/thousands-of-irish-workers-affected-by-cyberattack-on-us-medtech-firm-stryker) | 2026-11-11 | Reported |
| 26 | CNN via KEYT, Pro-Iran hackers claim cyberattack on major US medical device maker, 11 Mar 2026 | [keyt.com/politics/cnn-us-politics/2026/03/11/...](https://keyt.com/politics/cnn-us-politics/2026/03/11/pro-iran-hackers-claim-cyberattack-on-major-us-medical-device-maker/) | 2026-11-11 | Reported |
| 27 | Class action complaint, W.D. Mich. 1:26-cv-00832, ECF No. 1, 13 Mar 2026 | [npr.brightspotcdn.com/.../gov-uscourts-miwd-119719-1-0.pdf](https://npr.brightspotcdn.com/ac/87/ff761b5140179ef52af71e420fb0/gov-uscourts-miwd-119719-1-0.pdf) | 2026-11-11 | Confirmed |
| 28 | The HIPAA Journal, Employees drop class action lawsuit against Stryker, 3 Jul 2026 | [hipaajournal.com/...](https://www.hipaajournal.com/employees-drop-class-action-lawsuit-against-stryker-cyberattack/) | 2026-11-11 | Reported |
| 29 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl`, `groups.jsonl`, `group_to_technique.jsonl`, `campaigns.jsonl`, `software.jsonl`, `technique_to_d3fend.jsonl`, `d3fend_countermeasures.jsonl`, `data/weaknesses/capec.jsonl` and the `mitre/` tree | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) | 2026-11-11 | Confirmed |
| 30 | TeamStarWolf library, Threat Actors: Iran | [/case-studies/THREAT_ACTORS_IRAN.md](/case-studies/THREAT_ACTORS_IRAN.md) | 2026-11-11 | Confirmed |
| 31 | TeamStarWolf library, The Year 2026 in Intrusions: A Dated Record | [/case-studies/CHRONICLE_2026.md](/case-studies/CHRONICLE_2026.md) | 2026-11-12 | Confirmed |

Not opened, so not cited as sources: Israel's National Cyber Directorate warning of 6 March 2026 (relayed by [16]), the DOJ seizure-warrant affidavit, the Maryland Institute for EMS Systems notice itself (relayed by [26]), Handala's own claim page, the Q1 2026 earnings-call transcript, and the Unit 42 'Iranian Cyber Threat Evolution' article (16 March 2026), the Specops Software blog on the Stryker wipe (30 March 2026) and the DomainTools assessment 'Handala: MOIS Linked Cyber Influence Ecosystem' (6 April 2026) that ATT&CK's G1055 page cites.

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Threat Actors: Iran](/case-studies/THREAT_ACTORS_IRAN.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [Healthcare Threat Actor Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md), [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md), [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- Group, campaign and software: [G1055 VOID MANTICORE](/mitre/groups/G1055.md), [C0038 HomeLand Justice](/mitre/campaigns/C0038.md), [S1151 ZeroCleare](/mitre/software/S1151.md), [S1149 CHIMNEYSWEEP](/mitre/software/S1149.md), [S1150 ROADSWEEP](/mitre/software/S1150.md)
- Techniques: [T1583.001 Domains](/mitre/techniques/T1583-001.md), [T1585.001 Social Media Accounts](/mitre/techniques/T1585-001.md), [T1566 Phishing](/mitre/techniques/T1566.md), [T1078.004 Cloud Accounts](/mitre/techniques/T1078-004.md), [T1098 Account Manipulation](/mitre/techniques/T1098.md), [T1136.003 Cloud Account](/mitre/techniques/T1136-003.md), [T1651 Cloud Administration Command](/mitre/techniques/T1651.md), [T1072 Software Deployment Tools](/mitre/techniques/T1072.md), [T1485 Data Destruction](/mitre/techniques/T1485.md), [T1561.001 Disk Content Wipe](/mitre/techniques/T1561-001.md), [T1491.001 Internal Defacement](/mitre/techniques/T1491-001.md)
- Mitigations: [M1026 Privileged Account Management](/mitre/mitigations/M1026.md), [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1018 User Account Management](/mitre/mitigations/M1018.md), [M1053 Data Backup](/mitre/mitigations/M1053.md)
- CAPEC: [CAPEC-560](/mitre/capec/CAPEC-560.md), [CAPEC-98](/mitre/capec/CAPEC-98.md), [CAPEC-148](/mitre/capec/CAPEC-148.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [stryker-handala-wiper-2026.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/stryker-handala-wiper-2026.json)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
- [All case studies](/case-studies/README.md)
