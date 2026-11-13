# The Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751): A Case Study

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Check Point](/platforms/check-point.md), [The PAN-OS GlobalProtect authentication bypass](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [Threat Actors: Iran](/case-studies/THREAT_ACTORS_IRAN.md), [Healthcare Threat Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [CVE Reference](/CVE_REFERENCE.md), [Vulnerability Prioritization](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Firewall, network and edge-device teams that run Check Point gateways or Spark appliances, remote-access VPN owners, vulnerability management leads, incident responders and threat intelligence analysts

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,458 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run Check Point Remote Access or Mobile Access, you need the dated record of CVE-2026-50751 and its exploitation from May 2026, or you want to decide how to patch, reconfigure and hunt after a VPN authentication bypass that ran a month before disclosure

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 5: the defender and vulnerability-management view](#part-5-the-defender-and-vulnerability-management-view), [MITRE mappings](#mitre-mappings)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Check Point](/platforms/check-point.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

For the teams that run Check Point gateways, the hard part of June 2026 was the hunting window, not the patch. Check Point's research team began chasing suspicious VPN activity on 4 June 2026 [1] (**Confirmed**). By the time it published a hotfix on 8 June, it had traced the first exploitation back to 7 May [1] (**Confirmed**). A gateway patched on the day of disclosure could already have been open for a month (**Inferred** from [1]).

The flaw, CVE-2026-50751, is a logic weakness in how Remote Access and Mobile Access validate certificates during the deprecated IKEv1 key exchange. It lets an unauthenticated remote attacker set up a remote access VPN connection without a valid user password [4] (**Confirmed**). It only works when four configuration conditions all hold [2] (**Confirmed**). CISA added it to the Known Exploited Vulnerabilities (KEV) catalog on the day it was published, gave agencies three days, and marked ransomware use as Known [7] (**Confirmed**). Check Point reports one case with confirmed post-compromise activity associated with a Qilin ransomware affiliate, and assesses with medium confidence that the actor is financially motivated and uses Qilin [1] (**Reported**).

### Key facts at a glance

| Field | Value |
|---|---|
| Products | Quantum Security Gateway and Spark firewalls running Remote Access or Mobile Access [2] [4] |
| Flaw | Logic flaw in certificate validation in the deprecated IKEv1 key exchange; CWE-287 Improper Authentication (CNA, NVD and KEV) [4] [5] [7] |
| Precondition | All four: Remote Access or Mobile Access enabled; IKEv1 enabled for remote access; legacy Remote Access clients accepted; machine certificate not required [2] |
| Scores | CVSS 4.0 9.3 Critical (Check Point as CNA); CVSS 3.1 9.3 Critical (CISA ADP); SSVC: exploitation active, automatable yes, technical impact total [4] |
| Disclosed | 8 Jun 2026: CVE published 11:07 UTC (reserved 7 Jun 09:42 UTC); NVD received it 12:16 [4] [6] |
| Fixed | Jumbo Hotfix Accumulators R82.10 Take 24, R82 Take 107, R81.20 Take 146, R81.10 Take 187; Spark R82.00.10 Build 998002216 and R81.10.17 Build 996004901 [2] |
| KEV | Added 8 Jun 2026, due 11 Jun 2026; known ransomware campaign use: Known [7] |
| First seen | 7 May 2026, by Check Point's own account [1] |
| Actor | One case tied to a Qilin ransomware affiliate; financially motivated, medium confidence (vendor assessment) [1] |
| Victims | "A few dozen targeted organizations globally"; no names, sectors or exact count [1] |

### Key findings

- **The exposure window opened a month before the fix.** Exploitation began on 7 May; the hotfix shipped on 8 June [1] (**Confirmed**). The vendor's hunting window starts on 7 May for that reason [1] [2] (**Confirmed**).
- **Configuration decided exposure.** A vulnerable version was only exposed if all four conditions held [2] (**Confirmed**). Any one of the three documented configuration changes breaks the chain, though on locally managed Spark the machine certificate option does not apply and IKEv2 on Spark R81.10.X needs the StrongSWAN client (**Inferred** from [2]).
- **A third party reproduced it within four days.** watchTowr Labs reproduced the bypass on R82.10 JHF Take 19 on 12 June and confirmed that the hotfix rejects it [8] (**Demonstrated**).
- **Filtering the IKE ports is not enough.** watchTowr reports that the bypass also works over TCP 443 when UDP 500 and 4500 are filtered [8] (**Demonstrated**).
- **The ransomware link is narrow but real.** One case with confirmed post-compromise activity tied to a Qilin affiliate; the actor-level Qilin link is a medium-confidence vendor assessment [1] (**Reported**). Even so, CISA's KEV entry marks ransomware use as Known [7] (**Confirmed**).
- **Old appliances are stuck.** R80.40, R81 and Spark R80.20.X are affected and sk185033 lists no fix for them [2] (**Confirmed**). For those releases the configuration changes are the only control (**Inferred**).

### Top recommendations

1. Install the recommended Jumbo Hotfix Accumulator, or the standalone hotfix for your take, on every gateway running Remote Access or Mobile Access. For centrally managed Spark appliances, update the management server with sk184766 first [2] (**Confirmed** as the vendor's direction).
2. Where you cannot patch today, close the chain in configuration. Clear "Allow older clients to connect", set remote access to IKEv2 only, or make machine certificate authentication mandatory [2] (**Confirmed**). On locally managed Spark, the machine certificate option does not apply, and IKEv2 on R81.10.X needs the StrongSWAN client [2] (**Confirmed**).
3. Do not count the IPS protection named for this CVE as a fix. Check Point says it gives visibility only [2] (**Confirmed**).
4. Hunt back to 7 May 2026. Look for completed IKEv1 Quick Mode exchanges ("Key Install" events) from users or source addresses you do not recognize, from before you patched, and check the vendor's indicator list [1] [2] (**Confirmed**).
5. Plan the exit from R80.40, R81 and Spark R80.20.X, which have no listed fix [2] (**Confirmed**), and treat a hit as a possible ransomware precursor [1] [7] (**Inferred**).

## Scope and method

This brief covers CVE-2026-50751 from first exploitation in May 2026 to the record as it stood on 11 November 2026. It describes tradecraft at advisory level. No exploit steps, packet contents, attacker IP addresses or file hashes are reproduced; Check Point publishes its indicators in its advisory and sk185033 [1] [2].

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary record opened for this study: Check Point's advisory and support articles, the CVE, NVD and KEV records, and government advisories |
| Reported | A vendor's own assessment that no other source can test (victim counts, attribution at stated confidence), or a news report |
| Demonstrated | Reproduced by a third party (watchTowr Labs), or shown by this study's own check of the library's ATT&CK, CWE, CAPEC and D3FEND data files |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

Not checked: the hunting-guide PDF that sk185033 references, national CERT advisories other than the Canadian Centre for Cyber Security and CERT-EU, regulator filings and victim statements. No victim has been named publicly in any source opened for this study.

## Part 1: what happened

| Date | Event | Sources | Grade |
|---|---|---|---|
| 30 May 2024 | CVE-2024-24919, an earlier Check Point gateway flaw (CWE-200), enters KEV; ransomware use Known | [7] | Confirmed |
| 7 May 2026 | Earliest exploitation Check Point observed; start of the attacker indicator window | [1] [2] | Confirmed |
| 29 May 2026 | KEV adds the [PAN-OS authentication bypass CVE-2026-0257](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md), ransomware use Known (a news report gives 13 May) | [7] [13] | Confirmed / Reported |
| Early Jun 2026 | Exploitation attempts increase | [1] | Confirmed |
| 4 Jun 2026 | Check Point Research begins investigating suspicious activity; sk185033 created | [1] [2] | Confirmed |
| 7 Jun 2026 | CVE-2026-50751 reserved (09:42 UTC); sk185035 created for the companion CVE-2026-50752 | [3] [4] | Confirmed |
| 8 Jun 2026 | CVE published by Check Point as CNA (11:07 UTC); hotfix announcement; NVD receives the record (12:16) | [1] [4] [6] | Confirmed |
| 8 Jun 2026 | CISA adds the CVE to KEV, due 11 Jun; NVD logs the KEV update at 22:00. The Canadian Centre issues AV26-559 | [6] [7] [11] | Confirmed |
| 9 Jun 2026 | NVD initial analysis with CPE configurations; Check Point adds indicators; AV26-559 updated to note the KEV entry | [1] [6] [11] | Confirmed |
| 10 Jun 2026 | Check Point adds indicators | [1] | Confirmed |
| 11 Jun 2026 | KEV due date; more indicators; sk185033 adds R81.10 JHF Take 187 | [1] [2] [7] | Confirmed |
| 12 Jun 2026 | watchTowr Labs publishes its reproduction and analysis | [8] | Demonstrated |
| 13 Jun 2026 | sk185033 adds attacker addresses and a section on identifying hits on the IPS signature | [2] | Confirmed |
| 14 Jun 2026 | sk185033 adds hotfixes for R82 Takes 60 and 44 | [2] | Confirmed |
| 15 Jun 2026 | sk185033 adds JHF R82.10 Take 24, R82 Take 107 and R81.20 Take 146; the CPR weekly report records active exploitation and the Qilin case | [2] [9] | Confirmed / Reported |
| 17 Jun 2026 | The CNA adds affected-version data; CISA ADP adds its SSVC decision | [6] | Confirmed |
| 22 Jul 2026 | A later Check Point flaw, CVE-2026-16232 (SmartConsole), enters KEV | [7] | Confirmed |
| 4 Aug 2026 | SSVC changed; NVD record last modified | [5] [6] | Confirmed |
| 10 Sep 2026 | CERT-EU 2026-012 covers CVE-2026-85102 and CVE-2026-85103 in Check Point VPN; it does not mention CVE-2026-50751 | [12] | Confirmed |
| 22 Sep 2026 | CVE-2026-85102 and CVE-2026-93616 enter KEV with BOD 26-04 forensic triage marked Yes | [7] | Confirmed |
| 24 Sep 2026 | sk185033 last modified | [2] | Confirmed |
| 20 Oct 2026 | News report of Unit 42 research naming Qilin (Spikey Scorpius) among operators exploiting PAN-OS CVE-2026-0257 | [13] | Reported |

The Intelligence Hub feed indexes the KEV row (8 June) and the watchTowr post (12 June) for this CVE [15] (**Confirmed**).

### Discrepancies in the record

- **End-of-support fixes.** watchTowr says end-of-support versions get no hotfix [8] (**Reported**). sk185033 lists R81.10 among the end-of-support releases yet names R81.10 JHF Take 187 as a fix; it lists nothing for R80.40, R81 or Spark R80.20.X [2] (**Confirmed**). The vendor's fix list is the authority here (**Inferred**).
- **The weakness class.** The CNA, NVD and KEV all carry CWE-287 [4] [5] [7] (**Confirmed**). watchTowr labels it CWE-1337 in its own framing, and that is not the CNA's assignment [8] (**Reported**).
- **The victim count.** The vendor says "a few dozen" [1]. No other source offers a count, so the figure cannot be tested (**Reported**).

## Part 2: the technical record

**The flaw, at advisory level.** IKEv1 is the older key exchange, which Check Point calls deprecated, that Remote Access VPN clients can use to set up a tunnel [1] [4] (**Confirmed**). Check Point's CNA description calls the bug a logic flow weakness in certificate validation in that exchange. It lets an unauthenticated remote attacker skip user authentication and open a remote access VPN connection without a valid password [4] (**Confirmed**). watchTowr describes the root cause as the client deciding how thoroughly its own credentials are checked [8] (**Reported**, its framing). In its reading of the patch, the fix stops the gateway trusting a client-supplied value that controlled whether certificate proof was checked [8] (**Demonstrated**). watchTowr also reports that the legacy username and password (XAUTH) mode could not be bypassed [8] (**Demonstrated**).

**Scores.** Check Point scores it CVSS 4.0 9.3 Critical (AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N). CISA's ADP scores it CVSS 3.1 9.3 Critical (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N) and records SSVC as exploitation active, automatable yes, technical impact total [4] (**Confirmed**).

**Who was exposed.** Version alone did not decide exposure. A gateway was vulnerable only if all four conditions held: Remote Access or Mobile Access enabled, IKEv1 enabled for remote access, legacy Remote Access clients accepted, and no machine certificate required [2] (**Confirmed**).

| Line | Affected | Recommended fix |
|---|---|---|
| Quantum Security Gateway R82.10 | JHF Take 19 or below | JHF Take 24 (standalone hotfixes for earlier takes) |
| R82 | Take 103 or below | JHF Take 107 (standalone hotfixes for earlier takes, including Takes 60 and 44) |
| R81.20 | Take 141 or below | JHF Take 146 (standalone hotfixes for earlier takes) |
| R81.10 (end of support) | Affected | JHF Take 187 |
| R81, R80.40 (end of support) | Affected | None listed |
| Spark R82.00.X, R81.10.X | Affected | R82.00.10 Build 998002216; R81.10.17 Build 996004901 |
| Spark R80.20.X (end of support) | Affected | None listed |

Source for the table: sk185033 [2] (**Confirmed**). Centrally managed Spark appliances need the certificate and CRL validation fix in sk184766 on the management server before the Spark builds are installed [2] (**Confirmed**).

**What the bypass gives.** Check Point says an attacker who gets in still needs more activity to reach internal resources or escalate privileges [1] (**Confirmed**). The flaw opens a VPN session; it does not by itself hand over the gateway or the network behind it (**Inferred** from [1]).

**The companion flaw.** CVE-2026-50752 (sk185035) is an IKEv1 site-to-site certificate validation weakness. Where certificate authentication is used, a man-in-the-middle may be able to intercept or modify tunnel traffic. It is rated CWE-295, CVSS 7.4. Check Point found it in an extended internal review with its BLAST platform. It has the same affected versions and fixes, is mitigated by IKEv2-only communities, and has not been exploited or added to KEV [3] [10] (**Confirmed**).

## Part 3: who and why

**What Check Point says.** One case had confirmed post-compromise activity linked to a Qilin ransomware affiliate [1] (**Reported**). Check Point assesses, with medium confidence, that the actor is financially motivated and uses Qilin ransomware [1] (**Reported**). Check Point's actor profile adds these points [1] (**Reported**):

- Check Point believes the actor's infrastructure is also being used to exploit other vendors' VPN flaws, such as those published by Palo Alto Networks, Fortinet and F5.
- It may communicate over Tox.
- It ran dedicated VPS infrastructure at Kaupo Cloud HK, Shock Hosting and Vultr, sometimes geolocated in the victim's region. Check Point's example is Taiwan-geolocated infrastructure used against Taiwanese organizations.
- After access, attempts to download malicious ELF files from actor-controlled infrastructure showed an attributional overlap with Qilin Linux ransomware binaries.

The Check Point Research weekly report of 15 June repeats the account [9] (**Reported**). None of this should be stated more strongly than the vendor states it: one confirmed case, medium confidence.

**What ATT&CK records.** Qilin is ATT&CK software [S1242](/mitre/software/S1242.md) (alias Agenda), a ransomware-as-a-service operation active since at least 2022. ATT&CK names [Water Galura (G1050)](/mitre/groups/G1050.md) as its operators [14] [16] (**Confirmed**). Check Point names an affiliate, not Water Galura [1] (**Confirmed**), and no source opened here ties Water Galura itself to this CVE (**Inferred**).

**The wider pattern.** A news report of Unit 42 research names Qilin (tracked by Unit 42 as Spikey Scorpius) among the ransomware operators exploiting the PAN-OS authentication bypass CVE-2026-0257 [13] (**Reported**). [The PAN-OS GlobalProtect authentication bypass study](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md) is the home for that flaw and the Qilin and INC activity tied to it. KEV marks that CVE's ransomware use as Known [7] (**Confirmed**). Taken with Check Point's belief that the actor's infrastructure is exploiting other vendors' VPN flaws, the record points to affiliates working through edge VPN bugs as an access route (**Inferred**).

**Why.** Check Point's motive assessment is financial [1] (**Reported**). KEV's ransomware flag is CISA's designation [7] (**Confirmed**). No source says what data was taken or whether anyone was encrypted.

## Part 4: impact and response

**Victims and scale.** Check Point says exploitation was limited to "a few dozen targeted organizations globally" [1] (**Reported**). It names no victims or sectors. Its infrastructure example puts Taiwanese organizations among the targets [1] (**Confirmed** as the vendor's statement).

**The vendor record.** Check Point began investigating on 4 June after seeing suspicious activity, and shipped fixes four days later [1] (**Confirmed**). Over the next week it extended its indicator list three times (9, 10 and 11 June) and revised sk185033 almost daily: R81.10 JHF Take 187 on 11 June, attacker addresses and IPS identification on 13 June, R82 Take 60 and 44 hotfixes on 14 June, and the recommended accumulators on 15 June [1] [2] (**Confirmed**). The advisory's author is Lotem Finkelstein, VP Research at Check Point Research [1] (**Confirmed**).

**The government record.** CISA added the CVE to KEV on 8 June, the day it was published, with a due date of 11 June. Ransomware use is marked Known and the weakness is CWE-287. The required action is to apply mitigations per vendor instructions, follow BOD 22-01 guidance for cloud services, or discontinue use [7] (**Confirmed**). The Canadian Centre for Cyber Security issued AV26-559 on 8 June and updated it on 9 June to note the KEV addition; it says Check Point observed active exploitation [11] (**Confirmed**). CERT-EU's September advisory on later Check Point VPN flaws does not cover this CVE [12] (**Confirmed**). Other national CERTs: not checked.

**The vendor's later run.** CVE-2026-16232 (SmartConsole) entered KEV on 22 July, and CVE-2026-85102 and CVE-2026-93616 on 22 September with BOD 26-04 forensic triage marked Yes [7] (**Confirmed**). An earlier Check Point gateway flaw, CVE-2024-24919 (information disclosure, CWE-200, KEV 30 May 2024 with ransomware use Known), is covered in [Threat Actors: Iran](/case-studies/THREAT_ACTORS_IRAN.md) (AA24-241A, Pioneer Kitten) and the [Healthcare Threat Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md) [7] (**Confirmed**).

## Part 5: the defender and vulnerability-management view

**Inventory the configuration, not just the version.** A version scan says which gateways could be hit. Only the four settings say which ones were exposed [2] (**Confirmed** facts; triage reading **Inferred**). Record per gateway whether IKEv1 is on for remote access, whether older clients are allowed, and whether machine certificates are mandatory (**Inferred**).

**The three-day clock.** KEV allowed three days [7] (**Confirmed**). The recommended accumulators for R82.10, R82 and R81.20 arrived on 15 June, after the due date; before then the fix was standalone hotfixes or configuration [2] (**Confirmed**). A team working to the KEV date had to close the configuration first and patch second (**Inferred**).

**Do not lean on the edge controls.** The IPS protection detects and does not remediate [2] (**Confirmed**). Port filtering on UDP 500 and 4500 does not close the path because TCP 443 works too [8] (**Demonstrated**). And geolocation-based logon review is weaker here, because the actor sometimes used infrastructure in the victim's own region [1] (**Reported**; the effect on detection **Inferred**).

**Hunt as if patched late.** Search from 7 May 2026, or the last 60 days, for the vendor's listed addresses. Treat IKEv1 Quick Mode completion ("Key Install") events from before patching as suspicious [2] (**Confirmed**). watchTowr released a detection artefact generator to help test detections [8] (**Demonstrated**). A hit means a VPN session existed; the next question is what that session reached [1] (**Inferred**).

**Retire the deprecated path.** IKEv1 is described by the vendor as deprecated, and both June flaws live in it [1] [3] [4] (**Confirmed**). Moving remote access and site-to-site communities to IKEv2 mitigates both [2] [3] (**Confirmed**).

### What is overstated and what is understated

- **Overstated:** "authentication bypass" read as gateway takeover or mass exploitation. The vendor requires four configuration conditions, says further activity is needed after access, and reports a few dozen targeted organizations [1] [2] (**Inferred** reading of **Confirmed** facts). The Qilin link rests on one case at medium confidence [1] (**Reported**).
- **Understated:** that exploitation ran a month before disclosure [1]; that KEV allowed three days and marks ransomware use Known [7]; and that R80.40, R81 and Spark R80.20.X are affected with no listed fix [2] (**Confirmed**; the weighting **Inferred**).

## MITRE mappings

This Part binds the verified record to MITRE ATT&CK v20.0 Enterprise, CWE, CAPEC and D3FEND. Names and tactics come from the library's `data/attack/technique_profiles.jsonl`, `software.jsonl`, `groups.jsonl`, `technique_to_d3fend.jsonl`, `d3fend_countermeasures.jsonl` and `data/weaknesses/` files [16] (**Demonstrated**). No source names ATT&CK technique ids; each row is this study's mapping (**Inferred**). No ATT&CK for ICS table applies: no source describes an industrial victim or effect.

### Groups, software and campaigns

| Object | Name | Bound as | Sources |
|---|---|---|---|
| [`S1242`](/mitre/software/S1242.md) | Qilin | The ransomware tied to the one confirmed post-compromise case, via an affiliate (vendor assessment, medium confidence) | [1] [9] [14] |
| [`G1050`](/mitre/groups/G1050.md) | Water Galura | Context only: ATT&CK's named operators of Qilin; no source ties them to this CVE | [14] [16] |

No campaign object is bound: the library's `campaigns.jsonl` holds no entry for this CVE or for Qilin [16] (**Demonstrated**).

### ATT&CK Enterprise techniques

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | IKEv1 authentication bypass on internet-facing gateways, from 7 May (advisory and KEV, 8 Jun) | [1] [2] [4] [7] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | Persistence, Initial Access | Remote access VPN connection set up without a valid password (CVE record, 8 Jun) | [4] |
| [`T1583.003`](/mitre/techniques/T1583-003.md) | Virtual Private Server | Resource Development | Dedicated VPS at three hosting providers, sometimes in the victim's region (vendor assessment, 8 Jun) | [1] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | Command and Control | Post-access ELF download attempts from actor infrastructure, overlapping Qilin Linux ransomware binaries (vendor assessment, 8 Jun) | [1] |

Fit notes (**Inferred**): T1133 fits because the bypass yields a working remote access VPN session. Valid Accounts (T1078) is not bound, because the record says the session opens without a valid password and does not say whose identity it carries. T1105 rests on download attempts; no source says a payload ran. Data Encrypted for Impact (T1486) is not bound: no source describes encryption in any victim. Tox use is stated as possible, so no communication technique is bound for it.

### CWE and CAPEC

| CWE | Name | Where it is assigned | Sources |
|---|---|---|---|
| CWE-287 | Improper Authentication | CVE-2026-50751 (Check Point, NVD, KEV) | [4] [5] [7] |
| CWE-295 | Improper Certificate Validation | CVE-2026-50752, the site-to-site companion (Check Point) | [3] [10] |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | CVE-2024-24919, the 2024 predecessor (KEV) | [7] |

| CAPEC | Name | Via | Where it meets the record |
|---|---|---|---|
| [CAPEC-115](/mitre/capec/CAPEC-115.md) | Authentication Bypass | CWE-287 | VPN session without a valid password [4] (**Inferred** fit) |
| [CAPEC-22](/mitre/capec/CAPEC-22.md) | Exploiting Trust in Client | CWE-287 | The gateway trusted a client-supplied value about how to check credentials [8] (**Inferred** fit) |
| [CAPEC-94](/mitre/capec/CAPEC-94.md) | Adversary in the Middle (AiTM) | CWE-287 in the library (CVE-2026-50752 carries CWE-295) | Interception of site-to-site tunnels in the companion flaw [3] (**Inferred** fit) |

The library relates CWE-287 to further CAPEC entries (for example CAPEC-114, CAPEC-151 and CAPEC-593) and CWE-295 to CAPEC-459 and CAPEC-475; none of those meets this record as closely [16] (**Demonstrated**). No source assigns a CAPEC id. See the [CWE Reference](/CWE_REFERENCE.md) and [CAPEC Reference](/CAPEC_REFERENCE.md).

### D3FEND countermeasures

| D3FEND countermeasure | Techniques the library maps it to (from this study) | Where it meets the record |
|---|---|---|
| [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) | T1190, T1105 | The IPS protection for the CVE, detection only [2] |
| [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) | T1190 | Blocking the vendor's listed addresses; UDP port filtering alone fails because TCP 443 works [2] [8] (**Inferred** fit) |
| [User Geolocation Logon Pattern Analysis](/mitre/d3fend/user-geolocation-logon-pattern-analysis.md) | T1190, T1105 | Weakened by in-region VPS [1] (**Inferred**) |
| [Session Termination](/mitre/d3fend/session-termination.md) | T1133 | Ending VPN sessions from unrecognized users found in the hunt [2] (**Inferred** fit) |
| [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) | T1105 | Blocking the ELF downloads [1] (**Inferred** fit) |

The library relates no D3FEND countermeasure to T1583.003 [16] (**Demonstrated**). The vendor's main controls correspond to [Software Update](/mitre/d3fend/software-update.md) (the hotfixes) and [Certificate-based Authentication](/mitre/d3fend/certificate-based-authentication.md) (mandatory machine certificates). The library does not relate either to these techniques [2] [16] (**Demonstrated** for the data check). See the [D3FEND Reference](/D3FEND_REFERENCE.md).

### Navigator layer

The study's techniques are saved as an ATT&CK Navigator layer pinned to ATT&CK v20, [`navigator/library-layers/check-point-vpn-cve-2026-50751.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/check-point-vpn-cve-2026-50751.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/check-point-vpn-cve-2026-50751.json)), listed on [the Navigator layers page](/navigator/index.md). Scores: 75 for behavior in Check Point's advisory, the CVE record or KEV; 50 for behavior from the vendor's actor profile. Each technique's comment names its source numbers.

## Cross-cutting themes

- **Deprecated protocols stay live.** Both June flaws sit in IKEv1, which the vendor calls deprecated [1] [3] [4] (**Confirmed**). Backward compatibility for older clients was one of the four conditions [2] (**Confirmed**).
- **Disclosure is not the start of the clock.** A month of exploitation came before the advisory [1] (**Confirmed**). Hunting windows should start at first exploitation, not at the patch date (**Inferred**).
- **Edge VPNs feed ransomware access.** KEV marks ransomware use Known for this CVE, for CVE-2024-24919 and for [PAN-OS CVE-2026-0257](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md) [7] (**Confirmed**). See the [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md) and [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md).
- **The client must not grade its own exam.** watchTowr's framing, a client deciding how it is checked, is a design lesson for any authentication protocol [8] (**Demonstrated**; the general lesson **Inferred**).
- **End of support is a security state.** Appliances past support were affected and some have no fix [2] (**Confirmed**).

## Sources

All sources were opened on 11 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Check Point blog, Security Advisory: Action Required: Active Exploitation of Check Point VPN Authentication Bypass (CVE-2026-50751), Lotem Finkelstein, 8 Jun 2026, indicators added to 11 Jun 2026 | [blog.checkpoint.com/security/check-point-releases-important-hotfix-...](https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/) | 2026-11-11 | Confirmed (attribution and counts Reported) |
| 2 | Check Point support article sk185033 (CVE-2026-50751), created 4 Jun 2026, last modified 24 Sep 2026 | [support.checkpoint.com/results/sk/sk185033](https://support.checkpoint.com/results/sk/sk185033) | 2026-11-11 | Confirmed |
| 3 | Check Point support article sk185035 (CVE-2026-50752), created 7 Jun 2026 | [support.checkpoint.com/results/sk/sk185035](https://support.checkpoint.com/results/sk/sk185035) | 2026-11-11 | Confirmed |
| 4 | CVE Program record CVE-2026-50751 (CNA Check Point, with CISA ADP) | [cveawg.mitre.org/api/cve/CVE-2026-50751](https://cveawg.mitre.org/api/cve/CVE-2026-50751) | 2026-11-11 | Confirmed |
| 5 | NVD, CVE-2026-50751, 2.0 API record | [services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-50751](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-50751) | 2026-11-11 | Confirmed |
| 6 | NVD, CVE-2026-50751 change history | [services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId=CVE-2026-50751](https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId=CVE-2026-50751) | 2026-11-11 | Confirmed |
| 7 | CISA, Known Exploited Vulnerabilities catalog JSON, catalog version 2026.11.10 (rows CVE-2026-50751, CVE-2024-24919, CVE-2026-0257, CVE-2026-16232, CVE-2026-85102, CVE-2026-93616); entry page for CVE-2026-50751 also opened | [cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 2026-11-11 | Confirmed |
| 8 | watchTowr Labs, Marking Your Own Homework: Check Point Remote Access VPN IKEv1 Authentication Bypass (CVE-2026-50751), 12 Jun 2026 | [labs.watchtowr.com/marking-your-own-homework-...](https://labs.watchtowr.com/marking-your-own-homework-check-point-remote-access-vpn-ikev1-authentication-bypass-cve-2026-50751/) | 2026-11-11 | Demonstrated |
| 9 | Check Point Research, 15th June Threat Intelligence Report, 15 Jun 2026 | [research.checkpoint.com/2026/15th-june-threat-intelligence-report/](https://research.checkpoint.com/2026/15th-june-threat-intelligence-report/) | 2026-11-11 | Reported |
| 10 | CVE Program record CVE-2026-50752 (CNA Check Point) | [cveawg.mitre.org/api/cve/CVE-2026-50752](https://cveawg.mitre.org/api/cve/CVE-2026-50752) | 2026-11-11 | Confirmed |
| 11 | Canadian Centre for Cyber Security, Check Point security advisory AV26-559, 8 Jun 2026, updated 9 Jun 2026 | [cyber.gc.ca/en/alerts-advisories/check-point-security-advisory-av26-559](https://www.cyber.gc.ca/en/alerts-advisories/check-point-security-advisory-av26-559) | 2026-11-11 | Confirmed |
| 12 | CERT-EU, Security Advisory 2026-012, 10 Sep 2026 | [cert.europa.eu/publications/security-advisories/2026-012/](https://cert.europa.eu/publications/security-advisories/2026-012/) | 2026-11-11 | Confirmed |
| 13 | The Hacker News, Qilin and INC ransomware groups exploit PAN-OS flaw, 20 Oct 2026 (reporting Unit 42) | [thehackernews.com/2026/10/qilin-and-inc-ransomware-groups-exploit.html](https://thehackernews.com/2026/10/qilin-and-inc-ransomware-groups-exploit.html) | 2026-11-11 | Reported |
| 14 | MITRE ATT&CK, Software S1242 Qilin | [attack.mitre.org/software/S1242](https://attack.mitre.org/software/S1242) | 2026-11-11 | Confirmed |
| 15 | Team Star Wolf Intelligence Hub feed (index only) | [teamstarwolf.github.io/intelligence-hub/data/feed.json](https://teamstarwolf.github.io/intelligence-hub/data/feed.json) | 2026-11-11 | Confirmed |
| 16 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl`, `software.jsonl`, `groups.jsonl`, `campaigns.jsonl`, `technique_to_d3fend.jsonl`, `d3fend_countermeasures.jsonl` (ATT&CK v20.0), and `data/weaknesses/cwe.jsonl` and `capec.jsonl` | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-11 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Threat Actors: Iran](/case-studies/THREAT_ACTORS_IRAN.md), [Healthcare Threat Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Ransomware Ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md), [The Year 2024 in Intrusions](/case-studies/CHRONICLE_2024.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [Timeline](/case-studies/TIMELINE.md)
- Other 2026 edge and remote-access studies: [The PAN-OS GlobalProtect authentication bypass](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md), [The FortiCloud SSO authentication bypass](/case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md), [The Cisco Catalyst SD-WAN authentication bypass](/case-studies/CISCO_SDWAN_CVE_2026_20127.md), [The Citrix NetScaler zero-days](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md), [The Ivanti Connect Secure zero-day chain](/case-studies/IVANTI_CONNECT_SECURE_2026.md), [The BeyondTrust Remote Support and PRA command injection](/case-studies/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Check Point](/platforms/check-point.md), [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)
- Software and groups: [S1242 Qilin](/mitre/software/S1242.md), [G1050 Water Galura](/mitre/groups/G1050.md)
- Techniques: [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1133 External Remote Services](/mitre/techniques/T1133.md), [T1583.003 Virtual Private Server](/mitre/techniques/T1583-003.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md)
- CAPEC: [CAPEC-115](/mitre/capec/CAPEC-115.md), [CAPEC-22](/mitre/capec/CAPEC-22.md), [CAPEC-94](/mitre/capec/CAPEC-94.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [check-point-vpn-cve-2026-50751.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/check-point-vpn-cve-2026-50751.json)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
- [All case studies](/case-studies/README.md)
