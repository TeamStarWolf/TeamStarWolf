# The Ivanti Connect Secure Zero-Day Chain of October 2026 (CVE-2026-104935, CVE-2026-111357, CVE-2026-118527): A Case Study

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md), [AI Threats in the Cybersecurity Industry](/case-studies/AI_THREATS_2026.md), [PHP2Shell and October 2026](/case-studies/PHP2SHELL_OCTOBER_2026.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md), [Edge Device Security](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Vulnerability Prioritization](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Teams that run Ivanti Connect Secure or another remote-access VPN appliance, vulnerability management leads, incident responders and threat intelligence analysts

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 20 min (4,536 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run Ivanti Connect Secure, you need the facts of the October 2026 zero-day chain and its three CVEs, or you want to decide how to patch, hunt and recover an edge appliance whose integrity check came back clean

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 5: the defender and vulnerability-management view](#part-5-the-defender-and-vulnerability-management-view), [MITRE mappings](#mitre-mappings)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The people on the hook here were the teams who run Ivanti Connect Secure (ICS), the remote-access VPN appliance that Shadowserver counted on more than 5,000 internet-facing hosts [19] [20] (**Reported**). In October 2026 they were asked to patch the same appliance twice in just over two weeks, and told that a clean integrity check might not mean a clean box [10] [12] (**Confirmed**).

Volexity found the chain on a customer appliance fully patched at 22.8R2.4; exploitation of that appliance began on 3 October 2026 [12] (**Confirmed**). Ivanti disclosed CVE-2026-104935 on 13 October as under limited exploitation [1] (**Confirmed**). CVE-2026-111357, the root escalation that completed the chain, was published by the MITRE CNA on 15 October, and its record describes exploitation in the wild in October 2026; CISA's SSVC enrichment marked exploitation active the same day [4] [7] (**Confirmed**). Ivanti's fix for it did not ship until 29 October [12], and CISA's Known Exploited Vulnerabilities (KEV) catalog gave two of the three CVEs a three-day deadline with forensic triage [9] (**Confirmed**).

### Key facts at a glance

| Field | Value |
|---|---|
| Product | Ivanti Connect Secure (ICS), branches 22.8, 25.1.1 and 25.1.2 [3] [10] [15] |
| CVEs | CVE-2026-104935, CVE-2026-111357, CVE-2026-118527; classes and scores in Part 2 [3] [4] [5] |
| First exploitation | 3 Oct 2026 per Volexity [12]; 1 Oct per Defused as quoted in the press [19] [21] (**Reported**) |
| Disclosure and fixes | 13 Oct: 25.1.1.2, 25.1.3.0/25.1.3.1, 22.8R2.5 [1] [18]; 29 Oct: 25.1.1.3 and 22.8R2.6 [5] [12] [22] |
| KEV | CVE-2026-104935 added 13 Oct, due 16 Oct; CVE-2026-111357 and CVE-2026-118527 added 30 Oct, due 2 Nov and 13 Nov [9] |
| Actor | UTA0576, a previously unknown group tracked by Volexity; low-confidence criminal motive; medium-confidence use of large language models [12] |
| Victims | One appliance described; no sector, geography or count published [12] |

### Key findings

- **The October 13 builds did not close the chain.** INCIBE-CERT states that 25.1.1.2 and 22.8R2.5 do not fix the two later CVEs [15] (**Confirmed**). For 16 days after public disclosure on 13 October, the privilege escalation was exploited and unpatched [12] (**Confirmed**).
- **There was no implant to find.** UTA0576 planted no web shell or backdoor, and Ivanti's Integrity Checker Tool missed the in-memory library patching [10] [12] (**Confirmed**).
- **The appliance was a doorway to the directory.** The actor took LDAP, LAPS and BitLocker secrets, sniffed credentials and sprayed passwords, which Volexity assesses with high confidence as preparation for lateral movement [12] (**Confirmed**).
- **The record disagrees with itself.** Version cutoffs, the CWE and the CVSS score differ across sources, and CVE-2026-118527 was KEV-listed on 30 October, four days before its CVE record was published on 3 November [3] [4] [5] [7] [9] [10] [23] (**Confirmed**).
- **This is not the 2024 Ivanti story again.** Unlike the China-nexus Cutting Edge campaign, which used web shells and custom malware, UTA0576 left no implant, and Volexity assesses, with low confidence, a criminal rather than espionage motive [12] [24] (**Inferred** comparison).

### Top recommendations

1. Run 25.1.1.3, 25.1.3.1 or 22.8R2.6 or later, and plan the move off 22.8 before 31 Jan 2027 [10] [15] (**Confirmed** as INCIBE-CERT's and CISA's guidance).
2. Treat any appliance on an affected build that was internet-exposed from 1 October 2026 until it reached 25.1.1.3, 25.1.3.1 or 22.8R2.6 as possibly compromised (**Inferred** from [12] [19]), and do not accept an Integrity Checker pass as proof of a clean device; use memory and network forensics [10] [12] (**Confirmed** as CISA's and Volexity's guidance).
3. Recover by CISA's sequence: factory reset and upgrade, then reset every password, certificate and API key [10] (**Confirmed** as CISA's guidance).
4. Rotate the directory secrets the appliance could reach: LDAP bind, LAPS and BitLocker (**Inferred** from what Volexity saw taken [12]).
5. Watch for large numbers of requests to the welcome.cgi endpoint, and for mismatches between the request path and the routing header Volexity names; alert on authentication failures from the appliance's internal interface [12] [21] (**Confirmed** as Volexity's guidance; the internal-interface point is **Reported**).

## Scope and method

This brief covers the three Connect Secure CVEs from the first observed exploitation through the KEV catalog of 10 November 2026. It does not repeat the October roundup in [PHP2Shell and October 2026](/case-studies/PHP2SHELL_OCTOBER_2026.md) or the China-nexus Ivanti campaigns of 2024 and 2025 in [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md) [25]. [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md) places this chain among the year's other edge-device events in one paragraph and links here as the home study. Tradecraft is described at advisory level: no request formats, paths beyond the endpoint Volexity names for detection, or exploit steps. All times are UTC.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: Ivanti's own posts, the CVE and NVD records, the CISA KEV catalog and alert, Volexity's report, and national CERT advisories |
| Reported | Known through journalism or a secondary relay of a primary, including Rapid7's relay of Ivanti's version table |
| Demonstrated | Shown by this study's own check of data (the library's ATT&CK, CWE, CAPEC and D3FEND files) |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

Ivanti's own advisory could not be opened, so its content is known through CISA, the CVE records, NVD, the national CERTs and Rapid7.

## Part 1: what happened

| Date (2026) | Event | Sources | Grade |
|---|---|---|---|
| July | A portion of the CVE-2026-104935 flaw is patched in the 25.1.3.0 release | [18] | Reported |
| 30 Sep to 7 Oct | An attacker virtual private server runs an OpenVPN server | [12] | Confirmed |
| 1 Oct | Defused says it first saw the activity on public honeypots and in customer instances | [19] [21] | Reported |
| 3 Oct | Exploitation of the victim appliance, ICS 22.8R2.4 (Build 19097), begins | [12] | Confirmed |
| 5 to 10 Oct | Volexity investigates at a Network Security Monitoring customer and shares indicators with its customers on 10 Oct | [12] | Confirmed |
| 13 Oct, 14:33 to 16:17 | Ivanti discloses a Connect Secure flaw under limited exploitation; CVE-2026-104935 published by Ivanti as CNA, then by NVD | [1] [3] [6] | Confirmed |
| 13 Oct | KEV adds CVE-2026-104935, due 16 Oct; CISA alert issued; Volexity report and Canada's AV26-1035 published; Rapid7 urges emergency patching | [9] [10] [12] [14] [18] | Confirmed (Rapid7 Reported) |
| 14 Oct | INCIBE-CERT publishes INCIBE-2026-737 | [15] | Confirmed |
| 15 Oct | The MITRE CNA publishes CVE-2026-111357, whose record describes exploitation in the wild in October 2026; CISA's SSVC enrichment marks exploitation active the same day. No vendor fix exists yet | [4] [7] | Confirmed |
| 20 Oct | Singapore's CSA issues AL-2026-147 | [17] | Confirmed |
| 29 Oct | Ivanti ships 25.1.1.3 and 22.8R2.6, fixing CVE-2026-111357 and CVE-2026-118527, and updates its advisory | [5] [12] [20] [22] | Confirmed (advisory update day Reported) |
| 30 Oct | KEV adds CVE-2026-111357 (due 2 Nov) and CVE-2026-118527 (due 13 Nov); CISA revises its alert; Canada issues Update 2 | [9] [10] [14] | Confirmed |
| 2 Nov | HKCERT bulletin rates the risk High | [16] | Confirmed |
| 3 Nov | CVE-2026-118527 record published; INCIBE-CERT updates its advisory | [5] [8] [15] | Confirmed |
| 10 Nov | Ivanti's November Security Update does not mention Connect Secure | [2] | Confirmed |

### Discrepancies in the record

- **Affected versions.** CISA's revised alert lists 22.8R2.5 and prior and 25.1.1.2 and prior; the CVE-2026-104935 record lists 22.8R2.5 as unaffected; the CVE-2026-111357 record lists only 22.8R2.4; NVD's CPEs run to before 25.1.1.3 [3] [4] [7] [10] (**Confirmed**). Read together, the 13 October builds closed the bypass and code execution but not the full chain (**Inferred**).
- **Which weakness.** The CVE-2026-111357 record and NVD give CWE-829; the KEV entry gives CWE-306, CWE-862 and CWE-345 and names it "Missing Authentication for Critical Function" [4] [7] [9] (**Confirmed**).
- **Which score.** MITRE's CVSS for CVE-2026-111357 is 7.0; the press cites 8.8 [7] [23] (**Confirmed** for 7.0; 8.8 **Reported**).
- **KEV before CVE.** CVE-2026-118527 was added to KEV on 30 October, four days before its CVE record was published [5] [9] (**Confirmed**).
- **Start date.** Volexity gives 3 October; the 1 October date rests on Defused telemetry that was not opened [12] [19] [21] (**Reported** for 1 October).

## Part 2: the technical record

| CVE | CNA, published | Weakness and class | CVSS 3.1 | Fixed in | CISA SSVC |
|---|---|---|---|---|---|
| CVE-2026-104935 | Ivanti, 13 Oct | CWE-290, authentication bypass by spoofing; remote unauthenticated command execution | 8.6, AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L | 25.1.1.2, 25.1.3.0, 25.1.3.1, 22.8R2.5; 22.7R2.14 and prior not impacted | Active, automatable, total [3] [6] |
| CVE-2026-111357 | MITRE, 15 Oct | CWE-829; privilege escalation to root via the dsinvoked broker trusting DSCache configuration data | 7.0, AV:L/AC:H/PR:L | 25.1.1.3, 22.8R2.6 | Active, not automatable, total [4] [7] |
| CVE-2026-118527 | Ivanti, 3 Nov | CWE-340, predictable filenames; authenticated upload of attacker-controlled content to a known location | 4.3 | 25.1.1.3, 22.8R2.6 | Active, not automatable, partial [5] [8] |

Sources: the CVE records and NVD [3] to [8], fixed versions for CVE-2026-104935 as Rapid7 relays Ivanti's table [18] (**Reported**) and for the later two from the CVE-2026-118527 record and INCIBE-CERT [5] [15] (**Confirmed**).

**The chain, at advisory level.** Volexity describes three links [12] (**Confirmed**):

1. A request-routing authentication bypass that reaches protected CGI handlers.
2. A file write in an upload handler, combined with a race condition, that yields code execution. Ivanti tracks the bypass and the code execution together as CVE-2026-104935.
3. Privilege escalation to root through the dsinvoked broker trusting DSCache configuration data, now CVE-2026-111357.

The upload handler's predictable-path element matches the CVE-2026-118527 description, but Volexity's post never names that CVE; the mapping is ours (**Inferred**). CISA's KEV entries for both later CVEs say each can be chained with the other two [9] (**Confirmed**).

**What the actor did on the box.** With root, UTA0576 extracted stored LDAP credentials, ran LDAP queries for LAPS passwords and BitLocker recovery keys, used a custom tool able to Kerberoast (Volexity notes the Kerberoast function was not used), sprayed passwords, ran a renamed packet-capture tool that harvested LDAP and HTTP Basic credentials and NTLM hashes, and reviewed logs for valid usernames [12] (**Confirmed**). Volexity reports no lateral movement: the operation was detected and disrupted before the actor's objectives could be determined, and Volexity assesses with high confidence that the activity was preparation for lateral movement [12] (**Confirmed**).

**Why it was hard to see.** Commands, results and data moved through the exploit chain's own HTTPS requests and responses, with no separate command channel [12] (**Confirmed**). The actor patched library code only in memory, restored configuration afterward, and tampered with the Ivanti debug log and the Linux audit log; Volexity rebuilt the chain and found the sniffer through memory and core-dump analysis [12] (**Confirmed**). Rapid7 said at disclosure that reliable indicators were not yet available [18] (**Reported**); Volexity later published one exploitation IP and YARA rules [13] (**Confirmed**).

## Part 3: who and why

Volexity tracks the actor as UTA0576, a previously unknown group. It assesses with low confidence that the motive is criminal rather than espionage, and with medium confidence that the actor uses large language models for exploit development and post-exploitation work [12] (**Confirmed** as Volexity's assessment). None of the government advisories opened for this study names an actor; the CISA alert names no actor, victim or agency [10] [14] [15] [16] [17] (**Confirmed**).

The only earlier activity Volexity relates this to is UTA0533's similar reading of packet captures on SonicWall SMA; it does not mention UTA0178 or UNC5221 [12] (**Confirmed**). ATT&CK has no group object for UTA0576 [24] (**Demonstrated**).

The library's [Cutting Edge](/mitre/campaigns/C0029.md) campaign page records the December 2023 to February 2024 ICS zero-day campaign by suspected China-nexus UNC5221/UTA0178 and UNC5325, with web shells and custom malware [24] (**Confirmed**), and [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md) covers UNC5221's exploitation of CVE-2025-0282 from mid-December 2024 [25] (**Confirmed**). With no implant and only a low-confidence criminal assessment, the 2026 chain should not be attached to UNC5221 on the strength of the product alone (**Inferred**). Volexity's LLM assessment concerns how the actor built and ran its tooling, not an autonomous attack [12] (**Inferred** from Volexity's wording).

## Part 4: impact and response

**Victims.** Volexity describes one compromised appliance, gives no victim count, sector or geography, and says the operation was detected and disrupted, so the actor's ultimate objectives could not be determined [12] (**Confirmed**). Ivanti said at disclosure it was working directly with affected organizations [1] (**Confirmed**). Shadowserver's counts of over 5,500 exposed instances at disclosure and over 5,000 in early November come via BleepingComputer [19] [20] (**Reported**; the dashboard was not opened).

**The vendor.** Ivanti's 13 October post told customers to upgrade immediately and run the Integrity Checker Tool [1] (**Confirmed**). Ivanti later said the CVE-2026-104935 fix was already in QA when exploitation was found and that it chose not to delay it once the privilege escalation was discovered [20] [23] (**Reported**). It said limited indicators of compromise were available when it shipped the 29 October builds [22] (**Reported**).

**CISA and KEV.** All three KEV entries cite Binding Operational Directive (BOD) 26-04 and CISA's Forensics Triage Requirements [9] (**Confirmed**). BOD 26-04, issued 10 June 2026, requires federal civilian agencies to remediate or mitigate within three days where a KEV timeline includes forensic triage, and to assess whether the asset is compromised [11] (**Confirmed**). The two forensic-triage entries got exactly three days; CVE-2026-118527, without forensic triage, got 14 [9] (**Inferred** from the dates). KEV marks known ransomware use as Unknown for all three [9] (**Confirmed**).

| KEV context (catalog 2026.11.10) | Value |
|---|---|
| Ivanti entries | 38, of which 12 flagged Known ransomware use |
| Connect Secure and Pulse Connect Secure entries | 17 since 3 Nov 2021 (16 under vendor Ivanti, 1 under Pulse Secure), including the 2026 three |
| Earlier ICS entries (2024 and 2025) flagged Known | CVE-2023-46805, CVE-2024-21887, CVE-2024-21893, CVE-2025-0282, CVE-2025-22457 |
| The 2026 three | Unknown |

Source: computed from the KEV catalog [9] (**Confirmed**).

**National CERTs.** Canada's AV26-1035 (Update 2, 30 October) lists ICS prior to 25.1.1.3, 25.1.3.1 and 22.8R2.6 [14]; INCIBE-CERT says all three are exploited [15]; HKCERT (2 November) reports the two later CVEs exploited in the wild [16]; and Singapore's CSA (20 October) urged immediate updates for CVE-2026-104935 [17] (**Confirmed**).

## Part 5: the defender and vulnerability-management view

A scanner that read version strings on 14 October would have marked a 22.8R2.5 appliance as fixed while the root escalation was still open (**Inferred** from [4] [15]). The patch level that closes the known chain is 25.1.1.3, 25.1.3.1 or 22.8R2.6 [14] [15] (**Confirmed**).

| Control | Where it meets the record |
|---|---|
| Patch to the full-chain builds, then leave 22.8 | 25.1.1.2 and 22.8R2.5 do not fix the later CVEs [15]; 22.8 end of life 31 Jan 2027 [10] |
| Use memory and network forensics, not an integrity check alone | In-memory patching defeated the Integrity Checker Tool; memory forensics found the chain and the sniffer [10] [12] |
| Monitor for large numbers of welcome.cgi requests, and separately for request-path and routing-header mismatches | Volexity's two detection items [12] |
| Alert on auth failures from the appliance's internal interface | Volexity's Sean Koessel, as quoted [21] (**Reported**) |
| Factory reset, then rotate every credential and certificate | CISA's recovery sequence [10] |
| Rotate directory secrets the appliance could read | LDAP bind, LAPS and BitLocker (**Inferred** from [12]) |
| Use SSVC and KEV forensic-triage flags to order work | SSVC marked CVE-2026-104935 automatable with total impact [6]; KEV forensic triage drove three-day deadlines [9] [11] |

### What is overstated and what is understated

- **Overstated:** read alone, the CISA alert's grouping can suggest all three CVEs are internet entry points, but only CVE-2026-104935 is remote and unauthenticated on its record; CVE-2026-111357 is local and CVE-2026-118527 needs authentication [3] [4] [5] [10] (**Inferred**). The 1 October start date rests on unopened telemetry [21] (**Reported**). Any reading of this chain as AI-built goes further than Volexity's medium-confidence assessment that the actor used LLMs [12] (**Inferred**).
- **Understated:** the chain was first seen on a fully patched appliance [12]; the privilege escalation stayed unpatched for 16 days after disclosure while exploited [12]; the 13 October builds did not close the chain [15]; and an Integrity Checker pass was a false clean [12] (**Confirmed**). The victim count is not known, and one described appliance is a floor, not a total (**Inferred**).

## MITRE mappings

This Part binds the verified record to MITRE ATT&CK v20.0 Enterprise, CWE, CAPEC and D3FEND. Names and tactics come from the library's `data/attack/technique_profiles.jsonl`, `campaigns.jsonl`, `technique_to_d3fend.jsonl` and `data/weaknesses/` files [24] (**Demonstrated**). Revoked ids were resolved through `data/attack/superseded_by.jsonl` [24] (**Demonstrated**). No source names ATT&CK ids for this activity, so every id below is this study's mapping of a described behavior (**Inferred**). No industrial system is involved, so no ATT&CK for ICS techniques apply.

### Groups, software and campaigns

ATT&CK has no group object for UTA0576 and no software object for its tooling [24] (**Demonstrated**), so none is bound. One object is related, not bound:

| Object | ATT&CK id | Relationship to this record |
|---|---|---|
| Cutting Edge | [C0029](/mitre/campaigns/C0029.md) | The December 2023 to February 2024 ICS zero-day campaign by suspected China-nexus actors [24]. Lineage only; Volexity ties UTA0576 to no earlier Ivanti actor [12] |

### ATT&CK Enterprise techniques

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T1587.004`](/mitre/techniques/T1587-004.md) | Exploits | Resource Development | Zero-day chain used by UTA0576; Volexity assesses with medium confidence that LLMs were used for exploit development (13 Oct) | [12] |
| [`T1588.007`](/mitre/techniques/T1588-007.md) | Artificial Intelligence | Resource Development | Medium-confidence use of LLMs for exploit development and post-exploitation (Volexity, 13 Oct) | [12] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | Auth bypass and code execution against the appliance from 3 Oct | [3] [12] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | Privilege Escalation | Root via dsinvoked and DSCache, CVE-2026-111357 (15 Oct record) | [4] [12] |
| [`T1601.001`](/mitre/techniques/T1601-001.md) | Patch System Image | Defense Impairment | Library code patched only in memory during exploitation and then restored, which the Integrity Checker could not see (Volexity, 13 Oct) | [12] |
| [`T1070`](/mitre/techniques/T1070.md) | Indicator Removal | Stealth | Ivanti debug log tampered with (Volexity, 13 Oct) | [12] |
| [`T1685.006`](/mitre/techniques/T1685-006.md) | Clear Linux or Mac System Logs | Defense Impairment | Recent entries selectively removed from the Linux audit log (Volexity, 13 Oct) | [12] |
| [`T1036.003`](/mitre/techniques/T1036-003.md) | Rename Legitimate Utilities | Stealth | Renamed packet-capture tool (Volexity, 13 Oct) | [12] |
| [`T1552`](/mitre/techniques/T1552.md) | Unsecured Credentials | Credential Access | Stored LDAP credentials extracted; LDAP queries for LAPS passwords and BitLocker recovery keys (Volexity, 13 Oct) | [12] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | LDAP and HTTP Basic credentials and NTLM hashes harvested from traffic (Volexity, 13 Oct) | [12] |
| [`T1110.003`](/mitre/techniques/T1110-003.md) | Password Spraying | Credential Access | Spraying against directory accounts (Volexity, 13 Oct) | [12] |
| [`T1654`](/mitre/techniques/T1654.md) | Log Enumeration | Discovery | Logs reviewed for valid usernames (Volexity, 13 Oct) | [12] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Web Protocols | Command and Control | Commands and results carried in the exploit's HTTPS requests (Volexity, 13 Oct) | [12] |
| [`T1041`](/mitre/techniques/T1041.md) | Exfiltration Over C2 Channel | Exfiltration | Data returned in exploit responses, no separate channel (Volexity, 13 Oct); CISA cites data exfiltration (30 Oct) | [10] [12] |

Fit notes (**Inferred**): T1601.001 is written for network-device operating systems and covers in-memory changes at runtime; the ICS appliance is such a device, so the fit is close but not exact. T1552 is bound at the parent level because the sources do not say where the stored LDAP credentials lived. No technique is bound for the upload-handler file write; it is part of the T1190 exploitation. No technique is bound for Kerberoasting: Volexity says the tool's Kerberoast function was not used [12].

### CWE and CAPEC

| CWE | Name | Where it is assigned | Sources |
|---|---|---|---|
| CWE-290 | Authentication Bypass by Spoofing | CVE-2026-104935 record, NVD and KEV | [3] [6] [9] |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | CVE-2026-111357 record and NVD | [4] [7] |
| CWE-306 | Missing Authentication for Critical Functionality | CVE-2026-111357 KEV entry | [9] |
| CWE-862 | Missing Authorization | CVE-2026-111357 KEV entry | [9] |
| CWE-345 | Insufficient Verification of Data Authenticity | CVE-2026-111357 KEV entry | [9] |
| CWE-340 | Generation of Predictable Numbers or Identifiers | CVE-2026-118527 record, NVD and KEV | [5] [8] [9] |

CAPEC entries the library relates to these CWEs or techniques that meet the record [24]:

| CAPEC | Name | Via | Where it meets the record |
|---|---|---|---|
| [CAPEC-22](/mitre/capec/CAPEC-22.md) | Exploiting Trust in Client | CWE-290 | A request-routing bypass, with Volexity's header/path mismatch detection [12] (**Inferred**) |
| [CAPEC-565](/mitre/capec/CAPEC-565.md) | Password Spraying | T1110.003 | Spraying against directory accounts [12] |
| [CAPEC-158](/mitre/capec/CAPEC-158.md) | Sniffing Network Traffic | T1040 | The renamed packet-capture tool [12] |
| [CAPEC-268](/mitre/capec/CAPEC-268.md) | Audit Log Manipulation | T1070 | Debug and audit log tampering [12] |

The library relates no CAPEC to CWE-340, and the race condition Volexity describes has no CWE in any record, so no race-condition CAPEC is bound [8] [24] (**Demonstrated**). See the [CWE Reference](/CWE_REFERENCE.md) and [CAPEC Reference](/CAPEC_REFERENCE.md).

### D3FEND countermeasures

| D3FEND countermeasure | Techniques the library maps it to (from this study) | Where it meets the record |
|---|---|---|
| [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) | T1190 | Volexity's welcome.cgi request-volume monitoring [12] |
| [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md) | T1190, T1071.001, T1041, T1110.003 | Request-path and routing-header mismatch detection [12] |
| [Process Code Segment Verification](/mitre/d3fend/process-code-segment-verification.md) | T1068 | The in-memory code changes only memory forensics found [12] (**Inferred** fit) |
| [Credential Rotation](/mitre/d3fend/credential-rotation.md), with [Credential Revocation](/mitre/d3fend/credential-revocation.md) and [Reissue Credential](/mitre/d3fend/reissue-credential.md) | T1552, T1110.003 | CISA's reset of all passwords, revocation and reissue of certificates, and API key reset [10] |
| [Credential Compromise Scope Analysis](/mitre/d3fend/credential-compromise-scope-analysis.md) | T1552, T1110.003 | Scoping which LDAP, LAPS and BitLocker secrets were read [12] (**Inferred**) |

CISA's factory reset and configuration restore correspond to [Restore Software](/mitre/d3fend/restore-software.md) and [Restore Configuration](/mitre/d3fend/restore-configuration.md), which the library does not relate to these techniques [10] [24] (**Inferred**). See the [D3FEND Reference](/D3FEND_REFERENCE.md).

### Navigator layer

The study's techniques are saved as an ATT&CK Navigator layer, [`navigator/library-layers/ivanti-connect-secure-2026.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/ivanti-connect-secure-2026.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/ivanti-connect-secure-2026.json)), listed on [the Navigator layers page](/navigator/index.md). It is pinned to ATT&CK v20, domain `enterprise-attack`. A score of 75 means a CVE record or government advisory describes the behavior; 50 means Volexity's report describes it; 25 means a capability, an assessment or a close-but-inexact fit rather than an observed act (T1587.004, T1588.007, T1601.001). Each comment names the event and the source numbers.

## Cross-cutting themes

- **Edge appliances keep failing the same way.** Seventeen Connect Secure and Pulse Connect Secure KEV entries since November 2021 [9] say the VPN edge is a standing exposure, not an incident (**Inferred**). See [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md) for the 2024 and 2025 rounds.
- **Patch first, fix second.** Ivanti shipped the bypass fix it had, then the escalation fix 16 days later [12] [23]. The trade-off is defensible, but it leaves a window that version-based tools hide (**Inferred**).
- **Integrity checks are not forensics.** The vendor tool gave a false clean [10] [12] (**Confirmed**); recovery means a factory reset and full credential rotation, not a passing check (**Inferred**).
- **The record is a moving target.** Two CNAs, three CWE sets, two scores and a KEV entry that predates its CVE record's publication [4] [5] [7] [9] [23]. Programs that key on one feed will see a different chain (**Inferred**).
- **One assessment, not a trend.** Volexity's medium-confidence LLM finding [12] is a single data point; whether AI lowers the cost of zero-days is not established by this record (**Inferred**). See [AI Threats in the Cybersecurity Industry](/case-studies/AI_THREATS_2026.md).

## Sources

All sources were opened on 11 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Ivanti, October 2026 Security Update, 13 Oct 2026 14:33 UTC | [ivanti.com/blog/october-2026-security-update](https://www.ivanti.com/blog/october-2026-security-update) | 2026-11-11 | Confirmed |
| 2 | Ivanti, November 2026 Security Update, 10 Nov 2026 | [ivanti.com/blog/november-2026-security-update](https://www.ivanti.com/blog/november-2026-security-update) | 2026-11-11 | Confirmed |
| 3 | CVE Program record CVE-2026-104935 (CNA Ivanti) | [cveawg.mitre.org/api/cve/CVE-2026-104935](https://cveawg.mitre.org/api/cve/CVE-2026-104935) | 2026-11-11 | Confirmed |
| 4 | CVE Program record CVE-2026-111357 (CNA MITRE) | [cveawg.mitre.org/api/cve/CVE-2026-111357](https://cveawg.mitre.org/api/cve/CVE-2026-111357) | 2026-11-11 | Confirmed |
| 5 | CVE Program record CVE-2026-118527 (CNA Ivanti) | [cveawg.mitre.org/api/cve/CVE-2026-118527](https://cveawg.mitre.org/api/cve/CVE-2026-118527) | 2026-11-11 | Confirmed |
| 6 | NVD, CVE-2026-104935 | [services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-104935](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-104935) | 2026-11-11 | Confirmed |
| 7 | NVD, CVE-2026-111357 | [services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-111357](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-111357) | 2026-11-11 | Confirmed |
| 8 | NVD, CVE-2026-118527 | [services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-118527](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-118527) | 2026-11-11 | Confirmed |
| 9 | CISA, Known Exploited Vulnerabilities catalog JSON, version 2026.11.10 | [cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 2026-11-11 | Confirmed |
| 10 | CISA, CISA Urges Patching Newly Exploited Vulnerabilities in Ivanti Connect Secure, 13 Oct 2026, revised 30 Oct 2026 (the singular-slug URL serves the same alert) | [cisa.gov/news-events/alerts/2026/10/13/...](https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-urges-patching-newly-exploited-vulnerabilities-ivanti-connect-secure) | 2026-11-11 | Confirmed |
| 11 | CISA, BOD 26-04, Prioritizing Security Updates Based on Risk, 10 Jun 2026 | [cisa.gov/news-events/directives/bod-26-04-...](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) | 2026-11-11 | Confirmed |
| 12 | Volexity, A Series of Unauthenticated Events: Chained Exploitation of Ivanti Connect Secure Zero-Days, 13 Oct 2026, with an undated update note recording Ivanti's 29 Oct 2026 patch | [volexity.com/blog/2026/10/13/...](https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/) | 2026-11-11 | Confirmed |
| 13 | Volexity, threat-intel repository, 2026-10-13 Ivanti (IOCs and YARA) | [github.com/volexity/threat-intel/.../2026-10-13 Ivanti](https://github.com/volexity/threat-intel/tree/main/2026/2026-10-13%20Ivanti) | 2026-11-11 | Confirmed |
| 14 | Canadian Centre for Cyber Security, Ivanti security advisory AV26-1035, 13 Oct 2026, Update 2 30 Oct 2026 | [cyber.gc.ca/en/alerts-advisories/ivanti-security-advisory-av26-1035](https://cyber.gc.ca/en/alerts-advisories/ivanti-security-advisory-av26-1035) | 2026-11-11 | Confirmed |
| 15 | INCIBE-CERT, INCIBE-2026-737, Multiple vulnerabilities in Ivanti products, 14 Oct 2026, updated 3 Nov 2026 | [incibe.es/incibe-cert/alerta-temprana/avisos/...](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-productos-de-ivanti-4) | 2026-11-11 | Confirmed |
| 16 | HKCERT, Ivanti Connect Secure Multiple Vulnerabilities, 2 Nov 2026 | [hkcert.org/security-bulletin/...](https://www.hkcert.org/security-bulletin/ivanti-connect-secure-multiple-vulnerabilities_20261102) | 2026-11-11 | Confirmed |
| 17 | Cyber Security Agency of Singapore, AL-2026-147, 20 Oct 2026 | [csa.gov.sg/alerts-and-advisories/alerts/al-2026-147/](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-147/) | 2026-11-11 | Confirmed |
| 18 | Rapid7, ETR: Ivanti Connect Secure zero-day exploited in the wild (CVE-2026-104935), 13 Oct 2026 | [rapid7.com/blog/post/etr-ivanti-connect-secure-...](https://www.rapid7.com/blog/post/etr-ivanti-connect-secure-zero-day-exploited-in-the-wild-cve-2026-104935/) | 2026-11-11 | Reported |
| 19 | BleepingComputer, report on Ivanti's Connect Secure zero-day warning, 13 Oct 2026 | [bleepingcomputer.com/news/security/ivanti-warns-of-...](https://bleepingcomputer.com/news/security/ivanti-warns-of-connect-secure-zero-day-exploited-in-attacks) | 2026-11-11 | Reported |
| 20 | BleepingComputer, report on Ivanti patching two more chained zero-days, 2 Nov 2026 | [bleepingcomputer.com/news/security/ivanti-patches-two-more-...](https://bleepingcomputer.com/news/security/ivanti-patches-two-more-connect-secure-zero-days-chained-in-attacks) | 2026-11-11 | Reported |
| 21 | Cybersecurity Dive, report on chained Ivanti Connect Secure exploitation, 14 Oct 2026 | [cybersecuritydive.com/news/hacker-ivanti-connect-secure-chained-exploitation/832983/](https://www.cybersecuritydive.com/news/hacker-ivanti-connect-secure-chained-exploitation/832983/) | 2026-11-11 | Reported |
| 22 | The Stack, report on Ivanti's 29 Oct patches, 29 Oct 2026 | [thestack.technology/ivanti-patches-two-more-cves-...](https://www.thestack.technology/ivanti-patches-two-more-cves-amid-highly-unusual-connect-secure-exploitation/) | 2026-11-11 | Reported |
| 23 | The Hacker News, report on attackers chaining three Ivanti Connect Secure flaws, 31 Oct 2026 | [thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html](https://thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html) | 2026-11-11 | Reported |
| 24 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl`, `campaigns.jsonl`, `groups.jsonl`, `technique_to_d3fend.jsonl` (ATT&CK v20.0), `data/weaknesses/cwe.jsonl` and `capec.jsonl`, and the `mitre/` page tree including C0029 | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-11 | Demonstrated |
| 25 | TeamStarWolf, Threat Actors: China | [/case-studies/THREAT_ACTORS_CHINA.md](/case-studies/THREAT_ACTORS_CHINA.md) | 2026-11-11 | Confirmed |

Not opened, so not cited as sources: Ivanti's security advisory on its support hub (rendered only an error shell), CIS advisory 2026-115 (HTTP 404), Dark Reading's coverage (HTTP 403; its account of how Ivanti found the flaw is not checked), and the Defused and Shadowserver primaries behind the press figures.

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md), [AI Threats in the Cybersecurity Industry](/case-studies/AI_THREATS_2026.md), [PHP2Shell and October 2026](/case-studies/PHP2SHELL_OCTOBER_2026.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [Timeline](/case-studies/TIMELINE.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)
- Campaigns: [C0029 Cutting Edge](/mitre/campaigns/C0029.md)
- Techniques: [T1587.004 Exploits](/mitre/techniques/T1587-004.md), [T1588.007 Artificial Intelligence](/mitre/techniques/T1588-007.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1601.001 Patch System Image](/mitre/techniques/T1601-001.md), [T1070 Indicator Removal](/mitre/techniques/T1070.md), [T1685.006 Clear Linux or Mac System Logs](/mitre/techniques/T1685-006.md), [T1036.003 Rename Legitimate Utilities](/mitre/techniques/T1036-003.md), [T1552 Unsecured Credentials](/mitre/techniques/T1552.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1110.003 Password Spraying](/mitre/techniques/T1110-003.md), [T1654 Log Enumeration](/mitre/techniques/T1654.md), [T1071.001 Web Protocols](/mitre/techniques/T1071-001.md), [T1041 Exfiltration Over C2 Channel](/mitre/techniques/T1041.md)
- CAPEC: [CAPEC-22](/mitre/capec/CAPEC-22.md), [CAPEC-565](/mitre/capec/CAPEC-565.md), [CAPEC-158](/mitre/capec/CAPEC-158.md), [CAPEC-268](/mitre/capec/CAPEC-268.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [ivanti-connect-secure-2026.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/ivanti-connect-secure-2026.json)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
- [All case studies](/case-studies/README.md)
