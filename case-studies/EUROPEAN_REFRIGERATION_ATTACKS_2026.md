# Refrigeration-Controller Attacks on European Supermarkets and Blood Services, 2026: A Case Study

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [ICS Attacks and Advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [Threat Actors](/THREAT_ACTORS.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md), [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

OT and facilities security engineers, vulnerability management leads, retail and healthcare defenders, and the contractors who run refrigeration supervision

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 22 min (4,945 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need the facts of the 2026 attacks on supermarket and blood-service refrigeration controllers in Europe, you run or contract out Danfoss, Copeland or Dixell supervisors, or you want to know what France's attribution covers and what it does not

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: what happened](#part-1-what-happened), [Part 5: the defender and vulnerability-management view](#part-5-the-defender-and-vulnerability-management-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[ICS Attacks and Advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The people hit were supermarket staff, small butchers and food plants, and the contractors who look after their cold rooms [2] [22]. Overnight on 11 to 12 October 2026, someone reached the remote controllers of refrigeration installations at about 700 French retail sites and set their defrost parameters to high temperatures. Food spoiled and at least 15 fires started [2] (**Confirmed**). A second wave on the night of 1 to 2 November reached stores in Belgium, Luxembourg, Sweden, Ireland, Estonia, the Netherlands and the UK [22] [29] [30] (**Reported**). It also reached three sites of France's national blood service (EFS), where alarms caught the change before any blood product was lost [23] (**Reported**).

On 9 November France attributed the October wave to the Shahid Kaveh unit of Iran's IRGC [3] [2] (**Confirmed**). Its statements do not cover the November wave or EFS [3] (**Inferred**), and Infosecurity reports the attribution expressly excludes EFS [28] (**Reported**). No government has named a CVE for initial access, and none of these controllers' CVEs is in CISA's Known Exploited Vulnerabilities (KEV) catalog [10] (**Confirmed**). The record points to exposed, often end-of-life controllers and, at one examined site, default credentials [1] [4] [15] [25] (**Inferred**).

### Key facts at a glance

| Field | Value |
|---|---|
| Waves | 11 to 12 October 2026 (France); 1 to 2 November 2026 (several EU states and the UK) [2] [13] [30] |
| Equipment CERT-FR names | Danfoss AK-SM and AK-SC series; Copeland and Dixell xweb [1] |
| French scale | About 700 sites, at least 15 fire starts, food losses of several tens of millions of euros [2] [3] |
| Blood service | Three EFS sites; no loss of blood products, per EFS [23] [31] |
| Attribution | October wave: Shahid Kaveh unit, IRGC (France, 9 Nov 2026) [3] |
| CVE used for access | None named by any primary; Unit 42 calls initial access unconfirmed [18] |
| KEV | No Danfoss, Copeland or Dixell CVE at catalogVersion 2026.11.10 [10] |

### Key findings

- **The effect came from changing settings, not from new code.** Sekoia reports altered setpoints, defrost cycles and alarm thresholds, with no code execution needed [19] (**Reported**).
- **Much of the equipment was out of support.** Danfoss named the AK-SM 800 (support ended May 2021) and AK-SC 355 (discontinued 2016) [21] (**Reported**); Copeland's flaw is in an end-of-life XWEB EVO line [4] (**Confirmed**).
- **Resetting alone does not close this.** A factory reset alone removes the intruder's persistence, but an end-of-life unit left on the internet will almost certainly be compromised again [1] (**Confirmed**).
- **Alarms and people limited the harm.** EFS monitoring caught the change [23] [31] (**Reported**). In the UK, Langridge Organic stopped an attack by physically disconnecting a fridge [30] (**Reported**).
- **Attribution is narrower than the headlines.** France attributes the October wave only, and no government has attributed the November wave or EFS [3] [28] (**Inferred**; the EFS exclusion is **Reported** [28]). The pro-Russian claims are unverified [18] (**Reported**).

### Top recommendations

1. Take every refrigeration controller and supervisor off the public internet. Restore remote access only through a VPN or protected network [1] [15].
2. Check defrost ranges, setpoints, alarm settings and user accounts [1] [4] [15].
3. Retire or isolate end-of-life units; a reset is not a fix [1] [4].
4. Change default passwords and set Danfoss units to security level Strict [1] [15].
5. Keep independent temperature alarms, setpoint limits with deviation alerts and a practiced manual fallback [12] [34].

## Scope and method

This brief covers the October and November 2026 attacks on commercial refrigeration controllers in Europe and the CVE, vendor and government records around them. It does not repeat the earlier Iranian-linked ICS record; see [ICS Attacks and Advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) [37]. [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md) gives these attacks a paragraph in the year's record; this brief is their home study. Tradecraft is described at advisory level only.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: a government advisory or statement, a vendor bulletin, a CVE, NVD or KEV record, or the MITRE page itself |
| Reported | Known through journalism or a secondary account, or a researcher's judgement or claim (attribution, assessment) that the study cannot check against primary evidence |
| Demonstrated | Shown in a researcher's own work: vulnerability research, honeypot telemetry or scan data |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

## Part 1: what happened

| Date | Event | Sources | Grade |
|---|---|---|---|
| May to Aug 2025 | Danfoss AK-SM 8xxA flaws: CVE-2025-41450 published 8 May; CISA ICSA-25-140-03 published 20 May; CVE-2025-41451 and CVE-2025-41452 published 22 Aug; Update A on 26 Aug | [5] [6] | Confirmed |
| 26 Feb 2026 | CISA ICSA-26-057-10: 23 CVEs in Copeland XWEB Pro 1.12.1 and earlier | [7] | Confirmed |
| March to April 2026 | Sabotage of Israeli and US industrial equipment, including Israeli refrigeration, claimed by the unit C4 later names | [2] | Confirmed (as C4 states) |
| From April 2026 | Modbus reconnaissance on port 502, a technique C4 has seen from the unit since at least April 2026 | [2] | Confirmed (as C4 states) |
| 9 Aug 2026 | Claroty Team82 publishes its XWEB Pro research; fixed firmware 1.13 | [9] | Demonstrated |
| Late Aug 2026 | Freezer failures at US military commissaries, investigated as a suspected cyberattack; no link to Europe established | [26] | Reported |
| Early October | Reconnaissance against French targets more than a week before 11 October, per Sekoia's partner reporting | [19] | Reported |
| Night of 11 to 12 Oct | About 700 French retail sites compromised; defrost set high; goods lost; at least 15 fire starts | [2] [3] | Confirmed |
| Same period | Schneider Electric equipment at small French hydroelectric sites targeted, moderate effects; C4 links it to the same attack | [2] | Confirmed |
| 12 Oct | C4 alerted; CERT-FR alert CERTFR-2026-ALE-012 first published; Paris prosecutor opens an investigation | [1] [2] [20] | Confirmed; Reported for the prosecutor |
| 13 Oct | ALE-012 update adds other targeted equipment (the current version lists Copeland and Dixell xweb); CyberbanNews relays the attack | [1] [2] [21] | Confirmed; Inferred that the addition was Copeland and Dixell [1] [21] |
| 14 Oct | Copeland bulletin on XWEB EVO | [4] | Confirmed |
| 16 Oct | ALE-012 update revises the recommendations; campaigns probably still under way | [1] | Confirmed |
| 1 Nov, 22:00 to 22:30 | The only confirmed exploitation attempt Sekoia saw: about 30 minutes against four of its honeypots, a blocked attempt to rename an administrator account through a non-public flaw | [19] | Demonstrated |
| Night of 1 to 2 Nov | Second wave hits stores in several countries and three EFS sites | [22] [23] [29] | Reported |
| 2 Nov | CERT-SE in contact with affected grocery operators; Ransom-ISAC records 743 changes at one site; SecurityScorecard first sees XWEB PRO spam and proxy nodes | [16] [25] | Confirmed; Reported |
| 3 Nov | NCSC Ireland advisory; CSIRTs Network advisory CNW-2026-05; NoName057(16) and Z-Pentest claim on Telegram; EFS statement | [15] [14] [18] [23] | Confirmed; Reported |
| 4 Nov | ENISA, the Commission, Europol EC3, the CSIRTs Network and EU-CyCLONe issue a joint statement; Coolworld statement | [13] [23] | Confirmed; Reported |
| 5 Nov | CISA, FBI, HHS, USDA and DOT joint fact sheet | [11] [12] | Confirmed |
| 9 Nov | France attributes the October wave to Iran; C4 publishes CERTFR-2026-CTI-009 | [2] [3] | Confirmed |
| 10 Nov | KEV catalogVersion 2026.11.10 holds no Danfoss, Copeland or Dixell CVE | [10] | Confirmed |

The Intelligence Hub feed indexes the news and research rows on this topic; it is an index, not a source [36].

## Part 2: the intrusion record

**Equipment.** CERT-FR knows of numerous compromises of the equipment it lists [1] (**Confirmed**). Copeland's XWEB EVO flaw sits in an end-of-life line that gets no fixes [4], a different line from the patched XWEB Pro CVEs [7] (**Inferred**).

**What was changed.** The US fact sheet describes actors forcing continuous heating and defrost cycles. Its listed effects include fire hazard, inventory loss and denial of view [11] (**Confirmed**). Sekoia adds that alarm thresholds were changed, which delayed detection [19] (**Reported**). One ICA store had setpoints of +50 C that it could not change [22] (**Reported**). At one site examined by Ransom-ISAC, an intruder used default factory Administrator credentials on XWEB Pro. It read 31 devices and made 743 changes, including setpoints of 110 C and 150 C, muted alarms and locked keypads [25] (**Reported**). No evidence links that site to the other incidents [25].

**Access path.** No primary names a CVE for initial access [18] (**Reported**). The US fact sheet lists vector classes only: authentication bypass, arbitrary code injection and weak configurations [11] (**Confirmed**). NCSC Ireland says attackers reportedly reached controllers directly exposed to the internet [15] (**Confirmed** as stated). Sekoia could not confirm CVE-2025-41450. It assesses that the 1 November attempt used a non-public vulnerability [19] (**Demonstrated** for the telemetry, **Reported** for the assessment). The refrigeration contractor Sabcobel said the November attacker used the same vulnerability as in France. It also said a software update alone is not enough, because units need physical modifications [22] (**Reported**).

**The CVE record.** No government source opened for this study says any of these CVEs was exploited in these waves: CNW-2026-05 and the US fact sheet name no CVE, and KEV lists none [14] [11] [10] (**Inferred** from absence).

| CVE | Product | Weakness | Score | Fix | Sources |
|---|---|---|---|---|---|
| CVE-2025-41450 | Danfoss AK-SM 8xxA | Authentication bypass via datetime-based passwords (CWE-305 at NVD, CWE-287 at CISA) | CVSS 3.1 8.2 | R4.2 | [5] [6] |
| CVE-2025-41451 | Danfoss AK-SM 8xxA | Post-authentication command injection, alarm-to-mail fields (CWE-77) | CVSS 4.0 8.7 | 4.3.1 | [5] [6] |
| CVE-2025-41452 | Danfoss AK-SM 8xxA | External control of configuration, denial of service (CWE-15) | CVSS 4.0 6.8 | 4.3.1 | [5] [6] |
| CVE-2026-25085 | Copeland XWEB Pro 1.12.1 and earlier | Authentication bypass (CWE-394) | CISA 8.6; NVD 9.8 | Latest XWEB Pro | [7] [8] |
| CVE-2026-21718 | Copeland XWEB Pro 1.12.1 and earlier | Authentication bypass to pre-auth code execution (CWE-327) | CISA 10.0; NVD 9.8 | Latest XWEB Pro | [7] [8] |
| CVE-2026-24663 | Copeland XWEB Pro 1.12.1 and earlier | Unauthenticated OS command injection (CWE-78) | CISA 9.0; NVD 9.8 | Latest XWEB Pro | [7] [8] |

Claroty Team82 researchers found both sets: Tomer Goldschmidt for Danfoss and Amir Zaltzman for Copeland [5] [7]. SecurityScorecard links XWEB PRO controllers acting as spam and proxy nodes from 2 November to CVE-2026-25085, at low to medium confidence. It does not link them to the European attacks [25] (**Reported**).

**Exposure and reconnaissance.** On 11 October Censys counted nearly 3,000 exposed Danfoss StoreView panels, over 1,800 in France; the French count fell to 537 by 14 October [21] (**Reported**: Censys data relayed by SecurityWeek). Predicta Lab counted 2,752 exposed Danfoss systems, 1,590 in France [20], and Coalition 618 still exposed after the first wave [33] (**Reported**). Unit 42 counts over 5,000 exposed devices from the named vendors worldwide on 5 to 6 November [18] (**Demonstrated**). Sekoia's honeypots, emulating the Danfoss web interface in France and the Netherlands from 12 October, saw unauthenticated enumeration from 13 October, date and time reads from 19 to 25 October and password spraying of default accounts [19] (**Demonstrated**).

## Part 3: who and why

**France's attribution.** The C4 (ANSSI, COMCYBER, DGA, DGSE and DGSI) says it can attribute destabilisation attacks against French interests to two cyber-offensive units of the IRGC electronic and cyber centre, Shahid Shoostari and Shahid Kaveh [2] (**Confirmed**). The wider record of IRGC operations is in [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md). It attributes the October attack to the Shahid Kaveh unit as executor and the IRGC as sponsor [2] (**Confirmed**). It rests on a bundle of indicators, with no formal confidence scale. The attack infrastructure was also used to scan Schneider Electric equipment over Modbus on port 502. The operators used the FOFA scanning service. The outlet CyberbanNews relayed the attack from 13 October. Farsi traces were found in the infrastructure [2] (**Confirmed** as France's stated evidence).

C4 says Shahid Kaveh is led by Reza Salarvand and Mahdi Lashgarian. It names Hamid Reza Lashgarian as head of the IRGC electronic and cyber centre (CGRI-CEC) [2]. It says the unit acts through the personas CyberAveng3rs, Soldiers of Solomon, Mr. Soul and Cyber Isnaad Front [2]. It also says the unit claimed the November 2023 Unitronics campaign and the March to April 2026 sabotage. C4 adds that the unit has held scripts since at least June 2024 to scan, access and control Schneider Electric, Siemens and Rockwell equipment [2] (**Confirmed** as stated). The foreign ministry calls this the first cyber-offensive campaign on French territory run purely for sabotage. Iran's ambassador will be summoned and France will propose new EU sanctions; the EU already sanctioned Emennet Pasargad in March 2026 [3] (**Confirmed**). Press reports that Foreign Minister Jean-Noel Barrot confirmed IRGC responsibility at a G7 ministerial and that arrest warrants were requested for the unit's leadership [27] (**Reported**).

**What it does not cover.** The statements address only the October French wave [3] (**Inferred**); Infosecurity reports the attribution expressly excludes EFS [28] (**Reported**).

**Other claims.** NoName057(16) and Z-Pentest claimed responsibility on Telegram on 3 November; the public record on NoName057(16) is in [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md). Unit 42 calls the claims unverified [18], and Sekoia judges them unsubstantiated [19] (**Reported**). Before the attribution, Lupovis honeypots saw probing from bulletproof hosting used before in Russian-linked operations. SentinelLabs called Russian involvement one credible hypothesis and warned against assuming a single campaign [32] (**Reported**). Sekoia says similarities in timing, infrastructure, targeting and tradecraft suggest both waves may share one actor, and calls the French attribution consistent with an Iran-nexus hypothesis it gave clients on 15 October [19] (**Reported**). Belgium's CCB said it may never be possible to identify the perpetrators [29] (**Reported**).

**Lineage.** The 2023 Unitronics wave, the 2024 US Treasury sanctions on IRGC-CEC officials and the 2026 Iranian-affiliated PLC campaign are covered in [ICS Attacks and Advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) [37]; the wider record of Iran's state-linked operators is in [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md).

## Part 4: impact and response

**Victims and sectors.**

| Who | What happened | Sources | Grade |
|---|---|---|---|
| French retail, October | About 700 sites, mainly the Casino, Leclerc, Cooperative U, Metro, Carrefour and Intermarche groups, plus small butchers, an abattoir and cooperative food plants; fires and goods losses. The finance minister told lawmakers about 700 of about 10,000 supermarkets [21] | [2] [3] [21] | Confirmed; Reported for the minister |
| French hydroelectric sites | Schneider Electric devices targeted, moderate effects | [2] | Confirmed |
| Second wave, 2 November | More than 115 stores in one count: ICA and Coop in Sweden; Ahold Delhaize, Carrefour, Intermarche, Spar Colruyt and an Ikea in Belgium and Luxembourg; SuperValu in Ireland; Selver in Estonia; butchers and local shops in the Netherlands. Another count gives more than 50 Belgian stores and over a dozen sites elsewhere | [22] [29] | Reported |
| UK meat suppliers | Three members of the Association of Independent Meat Suppliers compromised through Copeland XWEB controllers, no meat lost; the UK NCSC called national impact minimal | [30] | Reported |
| EFS, French blood service | Three sites hit through a third-party refrigeration provider; temperature and defrost thresholds raised to extremely high levels; alarms caught it; no health impact or loss of blood products | [23] [24] [31] | Reported |

Le Canard enchaine named the EFS supplier as Coolworld. Coolworld confirmed an incident affecting a limited number of its units. It said the flaw was in a third-party component outside its direct control [23] [32] (**Reported**). EFS has not named its supplier. The 110 C figure for EFS comes from Le Canard enchaine, not EFS [31].

**Government and regulator record.** CERT-FR issued the first alert and two updates [1]. CNW-2026-05 indexes national alerts from CERT-FR, CCB, BSI, INCIBE-CERT, NCSC-IE, CERT-SE, CERT-AT and others, and lists no CVE [14] (**Confirmed**). CNW-2026-05 also lists the CCB's "patch immediately" warning [14] (**Confirmed**; date not established). The EU joint statement names no actor. It urges immediate action, manufacturer reporting through the Cyber Resilience Act single reporting platform (obligations since 11 September 2026) and NIS2 incident reporting [13] (**Confirmed**). The US fact sheet names no actor, vendor or CVE [11] (**Confirmed**). Health-ISAC sent its members a bulletin after the EFS incident [34] (**Reported**).

**Vendor record.** Danfoss said most of the affected devices are older AK-SM 800 and AK-SC 355 systems that have reached end of life and are no longer patched [21] (**Reported**). Copeland first declined to confirm CERT-FR's findings, then acknowledged a vulnerability [21] (**Reported**). On 4 November it said some XWEB solutions were affected and that it had re-sent patching guidance [32] (**Reported**).

**KEV.** At catalogVersion 2026.11.10 (1,779 entries), no Danfoss, Copeland, Dixell or XWEB CVE is listed [10] (**Confirmed**). The nearest precedent is CVE-2023-6448 (Unitronics Vision insecure default password), added on 11 December 2023 [10] (**Inferred** for 'nearest'; the KEV date is **Confirmed**).

## Part 5: the defender and vulnerability-management view

**What worked.** Exposure fell fast: Unit 42's French count went from 1,853 (1 to 15 October) to 316 (1 to 6 November) [18] (**Demonstrated**). Monitoring and on-call staff limited harm at EFS [23] [32], and Sabcobel's technicians began disconnecting installations at about 1 a.m. on 2 November [22] (**Reported**).

| Control | Source |
|---|---|
| Remove all public IP exposure; no port forwarding or DMZ | CERT-FR [1]; Copeland [4]; NCSC-IE [15]; US CPG 3.S [12] |
| Check insurance terms before cutting the contractor's data feed | CERT-FR [1] |
| Remote access only by VPN or protected network; contractor IP filtering as a stopgap | CERT-FR [1]; NCSC-IE [15] |
| Verify defrost ranges, setpoints, alarm categories and recipients, and accounts | CERT-FR [1]; Copeland [4]; NCSC-IE [15] |
| Danfoss security level Strict; change default passwords; phishing-resistant MFA | CERT-FR [1]; NCSC-IE [15]; US CPG 3.A, 3.B, 3.F [12] |
| Restore from a pre-intrusion backup, remove unknown users, reset passwords, send a test alarm | Copeland [4]; US CPG 3.O [12] |
| OT VLAN isolation, device and IP allowlisting, logging | US CPG 3.I, 3.H, 3.Q [12] |
| Setpoint range limits with deviation alerting | US fact sheet [12] |
| Patch, and retire or isolate end-of-life devices | CERT-FR [1]; NCSC-IE [15]; US CPG 2.A, 2.B [12] |

**The vulnerability-management lens.** Several points follow from the record (**Inferred** throughout):

- A program that ranks by KEV would not have flagged these controllers, because none is listed [10].
- The inventory must include contractor-managed supervisors and the remote paths into them.
- End-of-life units have no patch to deploy: isolate or replace them [1] [4].
- Treat a setpoint change as a security event. Alarms caught the EFS change [23], and Health-ISAC advises alarms independent of the controller [34].

**What is overstated and what is understated.**

- *Overstated:* the idea that Iran hit about 700 French sites and the blood bank. France attributes the October French wave only [3] [28]. The 110 C EFS figure comes from Le Canard enchaine, not from EFS [31]. CVE-2025-41450 as "the" vector is speculation [18] [19]. Ahold Delhaize's reported 200 to 250 million euro sales hit concerns a separate October incident; no company statement ties it to refrigeration [35] (**Inferred**).
- *Understated:* the access path the record supports is exposure, end-of-life devices and, at one examined site, default credentials, not a CVE any government named [1] [4] [25] (**Inferred**). A factory reset leaves end-of-life units open to re-compromise [1]. The same infrastructure scanned Schneider Electric equipment in energy and water units [2].

## Part 6: MITRE mappings

This Part binds the verified record to MITRE ATT&CK v20.0 for ICS and Enterprise, CWE, CAPEC and D3FEND. Names and tactics come from `data/attack/ics/technique_profiles.jsonl` and `data/attack/technique_profiles.jsonl` [38]. Each mapping is this study's (**Inferred**) reading of a behavior a cited source describes. This study binds no ATT&CK campaign or software object.

### 6.1 Objects

| Object | ATT&CK id | Library page | Relationship |
|---|---|---|---|
| CyberAv3ngers (associated name Soldiers of Soloman) | `G1027` | none (no generated page) | ATT&CK calls it a suspected IRGC-affiliated group [17]. C4 names the personas CyberAveng3rs and Soldiers of Solomon for Shahid Kaveh [2]; matching them to G1027 is **Inferred** |

NoName057(16), Z-Pentest and Shahid Kaveh get no object here.

### 6.2 ATT&CK for ICS techniques

The library has no per-technique ICS pages, so ids link to attack.mitre.org; see the [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md).

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T0883`](https://attack.mitre.org/techniques/T0883/) | Internet Accessible Device | Initial Access | Controllers reached while exposed to the internet (NCSC-IE, 3 Nov 2026; CERT-FR, 12 to 16 Oct 2026) | [1] [15] |
| [`T1694.001`](https://attack.mitre.org/techniques/T1694/001/) | Default Credentials | Persistence, Lateral Movement | Ransom-ISAC site, default Administrator credentials (2 Nov 2026); default-account spraying on Sekoia honeypots (Oct to Nov 2026) | [19] [25] |
| [`T0836`](https://attack.mitre.org/techniques/T0836/) | Modify Parameter | Impair Process Control | Defrost set high (11 to 12 Oct 2026); EFS thresholds raised and 743 setpoint changes (2 Nov 2026) | [2] [23] [25] |
| [`T0838`](https://attack.mitre.org/techniques/T0838/) | Modify Alarm Settings | Inhibit Response Function | Alarm thresholds altered (Sekoia, Nov 2026); alarms muted (Ransom-ISAC, 2 Nov 2026) | [19] [25] |
| [`T0831`](https://attack.mitre.org/techniques/T0831/) | Manipulation of Control | Impact | Forced continuous heating and defrost cycles (US fact sheet, 5 Nov 2026) | [11] |
| [`T0815`](https://attack.mitre.org/techniques/T0815/) | Denial of View | Impact | Denial of view listed as an effect (US fact sheet, 5 Nov 2026) | [11] |
| [`T0879`](https://attack.mitre.org/techniques/T0879/) | Damage to Property | Impact | At least 15 fire starts and goods losses (11 to 12 Oct 2026) | [2] [3] |
| [`T0828`](https://attack.mitre.org/techniques/T0828/) | Loss of Productivity and Revenue | Impact | Food losses of several tens of millions of euros (France, 9 Nov 2026) | [3] |

ICS mitigations the library profiles attach to these techniques [38]: [M0930 Network Segmentation](https://attack.mitre.org/mitigations/M0930/) (T0883); [M0801 Access Management](https://attack.mitre.org/mitigations/M0801/) and [M0927 Password Policies](https://attack.mitre.org/mitigations/M0927/) (T1694.001); [M0800 Authorization Enforcement](https://attack.mitre.org/mitigations/M0800/) (T0836, T0838); [M0810 Out-of-Band Communications Channel](https://attack.mitre.org/mitigations/M0810/) (T0815, T0831); [M0953 Data Backup](https://attack.mitre.org/mitigations/M0953/) (T0815, T0828, T0831); [M0805 Mechanical Protection Layers](https://attack.mitre.org/mitigations/M0805/) (T0879).

### 6.3 ATT&CK Enterprise techniques

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T1595`](/mitre/techniques/T1595.md) | Active Scanning | Reconnaissance | Modbus port 502 scanning of Schneider Electric equipment (from April 2026, C4); honeypot enumeration (from 13 Oct 2026) | [2] [19] |
| [`T1596.005`](/mitre/techniques/T1596-005.md) | Scan Databases | Reconnaissance | Operators used the FOFA scanning service (C4, 9 Nov 2026) | [2] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | Authentication bypass and code injection against exposed controllers (US fact sheet, 5 Nov 2026); exploitation attempt (Sekoia, 1 Nov 2026) | [11] [19] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Default Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Default Administrator credentials on XWEB Pro (2 Nov 2026) | [25] |
| [`T1110.003`](/mitre/techniques/T1110-003.md) | Password Spraying | Credential Access | Spraying of default accounts on Sekoia honeypots (Oct to Nov 2026) | [19] |
| [`T1199`](/mitre/techniques/T1199.md) | Trusted Relationship | Initial Access | EFS supervision reached via its refrigeration provider's remote-monitoring service (2 Nov 2026); whether trusted access was abused is not established [23] [31] (**Inferred**, low confidence) | [23] [31] |

The XWEB spam and proxy activity [25] is not mapped, because no source links it to these attacks.

### 6.4 Vulnerabilities, CWE and CAPEC

No CVE below is confirmed as used in these waves [18]. CAPEC entries are those the library relates to each CWE in `data/weaknesses/cwe.jsonl` [38].

| CVE | CWE (as the source lists it) | CAPEC the library relates |
|---|---|---|
| CVE-2025-41450 | CWE-305 (NVD), CWE-287 (CISA) | None for CWE-305; for CWE-287, 10 entries, for example [CAPEC-115](/mitre/capec/CAPEC-115.md) Authentication Bypass |
| CVE-2025-41451 | CWE-77 | 8 entries, for example [CAPEC-248](/mitre/capec/CAPEC-248.md) Command Injection |
| CVE-2025-41452 | CWE-15 | 10 entries, for example [CAPEC-176](/mitre/capec/CAPEC-176.md) Configuration/Environment Manipulation |
| CVE-2026-25085 | CWE-394 | None |
| CVE-2026-21718 | CWE-327 | 7 entries, for example [CAPEC-97](/mitre/capec/CAPEC-97.md) Cryptanalysis |
| CVE-2026-24663 | CWE-78 | 5 entries, for example [CAPEC-88](/mitre/capec/CAPEC-88.md) OS Command Injection |

Two CAPEC entries match observed behavior through the library's ATT&CK links: [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords (T1078.001) and [CAPEC-565](/mitre/capec/CAPEC-565.md) Password Spraying (T1110.003) [38].

### 6.5 D3FEND countermeasures

| D3FEND countermeasure | Techniques the library maps it to (from this study) | Where it meets the record |
|---|---|---|
| [Change Default Password](/mitre/d3fend/change-default-password.md) (D3-CDP) | T1078.001, T1110.003, T0812 (revoked; now T1694.001) | Default Administrator credentials [25] |
| [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (D3-MFA) | T1110.003, T0812 (revoked; now T1694.001) | Remote access hardening [12] |
| [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) (D3-SPP) | T1110.003, T0812 (revoked; now T1694.001) | Default-account spraying [19] |
| [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (D3-ITF) | T1190 | Removing exposure [1] |
| [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (D3-NTF) | T0836, T0838, T1110.003, T1190, T1199 | Contractor access paths [1] |
| [OT Variable Access Restriction](/mitre/d3fend/ot-variable-access-restriction.md) (D3-OVAR) | T0836 | Setpoint range limits [12] |
| [Message Authentication](/mitre/d3fend/message-authentication.md) (D3-MAN) | T0836, T0838 | Authenticated parameter and alarm writes (**Inferred**) |
| [Restore Configuration](/mitre/d3fend/restore-configuration.md) (D3-RC) | none of this study's techniques | Restoring parameters from backup [4], by analogy (**Inferred**) |

See the [D3FEND Reference](/D3FEND_REFERENCE.md).

### 6.6 Navigator layers

- ICS: [`navigator/case-studies/european-refrigeration-attacks-2026-ics.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/european-refrigeration-attacks-2026-ics.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/case-studies/european-refrigeration-attacks-2026-ics.json)), domain `ics-attack`, the techniques of 6.2.
- Enterprise: [`navigator/library-layers/european-refrigeration-attacks-2026-enterprise.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/european-refrigeration-attacks-2026-enterprise.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/european-refrigeration-attacks-2026-enterprise.json)), domain `enterprise-attack`, the techniques of 6.3.

Each comment names the event and source numbers. A score of 100 means membership in this study's record, not severity.

## Cross-cutting themes

- **Maintenance functions are attack surface.** The attackers used the defrost cycle the equipment already has, so the weapon was a setting [2] [11] (**Inferred**).
- **End of life is a security state.** With units out of support and no fix path, the remedy is isolation or replacement [1] [4] [21].
- **Outsourced assets stay in scope.** EFS was reached via its refrigeration provider's remote monitoring [23] (**Inferred** as a pattern).
- **KEV is silent on this attack surface.** The sabotage reached national scale with nothing in KEV [10].
- **Attribution arrives late and narrow.** It came four weeks after the first wave and covers one wave of two [3].

## Sources

All sources were opened on 11 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CERT-FR, alert CERTFR-2026-ALE-012, 12 Oct 2026, updated 13 and 16 Oct | [cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-012/](https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-012/) | 2026-11-11 | Confirmed |
| 2 | CERT-FR and C4, report CERTFR-2026-CTI-009, 9 Nov 2026 | [cert.ssi.gouv.fr/uploads/CERTFR-2026-CTI-009.pdf](https://cert.ssi.gouv.fr/uploads/CERTFR-2026-CTI-009.pdf) | 2026-11-11 | Confirmed |
| 3 | French Ministry for Europe and Foreign Affairs, attribution statement, 9 Nov 2026 | [diplomatie.gouv.fr/...](https://www.diplomatie.gouv.fr/fr/presse-et-ressources/decouvrir-et-informer/actualites/declaration-d-attribution-a-l-iran-de-cyberattaques-visant-la-france) | 2026-11-11 | Confirmed |
| 4 | Copeland Controls, XWEB security bulletin, 14 Oct 2026 | [dixell.fr/...](https://dixell.fr/wp-content/uploads/2026/10/Recommandations-pour-une-utilisation-securisee-des-superviseurs-XWEB-v1.0.pdf) | 2026-11-11 | Confirmed |
| 5 | CISA, ICSA-25-140-03 Danfoss AK-SM 8xxA, Update A 26 Aug 2025 | [cisa.gov/news-events/ics-advisories/icsa-25-140-03](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03) | 2026-11-11 | Confirmed |
| 6 | NVD, CVE-2025-41450, CVE-2025-41451 and CVE-2025-41452 | [nvd.nist.gov/vuln/detail/CVE-2025-41450](https://nvd.nist.gov/vuln/detail/CVE-2025-41450) | 2026-11-11 | Confirmed |
| 7 | CISA, ICSA-26-057-10 Copeland XWEB Pro, 26 Feb 2026 | [cisa.gov/news-events/ics-advisories/icsa-26-057-10](https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-10) | 2026-11-11 | Confirmed |
| 8 | NVD, CVE-2026-25085, CVE-2026-21718 and CVE-2026-24663 | [nvd.nist.gov/vuln/detail/CVE-2026-25085](https://nvd.nist.gov/vuln/detail/CVE-2026-25085), [CVE-2026-21718](https://nvd.nist.gov/vuln/detail/CVE-2026-21718), [CVE-2026-24663](https://nvd.nist.gov/vuln/detail/CVE-2026-24663) | 2026-11-11 | Confirmed |
| 9 | Claroty Team82, XWEB Pro research, 9 Aug 2026 | [claroty.com/team82/research/...](https://claroty.com/team82/research/chilling-discoveries-unpacking-vulnerabilities-in-copeland-xweb-pro-controllers) | 2026-11-11 | Demonstrated |
| 10 | CISA, KEV catalog JSON, catalogVersion 2026.11.10 | [cisa.gov/.../known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 2026-11-11 | Confirmed |
| 11 | CISA, FBI, HHS, USDA and DOT, joint fact sheet page, 5 Nov 2026 | [cisa.gov/resources-tools/resources/...](https://www.cisa.gov/resources-tools/resources/us-government-partners-urge-hardening-industrial-refrigeration-and-cold-chain-monitoring-systems) | 2026-11-11 | Confirmed |
| 12 | The same joint fact sheet, PDF | [cisa.gov/.../joint-fact-sheet-...-508c.pdf](https://www.cisa.gov/sites/default/files/2026-11/joint-fact-sheet-usg-partners-urge-hardening-industrial-refrigeration-cold-chain-monitoring-systems-508c.pdf) | 2026-11-11 | Confirmed |
| 13 | ENISA, DG CNECT, Europol EC3, CSIRTs Network and EU-CyCLONe, joint statement, 4 Nov 2026 | [enisa.europa.eu/news/...](https://www.enisa.europa.eu/news/joint-statement-on-cyber-incidents-in-refrigeration-systems-across-the-eu) | 2026-11-11 | Confirmed |
| 14 | EU CSIRTs Network, CNW-2026-05, 3 Nov 2026, updated to 10 Nov | [github.com/enisaeu/CNW/...](https://github.com/enisaeu/CNW/blob/main/advisories/2026/CNW-2026-05_retail-incidents.md) | 2026-11-11 | Confirmed |
| 15 | NCSC Ireland, refrigeration controller advisory, 3 Nov 2026 | [ncsc.gov.ie/pdfs/2611020249_Danfoss-Advisory.pdf](https://www.ncsc.gov.ie/pdfs/2611020249_Danfoss-Advisory.pdf) | 2026-11-11 | Confirmed |
| 16 | CERT-SE, attacks on connected freezer and refrigeration systems, 2 Nov 2026 | [cert.se/2026/11/...](https://www.cert.se/2026/11/cyberangrepp-mot-uppkopplade-frys-och-kylsystem.html) | 2026-11-11 | Confirmed |
| 17 | MITRE ATT&CK, group G1027 | [attack.mitre.org/groups/G1027/](https://attack.mitre.org/groups/G1027/) | 2026-11-11 | Confirmed |
| 18 | Palo Alto Networks Unit 42, Europe's refrigeration systems attacks, 6 Nov 2026 | [unit42.paloaltonetworks.com/...](https://unit42.paloaltonetworks.com/europes-refrigeration-systems-attacks/) | 2026-11-11 | Demonstrated (counts); Reported (assessments) |
| 19 | Sekoia, unpatched Danfoss controllers exploited, November 2026 | [sekoia.com/blog/...](https://www.sekoia.com/blog/the-cold-chain-on-fire-unpatched-danfoss-controllers-exploited) | 2026-11-11 | Demonstrated (honeypots); Reported (assessments) |
| 20 | BleepingComputer, French supermarkets, 12 Oct 2026 | [bleepingcomputer.com/...](https://www.bleepingcomputer.com/news/security/cyberattack-shuts-down-refrigerators-at-french-supermarkets/) | 2026-11-11 | Reported |
| 21 | SecurityWeek, attack widens to Copeland and Dixell, 15 Oct 2026 | [securityweek.com/...](https://www.securityweek.com/supermarket-refrigeration-attack-widens-to-copeland-dixell-controllers/) | 2026-11-11 | Reported |
| 22 | BleepingComputer, European supermarkets, 2 Nov 2026 | [bleepingcomputer.com/...](https://www.bleepingcomputer.com/news/security/hackers-disrupt-refrigeration-systems-at-european-supermarkets/) | 2026-11-11 | Reported |
| 23 | BleepingComputer, blood storage in France, 4 Nov 2026 | [bleepingcomputer.com/...](https://www.bleepingcomputer.com/news/security/cyberattack-disrupts-blood-storage-refrigeration-systems-in-france/) | 2026-11-11 | Reported |
| 24 | AABB, French blood banks, 4 Nov 2026 | [aabb.org/...](https://www.aabb.org/news-resources/news/article/2026/11/04/french-blood-banks-targeted-in-cyberattack) | 2026-11-11 | Reported |
| 25 | Help Net Security, XWEB controllers and spam botnet, 9 Nov 2026 | [helpnetsecurity.com/...](https://www.helpnetsecurity.com/2026/11/09/copeland-xweb-refrigeration-controllers-spam-botnet/) | 2026-11-11 | Reported |
| 26 | Security Affairs, US military base freezer failures, 29 Oct 2026 | [securityaffairs.com/...](https://securityaffairs.com/202073/hacking/us-probes-suspected-hack-behind-military-base-freezer-failures.html) | 2026-11-11 | Reported |
| 27 | The Record, France blames Iran, 9 Nov 2026 | [therecord.media/...](https://therecord.media/france-blames-iran-for-fridge-cyberattacks) | 2026-11-11 | Reported |
| 28 | Infosecurity Magazine, France blames Iran, 10 Nov 2026 | [infosecurity-magazine.com/...](https://www.infosecurity-magazine.com/news/france-blames-iran-supermarket/) | 2026-11-11 | Reported |
| 29 | The Record, grocery freezers across Europe, 2 Nov 2026 | [therecord.media/...](https://therecord.media/cyberattack-grocery-freezers-europe) | 2026-11-11 | Reported |
| 30 | The Record, British businesses, 3 Nov 2026 | [therecord.media/...](https://therecord.media/british-businesses-caught-in-europe-wide-supermarket-fridge-attacks) | 2026-11-11 | Reported |
| 31 | SecurityWeek, French blood bank, November 2026 | [securityweek.com/...](https://www.securityweek.com/cyberattack-hits-french-blood-bank-site-but-no-blood-products-are-compromised/) | 2026-11-11 | Reported |
| 32 | GovInfoSecurity, French blood bank, 4 Nov 2026 | [govinfosecurity.com/...](https://www.govinfosecurity.com/refrigeration-cyberattacks-nearly-sabotage-french-blood-bank-a-33293) | 2026-11-11 | Reported |
| 33 | The Register, researchers warned months before, 15 Oct 2026 | [theregister.com/...](https://www.theregister.com/security/2026/10/15/researchers-warned-attackers-could-defrost-the-food-months-before-french-supermarkets-got-hit/5303425) | 2026-11-11 | Reported |
| 34 | WUNC (NPR), Health-ISAC warning, 6 Nov 2026 | [wunc.org/...](https://www.wunc.org/2026-11-06/health-intel-sharing-group-warns-industry-in-wake-of-cyberattack-on-french-blood-bank) | 2026-11-11 | Reported |
| 35 | RetailDetail, Ahold Delhaize revenue hit, November 2026 | [retaildetail.eu/...](https://www.retaildetail.eu/news/food/cyberattack-costs-ahold-delhaize-up-to-250-million-euros-in-revenue/) | 2026-11-11 | Reported |
| 36 | TeamStarWolf Intelligence Hub, feed (index only) | [teamstarwolf.github.io/intelligence-hub/data/feed.json](https://teamstarwolf.github.io/intelligence-hub/data/feed.json) | 2026-11-11 | Confirmed (as an index) |
| 37 | TeamStarWolf library, ICS Attacks and Advisories, 2024 to 2026 | [/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) | 2026-11-11 | Confirmed |
| 38 | TeamStarWolf library data: `data/attack/ics/technique_profiles.jsonl`, `data/attack/technique_profiles.jsonl`, `data/attack/superseded_by.jsonl`, `data/attack/ics/groups.jsonl`, `data/attack/technique_to_d3fend.jsonl`, `data/attack/d3fend_countermeasures.jsonl`, `data/weaknesses/cwe.jsonl`, `data/weaknesses/capec.jsonl` and the `mitre/` tree | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) | 2026-11-11 | Confirmed |

Not opened, so not cited as sources: the EFS press release, the CCB Belgium advisory page, the Paris prosecutor's statement, Danfoss's own statements, the SentinelLabs assessment, the Le Canard enchaine article and the Telegram claims; each is relayed by a source above.

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [ICS Attacks and Advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), the [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), the [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md) and the [ICS, OT and hardware hub](/hubs/ics-ot-and-hardware.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- Techniques: [T1595 Active Scanning](/mitre/techniques/T1595.md), [T1596.005 Scan Databases](/mitre/techniques/T1596-005.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1078.001 Default Accounts](/mitre/techniques/T1078-001.md), [T1110.003 Password Spraying](/mitre/techniques/T1110-003.md), [T1199 Trusted Relationship](/mitre/techniques/T1199.md)
- CAPEC: [CAPEC-70](/mitre/capec/CAPEC-70.md), [CAPEC-565](/mitre/capec/CAPEC-565.md), [CAPEC-115](/mitre/capec/CAPEC-115.md), [CAPEC-88](/mitre/capec/CAPEC-88.md)
- Related studies: [ICS Attacks and Advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [Stuxnet](/case-studies/STUXNET.md), [Sandworm operations](/case-studies/SANDWORM_OPERATIONS.md)
- [Navigator layers](/navigator/index.md), including this study's two layers, [european-refrigeration-attacks-2026-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/european-refrigeration-attacks-2026-ics.json) and [european-refrigeration-attacks-2026-enterprise.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/european-refrigeration-attacks-2026-enterprise.json)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) for the live KEV ledger
- [All case studies](/case-studies/README.md)
