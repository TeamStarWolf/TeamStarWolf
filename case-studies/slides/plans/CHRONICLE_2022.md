# Slide plan: The Year 2022 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2022.md
- Cover title: The Year 2022 / in Intrusions / A Dated Record
- Subtitle: A war arrived on the wire, and identity became the front door
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2022.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The war began with wipers, and the quieter story was identity

- **Wipers came first:** WhisperGate on 13 January, HermeticWiper on 23 February, new attacks hours before the invasion.
- **One attack was felt across Europe:** KA-SAT modems were wiped through the network's own management plane.
- **Identity was the front door:** LAPSUS$, SMS phishing and MFA prompt flooding reached Okta, Cisco, Twilio and Uber.
- **Edge devices fell within days:** VMware, Confluence, F5, Fortinet, Citrix and Exchange.
- **Money became the lever:** the first mixer sanctions, Blender.io and then Tornado Cash.
Caption: Grades: agencies, victims, vendors, CVE, NVD and KEV records Confirmed; two ATT&CK-only claims Reported; data checks Demonstrated.
Notes: Wipers [4][16][18]. KA-SAT [19][6]. Identity [23][9][50][42][57]. Edge [29][30][38][91][62][72][59]. Sanctions [24][49]. That identity led several of the best-known breaches is the study's reading (Inferred).

## KEY FACTS | 555 KEV additions, a $620M theft, 237 operations in Ukraine

Stat: 555 | KEV entries added in 2022, 91 of them 2022 ids
Stat: ~$620M | taken from Ronin, tied to Lazarus Group
Stat: 237+ | operations against Ukraine by 27 April
Stat: 116 | Enterprise technique rows, plus 17 ICS
- Attributions: Russia for WhisperGate and Viasat (10 May), Lazarus for Ronin, Iran for Albania (September).
- Policy landmarks: CIRCIA (15 Mar), the Cyber Resilience Act proposal (15 Sep), BOD 23-01 (3 Oct).
- AA23-215A: older flaws were exploited more than new ones, led by FortiOS CVE-2018-13379.
Notes: KEV counts computed from catalog version 2026.11.10; the March spike is backfill [27]. Ronin [24]. Microsoft count, close to 40 destructive attacks [36]. Attributions [5][6][24][46][76]. Policy [102][108][109]. Top exploited [87]. MITRE binding counts from Part 11 of the study.

## PART 1 | The year in date order, from WhisperGate to the October outage

| Date | Event |
|---|---|
| 13 Jan | WhisperGate appears on Ukrainian systems |
| 21 Jan | A Sitel support workstation reaches two Okta tenants |
| 24 Feb | The KA-SAT attack disables modems across Europe |
| 15 Mar | CIRCIA enacted |
| 23 Mar | About $620 million stolen from the Ronin bridge |
| 8 Apr | Industroyer2 set to run against substations |
| 2 Jun | Confluence CVE-2022-26134 exploited and listed in KEV |
| 15 Jul | Destructive attack on the Albanian government |
| 15 Sep | Uber reached through a contractor's account |
| 10 Oct | Sandworm causes a power outage through SCADA software |
Notes: WhisperGate [4]. Okta and Sitel [9]. KA-SAT [19]. CIRCIA [102]. Ronin [24]. Industroyer2 [31]. Confluence [38][27]. Albania [45][46]. Uber [57]. October outage [63]. The December Slack token theft [98].

## PART 2 | Russia's first moves were wipers and a satellite network

Left: Wipers
- WhisperGate overwrote the boot record behind a fake ransom note.
- HermeticWiper hit hundreds of computers hours after DDoS attacks.
- AA22-057A listed five wiper families deployed since January.
- The NCSC tied WhisperGate to Russian military intelligence on 10 May.
Right: KA-SAT, 24 February
- Entry through a misconfigured VPN appliance.
- Legitimate management commands overwrote modem flash.
- Nearly 30,000 replacement modems were shipped.
- Wind farms in central Europe were disrupted.
Notes: WhisperGate [4]; Cadet Blizzard named in June 2023 [7]. HermeticWiper, no actor named by ESET [16]. MSTIC and FoxBlade [18]. AA22-057A [17]. NCSC [5]. KA-SAT [19]; EU, UK and US attribution [6]. The AcidRain tie rests on the ATT&CK record (Reported [128]). Home study: Sandworm.

## PART 2 | The grid was attacked twice, the second time with native tools

- **8 April:** Industroyer2 was set for 16:10 UTC against high-voltage substations, CaddyWiper for 16:20 UTC.
- **ESET, with CERT-UA,** attributed it to Sandworm with high confidence; ATT&CK says it had no impact.
- **10 October:** Sandworm used the utility's own MicroSCADA binary to cause an outage during missile strikes.
- **12 October:** a new CaddyWiper variant hit the company's IT systems.
- **11 October:** Prestige ransomware hit transport and logistics in Ukraine and Poland within an hour.
Caption: Between April and October the technique moved from purpose-built malware to a binary already on the server (Inferred).
Notes: Industroyer2 [31]; no impact, Reported [131]. October attack, campaign C0034 [63][119]. Prestige, IRIDIUM "very likely" [64]. Cyclops Blink, exposed 23 February [13][14]. AA22-110A on Russian units and aligned criminal groups [35].

## PART 3 | Iran destroyed, North Korea stole and China stayed inside

Left: Iran and North Korea
- Iran was in Albania's networks about 14 months before the July attack.
- A 2019 SharePoint flaw was the likely way in.
- Lazarus stole almost $620 million from Ronin.
- TraderTraitor pushed trojanized crypto apps to staff.
Right: China and unattributed APTs
- APT41 hit at least six US state governments.
- It re-compromised victims in late February 2022.
- PRC actors compromised telecoms through network devices.
- A defense contractor held intruders for about a year.
Notes: Albania [45][46]; OFAC and the MOIS [76]. MuddyWater as an MOIS element [20]. Ronin and Blender.io [24]. TraderTraitor [34]. Chrome zero-day [3]. APT41, campaign C0017 [21]. AA22-158A [39]. AA22-279A [60]. Defense Industrial Base intrusion [2].

## PART 4 | People and sessions, not code, opened the best-known breaches

- **Okta:** a Sitel engineer's workstation, controlled for 25 minutes, reached two customer tenants.
- **LAPSUS$:** bought credentials, MFA prompt spamming, SIM swaps, help-desk social engineering and insiders; no ransomware.
- **Cisco:** VPN access through an employee's personal Google account.
- **SMS phishing:** 76 Cloudflare staff targeted, Twilio reached; FIDO2 keys held at Cloudflare.
- **Uber:** a bought contractor password, then repeated approval requests until one was accepted.
Caption: That identity led several of the year's best-known breaches is the study's reading (Inferred).
Notes: Okta, first estimate 366 customers [9]. DEV-0537 [23]. Cisco Talos [50]. Cloudflare [48]; Twilio [42]. Uber, LAPSUS$ link is Uber's belief [57]. CISA phishing-resistant MFA fact sheet [117].

## PART 5 | Monthly ransomware advisories from June, sanctions on the money

- **June to December:** at least one joint advisory a month, on Karakurt, MedusaLocker, Maui, Zeppelin, Vice Society, Daixin, Hive and Cuba.
- **Hive** had more than 1,300 victims and about $100 million in payments.
- **Conti** disrupted Costa Rica's customs and tax platforms in April.
- **LockBit** was the most deployed variant of 2022, per AA23-165A.
- **Treasury sanctioned** Hydra and Garantex, Blender.io and Tornado Cash.
Notes: Advisories [81][43][44][51][55][66][69][70]. Hive, June 2021 to November 2022 [69]. Costa Rica [32]. LockBit 3.0 and the builder leak [82]. Sanctions [28][24][49]. Medibank [65][83]. Home study for the ransomware record: The Ransomware Ecosystem.

## PART 6 | Edge and server flaws were exploited within days, or before a fix

| CVE | Product | What happened | KEV added |
|---|---|---|---|
| CVE-2022-0609 | Chrome | Exploited from 4 January | 2022-02-15 |
| CVE-2022-22954 | VMware Workspace ONE | Exploit built within 48 hours | 2022-04-14 |
| CVE-2022-1388 | F5 BIG-IP | Authentication bypass | 2022-05-10 |
| CVE-2022-26134 | Confluence | Likely a zero-day | 2022-06-02 |
| CVE-2022-41082 | Exchange | Chained in August, patched 8 Nov | 2022-09-30 |
| CVE-2022-40684 | FortiOS | Authentication bypass, exploited | 2022-10-11 |
| CVE-2022-42475 | FortiOS SSL-VPN | Exploited in the wild | 2022-12-13 |
Caption: OpenSSL's pre-announced Critical flaw shipped as High, with no known working exploit, and is not in KEV.
Notes: Rows [89][3][90][29][91][38][87][59][62][71][27]. Spring [26]. Follina [37]. Citrix CVE-2022-27518 [72]. OpenSSL [67]. AA23-215A on older flaws [87]. Log4Shell's second year, home study Log4Shell [41][68].

## PART 7 | Tokens, vault backups and registries carried customer data out

Left: The developer estate
- Heroku's GitHub OAuth tokens were stolen and used.
- GitHub saw private repositories downloaded, npm's among them.
- LastPass lost a vault backup from cloud storage.
- torchtriton hit PyTorch nightly installs on Linux.
Right: Data exposure
- The ICRC: data on more than 515,000 people.
- Optus: about 9.5 million Australians, the OAIC alleges.
- Medibank: 9.7 million Australians, the OAIC alleges.
- The FTC held Drizly's CEO to a security order.
Notes: Heroku [96]. GitHub [95]. Slack tokens [98]. LastPass [54]. torchtriton [97]. ICRC [1]. Optus [100][58]. Medibank [65]. Drizly [101]. Microsoft's misconfigured endpoint and SOCRadar's overstated scope [99].

## PART 9 | Governments wrote reporting laws and asset-visibility rules

- **CIRCIA,** 15 March: 72-hour incident and 24-hour ransom payment reporting once the final rule takes effect.
- **The SEC** proposed incident and governance disclosure rules on 9 March.
- **BOD 23-01,** 3 October: asset discovery every 7 days, vulnerability enumeration every 14.
- **The Cyber Resilience Act** was proposed on 15 September; NIS2 followed in January 2023.
- **ED 22-03** answered the VMware flaws exploited within 48 hours.
Notes: CIRCIA [102][103]. SEC [104]. BOD 23-01 [109]. CRA [108]; NIS2 [114]. ED 22-03 [29]. OMB M-22-18 [107]. EO 14086 [110]. UK PSTI Act [112]. Quantum Computing Cybersecurity Preparedness Act [113]. ATT&CK v12 added campaigns [120].

## MITRE MAPPINGS | 116 Enterprise rows and 17 ICS, identity and impact at the centre

| Id | Technique | 2022 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Edge devices, ICRC, APT41 |
| T1078 | Valid Accounts | Uber's bought contractor password |
| T1621 | Multi-Factor Authentication Request Generation | DEV-0537 and Uber |
| T1199 | Trusted Relationship | Okta through Sitel; MSPs |
| T1495 | Firmware Corruption | KA-SAT modem flash |
| T1657 | Financial Theft | Wormhole, Ronin, Harmony, BNB |
| T0831 | Manipulation of Control (ICS) | October Sandworm outage |
Caption: ATT&CK v20.0 ids; revoked advisory ids mapped through superseded_by.jsonl; two Navigator layers. MITRE notice in the notes.
Notes: Rows [74][39][1][21][57][23][9][118][19][10][24][40][61][63]. Basis scores in the layers: 100 Source, 70 Behavior [130]. T1562 and T1562.001 in the advisories map to T1685 [122]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Phishing-resistant MFA and the KEV clock mattered most

Left: What 2022 taught
- Make MFA phishing-resistant before making it universal.
- Treat edge and management appliances as tier-zero assets.
- Give every path into a management plane an owner and MFA.
- Keep offline, immutable, tested backups for the wiper case.
Right: Where to look
- Bursts of MFA prompts to one user.
- New MFA devices on dormant accounts.
- Web shells on Exchange and tunnelling tools on servers.
- Native SCADA binaries issuing commands outside change windows.
Caption: CISA said systems not patched for Log4Shell after December 2021 should be treated as compromised.
Notes: Recommendations [48][42][22][117][41][29][19][9][118][17][69][70], with the generalizations Inferred. Hunting cues [23][22][57][59][68][63]; the cues are the study's reading. Log4Shell [41].

## CROSS-CUTTING THEMES | Destruction returned, and first estimates ran high

- **Destruction came back at scale:** wipers, a modem wipe by management command, a grid attempt and an outage in ten months.
- **The management plane is the crown jewel:** KA-SAT, Okta's support tools, MSPs and AD FS.
- **Old flaws, long dwell:** a 2019 SharePoint flaw opened Albania; intruders stayed a year or more.
- **Overstated:** Okta's 366 customers (two tenants), OpenSSL's Critical (High) and Log4Shell as a 2022 catastrophe.
- **Understated:** identity-only extortion, dwell time and the Ukraine record beyond a handful of cases.
Notes: Destruction [17][19][31][63]. Management plane [19][9][118][53]. Old flaws and dwell [45][87][46][2]. Overstated [9][67][106]. Understated [23][46][2][68][36][63]. The themes are the study's reading (Inferred).
