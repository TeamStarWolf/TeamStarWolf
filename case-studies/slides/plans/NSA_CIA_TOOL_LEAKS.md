# Slide plan: The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017

- Study: case-studies/NSA_CIA_TOOL_LEAKS.md
- Cover title: The Shadow Brokers and Vault 7 / The NSA and CIA Tool Leaks / 2016 to 2017
- Subtitle: Two leaks, one insider conviction, an early patch and two worms that reused the exploits
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/NSA_CIA_TOOL_LEAKS.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The people who paid for the leaks never met the leakers

- The Shadow Brokers posted NSA-linked "Equation Group" tools from 13 August 2016.
- WikiLeaks published CIA Center for Cyber Intelligence material as Vault 7 from 7 March 2017.
- A CIA developer was convicted for the Vault 7 theft; no record names the Shadow Brokers.
- MS17-010 fixed the SMBv1 flaws a month before the April 2017 Windows release.
- WannaCry and NotPetya reused the exploits 59 and 105 days after the patch.
Caption: Grades: Confirmed from vendor, court and government primaries; the leakers' posts are cited as their own claims.
Notes: Leaks [2][3][33]. Court record [39][40]. Shadow Brokers identity Inferred [28][29][31]. Patch [15][18]. Intervals Inferred from [15][20][23]. NHS [44].

## KEY FACTS | An early patch, a long tail and a 40-year sentence

Stat: 31 days | MS17-010 before "Lost in Translation"
Stat: 81 of 236 | NHS trusts in England infected by WannaCry
Stat: 180 GB+ | CIA DevLAN loss, as much as 34 TB
Stat: 40 years | Schulte's sentence, 1 February 2024
- Kaspersky found 347 RC5/RC6 instances tying the 2016 archive to Equation malware.
- The CIA learned of its loss from WikiLeaks, about a year after the theft.
- KEV listed the six MS17-010 CVEs between November 2021 and May 2022.
Notes: Interval Inferred from [15][7]. NHS [44]. CIA loss and discovery [42]. Sentence [39]. Kaspersky [2]. KEV [24].

## PART 1 | Two leaks, two very different records

| Item | Shadow Brokers | Vault 7 and Vault 8 |
|---|---|---|
| Source | NSA-linked tools | CIA CCI material |
| First post | 13 Aug 2016 | 7 Mar 2017 |
| Publisher | The group itself | WikiLeaks |
| Who took it | Unresolved | A CIA developer, per the court |
| Official review | None opened | CIA task force, Oct 2017 |
Caption: ATT&CK holds G0020 Equation with no sponsor named, and no object for any leaked tool.
Notes: Shadow Brokers [2][3]. Vault 7 [33][39]. Task force [42]. ATT&CK [25][77]. Identity Inferred [28][29][31].

## PART 3 | The first targets were firewalls, not Windows

- Cisco was alerted on 15 August 2016 and published two ASA advisories two days later.
- CVE-2016-6366 (EXTRABACON) was new; CVE-2016-6367 was fixed since ASA 8.4(3).
- Cisco named a persistent implant, JETPLOW, and pointed to signed software and Secure Boot.
- PIX and the Firewall Services Module never received a fix for CVE-2016-6366.
- Both Cisco CVEs reached KEV on 24 May 2022.
Caption: Fortinet's FG-IR-16-023 the same day does not mention the leak, so the study does not count it.
Notes: Cisco [11][12][13]. KEV [24]. Fortinet [14].

## PART 3 | The April release met a patch already shipped

| Exploit | Microsoft's finding |
|---|---|
| EternalBlue, EternalRomance and two more | Fixed by MS17-010 |
| EmeraldThread, EducatedScholar | Fixed by MS10-061, MS09-050 |
| EclipsedWing, EsikmoRoll | Fixed by MS08-067, MS14-068 |
| Three more | Did not reproduce on supported platforms |
Caption: MS17-010 credits no finder and marked the flaws not public and not exploited at release.
Notes: Release [7]. MSRC mapping, 15 April 2017 [18]. Bulletin [15]. Talos [19]. Countercept script [68].

## PART 4 | WikiLeaks' framing outran the CIA's own assessment

Left: What WikiLeaks said
- The CIA had lost control of the majority of its hacking arsenal.
- The archive circulated among former government hackers and contractors.
- 26 disclosures ran from March to November 2017.
Right: What the record shows
- One developer took the files, per the court record.
- The task force judged WikiLeaks did not hold the "Gold" folder.
- Cisco found CVE-2017-3881 while analyzing the documents.
Caption: WikiLeaks' claims are graded Reported; the DOJ count and task force findings are Confirmed.
Notes: WikiLeaks [33][34][35]. DOJ count [39]. Task force [42]. Cisco [71].

## PART 5 | An insider with a kept session on an unmonitored network

- 20 April 2016: restored revoked privileges, copied the CCI archives, deleted hundreds of logs.
- The files went to WikiLeaks over Tails and Tor; his home drives were wiped on 5 May.
- The task force found security "woefully lax" and shared administrator passwords.
- DevLAN had no user activity monitoring, so the loss could not be sized exactly.
- Convicted on eight counts in July 2022; sentenced to 40 years in February 2024.
Caption: The CIA learned of the loss from WikiLeaks' announcement, about a year after the theft.
Notes: Court record [39][40][38]. Task force [42]; release date Reported [43].

## PART 6 | No primary record names the Shadow Brokers

- Harold Martin: nine years for willful retention; the release says nothing of the group.
- Nghia Pho: 66 months for willful retention; no mention of any leak.
- Kaspersky's 2014 detection of suspected Equation code on a US system is its own account.
- The links to the group in public retellings come from journalism.
- Kaspersky's match is to its Equation cluster, not to the leakers.
Caption: Two retention cases and one antivirus detection, none tied by a primary to the releases (Inferred).
Notes: Martin [28]. Pho [29]. Kaspersky [30][2]. POLITICO, Reported [31].

## PART 7 | From leak to worm in eight weeks

Stat: 59 days | Patch to WannaCry, 12 May 2017
Stat: 105 days | Patch to NotPetya, 27 June 2017
- WannaCry scanned for TCP 445 and spread with the MS17-010 SMBv1 exploit.
- Microsoft patched XP, Windows 8 and Server 2003 a day later, a "highly unusual step".
- NotPetya spread mainly by credential theft, PsExec and WMI, also by two SMB exploits.
- The US attributed WannaCry to North Korea and NotPetya to the Russian military.
Caption: No US government statement opened links either attack to the NSA.
Notes: Intervals Inferred from [15][20][23]. WannaCry [20][64][65][21]. NotPetya [45][23]. Attribution [46][47][50][51].

## PART 7 | The tools were out before the leaks and long after

- Buckeye (APT3) used a DoublePulsar variant from 31 March 2016, per Symantec.
- APT31's "Jian" clones the Equation "EpMe" exploit; its exploit carries an October 2014 timestamp.
- ESET saw EternalBlue attempts peak in April 2018 above the 2017 highs.
- AA24-249A recorded EternalBlue use by GRU Unit 29155 in 2024.
- ATT&CK campaign C0064 records an AI agent tasked with an EternalBlue attempt.
Caption: NotPetya has its home in the Sandworm study; the Equation platform in the United States actors study.
Notes: Buckeye [69]. APT31 [70]. ESET [73]. AA24-249A [79]. C0064 [80]. Routing [32].

## PART 10 | KEV trailed the patch by years

| Measure | Value |
|---|---|
| Patch to public release | 31 days |
| Release to vendor triage | 1 day |
| Patch to WannaCry | 59 days |
| Patch to KEV, CVE-2017-0144 | Almost five years |
| CVSS 3.1, CVE-2017-0144 | 8.8, no CWE assigned |
Caption: Treat a credible public exploit release as the exploitation date; KEV is a floor, not a schedule (Inferred).
Notes: Intervals Inferred from [15][7][18][20][24]. NVD [16][17]. Lessons Inferred [24][44].

## DEFENDER VIEW | Retire the protocol, plan for stolen credentials, watch insiders

Left: SMB and spread
- Patch MS17-010, including on custom-support systems.
- Remove SMBv1; block TCP 445, UDP 137 to 138 and TCP 139 at the edge.
- Restrict PsExec and WMI; block workstation-to-workstation traffic.
- Keep offline backups.
Right: Devices and insiders
- Restrict SNMP on ASA; retire PIX and FWSM.
- Verify firmware with signed images and Secure Boot.
- Monitor privileged users on development networks.
- No shared administrator passwords; protect logs.
Caption: The task force named user activity monitoring and compartmentation among its recommendations.
Notes: SMB [15][21][63][20][62][67]. NotPetya [23]. Devices [11][13][71]. Insiders [39][42].

## MITRE MAPPINGS | ATT&CK binds the reusers, not the leaked tools

| Id | Technique | Where it appears |
|---|---|---|
| T1210 | Exploitation of Remote Services | WannaCry, NotPetya, Bad Rabbit |
| T1003.001 | LSASS Memory | NotPetya credential theft |
| T1195.002 | Compromise Software Supply Chain | M.E.Doc updater |
| T1542.002 | Component Firmware | Equation firmware module |
| T1078 | Valid Accounts | Kept administrator session (Inferred) |
Caption: ATT&CK v20.0; 38 Enterprise and 3 ICS techniques. G0020 Equation, S0366 WannaCry, S0368 NotPetya, C0064.
Notes: Techniques [25][26][27][23][45][39][1]. Objects [25][26][27][74][80]. CAPEC, CWE and D3FEND [77][17]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Overstated identities, understated controls

- **Overstated.** Who the Shadow Brokers were, and that the leaks created the SMBv1 risk.
- **Overstated.** That the CIA lost "the majority" of its arsenal.
- **Understated.** The firewall half of the 2016 dump, and PIX and FWSM never fixed.
- **Understated.** Credential theft, the insider-control failure and the long tail.
- **Policy.** The VEP charter excludes already-public flaws; the PATCH Act died in committee.
Notes: Identity [2][22][25][28][29]. SMBv1 [67][62]. WikiLeaks [33][42]. Devices [11][12][24]. Credentials [23]. Insider [39][42]. Tail [73][24][79][80]. Policy [57][58][59]. The framing is Inferred.
