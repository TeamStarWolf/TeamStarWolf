# Slide plan: Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution

- Study: case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md
- Cover title: Industrial Control System / Attacks and Advisories, / 2024 to 2026
- Subtitle: Incidents, CVEs and attribution: the disruptive attacks rarely needed a new CVE
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Attacks on controllers moved from defacement to physical effect

- Heat went off in more than 600 apartment buildings in Ukraine in January 2024; Lviv is the reported location.
- More than 30 Polish wind and solar farms lost contact with their grid operator on 29 December 2025.
- Water utilities in at least seven US states reported tampered PLCs, loss of pressure and flooding from 27 July 2026.
- Over the same period CISA published 1,389 ICS and medical-device advisories with more than 2,000 unique CVEs a year.
- Nearly every disruptive event with a stated access path used default passwords, exposed ports and native engineering tools, not a new CVE (Inferred).
Caption: Grades: incidents, advisories and counts are Confirmed; Norway, Denmark, Kansas, Minnesota and Asahi rest on press reports (Reported).
Notes: Lviv outage [5], location [4]. Poland [20]. US water [31]. Advisory and CVE counts, computed from CISA's CSAF repository [37]. Access paths [1][12][21][29][31]; the generalization is Inferred. Grades from the study's evidence-grade paragraph.

## KEY FACTS | A flood of advisories, and only a trickle in KEV

Stat: 1,389 | CISA ICS advisories with 2024 to 2026 ids
Stat: 2,426 | unique CVEs in the 2026 advisories
Stat: 21 | of those 2,426 are in KEV; 19 are IT parts
Stat: 54 days | median NVD-to-KEV gap, 13 OT-product CVEs
- Siemens advisories carry 70.0%, 59.2% and 50.9% of each year's unique CVEs, mostly third-party component bulletins.
- Only 5 of the 714 KEV entries added since 1 January 2024 cite a CISA ICS advisory.
- Rockwell CVE-2021-22681 waited 1,828 days between NVD publication and KEV.
Notes: 422, 506 and 461 advisories by id year [37]. Unique CVEs 2,041, 2,302 and 2,426 [37]. KEV at catalogVersion 2026.11.03, 1,767 entries [40]. 19 IT components such as Linux, Chromium, Fortinet and PAN-OS [37][40]. NVD-to-KEV gap [42]. Siemens share [37].

## PART 1 | Heat, water and wind farms felt the attacks

| Date | Event | What happened |
|---|---|---|
| Nov 2023 to Jan 2024 | Unitronics PLC defacements | At least 75 US devices, at least 34 in water; ladder logic erased |
| Jan 2024 | FrostyGoop | Heating out for over 600 buildings, about two days |
| Apr 2025 | Bremanger dam, Norway | A valve ran open for four hours (Reported) |
| 29 Dec 2025 | Poland energy attack | RTU damage cut operator links; production continued |
| From Mar 2026 | AA26-097A PLC campaign | Logic changed, alarms and shutdown logic disabled |
| From 27 Jul 2026 | US water, MicroLogix | Seven states; loss of pressure and flooding |
Caption: Several of the events with the clearest physical effect name no actor in the sources opened.
Notes: Unitronics [1]. FrostyGoop [5][85][4][72]. Bremanger, about 500 litres per second, over 7.2 million litres [14][15]. Poland [20][21]. AA26-097A [29][30]. US water [31]; CISA alert [32]. Minnesota, more than 30 systems, Reported [33]. Unattributed events [31][33][19][17].

## PART 1 | Iran escalated from erased ladder logic to disabled alarms

Left: 2023 to 2024
- IRGC-affiliated actors logged in to Unitronics PLCs on TCP 20256 with default or empty passwords.
- They erased the ladder logic and left an anti-Israel message.
- Treasury sanctioned six IRGC-CEC officials; the operation did not disrupt critical services.
- Claroty found the IOCONTROL implant on a Gasboy fuel control system.
Right: 2026
- AA26-097A: exposed Rockwell, Schneider and Siemens PLCs reached with the vendors' own programming software.
- Project logic modified and deleted; HMI and SCADA displays manipulated.
- Shutdown and alarm logic disabled; disruption and financial loss for some victims.
- The advisory names no group and calls CyberAv3ngers only "similar".
Caption: AA26-097A links the escalation, with a "likely", to hostilities between Iran and the United States and Israel.
Notes: AA23-335A [1]. Treasury [2]. IOCONTROL, with Team82's "allegedly" kept [3]. AA26-097A and its July update [29][30]. BAUXITE and PYROXENE wipers in June 2025 [26]. June 2025 fact sheet [28].

## PART 1 | Russia's services worked through personas, which overclaim

- The DOJ alleges the GRU founded, funded and directed CARR; CISA and partners assess unit 74455 likely supported its creation.
- CISM created NoName057(16) as a covert project, according to AA25-343A.
- The shared method: scan for VNC on ports 5900 to 5910, guess or skip the password, change HMI settings.
- Mandiant could not verify CARR's water and hydro claims; Claroty counted about 500 bricked Fuxnet gateways against 87,000 claimed.
- In Ukraine the record is wipers: ZEROLOT and Sting from April to September 2025, and ELECTRUM against eight ISPs.
Caption: AA25-343A says the groups often make false or exaggerated claims and portray minor incursions as significant breaches.
Notes: DOJ [11]. AA25-343A [12]. Mandiant [8]. Fuxnet [61]; Blackjack disputed the count [5]. TwoNet's honeypot claim [18]. Wipers [25][26]. APT44 [9][8].

## PART 1 | Poland, 29 December 2025: the most destructive event

Stat: 30+ | wind and solar farms hit
Stat: ~500,000 | heat customers of the targeted CHP plant
- RTU damage cut communication with the distribution operator, but energy production continued; EDR blocked the wiper at the CHP plant.
- Hitachi RTUs that supported secure update did not have it on; firmware went in through a web interface "Default" account.
- LazyWiper was likely written largely with a large language model and cannot be used for attribution, says CERT Polska.
Notes: CERT Polska incident and report [20][21]. Almost half a million heat customers [20]. CVE-2024-2617 would have bypassed secure update but was not needed [21]. LazyWiper [21][24].

## PART 1 | China pre-positions in IT, and ransomware stops the lines

Left: Pre-positioning
- Volt Typhoon held some victim IT footholds for at least five years (PRC state-sponsored, high confidence).
- One lateral move to a control system; no OT disruption in AA24-038A.
- Dragos: VOLTZITE reached US midstream pipelines through Sierra Wireless AirLink gateways.
- SYLVANITE handed VOLTZITE edge-device access.
Right: Ransomware
- Dragos counts 119 ransomware groups hitting industrial organizations in 2025, up from 80.
- About 3,300 organizations affected; manufacturing was more than two-thirds of victims.
- Average OT dwell time of 42 days.
- Jaguar Land Rover shut its systems down on 2 September 2025.
Notes: AA24-038A [6]. VOLTZITE and SYLVANITE as Dragos assessments [26][27]. Littleton dwell time, Reported [7]. Ransomware counts [26][27]. JLR [34]. Asahi, Reported [35].

## PART 2 | The CVE count measures supply chains more than attacks

Stat: 455 | CVEs in one Siemens bulletin, 2024
Stat: 486 | CVEs in one Siemens bulletin, 2025
Stat: 428 | CVEs in one Siemens bulletin, 2026
- Those bulletins cover Linux-based subsystems and third-party components: Apache httpd, Python, QEMU, dnsmasq, the Linux kernel.
- Counted once per advisory, 2026 is led by CWE-306 Missing Authentication for Critical Function, in 78 advisories.
- Outside Siemens, CWE-306 rose from 20 advisories in 2024 to 38 in 2025 and 71 in 2026.
Caption: A CVE count from these bulletins measures the size of an embedded operating system, not a controller's attack surface (Inferred).
Notes: ICSA-24-102-01, ICSA-25-226-07 and ICSA-26-295-11 [37]. Per-CVE notes [37]. CWE counts per advisory [37]. The shift toward missing authentication is Inferred [37].

## PART 2 | KEV reaches OT late, and advisories lag the signal

| CVE | Product | NVD to KEV |
|---|---|---|
| CVE-2025-0994 | Trimble Cityworks | 1 day |
| CVE-2026-110936 | Siemens Software Center | 5 days |
| CVE-2025-67038 | Lantronix | 104 days |
| CVE-2021-26828 | OpenPLC ScadaBR | 1,636 days |
| CVE-2021-22681 | Rockwell Logix | 1,828 days |
- A Lantronix advisory updated on 8 October 2026 still said no exploitation had been reported, months after the KEV entry.
- The "no known public exploitation" line appears in 253 of 461 advisories with 2026 ids.
Notes: NVD records with the cisaExploitAdd date [42]. Cityworks [46]. Siemens SSA-580366 revised to reference exploitation [44][45]. Lantronix [47][40]. ScadaBR [18][40]. Rockwell [43]. Advisory wording [37].

## PART 3 | The disruptive events needed no new CVE

| Incident | How the actors got in | CVE named |
|---|---|---|
| Unitronics wave | Default or no password on TCP 20256 | Assigned afterwards (CVE-2023-6448) |
| Pro-Russia HMI intrusions | Exposed VNC; default, weak or no password | None |
| Poland, Dec 2025 | Web interface "Default" account | CVE-2024-2617 not needed |
| AA26-097A, 2026 | Exposed PLCs on 44818, 2222, 102 and 502 | None on the web page |
| US water, Jul 2026 | Internet-facing MicroLogix | None |
Caption: Where a CVE did appear it was old, assigned after the fact or unnecessary (Inferred from the table).
Notes: Unitronics [1][42]. HMI intrusions [12]. Poland [21][22]. AA26-097A [29][30]. US water [31]. Where the records meet: CVE-2021-22681 and the 2026 campaign, ScadaBR and the hacktivists, AirLink, Cisco and FSB Center 16 [42][40][29][18][26][21][54]; each link is Inferred.

## PART 4 | One event, three attributions: Poland shows the gap

| Source | Actor named | Basis and confidence |
|---|---|---|
| CERT Polska | Static Tundra / Berserk Bear / Dragonfly cluster | Infrastructure overlap |
| ESET | Sandworm, for DynoWiper only | Medium confidence |
| Dragos | ELECTRUM, which overlaps Sandworm | Moderate confidence |
| ATT&CK C0063 | Dragonfly and Sandworm Team | "Some" versus "other" reporting |
- Governments name sponsors (IRGC-CEC, GRU unit 74455, CISM, FSB Center 16, PRC); vendors name clusters; Telegram personas claim credit.
- Both readings can be true if one group built access and another ran the wiper (Inferred).
Notes: CERT Polska [21][20]. ESET [22]. Dragos [23]. C0063 [79]. FBI on FSB Center 16 [54]. Sponsors [2][12][11][54][6]. Operator and customer split [62]; access handoff [22][27].

## MITRE MAPPINGS | 43 ICS and 79 Enterprise techniques, two layers

| Id | Technique | Where it appears |
|---|---|---|
| T0883 | Internet Accessible Device | Unitronics, CyberAv3ngers, AA26-097A, Fuxnet, AA25-343A |
| T1694.001 | Default Credentials | C0031, G1027, AA25-343A, C0063 |
| T0829 | Loss of View | C0031, C0041, C0063, Fuxnet, AA25-343A |
| T0889 | Modify Program | G1027 CyberAv3ngers |
| T1693.001 | System Firmware | C0041 FrostyGoop, C0063 Poland |
| T1021.005 | VNC | AA25-343A hacktivist HMI intrusions |
Caption: ATT&CK v20.0 for ICS and Enterprise: G1027, G0034, G0035, G1017; C0031, C0041, C0063. MITRE notice in the notes.
Notes: ICS rows [70][71][12][29][76][79][72]; Enterprise VNC [12]. Revoked ids still in advisories: T0812 to T1694.001, T0855 to T1692.001, T0857 to T1693.001 [12][21][82]. ICS layer of 49 entries and Enterprise layer of 98 entries; a score of 100 means only that a cited source maps it. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Take controllers off the internet and protect the logic

Left: Close the doors
- Take PLCs, HMIs and programming ports off the internet; reach them through a gateway or jump host.
- Find undocumented cellular modems; use a private APN or zero-trust access.
- Change every default password; put phishing-resistant MFA on remote access.
- Practise manual operation, as Kansas and Minnesota utilities had to.
Right: Watch and rank
- Put Rockwell mode switches in RUN, turn on Siemens programming protection, compare running logic to known-good.
- Alert on PLC program, mode-change and Modbus write traffic from anything but an engineering workstation (Inferred, untested).
- Rank ICS CVEs by KEV, SSVC and exposure, not CVSS; patch IT components inside OT like IT.
Caption: Dragos found poor IT and OT segmentation in 81% of assessments; EPA found over 70% of inspected water systems in violation.
Notes: Primary OT mitigations [90]. AA26-097A steps [29]. Modems [32]. EPA [89]. Manual operation [10][33][90]. Detection design [96][97][86], Inferred. Prioritization [48][92][93][51]. Dragos figures [27].

## CROSS-CUTTING THEMES | The attack surface is configuration; advisories are code

- **Two records, two clocks.** Part 1 is default passwords and native tools; Part 2 is embedded operating systems and memory bugs.
- **Escalation runs through the logic layer.** From erased ladder logic in 2023 to disabled shutdown and alarm logic in 2026.
- **Loss of view is the common impact.** It is why manual operation keeps appearing as a mitigation.
- **Signals arrive out of order.** Exploitation shows on honeypots, then in KEV, and sometimes never in the advisory text.
- **Persona claims inflate the record.** The events with the clearest physical effect were claimed by no one in the sources opened.
Notes: Configuration versus code [1][12][29][37], Inferred. Logic layer [1][29][21], Inferred. Loss of view [12][31][90] and T0829 across events, Inferred. Signal order [18][40][47], Inferred. Personas [8][18][61][5][31], Inferred. Attribution layers, Z-Pentest's three framings [11][12][13].
