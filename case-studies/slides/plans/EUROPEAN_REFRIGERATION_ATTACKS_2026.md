# Slide plan: Refrigeration-Controller Attacks on European Supermarkets and Blood Services, 2026: A Case Study

- Study: case-studies/EUROPEAN_REFRIGERATION_ATTACKS_2026.md
- Cover title: Refrigeration-Controller Attacks / European Supermarkets and Blood Services / 2026
- Subtitle: When the weapon was a defrost setting on an exposed, out-of-support controller
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/EUROPEAN_REFRIGERATION_ATTACKS_2026.md, told from the CERT-FR, French government, CISA, NVD, KEV, EU, NCSC Ireland and vendor record, with research and press graded as Reported. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Someone turned the cold rooms up

- **11 to 12 October 2026:** about 700 French retail sites had defrost set high; food spoiled and at least 15 fires started.
- **1 to 2 November:** a second wave reached stores in seven more countries and three French blood-service sites.
- **9 November:** France attributed the October wave to the IRGC's Shahid Kaveh unit.
- **No government named a CVE for access,** and none of these controllers' CVEs is in KEV.
- **The record points to exposure,** end-of-life units and, at one site, default credentials.
Caption: Grades: the French wave and attribution Confirmed; the November wave and EFS Reported; the access path Inferred.
Notes: French wave [2]. Second wave [22][29][30]; EFS [23]. Attribution [3][2]. No CVE named [18]; KEV [10]. Access path [1][4][15][25].

## KEY FACTS | National-scale sabotage with nothing in KEV

Stat: ~700 | French retail sites hit overnight
Stat: 15+ | fire starts in the October wave
Stat: 3 | French blood-service sites in November
Stat: 0 | controller CVEs in KEV at 2026.11.10
- Equipment CERT-FR names: Danfoss AK-SM and AK-SC; Copeland and Dixell xweb.
- Food losses of several tens of millions of euros, per France.
- EFS lost no blood products; alarms caught the change.
Notes: Sites and fires [2][3]. EFS [23][31]. KEV catalogVersion 2026.11.10 [10]. Equipment [1]. Losses [3].

## PART 1 | Two waves in four weeks

| Date | Event |
|---|---|
| 11 to 12 Oct | About 700 French retail sites compromised |
| 12 Oct | CERT-FR alert CERTFR-2026-ALE-012 |
| 14 Oct | Copeland bulletin on XWEB |
| 1 to 2 Nov | Second wave across Europe and three EFS sites |
| 3 to 5 Nov | NCSC Ireland, CNW-2026-05, EU joint statement, US fact sheet |
| 9 Nov | France attributes the October wave to Iran |
Caption: Reconnaissance on port 502 from April 2026 and freezer failures at US commissaries in August are in the study's timeline.
Notes: French wave [2][3]. ALE-012 [1]. Copeland [4]. Second wave [22][23][29]. Advisories [15][14][13][11][12]. Attribution [2][3].

## PART 2 | The effect came from settings, not new code

- Actors forced continuous heating and defrost cycles; effects include fire hazard and denial of view.
- Alarm thresholds were changed, which delayed detection.
- At one examined site: default Administrator credentials, 31 devices read, 743 changes.
- Setpoints of 110 C and 150 C, muted alarms and locked keypads at that site.
- No evidence links that site to the other incidents.
Caption: The US fact sheet lists vector classes only: authentication bypass, code injection and weak configurations.
Notes: Fact sheet [11]. Alarm thresholds, Sekoia [19] Reported. Ransom-ISAC site [25] Reported. Vector classes [11].

## PART 2 | The CVE record is real but unnamed as the way in

| CVE | Product | Weakness |
|---|---|---|
| CVE-2025-41450 | Danfoss AK-SM 8xxA | Authentication bypass |
| CVE-2025-41451 | Danfoss AK-SM 8xxA | Command injection |
| CVE-2026-25085 | Copeland XWEB Pro | Authentication bypass |
| CVE-2026-21718 | Copeland XWEB Pro | Pre-auth code execution |
| CVE-2026-24663 | Copeland XWEB Pro | OS command injection |
Caption: No government source says any of these was used; Copeland's XWEB EVO flaw is in an end-of-life line with no fix.
Notes: Danfoss [5][6]. Copeland [7][8]. Research [9]. Absence from CNW-2026-05, the US fact sheet and KEV [14][11][10] (Inferred). XWEB EVO [4].

## PART 2 | Exposure fell fast once people looked

Stat: ~3,000 | exposed Danfoss panels, 11 Oct (Censys via SecurityWeek)
Stat: 537 | French count by 14 Oct
Stat: 5,000+ | named-vendor devices worldwide, 5 to 6 Nov
- Sekoia honeypots saw enumeration from 13 October and default-account spraying.
- One confirmed exploitation attempt, 1 November: about 30 minutes, blocked.
- Sekoia assesses it used a non-public flaw, not CVE-2025-41450.
Notes: Censys counts relayed by SecurityWeek [21] Reported. Unit 42 count [18] Demonstrated. Honeypots [19] Demonstrated; the assessment is Reported.

## PART 3 | Attribution is narrower than the headlines

Left: What France says
- C4 attributes the October wave to the Shahid Kaveh unit, IRGC sponsor.
- Evidence: Modbus scanning, the FOFA service, CyberbanNews, Farsi traces.
- Personas include CyberAveng3rs and Soldiers of Solomon.
Right: What it does not cover
- The November wave and EFS are outside France's statements.
- NoName057(16) and Z-Pentest claims are unverified.
- Belgium's CCB said the perpetrators may never be known.
Caption: ATT&CK's G1027 CyberAv3ngers carries the alias Soldiers of Soloman; matching it to Shahid Kaveh is Inferred.
Notes: C4 [2]; statement [3]. Scope [3] Inferred; EFS exclusion [28] Reported. Claims [18][19]. CCB [29]. G1027 [17].

## PART 4 | Who was hit

| Who | What happened |
|---|---|
| French retail | About 700 sites; fires and goods losses |
| French hydroelectric sites | Schneider Electric devices, moderate effects |
| Second wave | 50+ Belgian stores; Sweden, Ireland, Estonia and more |
| UK meat suppliers | Three compromised via Copeland XWEB; no meat lost |
| EFS blood service | Three sites via a refrigeration provider; no product lost |
Caption: Alarms, on-call staff and one physically unplugged fridge limited the harm.
Notes: French retail and hydro [2][3]. Second wave [22][29] Reported. UK [30] Reported. EFS [23][24][31] Reported. Unplugged fridge [30].

## PART 4 | Governments warned; vendors pointed at legacy units

| Who | What they said |
|---|---|
| CERT-FR | First alert and two updates; campaigns probably still under way |
| EU CSIRTs Network | CNW-2026-05 indexes national alerts; names no CVE |
| EU joint statement | No actor named; CRA and NIS2 reporting urged |
| US joint fact sheet | No actor, vendor or CVE named |
| Danfoss | Limited number affected, mostly legacy products |
| Copeland | Some XWEB solutions affected; guidance re-sent |
Caption: Manufacturer reporting under the Cyber Resilience Act applies from 11 September 2026.
Notes: CERT-FR [1]. CNW-2026-05 [14]. EU statement [13]. US fact sheet [11]. Danfoss [21] Reported. Copeland [21][32] Reported.

## PART 5 | What is overstated and what is understated

Left: Overstated
- That Iran hit about 700 sites and the blood bank.
- The 110 C EFS figure, which comes from a newspaper.
- CVE-2025-41450 as the vector: speculation.
Right: Understated
- Exposure, end-of-life units and default credentials.
- Re-compromise of reset end-of-life units.
- The same infrastructure scanned energy and water equipment.
Caption: Ahold Delhaize's reported revenue hit concerns a separate October incident.
Notes: Overstated [3][28][32][18][19]. Understated [1][4][25][2]. Ahold Delhaize [35] Inferred.

## DEFENDER VIEW | Take the controllers off the internet

- Remove all public exposure; remote access only through a VPN or protected network.
- Check defrost ranges, setpoints, alarm settings and user accounts.
- Retire or isolate end-of-life units: a reset alone invites re-compromise.
- Change default passwords; set Danfoss units to security level Strict.
- Keep setpoint limits, deviation alerts and alarms independent of the controller.
- Put contractor-managed supervisors and their remote paths in the inventory.
Caption: A KEV-ranked program would not have flagged these controllers.
Notes: Exposure [1][4][15][12]. Checks [1][4][15]. End of life [1][4]. Passwords [1][15]. Alarms [12][34]. Inventory and KEV lens are Inferred [10].

## MITRE MAPPINGS | Fourteen techniques across ICS and Enterprise

| Id | Technique | Tie to the record |
|---|---|---|
| T0883 | Internet Accessible Device | Exposed controllers |
| T1694.001 | Default Credentials | Default Administrator account |
| T0836 | Modify Parameter | Defrost and setpoints set high |
| T0838 | Modify Alarm Settings | Thresholds altered, alarms muted |
| T0879 | Damage to Property | 15+ fire starts |
| T1596.005 | Scan Databases | FOFA scanning service |
Caption: ATT&CK v20.0; two Navigator layers. Object: G1027 CyberAv3ngers, no library page.
Notes: ICS [1][15][19][25][2][23][11][3]. Enterprise [2][19][11][25][23][31]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Maintenance functions are attack surface

- **The weapon was a setting:** the defrost cycle the equipment already has.
- **End of life is a security state:** no fix path means isolate or replace.
- **Outsourced assets stay in scope:** EFS was reached through its provider.
- **KEV is silent here:** national-scale sabotage with nothing listed.
- **Attribution arrives late and narrow:** four weeks, one wave of two.
Caption: Overstated: Iran hit 700 sites and the blood bank. Understated: exposure and end of life, not a named CVE.
Notes: Settings [2][11]. End of life [1][4][21]. Outsourcing [23] Inferred. KEV [10]. Attribution [3]. Overstated and understated [3][28][32][18][19][1][4][25].
