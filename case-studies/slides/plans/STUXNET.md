# Slide plan: Stuxnet: The Case Study

- Study: case-studies/STUXNET.md
- Cover title: Stuxnet / The Case Study
- Subtitle: A worm that crossed air gaps, rewrote PLC logic and showed operators a normal plant
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/STUXNET.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A plant off the internet was reached, and its controllers lied

- Stuxnet was a Windows worm with a second payload written for Siemens PLCs that drive frequency converters.
- It crossed air gaps on USB drives, used four zero-days plus MS08-067, and signed its drivers with compromised certificates.
- While the sabotage ran, it played recorded "normal" process values back to the operators.
- The IAEA recorded centrifuge changes at Natanz in 2009 and 2010 but never named a cause.
- No government has acknowledged building it in any source opened; the US and Israeli account rests on journalism.
Caption: Evidence grade: design and spread Confirmed; the Natanz causal link and the attribution Reported.
Notes: Symantec W32.Stuxnet Dossier on the goal and design [1]. Exploits [1][15]. Certificates [1][16]. Replay [1]. IAEA reports [35][36][37][38]. Press accounts [42][44][49].

## KEY FACTS | A narrow payload rode a worm that reached 155 countries

Stat: 100,000 | Infected hosts by 29 Sep 2010, about 60% in Iran
Stat: 4 + 1 | Zero-days, plus the older MS08-067 bug
Stat: 33 | Frequency converter drives the S7-315 payload required
Stat: 44 + 25 | Enterprise and ICS rows on ATT&CK S0603
- Earliest known version: Stuxnet 0.5, submitted to a scanning service on 15 November 2007; C&C domains from 3 November 2005.
- Public discovery: VirusBlokAda found samples on 17 June 2010; CERT/CC published VU#940193 on 15 July 2010.
- Coded stop date: infection stops after 24 June 2012 in the 1.x configuration.
Notes: Infection counts, over 40,000 external IPs in over 155 countries [1]. Exploits [15]. Drive count [1][2][14]. ATT&CK S0603 v1.5, v20.0 [30]. Version 0.5 dates [2]. Discovery [1][19][52]. Stop date [1][2].

## PART 1 | Five years of versions, from project files to a USB zero-day

| Version | Dates | How it spread |
|---|---|---|
| 0.5 | C&C domains from Nov 2005; seen Nov 2007; stops spreading 4 Jul 2009 | Only infected Step 7 project archives; no Microsoft flaw |
| 1.x, June 2009 | Earliest 1.x sample | autorun.inf on removable drives; no LNK exploit, no signed drivers |
| 1.x, March and April 2010 | First LNK (MS10-046) variant, March 2010 | LNK flaw, network routines, signed drivers |
| 1.x stop date | 24 June 2012 | Infection stops |
Caption: Kaspersky found a proto-Flame plugin inside the 2009 version's resource 207: the bridge to Flame.
Notes: Version labels from Symantec's 2013 paper [2] and the 2011 dossier [1]. 0.5 used the Siemens flaw CVE-2012-3015 to load its DLL and was partly based on the Flamer platform [2]. Resource 207, 520,192 bytes, holding a 351,768-byte file; Team F and Team D [4].

## PART 1 | Every Windows layer carried it in turn

| Route | Detail |
|---|---|
| Removable drives | LNK flaw ran the loader when a folder was merely viewed, no click needed |
| WinCC database | Hard-coded password (CVE-2010-2772, CWE-798) let it plant code in the database |
| Network shares | Copied as DEFRAG*.tmp, run by a scheduled job or WMI two minutes later |
| MS10-061 Print Spooler | Copied as winsta.exe; tried only before 1 June 2011 |
| MS08-067 Server service | The same bug Conficker used |
| Step 7 projects | Hooks made the Simatic manager load a dropped DLL when a project opened |
Caption: MS10-073 and a Task Scheduler flaw raised its privileges; peer-to-peer RPC kept versions updated.
Notes: Removable-drive files and the LNK flaw [1][16][20]. Five propagation routines [1][15]. CVE-2010-2772 in the wild July 2010 [18][28]. Print Spooler and MS08-067 [1][22][25]. Step 7 hooks, manager versions 5.3 and 5.4 SP4 [1]. Privilege escalation [1][3][23][24].

## PART 1 | Stolen signatures and a rootkit kept the Windows side quiet

Left: Signed drivers
- MrxCls.sys injected the payload; MrxNet.sys hid the .LNK and ~WTR files.
- Both drivers carried a compromised Realtek signature; one was signed on 25 January 2010.
- Windows showed no warning though the certificate expired in June 2010.
- On 17 July 2010 ESET found a driver signed with a JMicron certificate, revoked on 22 July.
Right: Guardrails and C2
- It exited on 64-bit hosts and skipped machines carrying the 19790509 registry marker.
- C2 ran over HTTP on port 80 to two domains pointing to Malaysia and Denmark.
- Data was XORed, hex-encoded and sent as index.php?data=.
Caption: Symantec dates the Realtek revocation to 16 July 2010 and ESET to 17 July; both are vendor primaries.
Notes: Drivers and file times [1]. Realtek signing and revocation [1][3][16]. JMicron [1][16]. Guardrails and the stop date [1]. C2 domains, 0xFF and the 31-byte key; Symantec monitored from 20 July 2010 [1].

## PART 1 | It waited 12.8 days, then pushed the S7-315 drives off range

Stat: 12.8 days | Monitoring before the first attack cycle
Stat: 1410 Hz | Maximum frequency, then 2 Hz, then 1064 Hz
Stat: 807 to 1210 | Hz range the attackers expected the drives to run in
- It ran only on a 6ES7-315-2 CPU with a CP 342-5 Profibus module and at least 33 Vacon NX or Fararo Paya drives.
- It halted the original OB1 and OB35 code and replayed recorded frequencies to WinCC.
- Langner reads it as a rotor-speed attack on IR-1 centrifuges, meant to stress rotors rather than destroy them at once.
Caption: Later cycles waited about 26.6 days; a flag in DB890 synchronized every S7-315 on the bus.
Notes: Target checks and sequences A and B [1]. Timing and frequencies [1]. Replay and the OB35 watchdog condition [1]. Langner's reading, 63,000 to 84,600 rpm and down to 120 rpm [14]. Grade: Confirmed as Langner's own analysis.

## PART 1 | The PLC rootkit answered every readback with clean code

Left: The S7-315 rootkit
- A fake s7otbxdx.dll replaced the library Step 7 uses to talk to PLCs; the original was renamed s7otbxsx.dll.
- Hooks on the block read and find calls hid its blocks and returned clean OB1 and OB35.
- Hooks on write and delete protected the infection from being overwritten.
Right: The S7-417 valve attack
- In 1.x the S7-417 routine is incomplete: DB8061 is never created.
- Stuxnet 0.5 carries it in full: 21 seconds of inputs replayed while valves close in six cascades.
- Symantec ties it to Natanz and says whether it succeeded is unknown.
Caption: Checking logic through the infected workstation could not reveal the change (Inferred from the mechanism).
Notes: PLC rootkit and hooks [1][15]. Sequence C in 1.x, six groups of 164 peripherals [1]. 0.5 valve attack in six of 18 cascades [2]. Langner's overpressure reading and the 2009 switch to the rotor-speed variant [14].

## PART 1 | All six flaws had fixes by December 2010; two are now in KEV

| CVE | Fix | Stuxnet use | KEV |
|---|---|---|---|
| CVE-2010-2568 (LNK) | MS10-046, 2 Aug 2010 | Removable-drive spread | Added 15 Sep 2022 |
| CVE-2010-2729 (Print Spooler) | MS10-061, 14 Sep 2010 | Network spread | Not listed |
| CVE-2008-4250 (Server service) | MS08-067, 23 Oct 2008 | Network spread | Added 20 May 2026 |
| CVE-2010-2743 (Win32k) | MS10-073, 12 Oct 2010 | Privilege escalation | Not listed |
| CVE-2010-3338 (Task Scheduler) | MS10-092, 14 Dec 2010 | Privilege escalation | Not listed |
| CVE-2010-2772 (WinCC password) | Siemens update, 2010 | WinCC database | Not listed |
Caption: Symantec's 0.5 paper lists CVE-2010-3888 for the Task Scheduler flaw; NVD notes the overlap.
Notes: Bulletins and dates [20][21][22][23][24][25]. CWE: CVE-2010-2772 is CWE-798 [28]. KEV [29]. ESET on the CRC32 check that MS10-092 replaced with SHA-256 [3]. The CVE-2010-3888 discrepancy [2][24][28].

## PART 2 | Infections began in 2009; the world learned of it in mid-2010

| Date | Event |
|---|---|
| 23 Jun 2009 | First initial infection, 12 hours after compile |
| 29 and 31 Jan 2010 | IAEA: centrifuges from 11 cascades of Unit A26 disconnected, no cause given |
| 17 Jun 2010 | VirusBlokAda reports the threat |
| 15 Jul 2010 | CERT/CC publishes VU#940193 on the LNK flaw |
| 2 Aug 2010 | MS10-046 published |
| 6 Aug 2010 | Symantec reports that Stuxnet injects and hides code on a PLC |
| 29 Sep 2010 | About 100,000 infected hosts in over 155 countries |
| Feb 2011 | Symantec W32.Stuxnet Dossier v1.4 |
Caption: Symantec cautions its timing data could be off because of time zones or wrongly set clocks.
Notes: Initial infections, ten in all, the last on 13 May 2010 [1]. IAEA GOV/2010/10 [36]. Discovery and advisories [1][19][52]. MS10-046 [20]. PLC report and the infection count [1]. Dossier [1].

## PART 3 | The IAEA recorded what changed at Natanz, never why

| Report | Date | What it records |
|---|---|---|
| GOV/2009/74 | 2 Nov 2009 | UF6 fed into 18 cascades of Unit A24 and 6 of Unit A26; 3,936 centrifuges fed |
| GOV/2010/10 | 29 and 31 Jan 2010 | 8,610 installed and 3,772 fed; the remaining 11 cascades of A26 disconnected |
| GOV/2010/62 | 5 to 22 Nov 2010 | 29 cascades fed on 5 Nov; none on 16 Nov; 28 on 22 Nov |
Caption: ISIS estimated about 1,000 IR-1 centrifuges replaced and called Stuxnet a reasonable but unproven explanation.
Notes: IAEA reports [35][36][38]. A full-text search of GOV/2009/74, GOV/2010/10, GOV/2010/46 and GOV/2010/62 found no use of Stuxnet, cyber or malware [35][36][37][38]. ISIS analysis; the 1,000 figure is ISIS's inference [39].

## PART 3 | Analysts traced the infections; authorship stays Reported

Left: What the analysts said
- Symantec traced about 12,000 infections to 10 initial ones at five organizations, all present in Iran.
- It cautioned twice against drawing attribution from the myrtus build path or the 19790509 marker.
- Kaspersky judged Equation and the Stuxnet developers the same or closely working; ATT&CK links no group to S0603.
Right: The press and the official record
- Press accounts citing anonymous officials describe a US and Israeli program called Olympic Games.
- In 2012 Michael Hayden called it "a good idea" and declined to speculate on authorship.
- A 2016 guilty plea in a leak case does not name Stuxnet or Iran.
Caption: No official acknowledgement by the US or Israeli government appeared in any source opened for the study.
Notes: Symantec on infections and the caution [1]. Kaspersky Equation assessment [6][7]; ATT&CK G0020 and S0603 [30][31]. Press accounts [42][44][49], Reported. Hayden on 60 Minutes [45]. Cartwright plea and pardon [47][48]. Absence of acknowledgement is Inferred.

## DEFENDER VIEW | Isolation is one control, and the screen is part of the attack

- **Treat the air gap as a control, not the defence.** NIST SP 800-82r3 says relying on air gaps alone is not enough.
- **Control removable media at every OT node.** Permit no unauthorized media and scan laptops and USB storage first.
- **Do not equate a valid signature with trust.** Watch for unusual driver loads and enable driver integrity protections.
- **Verify controller logic out of band.** Keep hashed offline backups and key switches in run with the key removed.
- **Remove hard-coded credentials and patch the Windows estate.** Every Windows exploit had a fix by 14 December 2010.
Caption: In the library's data, D3FEND IO Port Restriction and Hardware Component Inventory counter T1091 and ICS T0847.
Notes: NIST SP 800-82r3 [54]. Removable media guidance from 2010 [16][17] and NIST [54]. AA22-103A on signed drivers and offline backups [57]. Key switches [54]. CVE-2010-2772 [28]. Microsoft fixes [20][22][23][24][25]. D3FEND mapping [61].

## DEFENDER VIEW | Later ICS malware turned Stuxnet's lessons into reusable kits

| Year | Malware | What the primary says |
|---|---|---|
| 2016 | Industroyer / CRASHOVERRIDE | Dragos: Stuxnet was Siemens-specific and unique to Natanz; CRASHOVERRIDE codified process knowledge in a reusable framework |
| 2017 | TRITON / HatMan | Mandiant: follows Stuxnet and Industroyer in being able to stop safety mechanisms |
| 2022 | INCONTROLLER / PIPEDREAM | Mandiant: comparable to TRITON, INDUSTROYER and STUXNET, very likely state sponsored |
Caption: Dragos warns against treating an air-gapped network as a silver bullet: human defenders are required.
Notes: NIST on Industroyer and the 2017 SIS shutdown [54]. Dragos [55]. US-CERT TA17-163A [56]. Mandiant TRITON [58] and INCONTROLLER [59]. DHS HatMan [60]. AA22-103A [57].

## MITRE MAPPINGS | ATT&CK lists 69 technique rows on S0603 and links no group

| Id | Technique | Where it meets the record |
|---|---|---|
| T1091 | Replication Through Removable Media | autorun.inf in 2009; the LNK flaw from March 2010 |
| T1553.002 | Subvert Trust Controls: Code Signing | Driver signed with a compromised Realtek certificate |
| T0873.001 | Project File Infection: Siemens Project File Format | Step 7 project infection |
| T0836 | Modify Parameter | Drive frequencies set to 1410 Hz, 2 Hz and 1064 Hz |
| T0832 | Manipulation of View | Recorded values replayed to operators |
| T0851 | Rootkit | The PLC rootkit in the fake s7otbxdx.dll |
Caption: 44 Enterprise and 25 ICS rows in ATT&CK v20.0, with two Navigator layers. MITRE notice in the notes.
Notes: S0603 v1.5, last modified 24 April 2026 [30]. Rows [1][2][14][15][20][30]. Library data [61]. CWE-798 and CAPEC-70 for CVE-2010-2772 [28][32][33][61]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Trust anchors were borrowed, not broken

- **Precision is a design choice, and so is spread.** A narrow payload rode a worm to about 100,000 hosts.
- **The view is part of the attack surface.** Replayed values and clean readbacks deceived the screen operators trusted.
- **Trust anchors were borrowed, not broken.** Valid signatures, a vendor password and normal project sharing carried it.
- **Old bugs outlive their headlines.** MS08-067 was two years old when Stuxnet used it and entered KEV in 2026.
- **The record is lopsided.** Technical facts are Confirmed many times over; authorship remains Reported.
Notes: Payload checks and spread [1]. Replay and the rootkit [1][14]. Signatures [1], the WinCC password [28], Step 7 projects [1]. MS08-067 and KEV [25][29]. Overstated: destruction counts and attribution as fact [35][36][37][38][39][44][49].
