# Slide plan: The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study

- Study: case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md
- Cover title: The Citrix NetScaler / Zero-Days of / September and October 2026
- Subtitle: Three weeks of exploitation before the bulletin, and an appliance that held the keys
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Collect evidence, then patch, then rotate

- Administrators pulled appliances offline before Citrix said anything in public.
- Citrix published CTX697096 on Sunday 27 September; two CVEs were already exploited.
- KEV listed both that day with a three-day deadline and forensic triage.
- A third flaw, the SAML denial of service CVE-2026-88779, reached KEV on 4 October.
- Vendor researchers date exploitation from early September.
Caption: Evidence grade: Confirmed for the bulletins and KEV; the early-September start and the offline weekend are Reported.
Notes: Offline weekend [32][37]. Bulletin [1]. KEV [11]. Third flaw [2][11]. Start [25][26].

## KEY FACTS | Three KEV entries, three-day deadlines, no attribution

Stat: 3 | CVEs in KEV from this event
Stat: 3 | Days KEV allowed for each
Stat: 27 | Citrix entries in KEV
Stat: 0 | Actors named by any primary
- Product: customer-managed NetScaler ADC and Gateway 14.1 and 13.1, with FIPS and NDcPP builds.
- Full fixes: 14.1-73.41, 13.1-64.28, 14.1-73.41 FIPS or 13.1-37.282.
- Victims: two confirmed by Rapid7; larger counts are single-source press figures.
Notes: KEV entries and catalog count from catalog 2026.11.10 [11]. Attribution absence [25][26]. Product and builds [1][2]. Victims [27][43][45][46].

## PART 1 | From fingerprinting to the second bulletin

| Date (2026) | Event |
|---|---|
| 21 Aug | Version fingerprinting of more than 100 systems |
| Early Sep | CVE-2026-88772 campaign begins |
| 10 Sep | The NetScaler CNA reserves all three CVEs |
| 27 Sep | CTX697096; KEV adds CVE-2026-88771 and 88772 |
| 4 Oct | KEV adds CVE-2026-88779, due 7 Oct |
| 9 Oct | CVE-2026-107406 follows, SAML, CVSS 9.5 |
Caption: The fingerprinting and the campaign start come from vendor research (Reported); the rest is Confirmed.
Notes: Fingerprinting [26]. Campaign [25][26]. Reservation [5][6][7]. Bulletin and KEV [1][11]. Third flaw [2][11]. CVE-2026-107406 [20].

## PART 1 | The record disagrees with itself

- **Weakness.** Citrix and NVD give CWE-20 for CVE-2026-88771; KEV gives CWE-119.
- **Score.** CVE-2026-88772 is 9.5 on CVSS 4.0 and 8.1 on NVD's CVSS 3.1.
- **Exploited?** Citrix's bulletin for CVE-2026-88779 has no exploitation statement; KEV lists it.
- **One reservation day.** All three CVEs were reserved on 10 September.
Caption: Scanners and dashboards keyed on one feed can point in different directions (Inferred).
Notes: Weakness [1][8][11]. Score [8][9]. Exploitation [2][7][11]. Reservation [5][6][7].

## PART 2 | Three flaws, at advisory level

| CVE | Class | Precondition |
|---|---|---|
| CVE-2026-88771 | Unauthenticated RCE, CWE-20 | Default configuration |
| CVE-2026-88772 | Memory overflow, CWE-119 | DTLS enabled |
| CVE-2026-88779 | Memory overflow to DoS, CWE-119 | SAML SP or IdP |
Caption: The other six CVEs in CTX697096 are not marked exploited.
Notes: Classes, preconditions and scores [1][2][5] to [10]. Other six CVEs [1].

## PART 2 | What attackers did with root

Left: On the appliance
- Custom web shells, including WHIPSHOT behind native HTTP headers.
- A hidden PHP web shell behind a fake stylesheet path.
- Web-server configuration changes for persistence.
- Access logs scrubbed.
Right: Beyond the appliance
- SLAPSHOT, a Python tunneler, for manual internal reconnaissance.
- Credential harvesting.
- Configuration staged with bind secrets and TLS private keys.
- Those secrets survive any patch.
Caption: All of this is vendor research, graded Reported; watchTowr reproduced root-level execution (Demonstrated).
Notes: GTIG [25]. GreyNoise [28]. Rapid7 configuration theft [27]. watchTowr [29][30].

## PART 3 | No attribution, only suspicion and lineage

- No Citrix, CISA, NCSC UK, CERT-EU, NCSC-NL, GTIG or Unit 42 record names an actor.
- Mandiant's Consulting CTO suspects state-sponsored actors behind the first intrusions.
- After the public proof of concept, exploitation turned opportunistic.
- APT41 and Fox Kitten exploited earlier Citrix flaws; that is lineage, not evidence.
Caption: Later intrusions need not share an actor with the September ones (Inferred).
Notes: Absence [25][26]. Suspicion, Reported [46]. Opportunistic [45]. Lineage [53].

## PART 4 | The Netherlands switched itself off

- Central government disconnected its Citrix environments; remote civil servants could not log in.
- Z-CERT advised hospitals to take measures such as disabling the systems.
- Amphia and Elisabeth-TweeSteden patient portals were unavailable; care continued.
- An insurer warned customers before Citrix confirmed anything.
Caption: Self-inflicted downtime as a defensive choice, not a reported breach (Inferred).
Notes: Government [39]. Z-CERT [40]. Hospitals [41]. Insurer [36]. All Reported.

## PART 4 | Governments said: evidence before the patch

Stat: 3 | Days to remediate under KEV
Stat: 90 | Days of monitoring after recovery
- CISA: check indicators before patching and preserve evidence.
- NCSC-NL: treat appliances reachable before the update as possibly compromised.
- NCSC UK: isolate and replace, investigate, report, patch.
- BOD 26-04 ties KEV forensic triage to checking for compromise first.
Notes: KEV [11]. Monitoring [4][13]. CISA [13][14]. NCSC-NL [17][18]. NCSC UK [21][22]. BOD 26-04 [12].

## PART 5 | A patch does not undo three weeks

- Exploitation from early September outlived local log rotation on many appliances.
- Customers on 14.1-73.37 that use SAML had to upgrade a second time.
- CVE-2026-107406 followed on 9 October.
- A behavioural sensor flagged an attempt before any CVE signature existed.
Caption: Order the queue with KEV forensic triage and SSVC, not the CVSS score alone (Inferred).
Notes: Log rotation Inferred from [25][26]. Second upgrade [2][34]. CVE-2026-107406 [20]. Sensor, Reported [28]. KEV and SSVC [5][11].

## DEFENDER VIEW | Capture, patch, rebuild, rotate

Left: Before and during the patch
- Capture memory, disk and logs on any exposed appliance first.
- Forward logs off-box and keep a month.
- Disable DTLS or block inbound UDP/443 where patching lags.
- Never expose the management interface or NSIP.
Right: Recover
- Rebuild on current firmware.
- Rotate every secret the appliance stored, including keys and certificates.
- Reset Gateway and AAA users; investigate connected systems.
- Monitor for at least 90 days.
Notes: Evidence and logs [13][14][17][18]. Interim blocks, Reported [25]. Management interface [4][25]. Recovery [4][13].

## OVERSTATED AND UNDERSTATED | What the headlines got wrong in both directions

Left: Overstated
- Victim counts of dozens, 78 and over 100 are single-source and unreconciled.
- Exposure totals measure reachability, not compromise.
- "State-sponsored" is one executive's suspicion.
- CVE-2026-88779 as a third RCE goes beyond the primaries.
Right: Understated
- The three-week head start for attackers.
- Stolen bind secrets and TLS keys that survive any patch.
- The DoS flaw as a possible accelerator for injected code.
- The conflicts between feeds.
Notes: Overstated [27][43][45][46][2][10][11]. Understated [26][27][13][1][11]. Readings Inferred where labelled.

## MITRE MAPPINGS | Fifteen techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | CVE-2026-88771 and 88772 |
| T1505.003 | Web Shell | WHIPSHOT and others |
| T1572 | Protocol Tunneling | SLAPSHOT |
| T1552.004 | Private Keys | TLS keys in the configuration |
| T1070 | Indicator Removal | Access-log scrubbing |
| T1499.004 | Application or System Exploitation | SAML DoS |
Caption: ATT&CK v20.0; the other nine techniques are in the study's table and its Navigator layer. CWE-20, CWE-119, CWE-288.
Notes: Techniques and fit notes [1][11][13][25][27][28] with library data [52]. CWE [1][2][3][5][8][9][11]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The edge appliance is a standing exposure

- **Six Citrix KEV entries in 2026 alone.** 27 in all.
- **Patching starts the response.** Forensic triage is now written into KEV.
- **Disclosure timing is a public fight.** Rumours and CERT warnings beat the bulletin.
- **A low score can hide a role in the chain.** The DoS flaw may speed code execution.
- **Automation follows the proof of concept.** Attempts came within minutes.
Notes: KEV counts [11]. Forensic triage [11]. Timing [32][36][37]. DoS role [7][13]. Proof of concept [45]. The lessons are Inferred.
