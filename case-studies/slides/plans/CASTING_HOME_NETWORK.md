# Slide plan: Casting on the Home Network: The Local Control APIs Behind Chromecast, DIAL and AirPlay, and Their Security Record

- Study: case-studies/CASTING_HOME_NETWORK.md
- Cover title: Casting on the Home Network / The Local Control APIs / and Their Security Record
- Subtitle: A feature that trusts the network, the bugs that were patched, the design that was not, and the separation you control
- Published: 25 November 2026
- Notes: Slide plan for the deck of the study case-studies/CASTING_HOME_NETWORK.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The local service that trusts the network

- Casting rests on a device that announces itself and answers commands on the local network.
- The local cast service required no authentication before 2019: it trusted the LAN.
- The record is a local hijack, two reads of the unauthenticated interface, a protocol weakness, and an internet exposure.
- Fixed by a patch, narrowed but not closed, a design no patch removes, and the owner's own network choice are different things.
Caption: Evidence grade: Confirmed for the researcher write-ups, records and advisory; Reported for the incident; Inferred where it reasons.
Notes: Two IoT design choices [2]. Rickmote [1]. Location leak [2], its figure via Krebs [3]. Account-linking [5]. DIAL [6]. CastHack [4][5]. AirBorne comparison [7][8][9]. The pile split is the study's framing (Inferred).

## KEY FACTS | The stack, the leaks, the names

Stat: 10 m | the researcher's location figure, to Krebs
Stat: $107.5K | account-linking reward, reported 2021
Stat: 17 | CVEs from the 2025 AirBorne research
Stat: 8.8 | CISA score for the AirBorne UAF flaw
- Cast stack: Google Cast local HTTP on 8008 and 8443 over mDNS; DIAL over SSDP.
- Local hijack: Rickmote (2014) disconnects a nearby Chromecast into its setup mode.
- Internet exposure: CastHack (2019) drove cast and smart-TV endpoints from the public internet.
Notes: Leak figure, quoted by the researcher to Krebs [3]. Reward [5]. AirBorne CVE count [7]; the 8.8 is CISA enrichment on the CVE record [8]. Ports and discovery [5][6]. Rickmote [1]. CastHack [4].

## PART 1 | The record at a glance, 2014 to 2025

| Date | Event |
|---|---|
| Jul 2014 | Rickmote hijacks a Chromecast through its setup mode |
| Jun 2018 | The location leak via DNS rebinding is published |
| Jun 2019 | The local cast API begins requiring an auth token |
| Jan 2019 | CastHack drives internet-exposed cast and smart-TV devices |
| 2020 | Netflix updates the DIAL protocol |
| 2021 | Account-linking wiretap reported; fixed by 2022 |
| 2023 | DIALStranger (2019 research) published at Black Hat MEA |
| Mar 2025 | AirBorne: AirPlay flaws fixed in Apple software |
Caption: One root throughout: a local service that trusts the network, seen on the LAN, through a browser, and from the internet.
Notes: Rickmote [1]. Leak [2][3]. Token [5]. CastHack [4]. DIAL and the 2020 update [6]. Account-linking [5]. AirBorne [7][8][9].

## PART 1 | The cast stack, and whether anyone is checked

| Step | Protocol | What it does |
|---|---|---|
| Discovery | mDNS / DNS-SD | A controller finds a cast device, e.g. `_googlecast._tcp` |
| Control | HTTP on 8008 / 8443 | The device answers settings and commands on the LAN |
| DIAL discovery | SSDP, UDP | A controller finds DIAL televisions with M-SEARCH |
| DIAL launch | HTTP | The controller tells the television to open an app and play |
Caption: Before 2019 the cast control service checked nobody: commands were sent "without any form of authentication" [2].
Notes: mDNS discovery and the 8008/8443 ports [5]. No authentication at the protocol level [2]. DIAL discovery and launch [6].

## PART 2 | Taking over a device within range: Rickmote

- Bishop Fox's tool disconnects a nearby Chromecast; it reconfigures and "accepts commands from anyone within proximity" [1].
- The disconnect is a Wi-Fi deauthentication; the device then opens its own setup network, as Kunze describes [5].
- The condition is proximity, not being on the victim's network.
- Deauth frames are unprotected unless 802.11w is used; the Home Mini Kunze tested supports neither it nor WPA3 [5].
Caption: The 2014 outcome of casting to a stranger's TV is not what an updated device does; the recovery-state design property remains.
Notes: Mechanism and quote [1]. Deauth-to-setup-network and 802.11w [5]. Narrowing over time, design-property reading (Inferred).

## PART 3 | Reading the unauthenticated interface

Left: Location leak, 2018
- A web page used DNS rebinding to reach the unauthenticated local HTTP service.
- Wi-Fi survey data located the home; the researcher told Krebs it was within about ten metres [3].
- Google first called it intended behaviour, then planned a mid-July 2018 update [3].
Right: Account-linking wiretap, 2021
- Device info read over the LAN linked an attacker's cloud account.
- A scheduled routine turned the device's microphone into a wiretap.
- $107,500 reward; fixed by the time Kunze published in December 2022 [5].
Caption: Both turned read-only access into something useful elsewhere: survey data in one case, device identifiers in the other [2][5].
Notes: DNS rebinding and mitigations [2]; the ten-metre figure and Google's reply [3]. Account-linking mechanism, routines wiretap, reward, fix [5].

## PART 4 | The casting protocol's own weakness: DIALStranger

- DIAL is "a protocol co-developed by Netflix and YouTube with help from Sony and Samsung" [6].
- A 2019 research project found "most of TV vendors didnt implement protocol correctly" [6].
- Where a television does not check a cross-site request's origin, a page or device on the LAN can start apps and play content.
- Netflix updated the protocol in 2020; old televisions are not updated and will not be.
Caption: The application path is usually /apps/ but the port varies by vendor; reading that as uneven implementation is the study's gloss [6].
Notes: What DIAL is, the misimplementation finding, per-vendor ports, the 2020 update, the old-TV caveat, all [6]. Uneven-implementation and per-year readings (Inferred).

## PART 5 | Exposed to the internet: CastHack

- In January 2019 two accounts drove internet-exposed cast and smart-TV endpoints to urge a YouTube subscription.
- The advertised actions are the ordinary local-API commands seen from the wrong side of the network.
- The CastHack page itself said to disable UPnP and stop forwarding ports 8008, 8443 and 8009 [4].
- Kunze is more cautious: UPnP on cast devices is "used ... for local discovery, not for port forwarding", a likely misconfiguration [5].
Caption: The honest cross-link to the UPnP study is the shared lesson, a local-only interface exposed to the internet, by one cause or another.
Notes: Incident, handles, advertised actions, disable-UPnP advice [4]; thousands-exposed figure [5]. Kunze's cause assessment [5]. Owner-and-ISP problem (Inferred).

## PART 6 | AirPlay for comparison: AirBorne

- Apple's AirPlay is the same kind of feature: a device announcing on the LAN and taking media and commands.
- Oligo "disclosed 23 vulnerabilities to Apple in total, leading to 17 CVEs being issued" [7].
- CVE-2025-24252 (CISA score 8.8, adjacent-network) chained with CVE-2025-24206 reaches a Mac zero-click, but not on the default setting.
- CVE-2025-24132: Oligo demonstrated SDK code execution on a speaker and a car unit; the CVE record (6.5) calls it app termination [7][8].
Caption: Scores are CISA enrichment on the CVE records, not Oligo's; Apple's fixes were released 31 March 2025.
Notes: 23/17 and default-accessible commands [7]. CVE scores, vectors, CWE, app-termination wording [8]. Fixed versions and dates [9]. Zero-click needs a non-default receiver setting [7].

## PART 7 | Fixed, narrowed, design, and setting

| Pile | What it covers | What to do |
|---|---|---|
| Fixed by a patch | local API token (2019); account-link (by 2022); DIAL (2020); AirBorne (2025) | current firmware; retire unsupported devices |
| Narrowed or design | the device still trusts the LAN and drops to a recovery state | separate it; only disconnecting removes the property |
| Up to the owner | network segmentation; receiver on or off; firmware | decide against the trade-off |
Caption: Where a fix exists it has a version or a date; several items were narrowed, not closed, and some are design properties.
Notes: Fixed set with dates [5][6][9]. Trust-the-LAN property; Young's only complete fix is to disconnect [2]. Owner choices (Inferred for "most effective"); Oligo's steps [7].

## PART 7 | The trade-off in segmenting the network

- Putting cast devices on a separate network reduces exposure; Young's only complete fix is to disconnect them.
- Segmenting can break the convenience casting exists for: a phone on the main network may not see the speaker.
- Casting across segments then needs a guest mode or a deliberate exception.
- The study states the trade-off and does not tell anyone which way to set it.
Caption: This is the owner's decision. The study describes the setting and its effect, and gives no verdict.
Notes: Disconnect as the complete mitigation, segmentation reduces exposure [2]. The convenience trade-off is the study's framing (Inferred).

## DEFENDER VIEW | Check your own network, read-only

Left: What to read
- Which casting devices answer on the network, by browsing mDNS and SSDP service types.
- Whether cast devices share a network with general browsing, or sit on a guest or device network.
- Whether the router has DNS rebind protection, and whether any port-forward exposes casting ports.
Right: What it tells you
- What is advertising a casting interface (an inventory).
- Whether the devices are separated from browsing (a structural choice).
- Whether the router blocks rebinding and does not expose the ports (a setting and a possible fault).
Caption: None of these was run here. Confirming no internet exposure is a read of the router's forwarding table, not a general port scan.
Notes: Discovery works this way [5][6]. Segmentation [2]. DNS rebind protection, most routers off by default [2]. Exposure as a forwarding-table read [4][5]. Firmware currency per device (Inferred).

## MITRE MAPPINGS | The study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1046 | Network Service Discovery | mDNS/SSDP discovery of cast and DIAL devices; a browser subnet scan in the 2018 leak |
| T1210 | Exploitation of Remote Services | AirBorne's demonstrated zero-click RCE over AirPlay on-network |
| T1557 | Adversary-in-the-Middle | Oligo's described DoS-then-mDNS-spoof stream interception |
Caption: ATT&CK v20.0. No source names the ids; each row is the study's mapping. No group, software or campaign is bound.
Notes: Names and tactics from library data [10]; ties from [2][5][6][7][8]. No source shows a compromised device enumerating other cast devices. T1557 is a described scenario (Inferred). © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | What casting teaches

- **A local service that trusts the network is the common root.** Local services "must be designed as if they were directly exposed to the Internet" [2].
- **Reading is as dangerous as commanding.** Survey data and device identifiers, read without credentials, proved useful elsewhere [2][5].
- **Exposure changes everything.** The same interface is a convenience on the LAN and a public hazard on the internet [4][5].
- **A weakness has a year.** Where a fix exists it has a version or a date; the real exposure is equipment that stopped getting updates.
Notes: Design rule [2]. Read-becomes-useful [2][5]. Exposure [4][5]. Per-year and read-first are the study's framing (Inferred).
