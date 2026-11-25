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
- Fixed by a patch, a design no patch removes, and the owner's own network choice are three different things.
Caption: Evidence grade: Confirmed for the researcher write-ups, records and advisory; Reported for the incident; Inferred where it reasons.
Notes: Two IoT design choices [2]. Rickmote [1]. Location leak and account-linking [2][4]. DIAL [5]. CastHack [3][4]. AirBorne comparison [6][7][8]. The three-pile split is the study's framing (Inferred).

## KEY FACTS | The stack, the leaks, the names

Stat: 10 m | how close the 2018 leak located a home
Stat: $107.5K | paid for the 2022 account-linking chain
Stat: 17 | CVEs from the 2025 AirBorne AirPlay research
Stat: 8.8 | CVSS 3.1 for the AirBorne UAF flaw
- Cast stack: Google Cast local HTTP on 8008 and 8443 over mDNS; DIAL over SSDP.
- Local hijack: Rickmote (2014) drops a Chromecast to its open setup network.
- Internet exposure: CastHack (2019) drove cast and DIAL endpoints from the public internet.
Notes: Leak figure [2]. Bounty [4]. AirBorne CVE count [6]; CVE score from the NVD record [7]. Ports and discovery [4][5]. Rickmote [1]. CastHack [3].

## PART 1 | The record at a glance, 2014 to 2025

| Date | Event |
|---|---|
| Jul 2014 | Rickmote hijacks a Chromecast through its setup mode |
| Jun 2018 | The location leak via DNS rebinding is published |
| 2019 | The local cast API begins requiring an auth token |
| Jan 2019 | CastHack drives internet-exposed cast devices |
| 2019 | DIALStranger research; disclosed 2023 |
| 2020 | Netflix updates the DIAL protocol |
| 2021 | Account-linking wiretap reported; fixed the same year |
| Apr 2025 | AirBorne: AirPlay flaws fixed in Apple software |
Caption: One root throughout: a local service that trusts the network, seen on the LAN, through a browser, and from the internet.
Notes: Rickmote [1]. Leak and token [2][4]. CastHack [3]. DIAL and the 2020 update [5]. Account-linking [4]. AirBorne [6][7][8].

## PART 1 | The cast stack, and whether anyone is checked

| Step | Protocol | What it does |
|---|---|---|
| Discovery | mDNS / DNS-SD | A controller finds a cast device, e.g. `_googlecast._tcp` |
| Control | HTTP on 8008 / 8443 | The device answers settings and commands on the LAN |
| DIAL discovery | SSDP, UDP | A controller finds DIAL televisions with M-SEARCH |
| DIAL launch | HTTP | The controller tells the television to open an app and play |
Caption: Before 2019 the cast control service checked nobody: commands were sent "without any form of authentication" [2].
Notes: mDNS discovery and the 8008/8443 ports [4]. No authentication at the protocol level [2]. DIAL discovery and launch [5].

## PART 2 | Taking over a device on the LAN: Rickmote

- Ordinary Wi-Fi deauthentication frames are not authenticated, so anyone nearby can drop a device.
- A dropped Chromecast opens its own setup network and "accepts commands from anyone within proximity" [1].
- The fall-back-to-setup behaviour is a design property, not a one-off bug.
- Kunze confirmed in 2022 that a Home Mini still opened its setup network under the same attack.
Caption: Rickmote as a 2014 recipe does not reproduce on an updated device; the recovery-state design property is harder to remove.
Notes: Mechanism and quote [1]. Deauth frames unauthenticated [1][4]. 2022 reproduction on the Home Mini [4]. Design-property reading (Inferred).

## PART 3 | Reading the unauthenticated interface

Left: Location leak, 2018
- A web page used DNS rebinding to reach the unauthenticated local HTTP service.
- Wi-Fi survey data placed the home "within 10 meters" on a map.
- Fixed when the local API began requiring a token in 2019.
Right: Account-linking wiretap, 2021
- Device info read over the LAN linked an attacker's cloud account.
- A scheduled "call" routine turned the device's microphone into a wiretap.
- $107,500 reward; fixed in 2021 by requiring a Home invitation.
Caption: Both turned read-only access into a key used elsewhere: survey data in one case, device identifiers in the other [2][4].
Notes: DNS rebinding, the ten-metre figure, mitigations [2]. 2019 token [4]. Account-linking mechanism, routines wiretap, reward, Home Mini test, fix [4].

## PART 4 | The casting protocol's own weakness: DIALStranger

- DIAL is "a protocol co-developed by Netflix and YouTube with help from Sony and Samsung" [5].
- A 2019 research project found "most of TV vendors didnt implement protocol correctly" [5].
- Where a television does not check a request's origin, a page or device on the LAN can start apps and play content.
- Netflix updated the protocol in 2020; old televisions are not updated and will not be.
Caption: The DIAL interface sits on a different port and path per vendor, a sign of how unevenly the protocol was built [5].
Notes: What DIAL is, the misimplementation finding, the per-vendor ports, the 2020 update, and old-TV caveat, all [5]. Per-year reading (Inferred).

## PART 5 | Exposed to the internet: CastHack

- In January 2019 two people drove thousands of internet-exposed cast and DIAL endpoints to play a promo video.
- The advertised actions are the ordinary local-API commands seen from the wrong side of the network.
- Press blamed UPnP port-forwarding; the careful account differs.
- Kunze: UPnP on cast devices is "used ... for local discovery, not for port forwarding", so the likely cause was a misconfiguration [4].
Caption: The honest cross-link to the UPnP study is the shared lesson, a local-only interface exposed to the internet, not that UPnP did it.
Notes: Incident and advertised actions [3]. Kunze's cause assessment [4]. Exposure is an owner-and-ISP problem, not a vendor patch (Inferred).

## PART 6 | AirPlay for comparison: AirBorne

- Apple's AirPlay is the same kind of feature: a device announcing on the LAN and taking media and commands.
- Oligo "disclosed 23 vulnerabilities to Apple in total, leading to 17 CVEs being issued" [6].
- CVE-2025-24252 (UAF, CVSS 3.1 8.8) chained with CVE-2025-24206 (7.7) reaches a same-network zero-click on a Mac.
- CVE-2025-24132: Oligo calls it SDK code execution; the NVD record scores it 6.5 as "unexpected app termination" [6][7].
Caption: Scores are from the CVE records, not the summary; Oligo demonstrated the primitive on macOS, and estimates the third-party reach.
Notes: 23/17 and default-accessible commands [6]. CVE scores, vectors and the termination wording [7]. Fixed versions [7][8]. Tested macOS vs estimated reach [6].

## PART 7 | Fixed, design, and setting

| Pile | What it covers | What to do |
|---|---|---|
| Fixed by a patch | local API token (2019); account-link (2021); DIAL (2020); AirBorne (2025) | current firmware; retire unsupported devices |
| Design, no patch removes | the device trusts the LAN and drops to a recovery state | separate it from the network you browse on |
| Up to the owner | network segmentation; receiver on or off; firmware | decide against the trade-off |
Caption: Every fix here has a version and a date, so a 2014 or 2018 weakness is not a current one on an updated device.
Notes: Fixed set with dates [4][5][7][8]. Trust-the-LAN design property [2][4]. Owner choices, segmentation first [2][6].

## PART 7 | The trade-off in segmenting the network

- Putting cast devices on a separate network is the single most effective step in the study.
- It can break the convenience casting exists for: a phone on the main network may not see the speaker.
- Casting across segments then needs a guest mode or a deliberate exception.
- The study states the trade-off and does not tell anyone which way to set it.
Caption: This is the owner's decision. The study describes the setting and its effect, and gives no verdict.
Notes: Segmentation as the first mitigation [2]. The convenience trade-off and the guest-mode caveat are the study's framing (Inferred).

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
Notes: Discovery works this way [4][5]. Segmentation as the key read [2]. DNS rebind protection [2]. Exposure as a forwarding-table read [3][4]. Firmware currency per device (Inferred).

## MITRE MAPPINGS | The study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1046 | Network Service Discovery | mDNS and SSDP discovery; a compromised device scanning the LAN |
| T1210 | Exploitation of Remote Services | AirBorne's chained zero-click RCE over AirPlay on-network |
| T1557 | Adversary-in-the-Middle | Oligo's described DoS-then-mDNS-spoof stream interception |
Caption: ATT&CK v20.0. No source names the ids; each row is the study's mapping. No group, software or campaign is bound.
Notes: Names and tactics from library data [9]; ties from [2][4][5][6][7]. T1557 is a described scenario, not observed (Inferred). © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | What casting teaches

- **A local service that trusts the network is the common root.** Local services "must be designed as if they were directly exposed to the Internet" [2].
- **Reading is as dangerous as commanding.** Survey data and device identifiers, read without credentials, became keys used elsewhere [2][4].
- **Exposure changes everything.** The same interface is a convenience on the LAN and a public hazard on the internet [3][4].
- **A weakness has a year.** Each item was fixed in a version and a date; the real exposure is equipment that stopped getting updates.
Notes: Design rule [2]. Read-becomes-key [2][4]. Exposure [3][4]. Per-year reading and read-first are the study's framing (Inferred).
