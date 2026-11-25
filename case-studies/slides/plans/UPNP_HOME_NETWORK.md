# Slide plan: UPnP on the Home Network: The Internet Gateway Device Port-Mapping Service and Its Security Record

- Study: case-studies/UPNP_HOME_NETWORK.md
- Cover title: UPnP on the Home Network / The Port-Mapping Service / and Its Security Record
- Subtitle: A service that checks nobody, the bugs that were patched, the design that was not, and the setting you control
- Published: 25 November 2026
- Notes: Slide plan for the deck of the study case-studies/UPNP_HOME_NETWORK.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A service that checks nobody

- UPnP lets any host on the home network ask the router to open an inbound port.
- The first version of the port-mapping profile has no access control: no check on who asks or on whom the port is opened to.
- Half the record is implementation bugs that patches fixed; half is the protocol used as designed.
- Fixed by a patch or a replacement, a design no patch removes, and the owner's own setting are three different things.
Caption: Evidence grade: Confirmed for the records, specification and reports; Inferred where the study reasons from them.
Notes: No access control [4], the 2010 own-address rule devices may decline [6]. Implementation bugs [1][2]. Abuse as designed [7][8]. CallStranger [3][4][5]. The three-pile split is the study's framing (Inferred).

## KEY FACTS | The service, the exposure, the names

Stat: 81M | IPs answered UPnP discovery in a 2012 study
Stat: 17M | estimated to also answer control from the internet
Stat: 7.5 | CVSS 3.1 for CallStranger, CVE-2020-12695
Stat: 45K | routers carrying the EternalSilence injections
- Library flaws: libupnp CVE-2012-5958 to -5965 (fixed 1.6.18); MiniUPnPd CVE-2013-0229 and -0230, CVE-2017-1000494, CVE-2019-12107.
- Port-map abuse: UPnProxy builds proxies; EternalSilence re-exposed SMB 139 and 445.
- Malware: Pinkslipbot opened inbound ports over UPnP from April 2016.
Notes: Exposure, estimate [1]. CallStranger score [3]. EternalSilence count [7]. Library CVEs [1][2]. Malware [8].

## PART 1 | The record at a glance, 2012 to 2020

| Date | Event |
|---|---|
| Jun 2012 | Rapid7 scans every routable IPv4 address for UPnP |
| Jan 2013 | The exposure paper; libupnp fixed in 1.6.18 |
| 2013 | MiniUPnPd CVE-2013-0229 and CVE-2013-0230 |
| Apr 2016 | Pinkslipbot starts opening ports over UPnP |
| Jun 2017 | McAfee reports Pinkslipbot's UPnP use |
| Nov 2018 | Akamai reports UPnProxy and EternalSilence |
| Apr 2020 | The UPnP specification is updated |
| Jun 2020 | CallStranger, CVE-2020-12695, is published |
Caption: Two halves: implementations that could be attacked, then the protocol used as designed against the owner.
Notes: Scan and paper [1]. MiniUPnPd CVEs [2]. Pinkslipbot [8]. UPnProxy and EternalSilence [7]. Spec update and CallStranger [3][4].

## PART 1 | Four steps, and whether anyone is checked

| Step | Protocol | What it does |
|---|---|---|
| Discovery | SSDP, UDP 1900 | A device finds the router and its description URL |
| Description | HTTP XML | Lists services, including WANIPConnection, and the control URL |
| Control | SOAP | AddPortMapping opens a port; NewInternalClient is the forward target |
| Eventing | SUBSCRIBE | An HTTP method; the notify address rides in the CALLBACK header |
Caption: The first profile checks nobody; the 2010 profile recommends a map-to-own-address rule that devices may decline [4][6].
Notes: Four steps [1]. AddPortMapping fields [1][7]. SUBSCRIBE is an HTTP method, not an action [3]. No authentication [4]; own-address rule and error 606 [6].

## PART 2 | The implementations that could be attacked

- A 2012 study found the control plane turned the wrong way out on tens of millions of addresses.
- libupnp: SSDP parser flaws, about 23M addresses open to code execution from one UDP packet.
- MiniUPnPd: a denial-of-service flaw and a SOAP code-execution flaw, fixed upstream in 2009 but still shipping in 1.0.
- To home users Rapid7 said disable UPnP and replace dead devices; to ISPs, stop answering it from the internet.
Caption: 1,500 vendors and 6,900 products were vulnerable to at least one flaw in the 2012 paper [1].
Notes: Scan and counts, estimate for 17M [1]. libupnp CVE-2012-5958 to -5965, fixed 1.6.18 [1][2]. MiniUPnPd CVEs and the 2009 upstream fixes [1][2].

## PART 3 | Using the router as infrastructure

Left: UPnProxy
- AddPortMapping with NewInternalClient set to an outside host turns the router into a relay.
- A pool of about 3.5 million devices; about 277,000 expose the controls UPnProxy needs.
- Akamai says the technique could be used for spam, phishing, click fraud and DDoS.
Right: EternalSilence
- Injections pointed inward, exposing SMB ports 139 and 445 on devices behind the router.
- 45,113 routers carried them, naming an estimated 1.7 million internal addresses.
- The name came from the mapping description left behind, "galleta silenciosa".
Caption: Internet-side injection needs two faults: a router that answers controls on the WAN, and no check on the internal client [7].
Notes: UPnProxy pool and count [7]. Stated risk, not observed use [7]. EternalSilence ports, routers, and the address caveat [7]. Two-fault reading (Inferred).

## PART 4 | Aiming a device from outside: CallStranger

- UPnP eventing lets a subscriber give a callback address; the device sends traffic there.
- The spec before 17 April 2020 did not forbid a callback on a different network segment.
- So the subscriber can aim the device at a target of its choice, which is SSRF-shaped.
- CERT/CC names amplified DDoS and data exfiltration; the researcher adds DLP bypass and internal port scanning.
Caption: CVE-2020-12695, CVSS 3.1 7.5, CWE-276; a specification fix on 17 April 2020, then per-device firmware [3][5].
Notes: Spec wording and dates, score and CWE from NVD [3]. DDoS and exfiltration, and the Çadırcı/EY Turkey credit, from CERT/CC [4]. DLP and scan classes from the researcher [5].

## PART 5 | Malware that opens its own door

- Because the first profile checks nobody, malware on a device can open a port with no user action.
- Pinkslipbot (QakBot/QBot) used UPnP to open inbound ports and run control-server proxies from April 2016.
- McAfee called it, as far as it knew, the second executable malware to use UPnP port forwarding after Conficker in 2008.
- Its mappings are too generic to remove automatically, and anti-malware tools may not revert them.
Caption: McAfee's advice matched everyone else's: watch local port-forwarding rules and disable UPnP unless needed [8].
Notes: Pinkslipbot UPnP use and April 2016 [8]. Hedged Conficker comparison [8]. Generic rules, may-not-revert, cleanup caution [8].

## PART 6 | Fixed, design, and setting

| Pile | What it covers | What to do |
|---|---|---|
| Fixed by patch or replace | library bugs; a router answering UPnP on the internet side | current firmware; replace if unpatchable |
| Design, no patch removes | no caller check; any LAN host maps a port to itself | the 2010 own-address rule blocks map-to-others; only off removes it |
| Up to the owner | UPnP on or off; firmware; replacement | decide against the trade-off |
Caption: A router answering UPnP from the internet is a device fault, not a preference, so it sits in the first pile.
Notes: Fixed set [1][2][3]. Internet-side answer as a fault [1][7]. Design property and the 2010 rule [6][7][8]. Owner choices and 2013 default-on [1].

## PART 6 | The trade-off in turning UPnP off

- UPnP off means some apps cannot open their own ports, and may need a port forwarded by hand.
- Game consoles, voice and video calling, and peer-to-peer apps are the common users.
- Turning the service off is the only thing that removes the no-check design property fully.
- The study states the trade-off and does not tell anyone which way to set it.
Caption: This is the owner's decision. The study describes the setting and its effect, and gives no verdict.
Notes: The trade-off and the apps that rely on UPnP are the study's framing (Inferred); the design property [6][7][8].

## DEFENDER VIEW | Check your own network, read-only

Left: What to read
- Whether UPnP is enabled on the router's admin page.
- The port-mapping list: ask the router over UPnP (GetGenericPortMappingEntry); injected routers show nothing in the UI.
- Whether UPnP answers from the internet, with a UPnP exposure test against your public address.
Right: What it tells you
- Whether the service is on (a setting).
- What it has been asked to do (the mappings).
- Whether it answers where it should not (a fault to fix, not a setting).
Caption: None of these was run here. A general port checker cannot settle UDP 1900; with two routers the public address is the outer one's.
Notes: Setting and 2013 default-on [1]. Mapping-table audit and no-UI-visibility [7]. UDP and two-router notes (Inferred). Disable may not clear an injection [7].

## MITRE MAPPINGS | The study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1046 | Network Service Discovery | SSDP discovery of UPnP endpoints |
| T1090 | Proxy | UPnProxy turns injected routers into relays |
| T1133 | External Remote Services | EternalSilence re-exposes internal SMB |
| T1048 | Exfiltration Over Alternative Protocol | CallStranger aims traffic out of the network |
| T1498.002 | Reflection Amplification | CallStranger reflects traffic off UPnP devices |
Caption: ATT&CK v20.0. No source names the ids; each row is the study's mapping. No group, software or campaign is bound.
Notes: Names and tactics from library data [9]; ties from [1][4][5][7]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | What UPnP teaches

- **No caller check is not broken when used as designed.** A router enforcing the 2010 rule refuses UPnProxy and EternalSilence; only off refuses Pinkslipbot.
- **Exposure beats any single bug.** Rapid7 told home users to disable UPnP and ISPs to stop answering it from the internet.
- **The inside is not automatically trusted.** One infected device is enough to open the perimeter.
- **Read before you change.** Every step starts by reading the state; the change is the owner's to make.
Notes: Design reading [6][7][8]. Exposure, by audience [1]. Inside-trust [8]. Read-first is the study's framing (Inferred).
