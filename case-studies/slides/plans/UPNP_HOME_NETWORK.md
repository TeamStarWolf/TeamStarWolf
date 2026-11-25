# Slide plan: UPnP on the Home Network: The Internet Gateway Device Port-Mapping Service and Its Security Record

- Study: case-studies/UPNP_HOME_NETWORK.md
- Cover title: UPnP on the Home Network / The Port-Mapping Service / and Its Security Record
- Subtitle: A service with no front door, the bugs that were patched, the design that was not, and the setting you control
- Published: 25 November 2026
- Notes: Slide plan for the deck of the study case-studies/UPNP_HOME_NETWORK.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A service with no front door

- UPnP lets any device on the home network ask the router to open an inbound port.
- The port-mapping service has no authentication: the router does not check who is asking.
- Half the record is implementation bugs that patches fixed; half is the protocol used as designed.
- Fixed, design, and setting are three different things, and defence depends on telling them apart.
Caption: Evidence grade: Confirmed for the records and researcher reports; Inferred where the study reasons from them.
Notes: No-authentication design [1]. Implementation bugs [1][2]. Abuse as designed [4][5]. CallStranger [3]. The three-pile split is the study's framing (Inferred).

## KEY FACTS | The service, the exposure, the names

Stat: 81M | IPs answered UPnP discovery in a 2012 scan
Stat: 17M | of those also answered control from the internet
Stat: 7.5 | CVSS 3.1 for CallStranger, CVE-2020-12695
Stat: 45K | routers injected with proxy port-maps in one set
- Library flaws: libupnp CVE-2012-5958 to -5965 (fixed 1.6.18); MiniUPnPd CVE-2013-0229, -0230, -2017-1000494, -2019-12107.
- Port-map abuse: UPnProxy and EternalSilence; EternalSilence re-exposed SMB 139 and 445.
- Malware: Pinkslipbot opened inbound ports over UPnP from April 2016.
Notes: Exposure [1]. CallStranger score [3]. Injection count [4]. Library CVEs [1][2]. Malware [5].

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
Notes: Scan and paper [1]. MiniUPnPd CVEs [2]. Pinkslipbot [5]. UPnProxy and EternalSilence [4]. Spec update and CallStranger [3].

## PART 1 | Four steps, and the missing front door

| Step | Protocol | What it does |
|---|---|---|
| Discovery | SSDP, UDP 1900 | A device finds the router and its description URL |
| Description | HTTP XML | Lists services, including WANIPConnection, and the control URL |
| Control | SOAP | AddPortMapping opens a port; NewInternalClient is the forward target |
| Eventing | SUBSCRIBE | A callback address the device sends notifications to |
Caption: The control step has no authentication: any host that reaches the control URL can add a mapping [1].
Notes: Four steps [1]. AddPortMapping fields [1][4]. Eventing is the CallStranger step [3]. Trust-the-LAN assumption is the root (Inferred).

## PART 2 | The implementations that could be attacked

- A 2012 scan found the control plane turned the wrong way out on tens of millions of addresses.
- libupnp: SSDP parser flaws, about 23M addresses open to code execution from one UDP packet.
- MiniUPnPd: a denial-of-service flaw and a SOAP code-execution flaw, with more parser bugs later.
- Rapid7's first defence was not patching but disabling internet-facing UPnP and replacing dead devices.
Caption: 1,500 vendors and 6,900 products were vulnerable to at least one flaw in the 2012 paper [1].
Notes: Scan and counts [1]. libupnp CVE-2012-5958 to -5965, fixed 1.6.18 [1][2]. MiniUPnPd CVE-2013-0229, -0230, -2017-1000494, -2019-12107 [2].

## PART 3 | Using the router as infrastructure

Left: UPnProxy
- AddPortMapping with NewInternalClient set to an outside host turns the router into a relay.
- About 277,000 routers exposed the controls; at least 45,000 were actively injected.
- Used to hide traffic for spam, phishing, click fraud and DDoS.
Right: EternalSilence
- Injections pointed inward, exposing SMB ports 139 and 445 on devices behind the router.
- 45,113 routers carried them, exposing an estimated 1.7 million machines.
- The name came from the mapping description left behind, "galleta silenciosa".
Caption: Neither has a CVE: the service is working as designed, for a requester the design assumed was trusted [4].
Notes: UPnProxy counts and uses [4]. EternalSilence ports, counts and name [4]. No-CVE reading is the study's (Inferred from [4]).

## PART 4 | Aiming a device from outside: CallStranger

- UPnP eventing lets a subscriber give a callback address; the device sends traffic there.
- The spec before 17 April 2020 did not forbid a callback on a different network segment.
- So the subscriber can aim the device at a target of its choice, which is SSRF-shaped.
- Uses: reflected and amplified DDoS, data exfiltration past some controls, internal port scanning.
Caption: CVE-2020-12695, CVSS 3.1 7.5, CWE-276; a specification fix on 17 April 2020, then per-device firmware [3].
Notes: Spec wording and dates [3]. Score and CWE from NVD [3]. Abuse classes from the CERT/CC note [3]. Researcher Yunus Cadirci [3].

## PART 5 | Malware that opens its own door

- Because any LAN host can add a mapping, malware on a device can open a port with no user action.
- Pinkslipbot (QakBot/QBot) used UPnP to open inbound ports and run control-server proxies from April 2016.
- McAfee called it the second executable malware to use UPnP port forwarding after Conficker in 2008.
- Its mappings are too generic to remove automatically, and anti-malware tools do not revert them.
Caption: McAfee's advice matched everyone else's: watch local port-forwarding rules and disable UPnP unless needed [5].
Notes: Pinkslipbot UPnP use and April 2016 [5]. Conficker comparison [5]. Generic rules and cleanup caution [5].

## PART 6 | Fixed, design, and setting

| Pile | What it covers | What to do |
|---|---|---|
| Fixed | libupnp and MiniUPnPd bugs; CallStranger | Current device, current firmware; replace dead devices |
| Design | No authentication; any LAN host opens a port | Cannot be patched; only not running the service removes it |
| Setting | UPnP on or off; answered on the internet side | Owner's choice; the internet-facing answer should be off |
Caption: Turning UPnP off can affect consoles, calling and peer-to-peer apps; the study states the trade-off, not a verdict.
Notes: Fixed set [1][2][3]. Design property [1][4][5]. Setting and the WAN-side census [1]. Double-NAT nuance is the study's (Inferred).

## PART 6 | The trade-off in turning UPnP off

- UPnP off means some apps cannot open their own ports, and may need a port forwarded by hand.
- Game consoles, voice and video calling, and peer-to-peer apps are the common users.
- Turning the service off removes the no-authentication design property entirely; nothing else does.
- The study states the trade-off and does not tell anyone which way to set it.
Caption: This is the owner's decision. The study describes the setting and its effect, and gives no verdict.
Notes: The trade-off and the apps that rely on UPnP are the study's framing (Inferred); the design property [1][4][5].

## DEFENDER VIEW | Check your own network, read-only

Left: What to read
- Whether UPnP is enabled on the router's admin page.
- The current port-mapping table: entries you did not create, odd internal clients, SMB 139 or 445.
- Whether UDP 1900 and the control port answer from the internet (they should not).
Right: What it tells you
- Whether the service is on (a setting).
- What it has been asked to do (the mappings).
- Whether it is exposed where it should not be (a setting that should be off).
Caption: These checks change nothing. Disabling UPnP may not clear an existing injection; that can need a reboot or reset [4].
Notes: Setting and default-on [1]. Mapping-table audit [4]. WAN-side check against the 2012 census [1]. Two routers each keep their own (Inferred).

## MITRE MAPPINGS | The study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1046 | Network Service Discovery | SSDP discovery of UPnP endpoints |
| T1090 | Proxy | UPnProxy turns injected routers into relays |
| T1090.003 | Multi-hop Proxy | Walls of injected routers chain to hide traffic |
| T1133 | External Remote Services | EternalSilence re-exposes internal SMB |
| T1048 | Exfiltration Over Alternative Protocol | CallStranger aims traffic out of the network |
| T1498.002 | Reflection Amplification | CallStranger reflects traffic off UPnP devices |
Caption: ATT&CK v20.0. No source names the ids; each row is the study's mapping. No group, software or campaign is bound.
Notes: Names and tactics from library data [6]; ties from [1][3][4]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | What UPnP teaches

- **No authentication is not broken when abused.** Proxy injection and malware use the service as written.
- **Exposure beats any single bug.** The first defence was to stop answering UPnP from the internet.
- **The inside is not automatically trusted.** One infected device is enough to open the perimeter.
- **Read before you change.** Every step starts by reading the state; the change is the owner's to make.
Notes: Design reading [1][4][5]. Exposure [1]. Inside-trust [5]. Read-first is the study's framing (Inferred).
