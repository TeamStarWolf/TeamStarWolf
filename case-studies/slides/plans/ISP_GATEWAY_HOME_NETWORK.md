# Slide plan: The ISP-Supplied Gateway: Who Controls the Box at the Edge of the Home Network, and Its Security Record

- Study: case-studies/ISP_GATEWAY_HOME_NETWORK.md
- Cover title: The ISP-Supplied Gateway / Who Controls the Box at the Edge / of the Home Network
- Subtitle: A device the subscriber does not own, the bugs the vendor and ISP shipped, the design no patch removes, and the router you can put behind it
- Published: 25 November 2026
- Notes: Slide plan for the deck of the study case-studies/ISP_GATEWAY_HOME_NETWORK.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Who controls the box at the edge

- The ISP's gateway is modem, router, firewall and Wi-Fi in one, at the edge of the home network.
- Unlike a router you buy, the vendor writes its firmware and the ISP manages it remotely.
- So a hardcoded account, an exposed management port or a shared-code bug can sit there unseen by the owner.
- Fixed by the vendor or ISP, a design no patch removes, and the owner's own router behind it are different things.
Caption: Evidence grade: Confirmed for the researcher write-ups, records and advisories; Reported for a summary; Inferred where it reasons.
Notes: Combined device, ISP-managed [1][4]. SharknAT&To [1][2]. TR-069 outage [3][4][5]. Cable Haunt [6][7]. Misfortune Cookie [8][9]. The pile split is the study's framing (Inferred).

## KEY FACTS | The device, the record, the names

Stat: 200+ | device models exposed, Misfortune Cookie
Stat: 7547 | the TCP port the ISP manages the box on
Stat: 8.8 | NVD CVSS for the Cable Haunt overflow
Stat: 2005 | year the RomPager fix shipped to makers
- Vendor access: SharknAT&To (2017) found a hardcoded SSH superuser in AT&T's Arris gateways.
- Management plane: a 2016 Mirai variant hit TR-069 on port 7547; Deutsche Telekom's routers crashed.
- Browser-reachable: Cable Haunt (2020) overflowed a Broadcom modem component from a web page.
Notes: 200+ models is Check Point's count [8]. Port 7547 [3][4]. 8.8 is NVD's own score for CVE-2019-19494 [7]. 2005 fix [8]. SharknAT&To [1]. TR-069 [4][5]. Cable Haunt [6].

## PART 1 | The record at a glance, 2005 to 2020

| Date | Event |
|---|---|
| 2005 | AllegroSoft fixes RomPager; makers keep shipping the old one |
| Dec 2014 | Misfortune Cookie: RomPager found in 200+ device models |
| Nov 2016 | A Mirai variant hits gateways on the TR-069 port 7547 |
| Dec 2016 | Deutsche Telekom routers crash in the attack, not infected |
| Aug 2017 | SharknAT&To: hardcoded access in AT&T's Arris gateways |
| Jan 2020 | Cable Haunt: Broadcom cable-modem code execution via the browser |
Caption: One root throughout: a device the owner does not control, whose firmware and management belong to the vendor and ISP.
Notes: RomPager 2005 fix and 200+ models [8]. TR-069 attack and crash [4]. SharknAT&To [1]. Cable Haunt [6][7].

## PART 1 | What an ISP gateway is, and who controls it

- **Several devices in one, at the edge.** Modem, router, firewall and Wi-Fi; it holds the public address and answers the internet.
- **The ISP manages it remotely.** TR-069 "is designed to allow Internet Service Providers (ISP's) to remotely manage devices" [4], usually on port 7547.
- **The vendor writes the firmware, the ISP may add to it.** The owner runs code they did not write and cannot audit.
- The subscriber owns neither the firmware nor the management plane, so security rests with the vendor and ISP.
Caption: Control is the theme: the owner's realistic lever is to treat the gateway as untrusted, not to patch what is not theirs.
Notes: Internet-facing [1]. TR-069 purpose and port [3][4]. Vendor-or-ISP code [1]. The control reading is the study's framing (Inferred).

## PART 2 | Vendor-installed access: SharknAT&To

- Nomotion (2017) found AT&T's Arris NVG589 and NVG599 gateways carried a hardcoded SSH superuser account.
- That account reached a root shell; a hidden control server and an info-disclosure service made it worse.
- An undocumented proxy on one port let an outsider reach devices inside the home, bypassing the firewall.
- Nomotion could not tell whether the vendor or the ISP introduced them; no CVE was assigned.
Caption: No fixed firmware was available at disclosure; the last Arris firmware for many devices dated to May 2013 [2].
Notes: Hardcoded SSH, caserver, 61001 disclosure, 49152 proxy [1]. Vendor-or-ISP uncertainty [1]. No CVE [1]. No-fix and May 2013 [2]. No credentials or payloads reproduced.

## PART 3 | The remote-management channel: the 2016 TR-069 outage

- TR-064, a companion to TR-069 on port 7547, let a November 2016 Mirai variant run commands on gateways.
- CVE-2016-10372 describes it: the device "does not properly restrict the TR-064 protocol ... via TCP port 7547" [5].
- On Deutsche Telekom the attempt "failed and the routers where not infected ... the devices crashed" [4].
- The fix was ISP firmware and blocking port 7547 from everyone but the ISP.
Caption: The management port was never meant to answer anyone but the ISP; the outage is what happened when it answered the world.
Notes: Mechanism and reboot note [3]. CVE description, port 7547, NVD 9.8 [5]. Crashed-not-infected and the ISP response [4].

## PART 4 | A LAN-side bug via the browser: Cable Haunt

- A standard Broadcom cable-modem component, the spectrum analyzer, listens on the local network over a WebSocket.
- A web page can reach it past the browser's cross-origin rules; default credentials remove the last barrier.
- Overflowing it runs code on the modem: CVE-2019-19494 (NVD CVSS 8.8); a DNS-rebinding sibling is CVE-2019-19495 (9.8).
- Because the modem is the ISP's, its default credentials "will therefore be available for any attacker" who knows the pattern [6].
Caption: The same browser-reached pattern as casting, here on the ISP's modem; fixed firmware reaches the owner only via the ISP.
Notes: Spectrum analyzer, WebSocket-past-CORS, default creds [6]. NVD scores, both NVD's own [7]. The fixed versions are named in the CVE records [7].

## PART 5 | Shared code at scale: Misfortune Cookie

- RomPager, an embedded web server by AllegroSoft, sat in the management interface of many gateways.
- A crafted HTTP cookie corrupts memory and can "treat the current session with administrative privileges" [8].
- Check Point "detected at least 200 different models" exposing a vulnerable service on the internet [8].
- AllegroSoft fixed it in 2005; makers kept shipping the old version, and the version string could not be trusted [8].
Caption: TR-069's reach spread the vulnerable population; Check Point says it "is not a vulnerability related to the TR-069/CWMP per se" [8].
Notes: Mechanism and admin-session quote [8]. 200+ models, 2005 fix, version-string caveat, TR-069-not-cause [8]. CVE-2014-9222 description [9].

## PART 6 | Fixed, design, and setting

| Pile | What it covers | What to do |
|---|---|---|
| Fixed by vendor or ISP | Cable Haunt firmware; the 2005 RomPager fix; the 2016 port block | depends on the vendor or ISP shipping it |
| Design, no patch removes | internet-facing; ISP-managed; vendor code the owner cannot audit | treat the gateway as untrusted |
| Up to the owner | a router behind the gateway; bridge or pass-through; firmware | decide against the trade-off |
Caption: The subscriber rarely applies the fix; the vendor or ISP does, so an abandoned gateway is the real exposure.
Notes: Fixed set [4][7][8]. Design properties [1][4]. Owner's router-behind-the-gateway lever, a reader ran one in IP Passthrough mode [1].

## PART 6 | The trade-off: a router behind the gateway

- The strongest owner lever is to put an owned router behind the ISP gateway and treat the gateway as untrusted.
- On many gateways this means a bridge or pass-through mode, or accepting a second layer of address translation.
- A second layer of translation can complicate some applications, and not every gateway offers a clean bridge mode.
- The study states the trade-off and does not tell anyone which way to set it.
Caption: This is the owner's decision. The study describes the setting and its effect, and gives no verdict.
Notes: Router-behind-the-gateway and IP Passthrough [1]. The trade-off is the study's framing (Inferred).

## DEFENDER VIEW | Check your own network, read-only

Left: What to read
- What the gateway is, and whether it is routing or bridged (where the trusted firewall sits).
- Whether TCP port 7547 answers from the internet on your public address.
- Whether an owner-controlled router sits behind the gateway, with the household behind it.
Right: What it tells you
- Where the firewall the household relies on actually sits.
- Whether the management plane is exposed (the ISP's to close, not yours).
- Whether the gateway is still maintained by the vendor or ISP.
Caption: None of these was run here. A port that answers 7547 from the internet is the ISP's to close, not the owner's.
Notes: Architecture read [1]. Port 7547 exposure [4][5]. Router-behind read [1]. Firmware and support currency per device (Inferred).

## MITRE MAPPINGS | The study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Internet-facing gateway services in SharknAT&To, the 2016 attack, Misfortune Cookie |
| T1133 | External Remote Services | The vendor SSH account and the ISP's TR-069 management plane |
| T1584.005 | Compromise Infrastructure: Botnet | The 2016 Mirai variant's attempt to enslave gateways |
Caption: ATT&CK v20.0. No source names the ids; each row is the study's mapping. Only Mirai, a named botnet, is bound.
Notes: Names and tactics from library data [10]; ties from [1][3][4][5][8]. On Deutsche Telekom the botnet attempt failed (Inferred). © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | What the gateway teaches

- **Control decides security.** A hardcoded account or an exposed port can exist unseen; the fix is the vendor's or ISP's to ship [1].
- **The management plane is an attack surface.** When TR-069's port answered the internet, it became the way in [4][5].
- **Shared code spreads one flaw across millions of boxes.** A 2005 fix was still missing from 200+ models in 2014 [8].
- **The inside is reachable from the browser.** As with casting, Cable Haunt reached the ISP's modem through a web page [6][7].
Notes: Control [1]. Management plane [4][5]. Shared code [8]. Browser-reached inside [6][7]. Read-first is the study's framing (Inferred).
