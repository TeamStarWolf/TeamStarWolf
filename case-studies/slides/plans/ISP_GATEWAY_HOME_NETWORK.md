# Slide plan: The ISP-Supplied Gateway: Who Controls the Box at the Edge of the Home Network, and Its Security Record

- Study: case-studies/ISP_GATEWAY_HOME_NETWORK.md
- Cover title: The ISP-Supplied Gateway / Who Controls the Box at the Edge / of the Home Network
- Subtitle: A device the subscriber does not own, the bugs the vendor and ISP shipped, the design no patch removes, and the router you can put in front of it
- Published: 25 November 2026
- Notes: Slide plan for the deck of the study case-studies/ISP_GATEWAY_HOME_NETWORK.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Who controls the box at the edge

- The ISP's gateway is modem, router, firewall and Wi-Fi in one, at the edge of the home network.
- Unlike a router you buy, the vendor writes its firmware and the ISP manages it remotely.
- So a hardcoded account, an exposed management port or a shared-code bug can sit there unseen by the owner.
- Fixed by the vendor or ISP, a design no patch removes, and the owner's own router in front are different things.
Caption: Evidence grade: Confirmed for the write-ups, records and advisories; Reported for a summary or an ISP figure; Inferred where it reasons.
Notes: Combined device, ISP-managed [1][5]. SharknAT&To, four CVEs [1][3]. TR-069 outage [5][7][8]. Cable Haunt [9][10]. Misfortune Cookie [11][12]. The pile split is the study's framing (Inferred).

## KEY FACTS | The device, the record, the names

Stat: 4 | CVEs for SharknAT&To, AT&T's Arris gateways
Stat: 7547 | the TCP port the ISP manages the box on
Stat: 8.8 | NVD CVSS for the Cable Haunt overflow
Stat: 2005 | year the RomPager fix shipped to makers
- Vendor-or-ISP access: SharknAT&To (2017) found a hardcoded SSH account in AT&T's Arris gateways.
- Management plane: a 2016 Mirai variant hit TR-069 on port 7547; Deutsche Telekom's routers crashed.
- Browser-reachable: Cable Haunt (2020) overflowed a Broadcom modem component from a web page.
Notes: Four CVEs [3]. Port 7547 [5]. 8.8 is NVD's own score for CVE-2019-19494 [10]. 2005 fix [11]. SharknAT&To [1]. TR-069 [5][7]. Cable Haunt [9].

## PART 1 | The record at a glance, 2005 to 2020

| Date | Event |
|---|---|
| 2005 | AllegroSoft fixes RomPager; the old version keeps shipping |
| Dec 2014 | Misfortune Cookie: RomPager detected exposed in 200+ models |
| Nov 2016 | A Mirai variant hits gateways on the TR-069 port 7547 |
| Dec 2016 | Deutsche Telekom routers crash in the attack, not infected |
| Aug-Sep 2017 | SharknAT&To, then four CVEs, in AT&T's Arris gateways |
| Jan 2020 | Cable Haunt: Broadcom cable-modem code execution via the browser |
Caption: One root throughout: a device the owner does not control, whose firmware and management belong to the vendor and ISP.
Notes: RomPager 2005 fix and 200+ exposed [11]. TR-069 attack and crash [5]. SharknAT&To and the four CVEs [1][3]. Cable Haunt [9][10].

## PART 1 | What an ISP gateway is, and who controls it

- **Several devices in one, at the edge.** Modem, router, firewall and Wi-Fi; it holds the public address and answers the internet.
- **The ISP manages it remotely.** TR-069 (also called CWMP) lets a provider "remotely manage devices on their network" [5], usually on port 7547.
- **The vendor writes the firmware, the ISP may add to it.** The owner runs code they did not write and cannot audit.
- The subscriber owns neither the firmware nor the management plane, so security rests with the vendor and ISP.
Caption: Control is the theme: the owner's realistic lever is to treat the gateway as untrusted, not to patch what is not theirs.
Notes: Internet-facing [1]. TR-069 purpose and CWMP [5][11]; port 7547 [4][5]. Vendor-or-ISP code [1]. The control reading is the study's framing (Inferred).

## PART 2 | Vendor-or-ISP access: SharknAT&To

- Nomotion (2017) found AT&T's Arris NVG589 and NVG599 carried, in a firmware update, a hardcoded SSH account.
- That account reached a root shell; a caserver service and a port-61001 info-disclosure service made it worse.
- A proxy on a WAN port let an outsider reach a client device inside the home, if they knew its hardware address.
- Four CVEs followed (CVE-2017-14115/-14116/-14117/-10793), each only when the gateway is not in pass-through.
Caption: Nomotion could not tell whether vendor or ISP introduced them; no vendor fix date is in the record, though it gave owner steps [1][2].
Notes: Hardcoded SSH, caserver, 61001 disclosure, 49152 proxy [1]. Four CVEs, scores, pass-through condition [3]. Vendor-or-ISP uncertainty [1]. No-fix + self-mitigation [1][2]. No credentials or payloads reproduced.

## PART 3 | The remote-management channel: the 2016 TR-069 outage

- TR-064, on port 7547, let a November 2016 Mirai variant run commands on vulnerable gateways.
- CVE-2016-10372 is the Eir D1000's record: "does not properly restrict the TR-064 protocol ... via TCP port 7547" [6].
- On Deutsche Telekom the injection did not work; the routers crashed under the request flood [5][7].
- Deutsche Telekom said the malware failed to infect; about four percent of its customers had problems, some 900,000 routers offline [8].
Caption: Kaspersky gives the mechanism; Radware the crash; a hands-on test and DT's own account give the DT outcome. The port is the ISP's to close.
Notes: Mechanism and reboot note [4]. CVE description, port 7547, NVD 9.8 [6]. Crashed-not-infected [5]; DoS-by-three-requests [7]; DT figures as reported [8]. "should block" is Radware's recommendation [5].

## PART 4 | A LAN-side bug via the browser: Cable Haunt

- A Broadcom cable-modem component, the spectrum analyzer, listens on the local network over a WebSocket.
- A web page can reach it past the browser's cross-origin rules; the tested modems did not reject it.
- Overflowing it runs code: CVE-2019-19494 (NVD CVSS 8.8); a DNS-rebinding sibling is CVE-2019-19495 (9.8).
- Where a provider shares one support password across its modems, it is "available for any attacker owning any router" from it [9].
Caption: The same browser-reached pattern as casting, on the ISP's modem; one model's record names a fixed firmware, the others do not.
Notes: Spectrum analyzer, WebSocket-past-cross-origin, default creds, shared support password [9]; exec quote is report v2.5. NVD scores, both NVD's own [10]. Fix status uneven in the records [10].

## PART 5 | Shared code at scale: Misfortune Cookie

- RomPager, an embedded web server by AllegroSoft, sat in the management interface of many gateways.
- A crafted HTTP cookie corrupts memory and can "treat the current session with administrative privileges" [11].
- Check Point detected "at least 200 different models" exposed, about 12 million devices in 189 countries [11].
- AllegroSoft fixed it in 2005; Check Point said devices still shipped the old one, and had "no direct evidence yet" of attacks [11].
Caption: TR-069's reach spread the vulnerable population; Check Point says it "is not a vulnerability related to the TR-069/CWMP per se" [11].
Notes: Mechanism and admin-session quote [11]. 200 detected exposed + 12M/189 + no-evidence + 2005 fix + still-ship + TR-069-not-cause [11]. CVE-2014-9222 [12].

## PART 6 | Fixed, design, and setting

| Pile | What it covers | What to do |
|---|---|---|
| Fixed by vendor or ISP | Cable Haunt firmware (one model); the 2005 RomPager fix; the 2016 port block | depends on the vendor or ISP shipping it |
| Design, no patch removes | internet-facing; ISP-managed; vendor code the owner cannot audit | treat the gateway as untrusted |
| Up to the owner | a router in front; bridge or pass-through; firmware | decide against the trade-off |
Caption: The four 2017 CVEs applied only when the gateway was not in pass-through, so an owner's router in front is the records' own out-of-scope case.
Notes: Fixed set [5][10][11]. Design properties [1][5]. Owner's router-in-front lever grounded in the CVE pass-through condition [3].

## PART 6 | The trade-off: a router in front of your network

- The strongest owner lever is to put an owned router in front of the household and treat the gateway as untrusted.
- On many gateways this means a bridge or pass-through mode, or accepting a second layer of address translation.
- A second layer of translation can complicate some applications, and not every gateway offers a clean bridge mode.
- The study states the trade-off and does not tell anyone which way to set it.
Caption: This is the owner's decision. The study describes the setting and its effect, and gives no verdict.
Notes: Router-in-front grounded in the CVE pass-through condition [3]. The trade-off is the study's framing (Inferred).

## DEFENDER VIEW | Check your own network, read-only

Left: What to read
- What the gateway is, and whether it is routing or in pass-through (where the trusted firewall sits).
- Whether TCP port 7547 answers from the internet on your public address.
- Whether an owner-controlled router is doing the routing, with the household behind it.
Right: What it tells you
- Where the firewall the household relies on actually sits.
- Whether the management plane is exposed (the ISP's to close, not yours).
- Whether the gateway is still maintained by the vendor or ISP.
Caption: None of these was run here. A port that answers 7547 from the internet is the ISP's to close, not the owner's.
Notes: Architecture read, pass-through condition [3]. Port 7547 exposure [5][6]. Router-doing-routing read [3]. Firmware and support currency per device (Inferred).

## MITRE MAPPINGS | The study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Internet-facing gateway services in SharknAT&To, the 2016 attack, Misfortune Cookie |
| T1133 | External Remote Services | The hardcoded SSH account in the firmware and the ISP's TR-069 management plane |
| T1584.005 | Compromise Infrastructure: Botnet | The 2016 Mirai variant's attempt to enslave gateways |
Caption: ATT&CK v20.0. No source names the ids; each row is the study's mapping. Only Mirai, a named botnet, is bound.
Notes: Names and tactics from library data [13]; ties from [1][4][5][6][11]. The study does not claim who placed the SSH account. On Deutsche Telekom the botnet attempt failed (Inferred). © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | What the gateway teaches

- **Control decides security.** A hardcoded account or an exposed port can exist unseen; the fix is the vendor's or ISP's to ship [1].
- **The management plane is an attack surface.** When TR-069's port answered the internet, it became the way in [5][6].
- **Shared code spreads one flaw across many boxes.** A 2005 fix was still missing from 200+ exposed models in 2014 [11].
- **The inside is reachable from the browser.** As with casting, Cable Haunt reached the ISP's modem through a web page [9][10].
Notes: Control [1]. Management plane [5][6]. Shared code [11]. Browser-reached inside [9][10]. Read-first is the study's framing (Inferred).
