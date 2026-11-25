# The ISP-Supplied Gateway: Who Controls the Box at the Edge of the Home Network, and Its Security Record

*A TeamStarWolf case study. Published 25 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [UPnP on the Home Network](/case-studies/UPNP_HOME_NETWORK.md), [Casting on the Home Network](/case-studies/CASTING_HOME_NETWORK.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Home and small-network users, network and security engineers, incident responders, and anyone who uses an ISP-supplied gateway

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 22 min (4,971 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You use the gateway your ISP supplied, you want to understand who controls that box and its security record, or you are deciding whether to put your own router behind it

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 6: What is fixed, what is design, what is a setting](#part-6-what-is-fixed-what-is-design-what-is-a-setting), [Part 7: Check your own network](#part-7-check-your-own-network)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[UPnP on the Home Network](/case-studies/UPNP_HOME_NETWORK.md), [Casting on the Home Network](/case-studies/CASTING_HOME_NETWORK.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-25):

- The gateway most households got from their ISP is a modem, router, firewall and Wi-Fi in one, and its firmware and remote management belong to the vendor and the ISP, not the subscriber. ([Executive summary](#executive-summary))
- Because the owner does not control the device, a hardcoded account or an exposed management port can sit on it unseen, and the owner's realistic options are narrow. ([Part 1: What an ISP-supplied gateway is, and who controls it](#part-1-what-an-isp-supplied-gateway-is-and-who-controls-it))
- The TR-069 management port was meant for the ISP alone; the November 2016 Mirai outage is what happened when gateways answered it to the whole internet. ([Part 3: The remote-management channel, and the 2016 TR-069 outage](#part-3-the-remote-management-channel-and-the-2016-tr-069-outage))
- The owner's most effective lever is to treat the gateway as untrusted and put an owned router behind it, behind a firewall they do control. ([Part 6: What is fixed, what is design, what is a setting](#part-6-what-is-fixed-what-is-design-what-is-a-setting))

<!-- meta:end -->

## Executive summary

The box where a home's internet service arrives, the one most households were given by their internet-service provider (ISP) rather than bought, is usually a single device that is a modem, a router, a firewall and a Wi-Fi access point at once. It sits at the edge of the network, it is reachable from the internet by design, and, unlike a router a person buys, it is written by a vendor and managed by the ISP. The thread running through this study, the one it shares with the [UPnP](/case-studies/UPNP_HOME_NETWORK.md) and [casting](/case-studies/CASTING_HOME_NETWORK.md) studies, is a question of control: on an ISP-supplied gateway the firmware, the remote-management channel and sometimes the accounts and services on the device belong to the vendor and the ISP, not the subscriber, so the device's security depends on them far more than on the owner.

The public record shows what that has meant in practice, and it is written here from four well-documented cases across a decade. Researchers at Nomotion found, in 2017, that the Arris-manufactured gateways AT&T supplied to its U-verse customers shipped with a hardcoded superuser account reachable over SSH, a command-injection path to a root shell, and an undocumented service that let an outsider reach devices inside the home network, with the researchers unsure whether the vendor or the ISP introduced them [1] (**Confirmed**). In November 2016 a variant of the Mirai botnet tried to take over home gateways through the TR-069 remote-management port, and on Deutsche Telekom's network the attack failed to infect the devices but crashed them, knocking customers offline [3] [4] [5] (**Confirmed**). In 2020 the Cable Haunt research showed that a standard component of Broadcom-based cable modems, reachable from a web page in the browser, could be overflowed to run code on the modem (CVE-2019-19494, CVE-2019-19495) [6] [7] (**Confirmed**). And the 2014 Misfortune Cookie work found an embedded web server, fixed by its maker in 2005, still shipping in gateways from many vendors years later (CVE-2014-9222) [8] [9] (**Confirmed**).

The defensive reading sorts the way the other two studies do. Some of this is fixed by a patch with a version: the Cable Haunt CVEs list fixed firmware, the TR-069 outage was followed by ISP firmware and port blocking, and the embedded-web-server flaw had a vendor fix available in 2005. Some is a design property no patch removes, because a gateway that the ISP manages remotely, that answers the internet, and that may carry vendor-installed accounts is behaving as built, and the subscriber cannot see or change most of it. And some is up to the owner, whose most effective lever is not to trust the gateway at all but to put their own router behind it. A reader can check the state of their own edge with read-only steps, which the last Part sets out. None of those checks was run for this study, and nothing here was tested against any device.

## Key facts at a glance

| Field | Value |
|---|---|
| What it is | The ISP-supplied gateway at the edge of a home network: modem, router, firewall and Wi-Fi in one, vendor-written and ISP-managed, reachable from the internet and remotely managed over the TR-069 protocol on TCP port 7547 [3] [4] |
| Core control property | The subscriber does not own the firmware or the management plane: a vendor writes the code and the ISP manages the device remotely, so the gateway's security rests with them, not the owner (**Inferred** from the record [1] [4] [8]) |
| Vendor-installed access | SharknAT&To, 2017: AT&T's Arris gateways carried a hardcoded SSH superuser account and a command-injection path to root, with no CVE assigned and no fixed firmware available at disclosure [1] [2] (**Confirmed**) |
| Remote-management channel | CVE-2016-10372: the TR-064 service on TCP port 7547 let a November 2016 Mirai variant run commands on gateways; on Deutsche Telekom the devices crashed rather than being infected [3] [4] [5] |
| LAN-side bug via the browser | Cable Haunt, 2020: a Broadcom cable-modem component reachable over a WebSocket, past the browser's cross-origin rules, was overflowed to run code (CVE-2019-19494, NVD CVSS 3.1 8.8; CVE-2019-19495, 9.8) [6] [7] |
| Scale and the embedded web server | Misfortune Cookie, 2014: the RomPager web server, fixed by its maker in 2005, still shipped in at least 200 device models years later (CVE-2014-9222) [8] [9] |

## Scope and method

This is a reference study of one attack surface, the ISP-supplied home gateway, read across the public record from 2014 to 2020. It is written for a typical home network: the ISP's gateway at the edge, and behind it the household's own devices, sometimes including a router the owner added. It describes a widely deployed family of these devices as the public record describes it; it names a vendor or model only where a cited source names one, it ties the material to no particular household, and it tested nothing. It is a defensive study: it explains each protocol and service well enough to show why a problem worked, then what a reader can check and decide, and it reproduces no attack recipe, no exploit code, and none of the specific credentials the sources published.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: the researcher's own write-up, the vendor advisory, or the CVE and NVD record |
| Reported | Known through journalism or a secondary summary |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

The primaries are Nomotion's 2017 report and Tenable's analysis of it for the AT&T gateways [1] [2]; Kaspersky's and Radware's reports and the NVD record for the 2016 TR-069 attack [3] [4] [5]; the Lyrebirds Cable Haunt report and the NVD records for the 2020 cable-modem flaws [6] [7]; and Check Point's disclosure and the NVD record for the 2014 embedded-web-server flaw [8] [9]. Where a count of affected devices comes from a vendor, an ISP or a researcher, this study says whose figure it is.

## Part 1: What an ISP-supplied gateway is, and who controls it

A router a person buys at a shop is theirs: they hold the admin password, they choose when to update it, and nobody else is supposed to reach its management interface. The box an ISP supplies is a different kind of device, and three properties set it apart.

**It is several devices in one, at the edge.** The ISP gateway terminates the broadband line (the modem), hands out the home's addresses and does network address translation (the router), decides what may cross between the internet and the home (the firewall), and serves Wi-Fi. Because it is the modem, it holds the public address and is directly reachable from the internet, which is the position the UPnP study called the worst one for a home device to be in. Nomotion noted this plainly about the AT&T gateways, that they "route traffic, sensitive communications and trade secrets for millions of customers" and "are directly reachable from the Internet at large" [1] (**Confirmed**).

**The ISP manages it remotely.** Most ISP gateways speak TR-069, also called CWMP, a protocol whose purpose Radware states directly: it "is designed to allow Internet Service Providers (ISP's) to remotely manage devices on their network" [4] (**Confirmed**). The ISP's management server (an auto-configuration server, or ACS) can read and change the gateway's settings and push firmware, and the gateway listens for this, commonly on TCP port 7547 [3] [4] (**Confirmed**). This is a management plane the subscriber does not own and usually cannot turn off, and Parts 3 and 5 show what happens when it is reachable by anyone rather than only the ISP.

**The vendor writes the firmware, and the ISP may add to it.** The subscriber runs whatever code the vendor and ISP put on the device. Nomotion was explicit that it could not tell, from the firmware, whether the vendor or the ISP was responsible for what it found: "it is uncertain whether these gaping security holes were introduced by Arris (the OEM) or if these problems were added after delivery to the ISP (AT&T U-verse)", adding that AT&T engineers appeared to "have the authority and ability to add and customize code running on these devices" [1] (**Confirmed**). Either way, the accounts and services on the box are not the owner's to audit.

The consequence runs through the rest of the study, and it is this study's framing of the cases that follow (**Inferred**): on a device the owner does not control, whose code they did not write and whose management plane they cannot see, security is something the vendor and the ISP provide or fail to provide, and the owner's realistic options are narrow. The strongest of them, treating the gateway as untrusted and putting an owned router behind it, is the subject of Part 6.

## Part 2: Vendor-installed access, SharknAT&To

The clearest illustration of the control problem is a device that answers to someone other than its owner by design. In August 2017 the firm Nomotion published a report, titled SharknAT&To, on the Arris-manufactured gateways that AT&T supplied to its U-verse customers, naming the NVG589 and NVG599 models [1] (**Confirmed**). It described five issues, which Tenable summarised as hardcoded credentials, information exposure, authenticated command injection and a firewall bypass [2] (**Reported**). This study describes them at the level of what went wrong, not how to repeat it, and reproduces none of the credentials or payloads the report published.

**A hardcoded superuser, reachable over SSH.** Nomotion found that a firmware build for the NVG589 and NVG599 enabled SSH and carried a hardcoded username and password for a privileged account, giving anyone who knew them a menu shell on the device; because that shell ran as root and did not check its inputs, it could be turned into a full root shell [1] (**Confirmed**). The account was not a secret in the usual sense: Tenable noted that remote SSH access through this account had been mentioned on a public forum as early as November 2014 [2] (**Reported**). For the count of exposed devices Nomotion gave a measured figure and its source, that "Censys reports 14,894 hosts which are likely vulnerable", with the caveat that the number might not be complete [1] (**Confirmed** as the researchers' cited figure).

**A hidden control server, and a path to root.** A second service, an HTTPS server the report calls `caserver`, ran on an uncommon high port on the NVG599 with a default account, and it accepted commands that led again to code execution as root [1] (**Confirmed**). Because the port is one that internet-wide scanners do not usually probe, Nomotion could only estimate the reach, and it said so: "our ballpark figure is around 220,000 devices" [1] (**Confirmed** as the researchers' estimate).

**Reading the inside of the home, and reaching into it.** A third service exposed configuration and logs, including Wi-Fi credentials and the addresses of devices on the home network, to anyone who presented a hardcoded account and the gateway's serial number [1] (**Confirmed**). The most widespread issue was the fifth: an undocumented service that acted as a proxy from the internet into the home. Nomotion reported that "every single AT&T device observed has had this port (49152) open", that it let an outside party open a connection to a device inside the home network, bypassing the firewall, and that "it is believed that the original purpose of this service was to allow AT&T to connect to the AT&T issued DVR devices which reside on the internal LAN" [1] (**Confirmed** as the report's observation and stated belief). A feature the ISP built for its own convenience had become a hole in the perimeter.

What makes SharknAT&To a control story rather than only a bug story is the fix. Nomotion went straight to public disclosure and no CVE identifier was assigned to these issues, so there is no CVE record to cite for them. Tenable, checking a day later, reported that the last firmware Arris had released for many of these devices was "9.1.1h0d34 released back in May 2013", and that at the time of writing "no updated firmware that remediates these issues has yet been deployed or made available", so it pointed owners to Nomotion's own mitigation steps [2] (**Reported**). A subscriber could not patch the device, because the firmware was not theirs to change.

## Part 3: The remote-management channel, and the 2016 TR-069 outage

The management plane from Part 1 is itself an attack surface, and in late November 2016 it produced one of the most visible home-gateway incidents on record.

The weakness was in TR-064, a local-configuration companion to the TR-069 management protocol, exposed on the same TCP port 7547. The NVD record for CVE-2016-10372 describes it on the modem where it was first documented: "The Eir D1000 modem does not properly restrict the TR-064 protocol, which allows remote attackers to execute arbitrary commands via TCP port 7547", by steps that in the record included opening the device's web interface to the internet and abusing a server-name field [5] (**Confirmed**). Kaspersky, watching the attack in progress, saw requests arrive on port 7547 that made the device fetch and run a file, and identified the payload as a Mirai variant; it noted that because the malware could not write itself to the device's permanent storage, "the infection will not survive a reboot" [3] (**Confirmed**).

The scale came from where this was pointed. Radware reported that the attackers used "a customized Mirai botnet variant" against Deutsche Telekom and other networks, that the targeted devices "were configured to accept TR-064 commands from the Internet", and, importantly for how the incident is remembered, that on Deutsche Telekom's routers the takeover did not work as intended: "This attempt failed and the routers where not infected. Yet, the devices crashed due to an overload caused by the attack" [4] (**Confirmed** as Radware's analysis). So the outage that took a large number of Deutsche Telekom customers off the internet was a side effect of a failed infection, not a successful botnet recruitment (**Inferred** from Radware [4]).

The response is the template for this class. Radware recorded that ISPs moved to "block all IP address, except for their own range" from reaching port 7547, that Deutsche Telekom and UK ISPs pushed an update that "prevents third party access to the remote maintenance interface", and that users were told to power the device off and on so it would pull the new firmware [4] (**Confirmed**). The management port was never meant to answer anyone but the ISP; the incident was what happened when it answered the world, and the fix was to put it back behind the ISP.

## Part 4: A LAN-side bug reached through the browser, Cable Haunt

Not every gateway weakness faces the internet. Some sit on the inside, meant to be reachable only from the home network, and are reached anyway through the owner's own browser, the pattern the casting study described for Google's cast devices. Cable Haunt is that pattern on the ISP's cable modem.

In January 2020 the Danish group Lyrebirds published Cable Haunt, a flaw in a component that Broadcom-based cable modems share. The target is the spectrum analyzer, a standard tool in these modems for diagnosing the cable connection, which listens on the local network and takes requests as JSON over a WebSocket. The report's own summary is that the modems are vulnerable to "remote code execution through a websocket connection, bypassing normal CORS and SOC rules, and then subsequently by overflowing the registers", and that the exploit is possible because of a lack of proper authorisation of the WebSocket client, default credentials, and a programming error in the spectrum analyzer [6] (**Confirmed**). The browser angle is the important one: a WebSocket opened by a web page is not fully covered by the browser's cross-origin rules, so a page the victim merely visits can open a connection to the modem on the local network, and the modems the researchers tested did not reject it [6] (**Confirmed**). Default credentials, which the report found the ISP typically set to predictable values, removed the last barrier [6] (**Confirmed**).

The NVD records give the identifiers and the scores, and both are NVD's own, not a third party's. CVE-2019-19494 is the buffer overflow, scored CVSS 3.1 8.8 (High) by the NVD, described as affecting "Broadcom based cable modems across multiple vendors" and letting "a remote attacker to execute arbitrary code at the kernel level via JavaScript run in a victim's browser", with named examples including Sagemcom, NETGEAR, Technicolor and COMPAL models [7] (**Confirmed**). CVE-2019-19495 is a related DNS-rebinding issue on one tested model, scored 9.8 (Critical), that let an attacker reconfigure the modem from the browser and forward its internal Telnet server out to the internet for a root shell [7] (**Confirmed**). Where the CVE record names a fixed firmware version, for example a Sagemcom build "prior to 50.10.21_T4", that version is the fix, and it reaches a subscriber only when the ISP or vendor ships it [7] (**Inferred** from the record). The report also made the control point directly: because the modem is the ISP's, the default credentials that open it "will therefore be available for any attacker" who learns the ISP's pattern [6] (**Confirmed**).

## Part 5: The embedded web server, and scale, Misfortune Cookie

The last case is the oldest, and it is about how a single flaw in shared code becomes a flaw in millions of gateways that no one updates.

In December 2014 Check Point disclosed Misfortune Cookie, CVE-2014-9222. The flaw is in RomPager, an embedded web server made by AllegroSoft and built into the management interface of a great many home gateways. The NVD record describes it as "AllegroSoft RomPager 4.34 and earlier, as used in Huawei Home Gateway products and other vendors and products, allows remote attackers to gain privileges via a crafted cookie that triggers memory corruption" [9] (**Confirmed**). Check Point's own account is that a crafted HTTP cookie corrupts memory and can "trick the attacked device to treat the current session with administrative privileges" [8] (**Confirmed**).

Two things make it a gateway-scale story. First the count, which is Check Point's: its research "detected at least 200 different models" exposing a vulnerable service on the public internet [8] (**Confirmed** as Check Point's figure). Second the age of the fix. Check Point states that "AllegroSoft issued a fixed version to address the Misfortune Cookie vulnerability in 2005, which was provided to licensed manufacturers", nine years before the public disclosure [8] (**Confirmed**). The flaw persisted not because it was unfixable but because the fix never reached the shipped devices: manufacturers kept building the old version into new gateways, and Check Point warned that a vendor update "may patch RomPager to fix Misfortune Cookie without changing the displayed version number", so even the version string could not be trusted as a sign of safety [8] (**Confirmed**).

Check Point was also careful about a point this study has to keep straight: the role of the remote-management protocol. It wrote that "while the proliferation of devices managed by TR-069 is responsible for creating a very large vulnerable client population, Misfortune Cookie is not a vulnerability related to the TR-069/CWMP per se" [8] (**Confirmed**). The management protocol did not cause the bug; it explains why so many identical, rarely-updated boxes carried it. That is the scale property of ISP gateways in one sentence (**Inferred**).

## Part 6: What is fixed, what is design, what is a setting

The record sorts into three piles, and keeping them apart is the point of the study.

- **Fixed, by a patch with a version or a date.** The Cable Haunt flaws have fixed firmware versions in their CVE records, shipped through the ISP or vendor [7] (**Confirmed**). The embedded-web-server flaw had a vendor fix available in 2005, which only mattered where a manufacturer actually built it in [8] (**Confirmed**). The 2016 TR-069 attack was answered within days by ISP firmware and by blocking the management port from the public internet [4] (**Confirmed**). The common thread is that the subscriber is rarely the one who applies the fix; the vendor or the ISP is, which is why an unsupported or abandoned gateway is the real exposure.
- **Design, which no patch removes.** The gateway is reachable from the internet because it is the modem; it is managed remotely by the ISP because that is what TR-069 is for; and it runs vendor and ISP code the owner cannot audit, which is how a hardcoded account or an undocumented proxy can be present without the owner ever knowing. These are properties of the arrangement, not bugs in it, and no patch removes them. The one in the owner's hands is the trust boundary: a gateway the owner does not control can be treated as if it were part of the internet rather than part of the home.
- **Up to the owner.** The most effective lever in this study is to put an owned router behind the ISP gateway, so the household's devices sit behind a second firewall the owner does control, and the gateway is treated as untrusted. On many ISP gateways this is done by placing the gateway in a bridge or pass-through mode, or by accepting a second layer of address translation. A Nomotion reader reported doing exactly this, running an NVG599 "in IP Passthrough mode" with "my own firewall behind the gateway" [1] (**Reported** as a reader's account). The owner also controls whether the gateway's firmware is current where they can influence it, and whether to ask the ISP for a different device or run their own.

The trade-off belongs in the decision rather than hidden from it. Putting a second router behind the gateway adds a layer of address translation that can complicate some applications, and not every ISP gateway offers a clean bridge mode, so the choice has a cost. This study describes the setting and its effect and does not tell anyone which way to set it (**Inferred**).

## Part 7: Check your own network

These checks are read-only. They look at the current state of a network and change nothing, and none of them was run for this study. Deciding whether to add a router, change a mode, or ask the ISP for a different device comes after, and is the owner's decision.

1. **Identify the gateway and whether it is routing or bridged.** Read the device's own label and administration page to learn what it is and whether it is acting as the router for the home or passing the connection through to another router. This tells you where the firewall the household relies on actually sits (**Inferred** from the architecture in Part 1).
2. **Check whether the management port answers from the internet.** The 2016 incident was gateways that accepted TR-064 and TR-069 requests on TCP port 7547 from anyone, not only the ISP [4] [5] (**Confirmed**). A reader can check whether their public address answers on that port, remembering that a general port checker tests TCP and that, where a second router sits behind the gateway, the public address is the gateway's. A port that answers the internet here is the ISP's to close, not the owner's.
3. **Check for the owner's own router behind the gateway.** If a second, owner-controlled router is in place, confirm the household's devices are behind it and not on the gateway's own network. This is the Part 6 mitigation, read rather than assumed (**Inferred** [1]).
4. **Check the gateway's firmware and support status.** Because the fixes in this study are shipped by the vendor or the ISP, a gateway's exposure depends on whether it still receives them. Read the firmware version and whether the model is still supported; an old or abandoned gateway stays at whatever year it stopped being updated (**Inferred** from the dated fixes [7] [8]).

What these readings tell you maps onto Part 6: where the trusted firewall sits, whether the management plane is exposed, whether the owner has put a controlled device in front of their own network, and whether the gateway is still maintained. None of it requires touching another person's device or sending anything other than ordinary requests to your own equipment and public address.

## MITRE ATT&CK mappings

This Part binds the behaviours in the record to MITRE ATT&CK v20.0. No source names ATT&CK identifiers; each row is this study's own mapping, checked against the library's technique data (**Inferred**; names and tactics **Demonstrated** from `data/attack/technique_profiles.jsonl` [10]). The gateways are devices, not actors, so no group, software or campaign is bound, except that the 2016 case involved the Mirai botnet, which the botnet row notes.

| ID | Name | Tie to this record |
|---|---|---|
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | The internet-facing gateway services exploited in SharknAT&To, the 2016 TR-069 attack, and Misfortune Cookie [1] [5] [8] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | The vendor SSH account and the ISP's TR-069 management plane as remote access into the device [1] [4] |
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Compromise Infrastructure: Botnet | The 2016 Mirai variant's attempt to enslave gateways through port 7547 [3] [4] |

Fit notes (**Inferred**): T1190 is the nearest fit for exploiting a network-facing service on the device and is bound to the three cases that did so from the internet. T1133 covers both the vendor-installed SSH account and the ISP management channel, each a remote way into the device that is not the owner's. T1584.005 is bound to the Mirai case, where the goal was to add the gateways to a botnet; on Deutsche Telekom the attempt failed, which the record states.

## Cross-cutting themes

- **Control decides security here.** On a device the owner did not write and cannot fully manage, a hardcoded account, an undocumented proxy or an exposed management port can exist without the owner's knowledge, and the fix is the vendor's or the ISP's to ship. Nomotion could not even tell whether the vendor or the ISP introduced what it found [1] (**Confirmed**).
- **The management plane is an attack surface.** TR-069 exists so the ISP can manage the gateway remotely; when its port answered the internet rather than only the ISP, it became the way in, as the 2016 outage showed [4] [5] (**Confirmed**).
- **Shared code spreads a single flaw across millions of boxes.** An embedded web server fixed in 2005 was still shipping in at least 200 device models in 2014, because the fix never reached the devices [8] (**Confirmed**).
- **The inside is reachable from the browser.** As with casting, a service meant for the local network was reached through the victim's own web browser; Cable Haunt is that pattern on the ISP's modem [6] [7] (**Confirmed**). Read before you change: every defensive step here starts by reading the current state, and the change, where the owner can make one at all, is theirs to make (**Inferred**).

## Sources

All sources were opened on 25 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Nomotion, "SharknAT&To", 31 August 2017 (read via the Internet Archive), for the hardcoded SSH superuser, the caserver command injection, the port 61001 information disclosure, the port 49152 firewall-bypass proxy, the vendor-or-ISP uncertainty, and the Censys and 220,000 figures with their sources | [web.archive.org/web/2017/https://www.nomotion.net/blog/sharknatto/](https://web.archive.org/web/20170901163641id_/https://www.nomotion.net/blog/sharknatto/) | 2026-11-25 | Confirmed |
| 2 | Tenable (Carlos Perez), "Hardcoded Credentials Expose Customers of AT&T U-Verse", 1 September 2017, for the summary of the five issue types, the additional affected models, the May 2013 last-firmware date, and the no-fix-available status at disclosure | [tenable.com/blog/hardcoded-credentials-expose-customers-of-att-u-verse](https://www.tenable.com/blog/hardcoded-credentials-expose-customers-of-att-u-verse) | 2026-11-25 | Reported |
| 3 | Kaspersky Securelist (Stefan Ortloff), "New wave of Mirai attacking home routers", November 2016, for the port-7547 TR-064 request, the Mirai payload, and the note that the infection does not survive a reboot | [securelist.com/new-wave-of-mirai-attacking-home-routers/76791](https://securelist.com/new-wave-of-mirai-attacking-home-routers/76791/) | 2026-11-25 | Confirmed |
| 4 | Radware, "Deutsche Telekom Routers Takeover Attempt", 1 December 2016, for the customized Mirai variant, the TR-069 remote-management description, the TR-064-from-the-internet configuration, the crashed-not-infected outcome, and the ISP response | [radware.com/security/ddos-threats-attacks/threat-advisories-attack-reports/deutsche-telekom-routers-takeover](https://www.radware.com/security/ddos-threats-attacks/threat-advisories-attack-reports/deutsche-telekom-routers-takeover/) | 2026-11-25 | Confirmed |
| 5 | NVD, CVE-2016-10372 (Eir D1000 / TR-064), for the description, the TCP port 7547 vector, the CVSS 3.0 9.8 score (NVD primary) and CWE-264 | [nvd.nist.gov/vuln/detail/CVE-2016-10372](https://nvd.nist.gov/vuln/detail/CVE-2016-10372) | 2026-11-25 | Confirmed |
| 6 | Lyrebirds, Cable Haunt report (cablehaunt.com and the report PDF, version 2.4, January 2020), for the spectrum-analyzer buffer overflow, the WebSocket-past-CORS and DNS-rebinding mechanism, the default credentials, and the ISP-controlled-credential point | [github.com/Lyrebirds/Cable-Haunt-Report](https://github.com/Lyrebirds/Cable-Haunt-Report/releases/download/2.4/report.pdf) | 2026-11-25 | Confirmed |
| 7 | NVD, CVE-2019-19494 (CVSS 3.1 8.8, CWE-120) and CVE-2019-19495 (9.8, CWE-20), both NVD primary scores, for the Broadcom-modem code execution and the DNS-rebinding-to-root-shell issue, and the fixed firmware versions named | [nvd.nist.gov/vuln/detail/CVE-2019-19494](https://nvd.nist.gov/vuln/detail/CVE-2019-19494) | 2026-11-25 | Confirmed |
| 8 | Check Point, "Misfortune Cookie", December 2014, for the RomPager crafted-cookie mechanism, the at-least-200-models figure, the 2005 AllegroSoft fix, the version-string caveat, and the TR-069-proliferation-not-cause distinction | [sc1.checkpoint.com/misfortune-cookie/index.html](https://sc1.checkpoint.com/misfortune-cookie/index.html) | 2026-11-25 | Confirmed |
| 9 | NVD, CVE-2014-9222 (Misfortune Cookie), for the RomPager 4.34-and-earlier description, the crafted-cookie memory corruption, and the CVSS 2.0 10.0 score (NVD primary) and CWE-17 | [nvd.nist.gov/vuln/detail/CVE-2014-9222](https://nvd.nist.gov/vuln/detail/CVE-2014-9222) | 2026-11-25 | Confirmed |
| 10 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl` (ATT&CK v20.0), for the technique names and tactics in the mappings | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-25 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

## Related references

- [UPnP on the Home Network](/case-studies/UPNP_HOME_NETWORK.md), [Casting on the Home Network](/case-studies/CASTING_HOME_NETWORK.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md)
- [All case studies](/case-studies/README.md)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
