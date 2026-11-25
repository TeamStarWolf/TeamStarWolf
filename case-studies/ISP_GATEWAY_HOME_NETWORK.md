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

About 25 min (5,808 words at 230 words a minute)

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

- The gateway a household's ISP supplies is a modem, router, firewall and Wi-Fi in one, and its firmware and remote management belong to the vendor and the ISP, not the subscriber. ([Executive summary](#executive-summary))
- Because the owner does not control the device, a hardcoded account or an exposed management port can sit on it unseen, and the owner's realistic options are narrow. ([Part 1: What an ISP-supplied gateway is, and who controls it](#part-1-what-an-isp-supplied-gateway-is-and-who-controls-it))
- The TR-069 management port was meant for the ISP alone; the November 2016 Mirai outage is what happened when gateways answered it to the whole internet. ([Part 3: The remote-management channel, and the 2016 TR-069 outage](#part-3-the-remote-management-channel-and-the-2016-tr-069-outage))
- The owner's most effective lever is to treat the gateway as untrusted and put an owned router in front of their devices; the four 2017 CVE records applied only when the gateway was not in pass-through mode. ([Part 6: What is fixed, what is design, what is a setting](#part-6-what-is-fixed-what-is-design-what-is-a-setting))

<!-- meta:end -->

## Executive summary

The box where a home's internet service arrives, the one the internet-service provider (ISP) supplied rather than one the household bought, is usually a single device that is a modem, a router, a firewall and a Wi-Fi access point at once. It sits at the edge of the network, it is reachable from the internet by design, and, unlike a router a person buys, it is written by a vendor and managed by the ISP. The thread running through this study, the one it shares with the [UPnP](/case-studies/UPNP_HOME_NETWORK.md) and [casting](/case-studies/CASTING_HOME_NETWORK.md) studies, is a question of control: on an ISP-supplied gateway the firmware, the remote-management channel and sometimes the accounts and services on the device belong to the vendor and the ISP, not the subscriber, so the device's security depends on them far more than on the owner.

The public record shows what that has meant in practice, and it is written here from four well-documented cases between 2014 and 2020. Researchers at Nomotion found, in 2017, that the Arris-manufactured gateways AT&T supplied to its U-verse customers carried, in a firmware update, a hardcoded account reachable over SSH, a path to a root shell, and a service that let an outsider reach devices inside the home network; the four issues became CVE-2017-14115, CVE-2017-14116, CVE-2017-14117 and CVE-2017-10793, each recorded only when the gateway is not in IP Passthrough mode, and Nomotion was unsure whether the vendor or the ISP had introduced them [1] [3] (**Confirmed**). In late November 2016 a variant of the Mirai botnet tried to take over home gateways through the TR-069 remote-management port; on Deutsche Telekom's routers the published command injection did not work, and the devices crashed under the flood of requests instead, knocking a large share of customers offline [5] [7] [8] (**Confirmed** for the crash outcome; **Reported** for the figures). In 2020 the Cable Haunt research showed that a diagnostic component of Broadcom-based cable modems, reachable from a web page in the browser, could be overflowed to run code on the modem (CVE-2019-19494, CVE-2019-19495) [9] [10] (**Confirmed**). And the 2014 Misfortune Cookie work found an embedded web server, fixed by its maker in 2005, detected exposed on the internet in at least 200 device models years later (CVE-2014-9222) [11] [12] (**Confirmed**).

The defensive reading sorts the way the other two studies do. Some of this is fixed by a patch with a version: the Cable Haunt records name fixed firmware for one model, and the embedded-web-server flaw had a vendor fix available in 2005. Some is a design property no patch removes, because a gateway that the ISP manages remotely, that answers the internet, and that may carry accounts the subscriber cannot see is behaving as built. And some is up to the owner, whose most effective lever is not to trust the gateway at all but to put their own router behind it, the configuration the four 2017 CVE records name as the one in which the flaws do not apply. A reader can check the state of their own edge with read-only steps, which the last Part sets out. None of those checks was run for this study, and nothing here was tested against any device.

## Key facts at a glance

| Field | Value |
|---|---|
| What it is | The ISP-supplied gateway at the edge of a home network: modem, router, firewall and Wi-Fi in one, vendor-written and ISP-managed, reachable from the internet and remotely managed over the TR-069 protocol (also called CWMP [11]) on TCP port 7547 [4] [5] |
| Core control property | The subscriber does not own the firmware or the management plane: a vendor writes the code and the ISP manages the device remotely, so the gateway's security rests with them, not the owner (**Inferred** from the record [1] [5] [11]) |
| Vendor-or-ISP access | SharknAT&To, 2017: AT&T's Arris gateways carried, in a firmware update, a hardcoded SSH account and a path to root (CVE-2017-14115, -14116, -14117, -10793; NVD base scores 8.1, 8.1, 5.9 and 8.1, all NVD-primary), each applying only when the gateway is not in IP Passthrough mode [1] [3] (**Confirmed**) |
| Remote-management channel | CVE-2016-10372: the TR-064 service on TCP port 7547 let a November 2016 Mirai variant run commands on the Eir D1000 modem; on Deutsche Telekom the devices crashed rather than being infected [5] [6] [7] |
| LAN-side bug via the browser | Cable Haunt, 2020: a Broadcom cable-modem component reachable over a WebSocket, past the browser's cross-origin rules, was overflowed to run code (CVE-2019-19494, NVD CVSS 3.1 8.8; CVE-2019-19495, 9.8) [9] [10] |
| Scale and the embedded web server | Misfortune Cookie, 2014: the RomPager web server, fixed by its maker in 2005, was detected exposed on the internet in at least 200 device models, about 12 million devices (CVE-2014-9222) [11] [12] |

## Scope and method

This is a reference study of one attack surface, the ISP-supplied home gateway, read across the public record between 2014 and 2020. It is written for a typical home network: the ISP's gateway at the edge, and behind it the household's own devices, sometimes including a router the owner added. It describes a widely deployed family of these devices as the public record describes it; it names a vendor or model only where a cited source names one, it ties the material to no particular household, and it tested nothing. It is a defensive study: it explains each protocol and service well enough to show why a problem worked, then what a reader can check and decide, and it reproduces no attack recipe, no exploit code, and none of the specific account names, passwords or request strings the sources or the CVE records published.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: the researcher's own write-up, the vendor advisory, or the CVE and NVD record |
| Reported | Known through journalism or a secondary summary |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

The primaries are Nomotion's 2017 report, Tenable's analysis, and the four NVD records for the AT&T gateways [1] [2] [3]; Kaspersky's and Radware's reports, the NVD record for the Eir D1000, a hands-on analysis of the Deutsche Telekom devices, and Deutsche Telekom's statement as reported, for the 2016 TR-069 attack [4] [5] [6] [7] [8]; the Lyrebirds Cable Haunt report and the NVD records for the 2020 cable-modem flaws [9] [10]; and Check Point's disclosure and the NVD record for the 2014 embedded-web-server flaw [11] [12]. Where a count of affected devices comes from a vendor, an ISP or a researcher, this study says whose figure it is.

## Part 1: What an ISP-supplied gateway is, and who controls it

A router a person buys at a shop is theirs: they hold the admin password, they choose when to update it, and nobody else is supposed to reach its management interface. The box an ISP supplies is a different kind of device, and three properties set it apart.

**It is several devices in one, at the edge.** The ISP gateway terminates the broadband line (the modem), hands out the home's addresses and does network address translation (the router), decides what may cross between the internet and the home (the firewall), and serves Wi-Fi. Because it is the modem, it holds the public address and is directly reachable from the internet, which is the position the UPnP study called the worst one for a home device to be in. Nomotion noted this plainly about the AT&T gateways, that they "route traffic, sensitive communications and trade secrets for millions of customers" and "are directly reachable from the Internet at large" [1] (**Confirmed**).

**The ISP manages it remotely.** Many ISP gateways speak TR-069, which Check Point notes is also called CWMP [11] (**Confirmed**), and Radware states its purpose directly: the protocol exists for an internet provider to "remotely manage devices on their network" [5] (**Confirmed**). The ISP's management server can read and change the gateway's settings and push firmware, and the gateway listens for this, commonly on TCP port 7547 [4] [5] (**Confirmed**). This is a management plane the subscriber does not own and usually cannot turn off, and Parts 3 and 5 show what happens when it is reachable by anyone rather than only the ISP.

**The vendor writes the firmware, and the ISP may add to it.** The subscriber runs whatever code the vendor and ISP put on the device. Nomotion was explicit that it could not tell, from the firmware, whether the vendor or the ISP was responsible for what it found: "it is uncertain whether these gaping security holes were introduced by Arris (the OEM) or if these problems were added after delivery to the ISP (AT&T U-verse)", adding that AT&T engineers appeared to "have the authority and ability to add and customize code running on these devices" [1] (**Confirmed**). Either way, the accounts and services on the box are not the owner's to audit.

The consequence runs through the rest of the study, and it is this study's framing of the cases that follow (**Inferred**): on a device the owner does not control, whose code they did not write and whose management plane they cannot see, security is something the vendor and the ISP provide or fail to provide, and the owner's realistic options are narrow. The strongest of them, treating the gateway as untrusted and putting an owned router in front of their own network, is the subject of Part 6.

## Part 2: Vendor-or-ISP access, SharknAT&To

The clearest illustration of the control problem is a device that answers to someone other than its owner. In August 2017 the firm Nomotion published a report, titled SharknAT&To, on the Arris-manufactured gateways that AT&T supplied to its U-verse customers, naming the NVG589 and NVG599 models [1] (**Confirmed**). It described five vulnerabilities, which Tenable grouped into four types: hardcoded credentials, information exposure, authenticated command injection and a firewall bypass [2] (**Reported**). MITRE assigned four CVE identifiers, all published on 3 September 2017, and each record carries the same condition, that it applies when the gateway is not in IP Passthrough mode, and names the firmware build 9.2.2h0d83 [3] (**Confirmed**). This study describes the issues at the level of what went wrong, not how to repeat it, and reproduces none of the credentials, ports-as-payloads or request strings the report and the records published.

**A hardcoded account, reachable over SSH (CVE-2017-14115).** Nomotion found that a firmware update for the NVG589 and NVG599 enabled SSH and carried a hardcoded account that gave a menu shell on the device; because that shell ran with full privilege and did not check its inputs, it could be turned into a root shell [1] (**Confirmed**). The NVD scores CVE-2017-14115 at CVSS 3.0 8.1 (High), with the score from NVD itself, and classes it as hardcoded credentials (CWE-798) [3] (**Confirmed**). The account was not wholly secret: Tenable noted a forum post from November 2014 that already mentioned remote SSH access on this gateway [2] (**Reported**). For the count of exposed devices Nomotion gave a measured figure and its source, that "Censys reports 14,894 hosts which are likely vulnerable", with the caveat that the number might not be complete [1] (**Confirmed** as the researchers' cited figure).

**A hidden control server, and a path to root (CVE-2017-14116).** A second service, an HTTPS server the report calls `caserver`, ran on an uncommon high port on the NVG599 with a default account, and it accepted commands that led again to code execution as root [1] (**Confirmed**); the NVD scores it 8.1 (High), also hardcoded credentials [3] (**Confirmed**). Because the port is one that internet-wide scanners do not usually probe, Nomotion could only estimate the reach, and it said so: "our ballpark figure is around 220,000 devices" [1] (**Confirmed** as the researchers' estimate).

**Reading the inside of the home (CVE-2017-10793), and reaching into it (CVE-2017-14117).** A third service exposed configuration and logs, including Wi-Fi credentials and the addresses of devices on the home network, to anyone who presented a hardcoded account and the gateway's serial number; the NVD records it as an information exposure (CWE-200), scored 8.1 [1] [3] (**Confirmed**). The fourth issue was a proxy service on a WAN port that let an outside party open a TCP connection to a device inside the home, bypassing the firewall, but only to a client device and not to the gateway itself, and only if the attacker knew or could guess that device's hardware address; the NVD records it as an improper-authentication proxy (CWE-287), scored 5.9 (Medium), the lowest of the four [1] [3] (**Confirmed**). Nomotion reported that "every single AT&T device observed has had this port (49152) open", and that, in the report's words, "It is believed that the original purpose of this service was to allow AT&T to connect to the AT&T issued DVR devices which reside on the internal LAN" [1] (**Confirmed** as the report's observation and stated belief). A feature built for the ISP's own convenience had become a hole in the perimeter.

What makes SharknAT&To a control story rather than only a bug story is the condition and the fix. Every one of the four CVE records applies only when IP Passthrough mode is not used, which is to say when the gateway is doing the routing for the home rather than handing the connection to another router behind it [3] (**Confirmed**); Part 6 returns to what that means for an owner. On the fix, the public record is thin. Nomotion published a self-mitigation section with a step the owner could apply for each issue, so an owner was not without any recourse [1] (**Confirmed**). But no source opened for this study gives a vendor fix date for the NVG589 or NVG599; Tenable, a day after disclosure, reported that no remediating firmware had been made available, while noting that the various ISPs using these devices may have issued their own patches [2] (**Reported**). The firmware was not the subscriber's to change, so beyond Nomotion's steps the owner depended on the vendor or the ISP (**Inferred**).

One point of attribution matters throughout. It is tempting to call these a vendor's backdoor, but Nomotion could not establish that; the issues were present in the firmware on the device, and whether the vendor or the ISP put them there is, by the report's own account, unknown [1] (**Confirmed**).

## Part 3: The remote-management channel, and the 2016 TR-069 outage

The management plane from Part 1 is itself an attack surface, and in late November 2016 it produced one of the most visible home-gateway incidents on record.

The weakness was in TR-064, a configuration protocol in the TR-069 family, exposed on TCP port 7547. The NVD record for CVE-2016-10372 describes it on the modem where it was first documented: "The Eir D1000 modem does not properly restrict the TR-064 protocol, which allows remote attackers to execute arbitrary commands via TCP port 7547", by steps that in the record included opening the device's web interface to the internet and using the NewNTPServer feature [6] (**Confirmed**). Kaspersky, reporting as the attack unfolded, said users saw requests arrive on port 7547 that made the device fetch and run a file, identified the payload as a Mirai variant, and noted that because the malware could not write itself to the device's permanent storage, "the infection will not survive a reboot" [4] (**Confirmed**).

The scale and the outcome are the parts most often got wrong, so this study pins each to the source that supports it. Radware described the attackers as using "a customized Mirai botnet variant" against Deutsche Telekom and other networks, and reported the outcome there: "This attempt failed and the routers where not infected. Yet, the devices crashed due to an overload caused by the attack" [5] (**Confirmed** as Radware's account). A hands-on analysis at the time found why: on Deutsche Telekom's own routers the published command injection did not work, and the devices were, in the words of a write-up relaying that analysis, "put into a DoS condition by sending three requests on port 7547" [7] (**Reported**). So the outage was a side effect of a failed takeover, not a successful botnet recruitment. Deutsche Telekom, in a statement widely reported at the time and after a suspect's arrest in February 2017, said the malware had failed to infect its routers and that the disruption reached a minority of its customers, on the order of 4 to 5 percent of roughly 20 million, or about 900,000, when some router models crashed under the load [8] (**Reported**, as Deutsche Telekom's stated figures).

The response is the template for this class. Radware's guidance was that ISPs "should block all IP address, except for their own range" from reaching port 7547, a recommendation rather than a record of what each did, and that affected providers pushed firmware and told customers to power-cycle the device so it would pull the update [5] (**Confirmed** as Radware's recommendation and account). The management port was never meant to answer anyone but the ISP; the incident was what happened when it answered the world, and the fix was to put it back behind the ISP within days of the 27 November onset [4] [7] (**Inferred** from the dated reports).

## Part 4: A LAN-side bug reached through the browser, Cable Haunt

Not every gateway weakness faces the internet. Some sit on the inside, meant to be reachable only from the home network, and are reached anyway through the owner's own browser, the pattern the casting study described for Google's cast devices. Cable Haunt is that pattern on the ISP's cable modem.

In January 2020 the group Lyrebirds published Cable Haunt, a flaw in a component that Broadcom-based cable modems share. The target is the spectrum analyzer, a component these modems use to diagnose the cable connection, which listens on the local network and takes requests as JSON over a WebSocket. The report's summary, in the wording of version 2.5, is that the modems are vulnerable to "remote code execution through a websocket connection, bypassing normal CORS and SOC rules, and then subsequently by overflowing the registers" (the report writes "SOC" where its body elsewhere says the same-origin policy), and that the exploit is possible because of a lack of proper authorisation of the WebSocket client, default credentials, and a programming error in the spectrum analyzer [9] (**Confirmed**). The browser angle is the important one: a WebSocket opened by a web page is not fully covered by the browser's cross-origin rules, so a page the victim merely visits can open a connection to the modem on the local network, and the modems the researchers tested did not reject it [9] (**Confirmed**). The report also makes a control point that belongs to this study: where an internet provider uses one shared support-account password across its modems, that credential "will therefore be available for any attacker owning any router" from that provider, because anyone who owns one such modem can read it [9] (**Confirmed**).

The NVD records give the identifiers and the scores, and both are NVD's own, not a third party's. CVE-2019-19494 is the buffer overflow, scored CVSS 3.1 8.8 (High) by the NVD, described as affecting "Broadcom based cable modems across multiple vendors" and letting "a remote attacker to execute arbitrary code at the kernel level via JavaScript run in a victim's browser", with named examples including Sagemcom, NETGEAR, Technicolor and COMPAL models [10] (**Confirmed**). CVE-2019-19495 is a related DNS-rebinding issue on one tested model, scored 9.8 (Critical), that let an attacker reconfigure the modem from the browser and forward its internal Telnet server out to the internet for a root shell [10] (**Confirmed**). The fix status is uneven: one model's CVE entry names a fixed firmware version (a Sagemcom build given as prior to 50.10.21_T4), while the others list affected versions and CVE-2019-19495 names no fixed version, and a fix reaches a subscriber only when the ISP or vendor ships it [10] (**Confirmed** for what the records state).

## Part 5: The embedded web server, and scale, Misfortune Cookie

The last case is the oldest, and it is about how a single flaw in shared code becomes a flaw in many gateways that are slow to be updated.

In December 2014 Check Point disclosed Misfortune Cookie, CVE-2014-9222. The flaw is in RomPager, an embedded web server made by AllegroSoft and built into the management interface of a great many home gateways. The NVD record describes it as "AllegroSoft RomPager 4.34 and earlier, as used in Huawei Home Gateway products and other vendors and products, allows remote attackers to gain privileges via a crafted cookie that triggers memory corruption" [12] (**Confirmed**). Check Point's own account is that a crafted HTTP cookie corrupts memory and can "trick the attacked device to treat the current session with administrative privileges" [11] (**Confirmed**).

The scale is Check Point's to state, and it stated two numbers. Its research "detected at least 200 different models of devices of various manufacturers and brands currently exposing a vulnerable service on the public Internet", which is a count of models seen exposed, not of models still shipping [11] (**Confirmed** as Check Point's figure). And it put the device population at "approximately 12 million readily exploitable unique devices connected to the Internet present in 189 countries", adding that the true number might be greater [11] (**Confirmed** as Check Point's figure). Check Point did not claim to have watched the flaw being used; asked whether attackers were exploiting it, its answer was that it had "no direct evidence yet" [11] (**Confirmed**).

Two things make it a gateway-scale story. The fix was old: Check Point states that "AllegroSoft issued a fixed version to address the Misfortune Cookie vulnerability in 2005, which was provided to licensed manufacturers", nine years before the public disclosure [11] (**Confirmed**). And the fix had not reached the shipped devices: Check Point reported that it could confirm many devices still shipped with the vulnerable version in place, and warned that a vendor update "may patch RomPager to fix Misfortune Cookie without changing the displayed version number", so even the version string could not be trusted as a sign of safety [11] (**Confirmed**).

Check Point was also careful about a point this study has to keep straight: the role of the remote-management protocol. It wrote that "While the proliferation of devices managed by TR-069 is responsible for creating a very large vulnerable client population, Misfortune Cookie is not a vulnerability related to the TR-069/CWMP per se" [11] (**Confirmed**). The management protocol did not cause the bug; it explains why so many identical, rarely-updated boxes carried it. That is the scale property of ISP gateways in one sentence (**Inferred**).

## Part 6: What is fixed, what is design, what is a setting

The record sorts into three piles, and keeping them apart is the point of the study.

- **Fixed, by a patch with a version or a date.** The Cable Haunt records name a fixed firmware version for one model, shipped through the ISP or vendor [10] (**Confirmed**). The embedded-web-server flaw had a vendor fix available in 2005, which only mattered where a manufacturer actually built it in [11] (**Confirmed**). The 2016 TR-069 attack was answered within days by provider firmware and by blocking the management port from the public internet [5] (**Confirmed** as the reported response). The common thread is that the subscriber is rarely the one who applies the fix; the vendor or the ISP is, which is why an unsupported or abandoned gateway is the real exposure, and why the SharknAT&To issues, for which no vendor fix date appears in the record, sit here only in principle [2] (**Reported**).
- **Design, which no patch removes.** The gateway is reachable from the internet because it is the modem; it is managed remotely by the ISP because that is what TR-069 is for; and it runs vendor and ISP code the owner cannot audit, which is how a hardcoded account or an extra service can be present without the owner ever knowing. These are properties of the arrangement, not bugs in it, and no patch removes them. The one in the owner's hands is the trust boundary: a gateway the owner does not control can be treated as if it were part of the internet rather than part of the home.
- **Up to the owner.** The most effective lever in this study is to put an owned router in front of the household's devices, so they sit behind a second firewall the owner does control, and the gateway is treated as untrusted. The four 2017 CVE records make this concrete: each applies only when the gateway is not in IP Passthrough mode, so a gateway placed in pass-through, with the owner's router doing the routing, is the configuration the records themselves describe as out of scope for those flaws [3] (**Confirmed**). On many ISP gateways this is done by placing the gateway in a bridge or pass-through mode, or by accepting a second layer of address translation. The owner also controls whether the gateway's firmware is current where they can influence it, and whether to ask the ISP for a different device or run their own.

The trade-off belongs in the decision rather than hidden from it. Putting a second router in front of the household adds a layer of address translation that can complicate some applications, and not every ISP gateway offers a clean bridge mode, so the choice has a cost. This study describes the setting and its effect and does not tell anyone which way to set it (**Inferred**).

## Part 7: Check your own network

These checks are read-only. They look at the current state of a network and change nothing, and none of them was run for this study. Deciding whether to add a router, change a mode, or ask the ISP for a different device comes after, and is the owner's decision.

1. **Identify the gateway and whether it is routing or bridged.** Read the device's own label and administration page to learn what it is and whether it is acting as the router for the home or passing the connection through to another router. This tells you where the firewall the household relies on actually sits, and, as Part 6 notes, the 2017 CVE records applied only when the gateway was doing the routing rather than passing through [3] (**Confirmed** for the condition; the architecture reading is **Inferred**).
2. **Check whether the management port answers from the internet.** The 2016 incident was gateways that accepted TR-064 and TR-069 requests on TCP port 7547 from anyone, not only the ISP [5] [6] (**Confirmed**). A reader can check whether their public address answers on that port, remembering that a general port checker tests TCP and that, where a second router sits behind the gateway, the public address is the gateway's. A port that answers the internet here is the ISP's to close, not the owner's.
3. **Check whether an owner-controlled router is doing the routing.** If a second, owner-controlled router is in place and the gateway is in pass-through, confirm the household's devices are behind the owner's router and not on the gateway's own network. The CVE records' own pass-through condition (item 1) is what makes this worth reading [3] (**Confirmed**).
4. **Check the gateway's firmware and support status.** Because the fixes in this study are shipped by the vendor or the ISP, a gateway's exposure depends on whether it still receives them. Read the firmware version and whether the model is still supported; an old or abandoned gateway stays at whatever year it stopped being updated (**Inferred** from the dated fixes [10] [11]).

What these readings tell you maps onto Part 6: where the trusted firewall sits, whether the management plane is exposed, whether the owner has put a controlled device in front of their own network, and whether the gateway is still maintained. None of it requires touching another person's device or sending anything other than ordinary requests to your own equipment and public address.

## MITRE ATT&CK mappings

This Part binds the behaviours in the record to MITRE ATT&CK v20.0. No source names ATT&CK identifiers; each row is this study's own mapping, checked against the library's technique data (**Inferred**; names and tactics **Demonstrated** from `data/attack/technique_profiles.jsonl` [13]). The gateways are devices, not actors, so no group, software or campaign is bound, except that the 2016 case involved the Mirai botnet, which the botnet row notes.

| ID | Name | Tie to this record |
|---|---|---|
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | The internet-facing gateway services exploited in SharknAT&To, the 2016 TR-069 attack, and Misfortune Cookie [1] [6] [11] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | The hardcoded SSH account in the firmware and the ISP's TR-069 management plane, each a remote way into the device that is not the owner's [1] [5] |
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Compromise Infrastructure: Botnet | The 2016 Mirai variant's attempt to enslave gateways through port 7547 [4] [5] |

Fit notes (**Inferred**): T1190 is the nearest fit for exploiting a network-facing service on the device and is bound to the three cases that did so. T1133 covers both the hardcoded SSH account in the firmware and the ISP management channel, each a remote way into the device that is not the owner's; the study does not claim who placed the account there. T1584.005 is bound to the Mirai case, where the goal was to add the gateways to a botnet; on Deutsche Telekom the attempt failed, which the record states.

## Cross-cutting themes

- **Control decides security here.** On a device the owner did not write and cannot fully manage, a hardcoded account, an extra service or an exposed management port can exist without the owner's knowledge, and the fix is the vendor's or the ISP's to ship. Nomotion could not even tell whether the vendor or the ISP introduced what it found [1] (**Confirmed**).
- **The management plane is an attack surface.** TR-069 exists so the ISP can manage the gateway remotely; when its port answered the internet rather than only the ISP, it became the way in, as the 2016 outage showed [5] [6] (**Confirmed**).
- **Shared code spreads a single flaw across many boxes.** An embedded web server fixed in 2005 was still detected exposed in at least 200 device models, about 12 million devices, in 2014 [11] (**Confirmed** as Check Point's figures).
- **The inside is reachable from the browser.** As with casting, a service meant for the local network was reached through the victim's own web browser; Cable Haunt is that pattern on the ISP's modem [9] [10] (**Confirmed**). Read before you change: every defensive step here starts by reading the current state, and the change, where the owner can make one at all, is theirs to make (**Inferred**).

## Sources

All sources were opened on 25 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Nomotion, "SharknAT&To", 31 August 2017 (read via the Internet Archive), for the SSH account in a firmware update, the caserver service, the port 61001 information disclosure, the port 49152 proxy, the vendor-or-ISP uncertainty, and the Censys and 220,000 figures with their sources | [web.archive.org/web/2017/https://www.nomotion.net/blog/sharknatto/](https://web.archive.org/web/20170901163641id_/https://www.nomotion.net/blog/sharknatto/) | 2026-11-25 | Confirmed |
| 2 | Tenable (Carlos Perez), "Hardcoded Credentials Expose Customers of AT&T U-Verse", 1 September 2017, for the four issue types for five vulnerabilities, the additional affected models and the May 2013 last-firmware date for those, the November 2014 forum post, and the no-fix-available status at disclosure with the note that ISPs may have patched | [tenable.com/blog/hardcoded-credentials-expose-customers-of-att-u-verse](https://www.tenable.com/blog/hardcoded-credentials-expose-customers-of-att-u-verse) | 2026-11-25 | Reported |
| 3 | NVD, the four SharknAT&To records published 3 September 2017, each citing the Nomotion post, each conditioned on the gateway not being in IP Passthrough mode, firmware 9.2.2h0d83: CVE-2017-14115 (8.1, CWE-798), CVE-2017-14116 (8.1, CWE-798), CVE-2017-14117 (5.9, CWE-287), CVE-2017-10793 (8.1, CWE-200), all NVD-primary scores | [nvd.nist.gov/vuln/detail/CVE-2017-14115](https://nvd.nist.gov/vuln/detail/CVE-2017-14115) | 2026-11-25 | Confirmed |
| 4 | Kaspersky Securelist (Stefan Ortloff), "New wave of Mirai attacking home routers", November 2016, for the port-7547 request users saw, the Mirai payload, and the note that the infection does not survive a reboot | [securelist.com/new-wave-of-mirai-attacking-home-routers/76791](https://securelist.com/new-wave-of-mirai-attacking-home-routers/76791/) | 2026-11-25 | Confirmed |
| 5 | Radware, "Deutsche Telekom Routers Takeover Attempt", 1 December 2016, for the customized Mirai variant, the TR-069 remote-management description, the crashed-not-infected outcome, and the block-port-7547 recommendation | [radware.com/security/ddos-threats-attacks/threat-advisories-attack-reports/deutsche-telekom-routers-takeover](https://www.radware.com/security/ddos-threats-attacks/threat-advisories-attack-reports/deutsche-telekom-routers-takeover/) | 2026-11-25 | Confirmed |
| 6 | NVD, CVE-2016-10372 (Eir D1000 / TR-064), for the description, the TCP port 7547 vector and NewNTPServer step, the CVSS 3.0 9.8 score (NVD primary) and CWE-264 | [nvd.nist.gov/vuln/detail/CVE-2016-10372](https://nvd.nist.gov/vuln/detail/CVE-2016-10372) | 2026-11-25 | Confirmed |
| 7 | Pen Test Partners (Ken Munro), "TR-064 worm. It's not Mirai and the outages are interesting", 2 December 2016, relaying the Comsecuris analysis, for the finding that Deutsche Telekom's routers were put into a denial-of-service state by requests on port 7547 rather than infected | [pentestpartners.com/security-blog/tr-064-worm-its-not-mirai-and-the-outages-are-interesting](https://www.pentestpartners.com/security-blog/tr-064-worm-its-not-mirai-and-the-outages-are-interesting/) | 2026-11-25 | Reported |
| 8 | Deutsche Telekom's statement on the attack, as reported (WeLiveSecurity, "British man arrested...", 24 February 2017), for Deutsche Telekom's account that the malware failed to infect its routers, the roughly 900,000 of about 20 million customers affected, and the February 2017 arrest | [welivesecurity.com/2017/02/24/german-router-attack](https://www.welivesecurity.com/2017/02/24/german-router-attack/) | 2026-11-25 | Reported |
| 9 | Lyrebirds, Cable Haunt report (cablehaunt.com and the report PDF; the executive-summary wording quoted is version 2.5, January 2020), for the spectrum-analyzer buffer overflow, the WebSocket-past-cross-origin mechanism, the default credentials, and the shared-support-password point | [github.com/Lyrebirds/Cable-Haunt-Report](https://github.com/Lyrebirds/Cable-Haunt-Report/releases) | 2026-11-25 | Confirmed |
| 10 | NVD, CVE-2019-19494 (CVSS 3.1 8.8, CWE-120) and CVE-2019-19495 (9.8, CWE-20), both NVD primary scores, for the Broadcom-modem code execution and the DNS-rebinding-to-root-shell issue, and the fixed and affected firmware versions named | [nvd.nist.gov/vuln/detail/CVE-2019-19494](https://nvd.nist.gov/vuln/detail/CVE-2019-19494) | 2026-11-25 | Confirmed |
| 11 | Check Point, "Misfortune Cookie", December 2014, for the RomPager crafted-cookie mechanism, the at-least-200-models-detected-exposed and approximately-12-million-devices-in-189-countries figures, the no-direct-evidence-of-exploitation statement, the 2005 AllegroSoft fix, the still-shipping and version-string caveats, and the TR-069-proliferation-not-cause distinction | [sc1.checkpoint.com/misfortune-cookie/index.html](https://sc1.checkpoint.com/misfortune-cookie/index.html) | 2026-11-25 | Confirmed |
| 12 | NVD, CVE-2014-9222 (Misfortune Cookie), for the RomPager 4.34-and-earlier description, the crafted-cookie memory corruption, and the CVSS 2.0 10.0 score (NVD primary) and CWE-17 | [nvd.nist.gov/vuln/detail/CVE-2014-9222](https://nvd.nist.gov/vuln/detail/CVE-2014-9222) | 2026-11-25 | Confirmed |
| 13 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl` (ATT&CK v20.0), for the technique names and tactics in the mappings | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-25 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

## Related references

- [UPnP on the Home Network](/case-studies/UPNP_HOME_NETWORK.md), [Casting on the Home Network](/case-studies/CASTING_HOME_NETWORK.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md)
- [All case studies](/case-studies/README.md)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
