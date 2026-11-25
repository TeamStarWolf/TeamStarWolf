# UPnP on the Home Network: The Internet Gateway Device Port-Mapping Service and Its Security Record

*A TeamStarWolf case study. Published 25 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Home and small-network users, network and security engineers, incident responders, and anyone hardening a consumer router

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 17 min (4,019 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run a home or small network, you want to understand the UPnP port-mapping service and its security record, or you are deciding whether to leave UPnP on

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 6: What is fixed, what is design, what is a setting](#part-6-what-is-fixed-what-is-design-what-is-a-setting), [Part 7: Check your own network](#part-7-check-your-own-network)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-25):

- The UPnP port-mapping service has no authentication, so any device on the home network can ask the router to open an inbound port. ([Executive summary](#executive-summary))
- A 2012 internet scan found the control plane turned the wrong way out on tens of millions of addresses. ([Executive summary](#executive-summary))
- UPnProxy and EternalSilence are not bugs: they are the port-mapping service used as designed, for a requester the design assumed was trusted. ([Part 3: Using the router as infrastructure, UPnProxy and EternalSilence](#part-3-using-the-router-as-infrastructure-upnproxy-and-eternalsilence))
- The record sorts into three piles: bugs a patch fixes, a design property no patch removes, and a setting the owner controls. ([Executive summary](#executive-summary))

<!-- meta:end -->

## Executive summary

Universal Plug and Play (UPnP) is the service that lets a game console, a torrent client or a smart-home hub ask the home router to open an inbound port without anyone typing a forwarding rule. The part of UPnP that does this is the Internet Gateway Device (IGD) profile, and its central design choice is that it has no front door: any device on the local network can ask the router to open a port, and the router does not check who is asking [1] (**Confirmed**). That choice is the thread running through every problem in this study.

The record falls into two halves. The first is implementations that could be attacked directly. In 2012 a single internet-wide scan found more than 81 million addresses answering UPnP discovery, and about 17 million answering the control service to the whole internet, a position a home router should never be in; the two most common UPnP code libraries both held remotely exploitable flaws, and about 23 million addresses could be run code on with one packet [1] (**Confirmed**). The second half is the protocol used as designed but turned against the owner: attackers injecting router port-maps to build proxy networks (UPnProxy and EternalSilence) [4] (**Confirmed**), a specification flaw that let a device be aimed at a target of the attacker's choice (CallStranger, CVE-2020-12695) [3] (**Confirmed**), and malware that opens its own inbound port from inside the network (Pinkslipbot) [5] (**Confirmed**).

The defensive reading is steady across all of it. Some of these are bugs that a patch fixes. One is a design property that no patch removes, because a protocol with no authentication is behaving exactly as written. And the rest is a setting: whether UPnP is on, and whether the router ever answers it from the internet side. A reader can check all three on their own network with read-only steps, which the last Part sets out.

## Key facts at a glance

| Field | Value |
|---|---|
| What it is | The UPnP IGD port-mapping service on a home router, reached over SSDP discovery (UDP 1900), an XML device description, and SOAP control actions such as `AddPortMapping` [1] |
| Core design property | No authentication: any host that can reach the control URL can add a port mapping; the LAN is assumed trusted [1] (**Confirmed**) |
| 2012 internet exposure | More than 81 million IPs answered UPnP discovery; about 17 million exposed the SOAP control service to the internet [1] |
| Library flaws | Portable SDK for UPnP (libupnp) SSDP parser: CVE-2012-5958 to CVE-2012-5965, fixed in libupnp 1.6.18; MiniUPnPd: CVE-2013-0229, CVE-2013-0230, later CVE-2017-1000494 and CVE-2019-12107 [1] [2] |
| Port-map abuse | UPnProxy and EternalSilence: injected router mappings build proxy networks and re-expose internal SMB; about 45,000 routers injected in one set, exposing roughly 1.7 million machines [4] |
| Eventing flaw | CallStranger, CVE-2020-12695, CVSS 3.1 7.5; the UPnP SUBSCRIBE callback can be aimed at an attacker-chosen address; a specification fix, then per-device patches [3] |
| Malware use | Pinkslipbot (QakBot/QBot) opened inbound ports over UPnP to run control-server proxies from April 2016 [5] |

## Scope and method

This is a reference study of one attack surface, the UPnP IGD service on consumer routers, read across the public record from 2012 to 2020 and the vendor behaviour current as of 25 November 2026. It is written for a typical home network: a router or mesh system, a few streaming and smart-home devices, and sometimes a second router behind an internet-service-provider gateway. It is a defensive study. It explains the protocol well enough to show why each problem worked, then what a reader can check and decide, and it reproduces no attack recipe against any specific product and no exploit code.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: the CVE and NVD records, the researcher's own paper or disclosure site, or the vendor's own report |
| Reported | Known through journalism or a secondary summary |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

The primaries are HD Moore's 2013 Rapid7 paper for the internet-exposure measurement and the library flaws [1]; the CVE and NVD records for the named identifiers [2] [3]; Akamai's UPnProxy and EternalSilence report for the port-map injections [4]; the CVE and NVD records and the researcher's material for CallStranger [3]; and McAfee's 2017 report for Pinkslipbot [5].

## Part 1: What the service is, and why it has no front door

UPnP lets devices find each other and ask each other for things without configuration. On a home router the relevant piece is the Internet Gateway Device profile, and it works in four steps.

**Discovery.** A device finds the router with the Simple Service Discovery Protocol (SSDP), which runs over UDP on port 1900. A host sends a multicast search, and the router answers with the location of its description document. This is the step that an internet-wide scanner also uses: send the search, see who answers [1] (**Confirmed**).

**Description.** The device fetches an XML document from the router over HTTP. It lists the device and its services, including `WANIPConnection`, the service that manages NAT port mappings, and the URL to send control messages to [1] (**Confirmed**).

**Control.** The device sends SOAP messages to that control URL. The IGD actions include `GetExternalIPAddress`, `GetGenericPortMappingEntry`, `DeletePortMapping`, and the important one, `AddPortMapping`. `AddPortMapping` takes an external port, a protocol, an internal port, a description, and a field named `NewInternalClient`: the local address the router should forward the traffic to [1] [4] (**Confirmed**).

**Eventing.** A device can subscribe to be told when something changes, using an action called `SUBSCRIBE` that carries a callback address. The router then sends notifications to that address. This is the step CallStranger abused, and Part 4 returns to it [3] (**Confirmed**).

The design choice that matters is in the control step. The IGD profile has no authentication. There is no password, no token, and no check that the requester is who it claims to be. The protocol assumes that everything on the local network is trusted, so any host that can reach the control URL can call `AddPortMapping`. HD Moore's 2013 paper put the general version plainly: across UPnP devices, "Authentication is rarely implemented by device manufacturers, privileged capabilities are often exposed to untrusted networks" [1] (**Confirmed**).

The normal, intended use is harmless. A game console maps an external port to its own address so that inbound game traffic reaches it through NAT. The assumption is that `NewInternalClient` is the device making the request, mapping a port to itself. The protocol does not require the router to enforce that the internal client is the requester, and that gap is the root of the port-map abuse in Part 3 (**Inferred** from the protocol's own fields [1] [4]).

## Part 2: The implementations that could be attacked directly

The first set of problems is the ordinary kind: bugs in the code that speaks UPnP, made worse by that code being reachable from the wrong places.

**The exposure measurement.** From 1 June to 17 November 2012, Rapid7 sent UPnP discovery requests to every routable IPv4 address about once a week. More than 81 million unique addresses answered the discovery request, and about 17 million of those also exposed the SOAP control service to the internet [1] (**Confirmed**). A home router is supposed to answer UPnP only on the inside, to its own LAN. An address that answers discovery or control from the public internet has its control plane turned the wrong way out. The paper identified more than 1,500 vendors and 6,900 products vulnerable to at least one of the flaws it described [1] (**Confirmed**).

**The library flaws.** Most devices do not write their own UPnP stack; they use one of a few libraries. The paper found remotely exploitable flaws in the two most common. The Portable SDK for UPnP Devices, often called libupnp, had a set of flaws in the part that parses SSDP, tracked as CVE-2012-5958 through CVE-2012-5965, and about 23 million addresses were vulnerable to remote code execution through a single UDP packet; the fix was libupnp 1.6.18 [1] [2] (**Confirmed**). MiniUPnPd, another common implementation, had a denial-of-service flaw in its SSDP handling (CVE-2013-0229) and a code-execution flaw in its SOAP action handler (CVE-2013-0230) [1] [2] (**Confirmed**).

**It did not stop in 2013.** The same implementation kept yielding parser bugs for years. CVE-2017-1000494 is an uninitialised-memory flaw that lets an attacker crash MiniUPnPd before version 2.0, and CVE-2019-12107 lets a remote attacker leak information from the heap in MiniUPnPd through version 2.1 [2] (**Confirmed**). The pattern is the ordinary one for a C program that parses attacker-supplied network input: the surface stays, and bugs surface in it over time (**Inferred** from the CVE descriptions [2]).

The defence for this whole set is the one Rapid7 gave in 2013, and it still holds: find and disable any UPnP that is reachable from the internet, and keep the device's firmware current so the library fix reaches it [1] (**Confirmed**). The reason the paper stressed exposure over patching is that much of the vulnerable equipment would never be patched, so disabling the service, or replacing the device, was the only reliable close [1] (**Confirmed**).

## Part 3: Using the router as infrastructure, UPnProxy and EternalSilence

The second half of the record does not need a memory-corruption bug. It uses `AddPortMapping` exactly as written.

In 2018 Akamai reported a technique it called UPnProxy. An attacker who can reach a router's IGD control service sends `AddPortMapping`, but sets `NewInternalClient` to an address that is not a device on that router's LAN. The router, which does not check the field, now relays traffic between two outside points, and a wall of such routers becomes a proxy network that hides the attacker's traffic behind other people's addresses. Akamai described a pool of about 3.5 million devices running vulnerable UPnP, about 277,000 of them exposing the controls that UPnProxy needs, and at least 45,000 actively injected with these mappings [4] (**Confirmed**). The injected routers were used to conceal traffic for "spam, phishing, click fraud, and DDoS" [4] (**Confirmed**).

A later set of injections, which Akamai named EternalSilence, pointed the mappings the other way. Instead of relaying outside traffic, the injected mapping exposed a port on a device behind the router, specifically the SMB ports TCP 139 and 445, to the internet [4] (**Confirmed**). The name came from the description the attackers left on the mappings, "galleta silenciosa," Spanish for silent cookie [4] (**Confirmed**). Akamai counted 45,113 routers carrying these injections, exposing an estimated 1.7 million machines to the internet [4] (**Confirmed**). The point of EternalSilence is in its effect: a home PC behind NAT is reachable from the internet only if something forwards a port to it, and these injections did exactly that, "remove[ing] this implied protection granted by the NAT from the equation entirely" and re-exposing machines to the old SMB exploits [4] (**Confirmed**).

Neither UPnProxy nor EternalSilence has a CVE, because neither is a bug. They are the IGD service doing what it was built to do, for a requester the design assumed would be trusted. Akamai's defensive guidance is read-only first: audit the router's own NAT and port-mapping table for entries no one created, "scanning their UPnP NAT table to look for oddities," because an injected router gives its owner no other sign [4] (**Confirmed**). Disabling UPnP is the fix, with a caution Akamai states directly: disabling it "might not clear existing NAT injections," so a reboot or factory reset, plus a firmware update, may be needed to clear what is already there [4] (**Confirmed**).

## Part 4: Aiming a device from outside, CallStranger (CVE-2020-12695)

The eventing step from Part 1 carried its own flaw, and this one was in the specification rather than in any single product.

When a device subscribes to UPnP events with `SUBSCRIBE`, it supplies a callback address in a header, and the device sends event notifications to that address. The Open Connectivity Foundation UPnP specification before 17 April 2020 "does not forbid the acceptance of a subscription request with a delivery URL on a different network segment than the fully qualified event-subscription URL" [3] (**Confirmed**). In plain terms, the subscriber could tell the device to send its traffic to an address the attacker chose, which is the shape of a server-side request forgery: the attacker does not reach the target directly, the device reaches it for them. The record names the researcher Yunus Cadirci, who published the issue as CallStranger in June 2020 [3] (**Confirmed**).

NVD scores CVE-2020-12695 at CVSS 3.1 7.5, High, with the vector `AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:H`, and classifies it as CWE-276, incorrect default permissions; it was published on 8 June 2020 [3] (**Confirmed**). The CERT Coordination Center's note on the issue lays out what the aiming makes possible: using internet-facing UPnP devices as a source of reflected and amplified traffic for a denial-of-service attack, exfiltrating data out of a network in a way that bypasses some data-loss controls, and scanning internal ports from the outside [3] (**Confirmed**).

CallStranger is the clearest case of the fixed-versus-design split. The root is a specification that permitted the behaviour, so the Open Connectivity Foundation changed the specification on 17 April 2020, and then each device maker had to ship a firmware update that enforces the new rule [3] (**Confirmed**). There is no single patch; the fix arrived device by device, and devices that are no longer updated stay exposed (**Inferred** from the spec-level fix [3]). For a home network the exposure is narrower than the headline count suggests, because a correctly configured home router does not answer UPnP on its internet side; the reflection surface is the large population of other internet-facing UPnP devices and servers that do (**Inferred** from the exposure data [1] [3]).

## Part 5: Malware that opens its own door, Pinkslipbot

The design property in Part 1 has one more consequence worth stating on its own: because any host on the LAN can add a port mapping, malware on any device can open an inbound hole from the inside, with no user action and no router password.

McAfee reported in June 2017 that the banking malware Pinkslipbot, also tracked as QakBot or QBot, had used infected machines as control-server proxies since April 2016. To receive inbound connections from the internet, "Pinkslipbot uses universal plug and play (UPnP) to open ports, allowing incoming connections from anyone on the Internet to communicate with the infected machine" [5] (**Confirmed**). McAfee placed it in a short lineage: "the second executable-based malware to use UPnP for port forwarding after the infamous W32/Conficker worm in 2008" [5] (**Confirmed**).

Two defensive points come from that report. First, the mappings a program like this leaves behind are hard to clean automatically, because "the port-forwarding rules created by Pinkslipbot are too generic to remove automatically without risking accidental network misconfigurations," and ordinary anti-malware tools do not revert port-forwarding changes [5] (**Confirmed**). Second, McAfee's own advice is the same as everyone else's in this study: "keep tabs on their local port-forwarding rules and disable UPnP on their home routers unless they need it" [5] (**Confirmed**). The lesson is not that UPnP was broken here; it worked. The lesson is that a feature which lets any inside program open the perimeter is a feature an inside program will use (**Inferred** [5]).

## Part 6: What is fixed, what is design, what is a setting

The whole record sorts into three piles, and keeping them apart is the point of the study.

- **Fixed, by a patch.** The implementation bugs are ordinary vulnerabilities with ordinary fixes. The libupnp SSDP flaws were corrected in libupnp 1.6.18; the MiniUPnPd parser flaws were corrected in later releases; and CallStranger was corrected by the specification change of 17 April 2020 followed by per-device firmware [1] [2] [3] (**Confirmed**). A current device with current firmware is not exposed to these. A device that no longer receives firmware stays exposed, which is why Rapid7's advice ended at replacing equipment that will never be patched [1] (**Confirmed**).
- **Design, which no patch removes.** The IGD profile has no authentication, so any host on the local network can add a port mapping, and a device or a piece of malware can open an inbound port without the owner's involvement. This is not a bug; it is the protocol behaving as written, and UPnProxy, EternalSilence and Pinkslipbot all rely on it [1] [4] [5] (**Confirmed**). The only way to remove this property is to not run the service.
- **A setting, which the owner controls.** Whether UPnP is enabled at all is a setting. Whether the router answers UPnP discovery or control on its internet-facing side is a setting, and it should be off; the 2012 measurement is a census of routers where it was not [1] (**Confirmed**). Where a second router sits behind an internet-service-provider gateway, each router has its own UPnP setting, and a mapping added on the inner router does not by itself open a port on the outer gateway, because the IGD service does not chain across two routers; double NAT can blunt UPnP's reach outward, though it does not change the exposure of hosts on the inner network to each other (**Inferred** from how `AddPortMapping` and NAT work [1] [4]).

The trade-off in turning UPnP off is real and belongs in the decision rather than hidden from it. Some game consoles, voice and video calling, and peer-to-peer applications rely on UPnP to open their ports, and turning it off can require those ports to be forwarded by hand, or can degrade those applications. That is the owner's call to make; this study describes the setting and its effect, and does not tell anyone which way to set it (**Inferred**).

## Part 7: Check your own network

These checks are read-only. They look at the current state of a network and change nothing. Deciding whether to turn UPnP off, or to forward a port by hand, comes after, and is the owner's decision.

1. **Find out whether UPnP is on.** A home router's administration page has a UPnP setting, usually under a NAT, forwarding, or advanced-network section. Note whether it is enabled. Many routers enable it by default [1] (**Confirmed**).
2. **Read the current port-mapping table.** The same administration page, or a UPnP status page, lists the port mappings that exist now. Read the list and ask, for each entry, whether you or a device you recognise created it. Entries you cannot account for, entries whose internal client is an address you do not recognise, and entries for SMB ports 139 or 445 are the ones Akamai's guidance says to look at [4] (**Confirmed**).
3. **Confirm the router does not answer UPnP from the internet.** From outside the network, a reputable external port-check service can confirm that UDP 1900 and the router's control port are not open on the internet-facing address. A home router should not answer UPnP from the internet; the 2012 census is what it looks like when one does [1] (**Confirmed**).
4. **Account for every router.** If a second router sits behind the gateway, check the UPnP setting on both, because each keeps its own [4] (**Inferred**).
5. **If an entry looks wrong, remember that disabling UPnP may not clear it.** Akamai noted that turning UPnP off "might not clear existing NAT injections," so clearing an entry already present can need a reboot or a factory reset and a firmware update [4] (**Confirmed**).

What these four readings tell you maps onto Part 6: whether the service is on (a setting), what it has been asked to do (the mappings), and whether it is exposed where it should not be (a setting that should be off). None of that requires touching another person's device or sending anything other than a request to your own router.

## MITRE ATT&CK mappings

This Part binds the behaviours in the record to MITRE ATT&CK v20.0. No source names ATT&CK identifiers; each row is this study's own mapping, checked against the library's technique data (**Inferred**; names and tactics **Demonstrated** from `data/attack/technique_profiles.jsonl` [6]). UPnP itself is a protocol, not an actor or a piece of software, so no group, software or campaign is bound.

| ID | Name | Tie to this record |
|---|---|---|
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | Internet-wide and on-LAN SSDP discovery of UPnP endpoints [1] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | UPnProxy turns injected routers into relays [4] |
| [`T1090.003`](/mitre/techniques/T1090-003.md) | Multi-hop Proxy | Walls of injected routers chain to hide traffic [4] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | EternalSilence re-exposes internal SMB to the internet [4] |
| [`T1048`](/mitre/techniques/T1048.md) | Exfiltration Over Alternative Protocol | CallStranger aims a device's traffic out of the network [3] |
| [`T1498.002`](/mitre/techniques/T1498-002.md) | Reflection Amplification | CallStranger uses internet-facing UPnP devices to reflect traffic [3] |

Fit notes (**Inferred**): T1090 and T1090.003 describe adversary proxying, which is what the injected routers provide, not a flaw in the router. T1133 is the nearest fit for re-exposing an internal service to the internet; the technique is written for adversary use of such services, and the EternalSilence tie is the exposure that enables it. T1048 and T1498.002 describe the two directions CallStranger's aiming supports, out of a network and at a third party.

## Cross-cutting themes

- **A protocol with no authentication is not broken when it is abused.** UPnProxy, EternalSilence and Pinkslipbot are the IGD service working as written, which is why no patch addresses them and only not running the service does [1] [4] [5] (**Inferred**).
- **Exposure matters more than any single bug.** The 2012 census found the service turned the wrong way out on tens of millions of addresses; the library bugs were serious, but the first defence Rapid7 gave was to stop answering UPnP from the internet [1] (**Confirmed**).
- **The inside is not automatically trustworthy.** UPnP assumes every LAN host is friendly, and malware on one device is enough to break that assumption and open the perimeter [5] (**Inferred**).
- **Read before you change.** Every defensive step in this study starts with reading the current state: the setting, the mappings, the internet-facing answer. The change comes after, and is the owner's to make (**Inferred**).

## Sources

All sources were opened on 25 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | HD Moore (Rapid7), "Security Flaws in Universal Plug and Play: Unplug. Don't Play.", January 2013, for the 2012 internet-exposure measurement, the libupnp and MiniUPnPd flaws, the fixed libupnp version, and the disable-and-replace guidance | [hdm.io/writing/SecurityFlawsUPnP.pdf](https://hdm.io/writing/SecurityFlawsUPnP.pdf) | 2026-11-25 | Confirmed |
| 2 | CVE and NVD records for the UPnP implementation flaws: CVE-2012-5958 to CVE-2012-5965 (Portable SDK for UPnP), CVE-2013-0229 and CVE-2013-0230, CVE-2017-1000494 and CVE-2019-12107 (MiniUPnPd) | [cve.org/CVERecord?id=CVE-2017-1000494](https://www.cve.org/CVERecord?id=CVE-2017-1000494) | 2026-11-25 | Confirmed |
| 3 | CVE-2020-12695 (CallStranger): the CVE and NVD records for the description, CVSS 3.1 7.5 score and CWE-276, with the CERT/CC note VU#339275 for the abuse classes and the researcher Yunus Cadirci's disclosure | [nvd.nist.gov/vuln/detail/CVE-2020-12695](https://nvd.nist.gov/vuln/detail/CVE-2020-12695) | 2026-11-25 | Confirmed |
| 4 | Akamai (Chad Seaman), "UPnProxy: Eternal Silence", first posted November 2018, updated 2022, for the port-map injection technique, the device and router counts, the SMB re-exposure, and the NAT-table and disable guidance | [akamai.com/blog/security/upnproxy-eternal-silence](https://www.akamai.com/blog/security/upnproxy-eternal-silence) | 2026-11-25 | Confirmed |
| 5 | McAfee Labs, "McAfee Discovers Pinkslipbot Exploiting Infected Machines as Control Servers", 16 June 2017, for Pinkslipbot's use of UPnP to open inbound ports, the Conficker comparison, and the port-forwarding and disable guidance | [mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-discovers-pinkslipbot-exploiting-infected-machines-as-control-servers-releases-free-tool-to-detect-disable-trojan](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-discovers-pinkslipbot-exploiting-infected-machines-as-control-servers-releases-free-tool-to-detect-disable-trojan/) | 2026-11-25 | Confirmed |
| 6 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl` (ATT&CK v20.0), for the technique names and tactics in the mappings | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-25 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

## Related references

- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md)
- [All case studies](/case-studies/README.md)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
