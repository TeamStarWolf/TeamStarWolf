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

About 21 min (4,737 words at 230 words a minute)

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

- The first version of the UPnP port-mapping profile has no access control, so any host on the home network can ask the router to open an inbound port. ([Executive summary](#executive-summary))
- A 2012 study found more than 81 million addresses answering UPnP discovery, and an estimated 17 million answering the control service to the internet. ([Executive summary](#executive-summary))
- UPnProxy and EternalSilence are not a single fault: injection from the internet needs both a device that answers its controls from the internet and a protocol that checks nobody. ([Part 3: Using the router as infrastructure, UPnProxy and EternalSilence](#part-3-using-the-router-as-infrastructure-upnproxy-and-eternalsilence))
- The record sorts into three piles: bugs a patch or a replacement fixes, a design property no patch removes, and what the owner controls. ([Executive summary](#executive-summary))

<!-- meta:end -->

## Executive summary

Universal Plug and Play (UPnP) is the service that lets a game console, a torrent client or a smart-home hub ask the home router to open an inbound port without anyone typing a forwarding rule. The part of UPnP that does this is the Internet Gateway Device (IGD) profile, and the first version of that profile has no access control: any host on the local network can ask the router to open a port, and the protocol checks neither who is asking nor whom the port is opened to [4] (**Confirmed**). That choice is the thread running through this study.

The record falls into two halves. The first is implementations that could be attacked directly. In a 2012 study that sent probes to every routable address about once a week for five and a half months, more than 81 million addresses answered UPnP discovery, and an estimated 17 million answered the control service to the internet, a position a home router should never be in; the two most common UPnP code libraries both held remotely exploitable flaws, and a single UDP packet was enough to run code on about 23 million addresses [1] (**Confirmed**). The second half is the protocol used as designed but turned against the owner: attackers injecting router port-maps to build proxy networks and to re-expose internal machines (UPnProxy and EternalSilence) [7] (**Confirmed**), a specification flaw that let a device be aimed at a target of the attacker's choice (CallStranger, CVE-2020-12695) [3] [4], and malware that opens its own inbound port from inside the network (Pinkslipbot) [8] (**Confirmed**).

The defensive reading sorts the record into three piles. Some of it is fixed by a patch or by replacing the device: the library bugs, and a router that answers UPnP on its internet side, which is a fault, not a preference. Some is a design property that no patch removes, because a protocol with no caller authentication is behaving as written; only not running the service removes it. And the rest is up to the owner: whether UPnP is on where the router offers it, whether firmware is current, and whether to replace equipment that cannot be fixed. A reader can check the state of all three on their own network with read-only steps, which the last Part sets out.

## Key facts at a glance

| Field | Value |
|---|---|
| What it is | The UPnP IGD port-mapping service on a home router, reached over SSDP discovery (UDP 1900), an XML device description, and SOAP control actions such as `AddPortMapping` [1] |
| Core design property | The first IGD profile has no access control: the protocol "does not implement any form of authentication or verification" [4] (**Confirmed**); the 2010 profile recommends a map-to-own-address rule that devices may decline [6] |
| 2012 internet exposure | More than 81 million IPs answered UPnP discovery; an estimated 17 million exposed the control service to the internet [1] |
| Library flaws | Portable SDK for UPnP (libupnp) SSDP parser: CVE-2012-5958 to CVE-2012-5965, fixed in libupnp 1.6.18; MiniUPnPd: CVE-2013-0229, CVE-2013-0230, later CVE-2017-1000494 and CVE-2019-12107 [1] [2] |
| Port-map abuse | UPnProxy builds proxy networks; EternalSilence re-exposes internal SMB; 45,113 routers carried the EternalSilence injections [7] |
| Eventing flaw | CallStranger, CVE-2020-12695, CVSS 3.1 7.5; the UPnP SUBSCRIBE callback can be aimed at an attacker-chosen address; a specification fix, then per-device patches [3] [4] [5] |
| Malware use | Pinkslipbot (QakBot/QBot) opened inbound ports over UPnP to run control-server proxies from April 2016 [8] |

## Scope and method

This is a reference study of one attack surface, the UPnP IGD service on consumer routers, read across the public record from 2012 to 2020. It is written for a typical home network: a router or mesh system, a few streaming and smart-home devices, and sometimes a second router behind an internet-service-provider gateway. It is a defensive study. It explains the protocol well enough to show why each problem worked, then what a reader can check and decide, and it reproduces no attack recipe against any specific product and no exploit code.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: the CVE and NVD records, the UPnP specification, the researcher's own disclosure, or the vendor or coordinator report |
| Reported | Known through journalism or a secondary summary |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

The primaries are HD Moore's 2013 Rapid7 paper for the internet-exposure measurement and the library flaws [1]; the CVE and NVD records for the named identifiers [2] [3]; the CERT/CC note and the researcher's own material for CallStranger [4] [5]; the UPnP Forum's gateway specification for the access-control rules [6]; Akamai's UPnProxy and EternalSilence report for the port-map injections [7]; and McAfee's 2017 report for Pinkslipbot [8].

## Part 1: What the service is, and whether it checks who is asking

UPnP lets devices find each other and ask each other for things without configuration. On a home router the relevant piece is the Internet Gateway Device profile, and it works in four steps.

**Discovery.** A device finds the router with the Simple Service Discovery Protocol (SSDP), which runs over UDP on port 1900. A host sends a multicast search, and the router answers with the location of its description document. This is the step that an internet-wide scanner also uses: send the search, see who answers [1] (**Confirmed**).

**Description.** The device fetches an XML document from the router over HTTP. It lists the device and its services, including `WANIPConnection`, the service that manages NAT port mappings, and the URL to send control messages to [1] (**Confirmed**).

**Control.** The device sends SOAP messages to that control URL. The IGD actions include `GetExternalIPAddress`, `GetGenericPortMappingEntry`, `DeletePortMapping`, and the important one, `AddPortMapping`. `AddPortMapping` takes an external port, a protocol, an internal port, a description, and a field named `NewInternalClient`: the local address the router should forward the traffic to [1] [7] (**Confirmed**).

**Eventing.** A device can ask to be told when something changes. It sends `SUBSCRIBE`, which is an HTTP request method the protocol adds rather than a SOAP action, and it carries the address to notify in the `CALLBACK` header. The router then sends notifications to that address. This is the step CallStranger abused, and Part 4 returns to it [3] (**Confirmed**).

The question that matters is in the control step: does the router check who is asking, and whom the port is opened to. In the first version of the profile the answer is no. CERT/CC's analysis states that the protocol "does not implement any form of authentication or verification" [4] (**Confirmed**). An optional UPnP Device Protection service was defined, but CERT/CC notes it was not widely adopted [4] (**Confirmed**). The second version of the gateway profile, published in 2010, narrowed the gap on paper: it recommends that unauthenticated control points be "only allowed to control port mappings which have InternalClient value equals to the control point's IP address", with ports at or above 1024, and a request that breaks the rule returns error 606. The same text adds that "devices MAY choose a different security policy" [6] (**Confirmed**). So whether a given router checks the requester, and whether it will map a port to some other host, depends on the device, and many enforce nothing (**Confirmed** for the specification text; **Inferred** that enforcement varies in the field).

The normal, intended use is harmless. A game console maps an external port to its own address so that inbound game traffic reaches it through NAT, which is the case the 2010 own-address rule is written for. The two abuses in Part 3 come from the gap the rule was meant to close and that many devices leave open: a request that names some other host as the internal client, and a service that answers the request from the internet side (**Inferred** from the specification and the fields [1] [6] [7]).

## Part 2: The implementations that could be attacked directly

The first set of problems is the ordinary kind: bugs in the code that speaks UPnP, made worse by that code being reachable from the wrong places.

**The exposure measurement.** From 1 June to 17 November 2012, Rapid7 sent UPnP discovery requests to every routable IPv4 address about once a week. More than 81 million unique addresses answered the discovery request; a December follow-up on a sample put an estimated 17 million of them as also exposing the SOAP control service to the internet [1] (**Confirmed**). A home router is supposed to answer UPnP only on the inside, to its own LAN. An address that answers discovery or control from the public internet has its control plane turned the wrong way out. The paper identified more than 1,500 vendors and 6,900 products vulnerable to at least one of the flaws it described [1] (**Confirmed**).

**The library flaws.** Most devices do not write their own UPnP stack; they use one of a few libraries. The paper found remotely exploitable flaws in the two most common. The Portable SDK for UPnP Devices, often called libupnp, had a set of flaws in the part that parses SSDP, tracked as CVE-2012-5958 through CVE-2012-5965, and about 23 million addresses were vulnerable to remote code execution through a single UDP packet; the fix was libupnp 1.6.18 [1] [2] (**Confirmed**). MiniUPnPd, another common implementation, had a denial-of-service flaw in its SSDP handling (CVE-2013-0229) and a code-execution flaw in its SOAP action handler (CVE-2013-0230) [1] [2] (**Confirmed**). Those two had already been fixed upstream in 2009, in MiniUPnPd 1.1 and 1.4; what the 2012 scan found was devices still shipping the older 1.0, which supports the paper's wider point that a library fix does not reach a device on its own [1] (**Confirmed**).

**It did not stop in 2013.** The same implementation kept yielding memory-safety bugs for years. CVE-2017-1000494 is an uninitialised-memory flaw that lets an attacker crash MiniUPnPd before version 2.0, and CVE-2019-12107 lets a remote attacker leak information from the heap in MiniUPnPd through version 2.1 through an unchecked `snprintf` return value in event handling [2] (**Confirmed**). The pattern is the ordinary one for a C program that handles attacker-supplied network input: the surface stays, and bugs surface in it over time (**Inferred** from the CVE descriptions [2]).

The defence for this set is the one Rapid7 gave in 2013. To home users its advice was to disable UPnP on the router, ask the maker if it cannot be disabled, and replace the device as a last resort; its separate advice to ISPs and businesses was to find and disable any UPnP reachable from the internet [1] (**Confirmed**). The reason the paper stressed exposure and replacement over patching is that much of the vulnerable equipment would never receive a library fix [1] (**Confirmed**).

## Part 3: Using the router as infrastructure, UPnProxy and EternalSilence

The second half of the record does not need a memory-corruption bug. It uses `AddPortMapping` on a router that does not enforce the 2010 own-address rule.

In 2018 Akamai reported a technique it called UPnProxy. An attacker who can reach a router's IGD control service sends `AddPortMapping` but sets `NewInternalClient` to an address that is not a device on that router's LAN. The router, which does not check the field, now relays traffic between two outside points, and a wall of such routers becomes a proxy network that hides the attacker's traffic behind other people's addresses. Akamai described a pool of about 3.5 million devices running vulnerable UPnP, about 277,000 of them exposing the controls that UPnProxy needs [7] (**Confirmed**). Akamai says the injected routers could be used to conceal traffic for spam, phishing, click fraud and distributed denial of service; it reports the technique and the exposure, not those uses as observed [7] (**Confirmed** as the stated risk).

A later set of injections, which Akamai named EternalSilence, pointed the mappings the other way. Instead of relaying outside traffic, the injected mapping exposed a port on a device behind the router, specifically the SMB ports TCP 139 and 445, to the internet [7] (**Confirmed**). The name came from the description the attackers left on the mappings, "galleta silenciosa", Spanish for silent cookie [7] (**Confirmed**). Akamai counted 45,113 routers carrying these injections, and reached an estimated 1.7 million by adding up the unique internal addresses named in the mappings; it says it cannot tell whether a machine actually held each address or was exposed [7] (**Confirmed**). The point of EternalSilence is in its effect: a home PC behind NAT is reachable from the internet only if something forwards a port to it, and these injections did exactly that. Akamai's phrasing is that the EternalSilence attacks "remove this implied protection granted by the NAT from the equation entirely", re-exposing machines to the old SMB exploits [7] (**Confirmed**).

Internet-side injection needs two things at once, and it is worth keeping them apart. One is an implementation fault: the router answers its IGD control service on the WAN side, where no outside party should be able to reach it. Akamai attributes this to routers running vulnerable UPnP implementations and tells owners to look for a firmware fix or a router without the fault, so it is a bug a vendor can fix [7] (**Confirmed**). The other is the design property from Part 1: nothing checks who asks or whom the mapping serves. Injection from the internet needs both; Pinkslipbot in Part 5, which runs from inside, needs only the second. Reading these as "the service doing what it was built to do" is this study's framing, and it holds only for the second of the two requirements (**Inferred**).

Akamai's defensive guidance is read-only first: audit the router's own NAT and port-mapping table for entries no one created, "scanning their UPnP NAT table to look for oddities", because an injected router gives its owner no other sign [7] (**Confirmed**). Disabling UPnP is the fix, with a caution Akamai states directly: disabling it "might not clear existing NAT injections", so a reboot or factory reset, plus a firmware update, may be needed to clear what is already there [7] (**Confirmed**).

## Part 4: Aiming a device from outside, CallStranger (CVE-2020-12695)

The eventing step from Part 1 carried its own flaw, and this one was in the specification rather than in any single product.

When a control point subscribes to UPnP events with `SUBSCRIBE`, it supplies an address in the `CALLBACK` header, and the device sends event notifications to that address. The Open Connectivity Foundation UPnP specification before 17 April 2020 "does not forbid the acceptance of a subscription request with a delivery URL on a different network segment than the fully qualified event-subscription URL" [3] (**Confirmed**). In plain terms, the subscriber could tell the device to send its traffic to an address the attacker chose, which is the shape of a server-side request forgery: the attacker does not reach the target directly, the device reaches it for them. CERT/CC's acknowledgement credits the researcher Yunus Çadırcı of EY Turkey, who published the issue as CallStranger in June 2020 [4] (**Confirmed**).

NVD scores CVE-2020-12695 at CVSS 3.1 7.5, High, with the vector `AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:H`, and classifies it as CWE-276, incorrect default permissions; it was published on 8 June 2020 [3] (**Confirmed**). What the aiming makes possible depends on the source. CERT/CC's note names two outcomes: using internet-facing UPnP devices as a source of amplified reflected traffic for a denial-of-service attack, and data exfiltration [4] (**Confirmed**). The researcher's own material adds two more: bypassing data-loss controls on the way out, and scanning internal ports from the outside [5] (**Confirmed** as the researcher's claim).

CallStranger is the clearest case of the fixed-versus-design split. The root is a specification that permitted the behaviour, so the Open Connectivity Foundation changed the specification on 17 April 2020, and then each device maker had to ship a firmware update that enforces the new rule [3] [5] (**Confirmed**). There is no single patch; the researcher notes that "because this is a protocol vulnerability, it may take a long time for vendors to provide patches", and devices that are no longer updated stay exposed [5] (**Confirmed**). For a home network the exposure is narrower than the headline count suggests, because a correctly configured home router does not answer UPnP on its internet side; the reflection surface is the large population of other internet-facing UPnP devices and servers that do (**Inferred** from the exposure data [1] [4]).

## Part 5: Malware that opens its own door, Pinkslipbot

The design property in Part 1 has one more consequence worth stating on its own: because the first IGD profile checks nothing, malware on any device on the LAN can open an inbound hole from the inside, with no user action and no router password.

McAfee reported in June 2017 that the banking malware Pinkslipbot, also tracked as QakBot or QBot, had used infected machines as control-server proxies since April 2016. To receive inbound connections from the internet, "Pinkslipbot uses universal plug and play (UPnP) to open ports, allowing incoming connections from anyone on the Internet to communicate with the infected machine" [8] (**Confirmed**). McAfee placed it in a short lineage, with its own hedge: as far as the company knew, it was "the second executable-based malware to use UPnP for port forwarding after the infamous W32/Conficker worm in 2008" [8] (**Confirmed**).

Two defensive points come from that report. First, the mappings a program like this leaves behind are hard to clean automatically, because "the port-forwarding rules created by Pinkslipbot are too generic to remove automatically without risking accidental network misconfigurations", and McAfee says ordinary anti-malware tools may not revert port-forwarding changes [8] (**Confirmed**). Second, McAfee's own advice is the same as everyone else's in this study: "keep tabs on their local port-forwarding rules and disable UPnP on their home routers unless they need it" [8] (**Confirmed**). The lesson is not that UPnP was broken here; it worked. The lesson is that a feature which lets any inside program open the perimeter is a feature an inside program will use (**Inferred** [8]).

## Part 6: What is fixed, what is design, what is a setting

The whole record sorts into three piles, and keeping them apart is the point of the study.

- **Fixed, by a patch or a replacement.** The implementation bugs are ordinary vulnerabilities with ordinary fixes: libupnp 1.6.18 for the SSDP flaws, later MiniUPnPd releases for its parser and event-handling flaws, and, for CallStranger, the specification change of 17 April 2020 followed by per-device firmware [1] [2] [3] (**Confirmed**). A router that answers UPnP discovery or control on its internet side belongs in this pile too: that is a device fault, which the maker can fix in firmware and which the owner otherwise closes by replacing the device, not a preference to be left as it is [1] [7] (**Confirmed**). A device that no longer receives firmware stays exposed, which is why Rapid7's advice ended at replacing equipment that will never be patched [1] (**Confirmed**).
- **Design, which no patch removes.** The first IGD profile authenticates nothing, so any host on the local network can add a port mapping. The 2010 profile recommends that an unauthenticated request be allowed to map only the requester's own address, which a router that enforces it uses to refuse the map-to-another-host shape that UPnProxy and EternalSilence rely on; but it still permits a host, or malware on a host, to open an inbound port to itself, which is the Pinkslipbot shape, and devices may decline the rule entirely [6] [7] [8] (**Confirmed** for the rule; **Inferred** for the split). The only way to remove the property fully is to not run the service.
- **Up to the owner.** Whether UPnP is enabled where the router offers it is the owner's choice, as is keeping firmware current and replacing equipment that cannot be fixed. The 2012 measurement is a census of routers that answered UPnP from the internet; as of that measurement UPnP was also enabled by default on many home gateways [1] (**Confirmed** as of 2013).

The trade-off in turning UPnP off is real and belongs in the decision rather than hidden from it. Some game consoles, voice and video calling, and peer-to-peer applications rely on UPnP to open their ports, and turning it off can require those ports to be forwarded by hand, or can degrade those applications. That is the owner's call to make; this study describes the setting and its effect, and does not tell anyone which way to set it (**Inferred**).

## Part 7: Check your own network

These checks are read-only. They look at the current state of a network and change nothing, and none of them was run for this study. Deciding whether to turn UPnP off, or to forward a port by hand, comes after, and is the owner's decision.

1. **Find out whether UPnP is on.** A home router's administration page has a UPnP setting, usually under a NAT, forwarding, or advanced-network section. Note whether it is enabled. As of the 2013 measurement, many routers enabled it by default [1] (**Confirmed** as of 2013).
2. **Read the current port-mapping table.** Some routers list their UPnP port mappings in the administration interface and many do not, and Akamai notes that an injected router gives its owner no visibility into the injection from the interface alone [7] (**Confirmed**). The dependable read-only method is to ask your own router for its mapping list with a UPnP client, which is the `GetGenericPortMappingEntry` action. Read the list and ask, for each entry, whether you or a device you recognise created it. Entries you cannot account for, entries whose internal client is an address you do not recognise, and entries for SMB ports 139 or 445 are the ones Akamai's guidance says to look at [7] (**Confirmed**).
3. **Confirm the router does not answer UPnP from the internet.** A general port-check service tests TCP and cannot reliably tell a closed UDP port from a filtered one, so it will not settle UDP 1900. Use a UPnP exposure test that sends the discovery request to your public address and reports whether anything answers. Where a second router sits behind the gateway, the public address is the outer router's. A home router should not answer UPnP from the internet; the 2012 census is what it looks like when one does [1] (**Confirmed**).
4. **Account for every router.** If a second router sits behind the gateway, check the UPnP setting on both, because each keeps its own [7] (**Inferred**).
5. **If an entry looks wrong, remember that disabling UPnP may not clear it.** Akamai noted that turning UPnP off "might not clear existing NAT injections", so clearing an entry already present can need a reboot or a factory reset and a firmware update [7] (**Confirmed**).

What these readings tell you maps onto Part 6: whether the service is on and where it answers (a setting and, for the internet side, a fault), and what it has been asked to do (the mappings). None of it requires touching another person's device or sending anything other than a request to your own router.

## MITRE ATT&CK mappings

This Part binds the behaviours in the record to MITRE ATT&CK v20.0. No source names ATT&CK identifiers; each row is this study's own mapping, checked against the library's technique data (**Inferred**; names and tactics **Demonstrated** from `data/attack/technique_profiles.jsonl` [9]). UPnP itself is a protocol, not an actor or a piece of software, so no group, software or campaign is bound.

| ID | Name | Tie to this record |
|---|---|---|
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | Internet-wide and on-LAN SSDP discovery of UPnP endpoints [1] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | UPnProxy turns injected routers into relays [7] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | EternalSilence re-exposes internal SMB to the internet [7] |
| [`T1048`](/mitre/techniques/T1048.md) | Exfiltration Over Alternative Protocol | CallStranger aims a device's traffic out of the network [4] [5] |
| [`T1498.002`](/mitre/techniques/T1498-002.md) | Reflection Amplification | CallStranger uses internet-facing UPnP devices to reflect traffic [4] |

Fit notes (**Inferred**): T1090 describes adversary proxying, which is what the injected routers provide, not a flaw in the router. T1133 is the nearest fit for re-exposing an internal service to the internet; the technique is written for adversary use of such services, and the EternalSilence tie is the exposure that enables it. T1048 and T1498.002 describe the two directions CallStranger's aiming supports, out of a network and at a third party.

## Cross-cutting themes

- **A protocol with no caller authentication is not broken when it is used as designed.** UPnProxy, EternalSilence and Pinkslipbot rely on a router that does not check who asks or whom a mapping serves; a router that enforces the 2010 own-address rule refuses the first two, and only not running the service refuses the third. Internet-side injection also needs a separate fault, the control service answering on the WAN [6] [7] [8] (**Inferred**).
- **Exposure matters more than any single bug.** The 2012 census found the service turned the wrong way out on tens of millions of addresses; the library bugs were serious, but the first defence Rapid7 gave to home users was to disable UPnP, and to ISPs and businesses to stop answering it from the internet [1] (**Confirmed**).
- **The inside is not automatically trustworthy.** The first profile assumes every LAN host is friendly, and malware on one device is enough to break that assumption and open the perimeter [8] (**Inferred**).
- **Read before you change.** Every defensive step in this study starts with reading the current state: the setting, the mappings, the internet-facing answer. The change comes after, and is the owner's to make (**Inferred**).

## Sources

All sources were opened on 25 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | HD Moore (Rapid7), "Security Flaws in Universal Plug and Play: Unplug. Don't Play.", January 2013, for the 2012 internet-exposure measurement, the libupnp and MiniUPnPd flaws, the 2009 upstream fixes, the fixed libupnp version, and the disable, ask-the-maker and replace guidance | [hdm.io/writing/SecurityFlawsUPnP.pdf](https://hdm.io/writing/SecurityFlawsUPnP.pdf) | 2026-11-25 | Confirmed |
| 2 | CVE Program and NVD records for the UPnP implementation flaws, each id resolving at cve.org/CVERecord?id=\<id\> and nvd.nist.gov/vuln/detail/\<id\>: CVE-2012-5958 to CVE-2012-5965 (Portable SDK for UPnP), CVE-2013-0229 and CVE-2013-0230, CVE-2017-1000494 and CVE-2019-12107 (MiniUPnPd) | [cve.org/CVERecord?id=CVE-2017-1000494](https://www.cve.org/CVERecord?id=CVE-2017-1000494) | 2026-11-25 | Confirmed |
| 3 | NVD, CVE-2020-12695 (CallStranger), for the description, the CVSS 3.1 7.5 score and vector, CWE-276, and the 8 June 2020 date | [nvd.nist.gov/vuln/detail/CVE-2020-12695](https://nvd.nist.gov/vuln/detail/CVE-2020-12695) | 2026-11-25 | Confirmed |
| 4 | CERT/CC Vulnerability Note VU#339275, for the protocol's lack of authentication or verification, the little-adopted Device Protection service, the amplified-DDoS and data-exfiltration outcomes, and the credit to Yunus Çadırcı of EY Turkey | [kb.cert.org/vuls/id/339275](https://kb.cert.org/vuls/id/339275) | 2026-11-25 | Confirmed |
| 5 | Yunus Çadırcı, CallStranger disclosure material (project README and callstranger.com), for the bypassing-DLP and internal-port-scan abuse classes and the note that a protocol fix reaches devices slowly | [github.com/yunuscadirci/CallStranger](https://github.com/yunuscadirci/CallStranger) | 2026-11-25 | Confirmed |
| 6 | UPnP Forum, WANIPConnection:2 service specification (IGD2), 10 September 2010, for the recommendation that unauthenticated control points map only their own address with ports at or above 1024, error 606 otherwise, and that devices may choose a different policy | [upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf](https://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf) | 2026-11-25 | Confirmed |
| 7 | Akamai (Chad Seaman), "UPnProxy: Eternal Silence", first posted November 2018, updated 2022, for the port-map injection technique, the device and router counts, the SMB re-exposure and its address caveat, the stated risks, and the NAT-table and disable guidance | [akamai.com/blog/security/upnproxy-eternal-silence](https://www.akamai.com/blog/security/upnproxy-eternal-silence) | 2026-11-25 | Confirmed |
| 8 | McAfee Labs, "McAfee Discovers Pinkslipbot Exploiting Infected Machines as Control Servers", 16 June 2017, for Pinkslipbot's use of UPnP to open inbound ports, the hedged Conficker comparison, and the port-forwarding and disable guidance | [mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-discovers-pinkslipbot-exploiting-infected-machines-as-control-servers-releases-free-tool-to-detect-disable-trojan](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-discovers-pinkslipbot-exploiting-infected-machines-as-control-servers-releases-free-tool-to-detect-disable-trojan/) | 2026-11-25 | Confirmed |
| 9 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl` (ATT&CK v20.0), for the technique names and tactics in the mappings | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-25 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

## Related references

- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md)
- [All case studies](/case-studies/README.md)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
