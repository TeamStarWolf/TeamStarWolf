# Casting on the Home Network: The Local Control APIs Behind Chromecast, DIAL and AirPlay, and Their Security Record

*A TeamStarWolf case study. Published 25 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [UPnP on the Home Network](/case-studies/UPNP_HOME_NETWORK.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Home and small-network users, network and security engineers, incident responders, and anyone hardening streaming and smart-home devices

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 25 min (5,860 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run a home network with casting devices, you want to understand the local control APIs behind Chromecast, DIAL and AirPlay and their security record, or you are deciding how to separate those devices from the rest of your network

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 7: What is fixed, what is design, what is a setting](#part-7-what-is-fixed-what-is-design-what-is-a-setting), [Part 8: Check your own network](#part-8-check-your-own-network)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[UPnP on the Home Network](/case-studies/UPNP_HOME_NETWORK.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-25):

- On the home network, casting rests on a local control service that trusts the local network, the same assumption as the UPnP port-mapping service. ([Executive summary](#executive-summary))
- In 2018 a web page could use DNS rebinding to reach the unauthenticated local cast API and read the Wi-Fi survey data that placed a home within about ten metres. ([Part 3: Reading the unauthenticated local interface](#part-3-reading-the-unauthenticated-local-interface))
- The 2021 account-linking issue turned data read over the LAN into a credential: the device's own identifiers were enough to link an attacker's cloud account and drive the device remotely. ([Part 3: Reading the unauthenticated local interface](#part-3-reading-the-unauthenticated-local-interface))
- Every weakness here was fixed in a version and a date, so a 2014 or 2018 weakness is not a current one on an updated device; the real exposure is equipment that stopped getting updates. ([Part 7: What is fixed, what is design, what is a setting](#part-7-what-is-fixed-what-is-design-what-is-a-setting))

<!-- meta:end -->

## Executive summary

Casting is the feature that sends a video, a song or a screen from a phone to a television, a speaker or a display. On the home network it rests on a small set of protocols: a device announces itself over multicast DNS, a controller finds it, and the controller sends commands to a local service on the device. The pattern that runs through this study is the one casting shares with the UPnP port-mapping service covered in a [companion study](/case-studies/UPNP_HOME_NETWORK.md): the local service on the device trusts the local network. Craig Young, who found a location leak in Google's cast devices in 2018, put the underlying assumption as two design choices common to home devices, that they "rarely require authentication for connections received on a local network" and that "HTTP is frequently used to configure or control embedded devices" [2] (**Confirmed**).

The record of what that assumption allowed falls into a few groups. One is taking over a device on the local network: the 2014 Rickmote, which knocked a Chromecast off its Wi-Fi so that it fell back to an open setup mode and accepted commands from anyone nearby [1] (**Confirmed**). One is reading or abusing the unauthenticated local control interface: the 2018 location leak, where a web page used DNS rebinding to reach the device's local HTTP service and pull the Wi-Fi survey data that places a home to within about ten metres [2] (**Confirmed**), and the 2021 account-linking issue, where the device's own identifying information, read over the local network, was enough to link an attacker's cloud account and then drive the device remotely, including a wiretap built from a scheduled call, for which Google paid a researcher a total of 107,500 US dollars [4] (**Confirmed**). One is the casting protocols' own weaknesses: DIAL, the discover-and-launch protocol behind much smart-TV casting, which a 2019 research project found most television vendors had not implemented correctly [5] (**Confirmed**). And one is what happens when any of this is exposed to the internet rather than kept on the LAN, which is the 2019 CastHack incident [3] [4] (**Reported** for the incident; the exposure cause **Confirmed** as the researcher's own assessment).

The defensive reading sorts the same way as the UPnP study. Some of these are bugs that a patch fixed, and the fix has a version and a date: the local cast API began requiring an authorization token in 2019, the account-linking path was closed in 2021, DIAL's protocol gaps were narrowed by a 2020 update from Netflix, and Apple's AirPlay flaws (AirBorne, included here for comparison) were fixed in 2025 software [4] [5] [6] [7] [8] (**Confirmed**). Some is a design property that no patch removes, because a local service that trusts the LAN behaves as written, and the only full defence is to separate the device from the network the owner browses on. And some is up to the owner: whether the casting network is segmented, whether a receiver that is not used is turned off, and whether firmware is current. A reader can check the state of all three on their own network with read-only steps, which the last Part sets out. None of those checks was run for this study.

## Key facts at a glance

| Field | Value |
|---|---|
| What it is | The local control interfaces behind casting: Google Cast's local HTTP service (ports 8008 and 8443) reached over multicast DNS, and DIAL (DIscovery And Launch) reached over SSDP, both answering on the LAN [2] [4] [5] |
| Core design property | The local cast service trusted the LAN and required "no form of authentication" before 2019; commands to set the device name and Wi-Fi were "sent directly to the device without any form of authentication" [2] (**Confirmed**) |
| Local hijack | Rickmote, 2014: a deauthentication burst drops a Chromecast to its open setup network, which "accepts commands from anyone within proximity" [1] (**Confirmed**) |
| Location leak | 2018: DNS rebinding reached the unauthenticated local API and used Wi-Fi survey data to place a home "within 10 meters"; fixed when the API began requiring a token in 2019 [2] [4] (**Confirmed**) |
| Account-linking wiretap | 2021 report: device info read over the LAN linked an attacker's cloud account, giving remote control and a scheduled-call microphone feed; 107,500 US dollars; fixed 2021 [4] (**Confirmed**) |
| Protocol weakness | DIALStranger, 2019 research disclosed 2023: "most of TV vendors didnt implement protocol correctly"; Netflix updated the protocol in 2020 [5] (**Confirmed**) |
| Apple comparison | AirBorne, 2025: 23 vulnerabilities, 17 CVEs in AirPlay and its SDK; CVE-2025-24252 (CVSS 3.1 8.8) chained with CVE-2025-24206 (7.7) for a same-network zero-click; fixed in April 2025 software [6] [7] [8] |

## Scope and method

This is a reference study of one attack surface, the local control interfaces behind home casting, read across the public record from 2014 to 2025. It is written for a typical home network: a router or mesh system, a television or streaming dongle, a smart speaker or display, and sometimes a second router behind an internet-service-provider gateway. It is a defensive study. It explains each protocol well enough to show why a problem worked, then what a reader can check and decide, and it reproduces no attack recipe against any specific product and no exploit code. Nothing here was tested against any device; the checks in the last Part are described as read-only steps a reader could take, and none was run.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: the researcher's own write-up, the vendor advisory, or the CVE and NVD record |
| Reported | Known through journalism or a secondary summary |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

The primaries are Dan Petro's Bishop Fox post for Rickmote [1]; Craig Young's Tripwire write-up for the 2018 location leak [2]; the archived CastHack page for the 2019 exposure, with Matt Kunze's analysis of its likely cause [3] [4]; Kunze's own write-up for the 2021 account-linking issue [4]; Yunus Çadirci's DIALStranger material for the DIAL weaknesses [5]; Oligo Security's report for AirBorne, with the NVD records and Apple's advisory for the identifiers, scores and fixed versions [6] [7] [8]. Where a statement is a researcher's own claim about reach or impact rather than a measured fact, this study says so.

## Part 1: What casting is, and whether it checks who is asking

Casting is not one protocol but a small stack, and the home has more than one casting system on it at once. The parts that matter for security are discovery, the local control service, and, for televisions, the DIAL launch protocol.

**Discovery.** A cast device announces itself on the local network with multicast DNS (mDNS) and DNS-based service discovery (DNS-SD). A Google Cast device, for example, advertises the service type `_googlecast._tcp`, and a controller browsing for that service finds the device's name and address without any configuration. Matt Kunze's write-up shows exactly this, using the `dns-sd` tool to list a Chromecast, a Nest Hub and a Home Mini on one network [4] (**Confirmed**). DIAL televisions are found a different way, over the Simple Service Discovery Protocol (SSDP), the same UDP discovery used by UPnP: a controller sends an `M-SEARCH` request and DIAL devices answer, which is how the DIALStranger scanner enumerates them [5] (**Confirmed**).

**The local control service.** Once found, a Google Cast device exposes a local HTTP service. Kunze found it on TCP port 8008 and, over TLS, 8443, with port 8008 deprecated in favour of 8443, and he read device settings and information straight from it [4] (**Confirmed**). The question that matters is whether that service checks who is asking. Before 2019 it did not. Craig Young's 2018 analysis states that commands "to do things like setting the device name and WiFi connection are sent directly to the device without any form of authentication", and that although the official app implies you must be signed in to a linked account, "there is, in fact, no authentication mechanism built into the protocol level" [2] (**Confirmed**). That is the cast stack's version of the property the UPnP study describes: the service trusts the local network and the inside is assumed friendly.

**DIAL, discover and launch.** DIAL is a separate protocol for the specific job of letting a phone tell a television to open an app and play something. Çadirci's material describes it plainly: "Discovery and Launch (DIAL) is a protocol co-developed by Netflix and YouTube with help from Sony and Samsung" [5] (**Confirmed**). After SSDP discovery, the controller uses a small HTTP interface on the television to start an application such as YouTube or Netflix and hand it what to play. DIAL is the casting path for most smart televisions, and Part 4 returns to how it was implemented.

The normal, intended use of all of this is harmless and is the reason the design is the way it is: a guest on the home Wi-Fi should be able to cast a video to the living-room television without typing a password into the television. The problems in the rest of this study come from the same place that convenience does, which is that the device answers whoever can reach it on the network, and from what happens when the set of things that can reach it grows beyond the household (**Inferred** from the protocol descriptions [2] [4] [5]).

## Part 2: Taking over a device on the local network, Rickmote

The earliest problem in the record does not touch the control API at all. It uses the way a cast device recovers when it loses Wi-Fi.

In 2014 Dan Petro, then at Bishop Fox, built the Rickmote, a tool that hijacks a nearby Chromecast and plays a music video on the attached television. The mechanism is in Bishop Fox's own description: the tool "accomplishes this by briefly disconnecting nearby Chromecasts from their Wi-Fi. When this loss of connectivity occurs, the Chromecast tries to reconfigure and accepts commands from anyone within proximity" [1] (**Confirmed**). The disconnection is possible because ordinary Wi-Fi management frames, including the deauthentication frame that tells a client to drop its connection, are not authenticated on a network using WPA2, so anyone nearby can send them. When the Chromecast drops, it opens its own setup network so its owner can reconnect it, and in that state it will take configuration from whoever reaches it first.

Two things are worth stating about how current this is. First, the fall-back-to-setup behaviour is a design property of how cast devices recover, not a one-off bug, and it persisted for years: Kunze confirmed in 2022 that forcing a Google Home Mini off its network with a deauthentication attack still made it open its own setup network, from which he could read the device's information [4] (**Confirmed** for the 2022 reproduction). Second, what an attacker can do from that setup network narrowed over time. In 2014 the open setup mode accepted casting commands directly; by 2019 the local API required a token, and by 2021 the device information read from setup mode was no longer enough on its own to link an account, as Parts 3 and 7 describe. On devices with a screen, the setup network is now protected with a password shown on the display, which Kunze notes closes the open-network step entirely for those models [4] (**Confirmed**). So Rickmote as a 2014 recipe does not reproduce on a current, updated device, but the underlying design property, that a cast device will drop to a recovery state an attacker can trigger, is the kind that no single patch removes (**Inferred**).

## Part 3: Reading the unauthenticated local interface

The local control service from Part 1 was reachable without credentials, and two separate pieces of research turned that into real consequences four years apart.

**The location leak, 2018.** Craig Young set out to build a training exercise and found a larger issue. Because the cast device's local HTTP service answered without authentication, a web page open in a browser on the same network could reach it using DNS rebinding, a technique that tricks the browser into treating the attacker's web server and the local device as the same origin. Young used it to hijack the screen attached to a Chromecast and, more seriously, to read the Wi-Fi survey data the device collects, the list of nearby wireless networks and their signal strengths. Fed to a geolocation service, that data places the device with the same accuracy a phone gets indoors: Young writes that even without a GPS receiver, mapping "has typically been able to locate my machine within 10 meters" [2] (**Confirmed**). The result is that a web page, with no special permission, could work out the street address of the home it was being viewed in.

Young's own mitigations are the defensive core of this study, and they are read-only or structural rather than exploit-specific. He keeps connected devices on a separate network from the one he browses on, and gives the simple version of that for ordinary users: add a second router for connected devices, so that, in his words, "attacker code running on the main network will not have a path to abuse those connected devices" [2] (**Confirmed**). He also points to DNS rebind protection, noting that the DNS software in many consumer routers can block the rebinding step, and that "OpenWRT and DD-WRT users can and should enable this protection" [2] (**Confirmed**). The leak was published in June 2018 in coordination with Brian Krebs, and the unauthenticated-access path it used was closed when the local cast API began requiring an authorization token in 2019, a change Kunze records in his own timeline of the platform [4] (**Confirmed** for the 2019 token requirement; **Inferred** that it closed this specific path).

**The account-linking wiretap, 2021.** Matt Kunze reported a subtler issue in January 2021 and published it in December 2022 after it was fixed. A linked Google account gives broad control of a cast device, including the "routines" feature, which can run voice commands on the device on a schedule. Kunze found that the information needed to link an account, the device's name, certificate and cloud identifier, was served by the local API, and that this information, read over the LAN, was effectively the credential: with it, an attacker could link their own account through Google's cloud and then drive the device remotely. From there, routines gave a wiretap. Kunze built a routine that told the device to call his phone, picked up, and listened to the room through the device's microphone, with the only visible sign being an LED he describes as easily mistaken for a firmware update [4] (**Confirmed**). Because the device information could also be read from the Rickmote-style setup network, an attacker did not even need the Wi-Fi password: deauthenticate the device, read its information from the open setup network, then link the account from anywhere [4] (**Confirmed**).

Kunze tested all of this on a Google Home Mini (first-generation hardware, firmware 1.56.309385, dated August 2022) and writes that he assumes it worked similarly on other models, which is his inference rather than a tested result [4] (**Confirmed** for the Home Mini; the other models are the researcher's assumption). Google paid him a total of 107,500 US dollars and deployed the fixes Part 7 lists. The point that carries beyond the specific bug is the one Young had already made in 2018: an unauthenticated local service does not only let an attacker send commands, it lets an attacker read identifying data that becomes a key elsewhere.

## Part 4: The casting protocol's own weaknesses, DIALStranger

The problems above are mostly about Google's cast devices and their local API. DIAL, the protocol behind most smart-television casting, carried weaknesses in the protocol itself and in how vendors built it.

Yunus Çadirci, who also published the CallStranger UPnP issue covered in the UPnP study, researched DIAL in 2019 and disclosed it in 2023 under the name DIALStranger. His summary is direct: "I found protocol doesn't cover some basic security features and most of TV vendors didnt implement protocol correctly. Hackers can play any video on the TVs with or without user interaction" [5] (**Confirmed**). The shape of the problem is familiar from the rest of this study: DIAL answers on the local network, and where a television's DIAL interface does not properly check the origin of a request, a web page or another device on the network can start apps and play content on the television. Çadirci documents that the DIAL interface sits on a different port and path on each vendor's television, listing examples such as LG on port 36866, Samsung on 8001 under `/ws/apps/`, and others, which is a sign of how unevenly the protocol was implemented across the market [5] (**Confirmed**).

Çadirci waited four years to disclose, and his stated reason is the same slow-patch problem the UPnP study describes for CallStranger: protocol-level issues take a long time to reach every device. He is explicit that the situation improved but is not closed. On the better side, he records that "Netflix updated protocol 2020 and covered some holes", that responsible vendors updated devices, and that browsers removed features (such as FTP support and WebRTC local-IP disclosure) that had helped attackers find local devices [5] (**Confirmed**). On the unresolved side, he notes that old televisions are not updated and will not be, and he argues that DIAL is not purely a local-network concern because, he states, millions of televisions are exposed to the internet and can be reached by the nature of the protocol [5] (**Confirmed** as the researcher's claim). For a reader the practical reading is per-device and per-year: a television patched after 2020, from a vendor that shipped the update, is in a different position from one that stopped receiving firmware before then (**Inferred**).

## Part 5: What happens when casting is exposed to the internet, CastHack

Everything in Parts 1 to 4 assumes the attacker is on the local network or reaching it through a browser on it. In January 2019 a public incident showed what the same interfaces allow when they answer from the internet instead.

Under the name CastHack, two people used internet-exposed Google Cast and DIAL control endpoints to force thousands of devices to play a video promoting a YouTube channel. The capabilities they advertised are the ordinary local-API actions seen from the wrong side of the network: the archived CastHack page lists being able to "play media on your device, rename your device, factory reset or reboot the device, force it to forget all wifi networks, force it to pair to a new bluetooth speaker/wifi point, and so on" [3] (**Reported**). This is the clearest link between this study and the UPnP study: a control interface that is safe only because it is supposed to be reachable only from inside becomes dangerous the moment it answers the internet.

The cause is worth stating carefully, because the popular account and the careful one differ. Early coverage attributed CastHack to UPnP automatically opening ports on home routers, the exact mechanism the UPnP study examines. Kunze, looking at it directly, reaches a more cautious conclusion: he writes that "it appears that UPnP is only used by Cast devices for local discovery, not for port forwarding, so the likely cause was a widespread networking misconfiguration (that might be related to UPnP somehow)" [4] (**Confirmed** as the researcher's assessment). So the honest cross-link to the UPnP study is not that UPnP port-forwarding caused CastHack, but that CastHack is the same lesson from a different cause: a local-only control interface exposed to the internet, whether by a UPnP port map or by some other router misconfiguration, is reachable by anyone. Kunze also notes that this exposure is a networking problem the device vendor cannot fix, which puts it, like a router answering UPnP on its WAN side, in the owner-and-ISP column rather than the vendor-patch column (**Inferred** [3] [4]).

## Part 6: AirPlay for comparison, AirBorne

Casting is not only a Google and smart-television story. Apple's AirPlay is the same kind of feature, a device announcing itself on the LAN and taking media and commands from controllers, and a 2025 research project shows the same design assumption producing much more serious bugs. It is included here for comparison, not because it is the owner's likely equipment.

In April 2025 Oligo Security published AirBorne, a set of flaws in AirPlay and in the AirPlay software development kit (SDK) that third-party speakers and televisions use. Oligo states that it "disclosed 23 vulnerabilities to Apple in total, leading to 17 CVEs being issued" [6] (**Confirmed**). The flaws start from the same place as the rest of this study: AirPlay listens on a port (7000) and, in Oligo's account, "many protocol commands were fully accessible in the default settings" [6] (**Confirmed**). Where AirBorne goes further than the cast issues is in impact. Two of the flaws reach remote code execution, the ability to run the attacker's code on the device, rather than only sending it commands.

The identifiers and scores here are taken from the CVE records rather than from the research summary, because they differ in an informative way. CVE-2025-24252 is a use-after-free memory flaw (CWE-416) that the NVD scores at CVSS 3.1 8.8 (High), with the vector `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, where `AV:A` means the attacker must be on the adjacent network, not anywhere on the internet [7] (**Confirmed**). Oligo describes chaining it with CVE-2025-24206, a user-interaction-bypass flaw (CWE-288, NVD CVSS 3.1 7.7), to reach a zero-click, no-interaction takeover of a Mac that has the AirPlay receiver enabled for "Anyone on the same network" or "Everyone", and says this chain can be made to spread from device to device, which is what "wormable" means [6] [7] (**Confirmed** for the records; the chaining is Oligo's demonstrated result). The third, CVE-2025-24132, is a stack buffer overflow in the AirPlay SDK, and here the sources diverge usefully: Oligo describes it as a zero-click remote-code-execution flaw on third-party speakers and receivers, while the NVD record scores it at CVSS 3.1 6.5 and describes the effect more narrowly as that an attacker "may cause an unexpected app termination", a crash rather than code execution [6] [7] (**Confirmed** for each source's own words; this study does not resolve the difference). The honest statement is that the CVE record scores it as a denial of service, and the higher claim of code execution is the researcher's.

What the research tested is also worth separating from what it reasons about. Oligo shows its memory-corruption primitive working on macOS in a video, overwriting an application in real time [6] (**Confirmed** for macOS). Its statements about the reach of the SDK flaw across third-party devices are framed around populations it estimates rather than a named, tested product, for example "the number of third-party audio devices that support AirPlay can be estimated in the 10s of millions", which is an estimate, not a count [6] (**Confirmed** as Oligo's estimate). Apple fixed the operating-system flaws in its April 2025 releases (iOS and iPadOS 18.4, iPadOS 17.7.6, macOS Sequoia 15.4, macOS Sonoma 14.7.5, macOS Ventura 13.7.5, tvOS 18.4 and visionOS 2.4) and the SDK flaw in AirPlay audio SDK 2.7.1, AirPlay video SDK 3.6.0.126 and the CarPlay plug-in R18.1 [7] [8] (**Confirmed**). The comparison the study draws is that AirPlay is a casting protocol with the same trust-the-LAN starting point as Google Cast and DIAL, and that the starting point is what let a memory bug in it become a same-network takeover; the defences are the same ones Young gave in 2018, update the software and keep the receiver off or restricted when it is not in use (**Inferred**).

## Part 7: What is fixed, what is design, what is a setting

The whole record sorts into three piles, and keeping them apart is the point of the study.

- **Fixed, by a patch with a version and a date.** The unauthenticated local cast API was closed when it began requiring an authorization token in 2019 [4] (**Confirmed**). The account-linking path was closed in 2021: Kunze records that linking an account through the cloud API now requires an invitation to the device's "Home", so that an attacker who only read the device information receives a permission error, and that the remote "call a number" routine that made the wiretap no longer runs remotely [4] (**Confirmed**). DIAL's protocol gaps were narrowed by Netflix's 2020 update and by per-vendor firmware, unevenly [5] (**Confirmed**). AirPlay's AirBorne flaws were fixed in Apple's April 2025 operating-system releases and in AirPlay SDK 2.7.1 and later for third-party devices [7] [8] (**Confirmed**). A device that no longer receives firmware stays where it was, which is why an old smart television or an abandoned speaker is the real exposure.
- **Design, which no patch removes.** A cast device answers the local network, and it falls back to a recovery state when it loses Wi-Fi. Both are deliberate, because both make the device easy to set up and use, and neither is removed by a patch. The 2019 token and the 2021 invitation requirement raise the bar on what an unauthenticated LAN or setup-network peer can do, but the device still trusts the local segment for discovery and basic interaction, and an attacker who is on that segment, or who reaches it through a browser, is inside the trust boundary. The only way to remove that property is to put the device on a network the owner does not browse on, which is a structural choice, not a device setting [2] [4] (**Inferred** from the researchers' own framing).
- **Up to the owner.** Whether casting devices sit on a separate network from the one used for general browsing is the owner's choice, and it is the single most effective one in this study, because it is Young's own first mitigation [2] (**Confirmed**). So is whether a receiver that is not used, such as AirPlay's receiver on a Mac, is turned off or restricted to the current user [6] (**Confirmed** as Oligo's advice). So is keeping firmware current and retiring equipment that no longer gets updates.

The trade-off, as with UPnP, belongs in the decision rather than hidden from it. Putting cast devices on a separate network can break the convenience that casting exists for, because a phone on the main network may no longer see a speaker on the device network, and casting across segments needs either a guest mode or a deliberate exception. That is the owner's call to make; this study describes the setting and its effect, and does not tell anyone which way to set it (**Inferred**).

## Part 8: Check your own network

These checks are read-only. They look at the current state of a network and change nothing, and none of them was run for this study. Deciding whether to segment the network, turn a receiver off, or retire a device comes after, and is the owner's decision.

1. **List the casting devices that answer on the network.** A cast device announces itself over multicast DNS; a controller or a network tool can browse the service types (such as `_googlecast._tcp` for Google Cast) and list what answers. Reading this list tells you which devices are advertising a casting interface on your LAN, which is the first thing any attacker on the network would also enumerate [4] (**Confirmed** that discovery works this way; the enumeration here is described, not run).
2. **Check whether casting devices share a network with general browsing.** The strongest mitigation in this study is Young's: keep connected devices on a separate network from the one used to browse the web, so a rogue web page or app cannot reach them [2] (**Confirmed**). Read your own setup to see whether that separation exists, for example whether a guest network or a second router carries the connected devices, without changing anything yet.
3. **Check for DNS rebind protection on the router.** The 2018 location leak relied on DNS rebinding, which router DNS software can block. Young notes that OpenWRT and DD-WRT can enable this protection [2] (**Confirmed**). Read whether your router offers it and whether it is on.
4. **Check that casting interfaces do not answer from the internet.** The CastHack incident was devices answering their control interface to the public internet [3] (**Reported**). A home device should answer casting only on the inside. Confirming the negative from outside is not something a general port checker settles reliably, and where a second router sits behind a gateway the public address is the outer router's; the dependable reading is to know that no port-forward or router misconfiguration exposes the casting ports, which is a read of the router's own forwarding table, the same read the UPnP study describes [3] [4] (**Inferred**).
5. **Check firmware currency and support status per device.** Because every fix in this study has a version and a date, a device's exposure depends on whether it still receives updates. Read each casting device's firmware version and whether the vendor still supports it; a television or speaker past its update window stays at whatever year it stopped (**Inferred** from the dated fixes [4] [5] [7]).

What these readings tell you maps onto Part 7: whether the devices are separated from general browsing (a structural choice), whether the router blocks the rebinding step and does not expose the ports (settings and a possible fault), and whether firmware is current (a setting and a support question). None of it requires touching another person's device or sending anything other than ordinary discovery to your own network.

## MITRE ATT&CK mappings

This Part binds the behaviours in the record to MITRE ATT&CK v20.0. No source names ATT&CK identifiers; each row is this study's own mapping, checked against the library's technique data (**Inferred**; names and tactics **Demonstrated** from `data/attack/technique_profiles.jsonl` [9]). The casting protocols are not actors or software, so no group, software or campaign is bound, and the table is kept to behaviours a cited source actually shows.

| ID | Name | Tie to this record |
|---|---|---|
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | mDNS and SSDP discovery of cast and DIAL devices, and a compromised device scanning the LAN for others [2] [4] [5] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | AirBorne's chained zero-click code execution over AirPlay against devices on the same network [6] [7] |
| [`T1557`](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | Oligo's described denial-of-service-then-mDNS-spoof interception of an AirPlay stream [6] |

Fit notes (**Inferred**): T1046 covers both the attacker's enumeration of cast devices and a compromised device's scan of the LAN, both of which the cited researchers demonstrate. T1210 is the nearest fit for AirBorne's remote code execution, which is the exploitation of a network-facing service to run code; it is bound only to the AirBorne items, not to the command-level cast abuses. T1557 is bound to a scenario Oligo describes rather than one observed in the wild, and is labelled as such.

## Cross-cutting themes

- **A local service that trusts the network is the common root.** Rickmote, the location leak, the account-linking issue, DIAL's weaknesses and AirBorne all start from a device that answers the local segment without authenticating the caller. Young stated the fix as a design rule in 2018: local services, especially HTTP ones, "must be designed as if they were directly exposed to the Internet", and that "any data accessible on the local network without credentials is also accessible to hostile adversaries" [2] (**Confirmed**).
- **Reading is as dangerous as commanding.** The 2018 leak and the 2021 account-linking issue both turned on data read from an unauthenticated interface, Wi-Fi survey data in one case and device identifiers in the other, becoming a key somewhere else. An interface that only reveals information is not automatically safe [2] [4] (**Confirmed**).
- **Exposure changes everything.** The same control interface is a convenience on the LAN and a public hazard on the internet; CastHack is the local-only design meeting the open internet through a router misconfiguration [3] [4] (**Confirmed** as the researcher's assessment).
- **A weakness has a year.** Each item here was fixed in a version and a date, so a 2014 or 2018 weakness is not a current one on an updated device, and the real exposure is equipment that stopped receiving updates. Read before you change: every defensive step in this study starts by reading the current state, and the change is the owner's to make (**Inferred**).

## Sources

All sources were opened on 25 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Dan Petro (Bishop Fox), "The Rickmote Controller: Hacking One Chromecast at a Time", 2014, for the deauthentication-to-setup-mode hijack and the quoted mechanism | [bishopfox.com/blog/rickmote-controller-hacking-one-chromecast-time](https://bishopfox.com/blog/rickmote-controller-hacking-one-chromecast-time) | 2026-11-25 | Confirmed |
| 2 | Craig Young (Tripwire VERT), "Google's Newest Feature: Find My Home", June 2018, for the two IoT design choices, the unauthenticated local API, the DNS-rebinding location leak and the ten-metre figure, and the segmentation and DNS-rebind-protection mitigations | [tripwire.com/state-of-security/googles-newest-feature-find-my-home](https://www.tripwire.com/state-of-security/googles-newest-feature-find-my-home) | 2026-11-25 | Confirmed |
| 3 | CastHack promotional page (archived), January 2019, for the advertised local-API actions used against internet-exposed cast devices | [web.archive.org/web/20211114052648/https://casthack.thehackergiraffe.com/](https://web.archive.org/web/20211114052648/https://casthack.thehackergiraffe.com/) | 2026-11-25 | Reported |
| 4 | Matt Kunze, "Turning Google smart speakers into wiretaps for $100k", December 2022, for the account-linking mechanism, the routines wiretap, the 107,500 US dollar reward, the Home Mini test and firmware, the fixes, the 2019 local-API token, and the assessment of CastHack's cause | [downrightnifty.me/blog/2022/12/26/hacking-google-home.html](https://downrightnifty.me/blog/2022/12/26/hacking-google-home.html) | 2026-11-25 | Confirmed |
| 5 | Yunus Çadirci, DIALStranger (research 2019, disclosed 2023), for what DIAL is, the vendor-misimplementation finding, the 2020 Netflix protocol update, and the per-vendor DIAL ports | [github.com/yunuscadirci/DIALStranger](https://github.com/yunuscadirci/DIALStranger) | 2026-11-25 | Confirmed |
| 6 | Oligo Security (Uri Katz, Gal Elbaz, Avi Lumelsky), "AirBorne", April 2025, for the 23 vulnerabilities and 17 CVEs, the default-accessible commands, the wormable zero-click chain, the macOS demonstration, the third-party-device estimates, and the remediation advice | [oligo.security/blog/airborne](https://www.oligo.security/blog/airborne) | 2026-11-25 | Confirmed |
| 7 | NVD records for the AirBorne identifiers cited, each resolving at nvd.nist.gov/vuln/detail/\<id\>: CVE-2025-24252 (CVSS 3.1 8.8, CWE-416), CVE-2025-24206 (7.7, CWE-288), CVE-2025-24132 (6.5, CWE-119, described as app termination) | [nvd.nist.gov/vuln/detail/CVE-2025-24252](https://nvd.nist.gov/vuln/detail/CVE-2025-24252) | 2026-11-25 | Confirmed |
| 8 | Apple security advisory, "About the security content of the AirPlay audio SDK and AirPlay video SDK", for the fixed SDK versions (AirPlay audio SDK 2.7.1, AirPlay video SDK 3.6.0.126, CarPlay plug-in R18.1) and, with the OS advisories it links, the April 2025 operating-system fixes | [support.apple.com/en-us/122403](https://support.apple.com/en-us/122403) | 2026-11-25 | Confirmed |
| 9 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl` (ATT&CK v20.0), for the technique names and tactics in the mappings | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-25 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

## Related references

- [UPnP on the Home Network](/case-studies/UPNP_HOME_NETWORK.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md)
- [All case studies](/case-studies/README.md)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
