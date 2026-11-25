# The Always-On Home: Mesh Wi-Fi, Thread Border Routers and Smart Speakers, and Their Security Record

*A TeamStarWolf case study. Published 25 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [UPnP on the Home Network](/case-studies/UPNP_HOME_NETWORK.md), [Casting on the Home Network](/case-studies/CASTING_HOME_NETWORK.md), [The ISP-Supplied Gateway](/case-studies/ISP_GATEWAY_HOME_NETWORK.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Home and small-network users, network and security engineers, incident responders, and anyone running mesh Wi-Fi, smart speakers or Thread devices

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 18 min (4,089 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You run mesh Wi-Fi, a smart speaker or display, or Thread smart-home devices, and you want to understand the attack surface they add and their security record

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 6: What is fixed, what is design, what is a setting](#part-6-what-is-fixed-what-is-design-what-is-a-setting), [Part 7: Check your own devices](#part-7-check-your-own-devices)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Casting on the Home Network](/case-studies/CASTING_HOME_NETWORK.md), [The ISP-Supplied Gateway](/case-studies/ISP_GATEWAY_HOME_NETWORK.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-25):

- Mesh Wi-Fi, Thread border routers and smart speakers are always-on devices that add microphones, radios or a bridging role the owner cannot easily inspect. ([Executive summary](#executive-summary))
- A mesh Wi-Fi system is not one device but several, a router and its satellites, and the 2023 Netgear Orbi flaws were across both. ([Part 2: The mesh Wi-Fi system, Netgear Orbi](#part-2-the-mesh-wi-fi-system-netgear-orbi))
- A smart speaker is built around an always-on microphone, so if its code is replaced, as the 2017 Amazon Echo hardware attack showed, it becomes a listening device. ([Part 3: The smart speaker as a listening device, the Echo hardware attack](#part-3-the-smart-speaker-as-a-listening-device-the-echo-hardware-attack))
- Unlike the ISP gateway, these devices the owner controls, so the levers are firmware updates, the physical mute and wake-word controls, and how many always-on devices to run. ([Part 6: What is fixed, what is design, what is a setting](#part-6-what-is-fixed-what-is-design-what-is-a-setting))

<!-- meta:end -->

## Executive summary

The devices this study covers are the ones a household buys to make a home network bigger and smarter: mesh Wi-Fi systems that spread coverage across several nodes, Thread border routers that join a low-power smart-home mesh to the home's internet connection, and smart speakers and displays that listen for a wake word. They are the sequel to the three devices in this series' earlier studies, and they share a property worth naming at the start: each is always on, each adds radios, microphones or a bridging role to the network, and each widens the home's attack surface in a way the owner cannot easily inspect.

The public record is written here from four well-documented cases. In work Cisco Talos disclosed in 2023, a widely sold mesh Wi-Fi system, the Netgear Orbi, held four flaws across its router and its satellite, including command execution reachable by an attacker who had authenticated to the mesh, with one of the four still awaiting a patch when the advisories were published [1] [2] (**Confirmed**). In 2017 researchers at MWR InfoSecurity showed that an attacker with physical access to an Amazon Echo could boot their own code on it and turn its always-listening microphone into a remote wiretap, a flaw fixed in later hardware [3] (**Confirmed**). In 2022 the Alexa versus Alexa research showed a smart speaker could be made to act on commands played through its own speaker, recorded as CVE-2022-25809 [4] [5] (**Confirmed**). And the Thread border router, the newest of these roles, carries its own flaws: a 2026 issue in OpenThread, a common implementation, let an attacker on the adjacent network inject corrupted packets into the Thread mesh (CVE-2026-8369) [6] (**Confirmed**).

The defensive reading sorts the way the earlier studies' did. Some of this is fixed by a patch with a version, which the owner must apply: Netgear shipped updates for three of the four Orbi flaws, Amazon changed the Echo hardware, and the OpenThread issue has a fix commit. Some is a design property no patch removes, because an always-listening microphone, a mesh satellite that is a second way in, and a border router that bridges two networks are all behaving as built. And some is up to the owner: keeping firmware current, using the physical controls these devices provide, and deciding where on the network each device sits. A reader can check the state of their own devices with read-only steps, which the last Part sets out. None of those checks was run for this study, which describes these product families as the public record describes them, names a vendor or model only where a cited source names one, ties nothing to any household, and tested no device.

## Key facts at a glance

| Field | Value |
|---|---|
| What it covers | Always-on home devices: mesh Wi-Fi systems, Thread border routers, and smart speakers and displays, each adding radios, microphones or a bridging role to the home network |
| Mesh Wi-Fi | Netgear Orbi, disclosed by Cisco Talos in 2023: four flaws across router and satellite; CVE-2022-37337 is command execution reachable by an attacker authenticated to the mesh (NVD CVSS 3.1 8.8) [1] [2] |
| Smart speaker, physical | A 2017 MWR InfoSecurity attack booted attacker code on a 2015 or 2016 Amazon Echo through its debug pads and streamed its microphone to a remote host; physical access was required, and later hardware was not vulnerable [3] |
| Smart speaker, self-issued | Alexa versus Alexa, 2022 (CVE-2022-25809, NVD CVSS 3.1 9.8): a 3rd- or 4th-generation Echo Dot acted on commands played through its own speaker, via a malicious skill or a Bluetooth device [4] [5] |
| Thread border router | CVE-2026-8369: improper input validation in OpenThread's NAT64 translator let an attacker on the adjacent IPv4 network inject corrupted IPv6 packets into the Thread mesh (OpenThread before commit 26a882d) [6] |
| Core property | Each device is always on and adds a microphone, a radio or a bridging role the owner cannot easily inspect, which is the attack surface these cases exploit (**Inferred**) |

## Scope and method

This is a reference study of a group of always-on home devices, read across the public record from 2017 to 2026. It is written for a typical home network, where these devices sit alongside the router and gateway of the earlier studies. It describes the product families as the public record describes them; it names a vendor or model only where a cited source names one, gives no detail that did not come from a cited public source, ties nothing to any household, and tested no device. It is a defensive study: it explains each weakness well enough to show why it worked, then what a reader can check and decide, and it reproduces no attack recipe and no exploit code.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: the researcher's own write-up, the vendor advisory, or the CVE and NVD record |
| Reported | Known through journalism or a secondary summary |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

The primaries are Cisco Talos's report and the NVD records for the mesh Wi-Fi flaws [1] [2]; MWR InfoSecurity's write-up for the Echo hardware attack [3]; the Alexa versus Alexa researchers' material and the NVD record for the self-issued-command flaw [4] [5]; and the NVD record for the Thread border-router flaw [6]. Where a CVE carries scores from more than one source, this study says which score is the NVD's and which is a vendor's or coordinator's.

## Part 1: What these devices are, and the surface they add

The earlier studies in this series were about devices at the edge of the home: the router, the casting receiver, the ISP's gateway. The devices here sit inside the home and multiply, and three properties set them apart.

**They are always on, and several of them listen.** A smart speaker or display keeps a microphone active to hear a wake word; a mesh system and a border router run continuously to keep the network up. An always-on device is one an attacker can reach at any time, and a microphone is a sensor whose compromise is more serious than a lost configuration (**Inferred**).

**They add radios and nodes.** A mesh Wi-Fi system is not one device but several, a router and one or more satellites, each a full networked computer. A Thread border router adds a second radio network, the low-power Thread mesh, and joins it to the home's internet connection. Each node and each radio is another place to attack, and Part 2 shows a mesh whose satellite was a way in alongside its router [1] (**Confirmed**).

**They bridge, and they tie to the cloud.** A border router exists to pass traffic between the Thread mesh and the internet protocol network, which is a bridging role; CVE-2026-8369 is a flaw in exactly that translation step [6] (**Confirmed**). A smart speaker is tied to a cloud account and runs third-party add-ons, which Part 4 shows can be a path back to the device. These are not faults in themselves, but they are the structure the cases exploit.

The through-line of the series continues, with a change of emphasis (**Inferred**). The gateway study turned on a device the subscriber did not control. These devices the household does own and control, but they are hard to inspect, they are always on, and they carry sensors and bridges that a plain router does not, so the owner's security problem is less about who holds the keys and more about a larger, always-present surface.

## Part 2: The mesh Wi-Fi system, Netgear Orbi

A mesh Wi-Fi system replaced the single home router with a set of cooperating nodes, and in doing so it multiplied the device that had to be secured.

In a report published on 21 March 2023, Cisco Talos described four vulnerabilities its researchers found in the Netgear Orbi mesh system, testing the RBR750 router and RBS750 satellite on firmware 4.6.8.5 [1] (**Confirmed**). The most serious for this study is CVE-2022-37337, which the NVD records as "A command execution vulnerability exists in the access control functionality of Netgear Orbi Router RBR750 4.6.8.5", reached by a specially crafted HTTP request [2] (**Confirmed**). It is not an unauthenticated flaw: Talos states plainly that "The user needs to authenticate into the mesh system first", and then the crafted request runs commands on the device [1] (**Confirmed**). The score depends on who assigned it, which is worth keeping straight: the NVD gives CVE-2022-37337 a CVSS 3.1 base score of 8.8 (High) as its own primary score, while Cisco, as the assigning authority, rates it 9.1 [2] (**Confirmed**). It is classed as OS command injection (CWE-78) by Cisco; the NVD assigned no weakness of its own [2] (**Confirmed**).

The other three show the shape of a mesh attack surface. Talos lists a command-execution flaw in the main router reached by a crafted network request (CVE-2022-38452), another command execution through a crafted JSON object (CVE-2022-36429), and a man-in-the-middle flaw in the Web Services Management tool that discloses sensitive information (CVE-2022-38458) [1] (**Confirmed**). The router and the satellite are both in the list, which is the point: a mesh system is several computers, and each is a target.

The fix is the owner's to apply, and it was incomplete at disclosure. Talos worked with Netgear, and updates were available for three of the four flaws; for the fourth, the main-router command execution it tracks as TALOS-2022-1595, Talos wrote that "the company is still developing a patch for TALOS-2022-1595", so that one was unpatched when the advisories went out under Talos's 90-day timeline [1] (**Confirmed**). A mesh Wi-Fi system is firmware like any other, and it is only as current as its owner, or its automatic-update setting, keeps it.

## Part 3: The smart speaker as a listening device, the Echo hardware attack

A smart speaker's defining feature is a microphone that is always on to hear a wake word. The 2017 work on the Amazon Echo showed what that microphone becomes if an attacker can reach the hardware.

Researchers at MWR InfoSecurity, in a write-up published on 1 August 2017, described a physical attack on the Amazon Echo. It required physical access to the device: removing the rubber base of the unit exposes a set of debug pads, and through them the device can be made to boot the attacker's own software rather than its normal firmware [3] (**Confirmed**). From there the researchers could, in their words, "gain a root shell on the underlying Linux operating system", install software that persisted on the device, and stream the raw feed from the always-listening microphone to a remote host, while, they noted, the attack "does not affect the functionality of the Amazon Echo", so the owner would see nothing wrong [3] (**Confirmed**). This study describes the result, not the boot procedure, and reproduces no steps.

Two things keep this in proportion. First, it needed hands on the device, which is a high bar for most homes but not for a shared or public setting, which is why the researchers raised the example of a device in a hotel room [3] (**Confirmed**). Second, it was fixed in hardware: the researchers confirmed the flaw on the 2015 and 2016 editions of the Echo and state that "the 2017 edition is not vulnerable to this physical attack", because Amazon changed the board so an external card could no longer drive the boot [3] (**Confirmed**). The durable point is the one about the sensor: a device built around an always-on microphone is, if its code is ever replaced, a ready-made listening device, which is why the physical mute control these devices carry matters (**Inferred** from the write-up [3]).

## Part 4: Turning the speaker against itself, Alexa versus Alexa

The Echo attack needed physical access. The 2022 Alexa versus Alexa work showed a different route, one that used the speaker's own output against it.

Researchers Sergio Esposito and Daniele Sgandurra, then at Royal Holloway, University of London, with Giampaolo Bella of the University of Catania, described an attack they summarise as "using the device speaker to issue commands to the device itself": if an Echo can be made to play audio that contains the wake word and a command, the device hears and obeys it [4] (**Confirmed**). They showed two ways to make the device play such audio: a malicious voice add-on (a skill), and a paired Bluetooth device. The NVD records the issue as CVE-2022-25809, "Improper Neutralization of audio output from 3rd and 4th Generation Amazon Echo Dot devices", and scores it CVSS 3.1 9.8 (Critical) as its own primary score [5] (**Confirmed**). It is worth noting that this high score treats the flaw as network-reachable, while the demonstrated routes needed either a malicious skill the user had enabled or a Bluetooth device within range, which the study flags rather than resolves (**Inferred** from the record and the researchers' account [4] [5]).

The disclosure and fix are on the researchers' record. They reported the issue to Amazon in January 2021, Amazon rated it medium in April 2021, and the CVE was entered in February 2022 [4] (**Confirmed**). Amazon fixed the route that let a skill wake the device remotely, but the researchers state that "It is still possible to self-issue commands via Bluetooth", so the Bluetooth route remained at the time of writing [4] (**Confirmed**). They also say they are "not aware of the vulnerability being exploited in the wild" [4] (**Confirmed**). Their advice to owners is the kind this series keeps returning to: mute the microphone when away, enable the audible wake-word indicator, check the assistant's command history for commands no one issued, and set a voice code for sensitive actions [4] (**Confirmed**).

## Part 5: The Thread border router, the newest role

The last case is about the newest device here, and the one whose public record is still thin: the Thread border router.

Thread is a low-power wireless mesh for smart-home devices, separate from Wi-Fi, and a Thread border router is the device that joins that mesh to the home's internet-protocol network so the two can exchange traffic. OpenThread is a common open-source implementation of the Thread stack. The bridging step is where a 2026 flaw sits: the NVD record for CVE-2026-8369 describes "Improper Input Validation in the NAT64 translator in The OpenThread Authors OpenThread before commit 26a882d", by which an attacker on the adjacent IPv4 network can inject corrupted IPv6 packets into the Thread mesh or bypass security checks with crafted packets [6] (**Confirmed**). NAT64 is the translation between the IPv6 the Thread mesh uses and the IPv4 of the wider network, so this is a flaw in the border router's core job of bridging the two.

The scoring here is a good example of why the source of a score matters. CVE-2026-8369 carries only a CVSS 4.0 base score of 6.0 (Medium), and that score is from the assigning authority, Google, not from the NVD, which had not scored the record as of this writing [6] (**Confirmed**). The fix is a specific commit in the OpenThread source, which reaches a home device only when the device maker ships a firmware build that includes it, the same vendor-dependent path the gateway study described [6] (**Inferred**). The wider point is that the Thread border router adds a second network and a bridge between it and the home, and that bridge, like any, is an attack surface; the public vulnerability record for it is young, which is a reason to watch it rather than to assume it is safe (**Inferred**).

## Part 6: What is fixed, what is design, what is a setting

The record sorts into three piles, and keeping them apart is the point of the study.

- **Fixed, by a patch with a version, that the owner applies.** Netgear shipped updates for three of the four Orbi flaws, leaving one in development at disclosure [1] (**Confirmed**). The Echo hardware attack was closed by a board change in the 2017 edition, so it is fixed for anyone on newer hardware [3] (**Confirmed**). The OpenThread flaw has a fix commit, which reaches a device through its maker's firmware [6] (**Confirmed** for the commit; **Inferred** for the delivery path). The constant is that a mesh node, a speaker or a border router is firmware, and an un-updated one stays where it was.
- **Design, which no patch removes.** A smart speaker's microphone is always on by design, so replaced code turns it into a listening device, as Part 3 showed; a mesh system is several computers, so it has several attack surfaces, as Part 2 showed; a border router bridges two networks, so the bridge is exposed, as Part 5 showed. None of these is a bug, and none is removed by a patch. What the owner holds against them is the physical control (a mute switch), the choice of how many such devices to run, and where on the network to place them.
- **Up to the owner.** Keeping firmware current, or leaving automatic updates on where the device offers them, is the owner's lever on the first pile. Using the mute control and the wake-word indicator, and checking the command history, are the owner's levers on an always-on microphone, which the Alexa versus Alexa researchers set out directly [4] (**Confirmed**). And deciding how many always-on devices to admit, and whether to place them where they can reach the rest of the household, is a choice only the owner can make.

The trade-off is the familiar one, and it belongs in the decision. These devices exist for convenience, coverage and voice control, and the mute switch, the extra network segment or the decision not to add a device each costs some of that convenience. This study describes the controls and their effect and does not tell anyone which way to set them (**Inferred**).

## Part 7: Check your own devices

These checks are read-only. They look at the current state of a device and change nothing, and none of them was run for this study. Deciding whether to update, mute, segment or remove a device comes after, and is the owner's decision.

1. **Inventory the always-on devices and their firmware.** Read, from each device's app or administration page, what it is and which firmware version it runs, and whether automatic updates are on. Because every fix in this study reaches a device as firmware, a device's exposure depends on whether it is current (**Inferred** from the dated fixes [1] [3] [6]).
2. **For a mesh system, account for every node.** A mesh is a router and one or more satellites, each its own computer; the Orbi flaws were across both [1] (**Confirmed**). Read the firmware of each node, not only the main one.
3. **Read the physical and privacy controls on a smart speaker or display.** These devices carry a hardware microphone mute and, on many, a camera shutter; read whether they are available and used, and whether the audible wake-word indicator is on. The Alexa versus Alexa researchers recommend the mute and the indicator, and checking the command history for entries no one issued [4] (**Confirmed**).
4. **Note what bridges to what.** A Thread border router joins the Thread mesh to the home network, and a mesh or smart-home hub may reach the rest of the household; read which devices bridge networks, so you know where a compromise could spread. This is a read of the network's shape, not a change to it (**Inferred** from the bridging role in Part 5 [6]).

What these readings tell you maps onto Part 6: whether firmware is current, how many always-on surfaces are present, whether the microphone controls are in use, and where the bridges are. None of it requires touching another person's device or sending anything other than ordinary requests to your own equipment.

## MITRE ATT&CK mappings

This Part binds the behaviours in the record to MITRE ATT&CK v20.0. No source names ATT&CK identifiers; each row is this study's own mapping, checked against the library's technique data (**Inferred**; names and tactics **Demonstrated** from `data/attack/technique_profiles.jsonl` [7]). The devices are not actors, so no group, software or campaign is bound. ATT&CK is an imperfect lens for consumer, physical and voice-assistant issues, so the table is deliberately small and the fit notes say what is left unmapped.

| ID | Name | Tie to this record |
|---|---|---|
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | The Orbi command-execution flaws reached over the mesh system's network service [1] [2] |
| [`T1557`](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | The Orbi Web Services Management flaw that discloses information through a man-in-the-middle position (CVE-2022-38458) [1] |

Fit notes (**Inferred**): T1190 fits exploiting a network-facing service on the device to run commands, which is the Orbi command-execution flaws. T1557 fits the Orbi man-in-the-middle disclosure. The physical Echo hardware attack, the Alexa versus Alexa self-issued-command abuse, and the Thread packet-injection flaw are not mapped here, because no ATT&CK technique fits them cleanly and this study maps only what a source supports.

## Cross-cutting themes

- **Always-on is always reachable.** A device that listens or routes around the clock is one an attacker can reach at any time, and a microphone is a sensor whose compromise matters more than a setting's; the Echo work is that lesson in hardware [3] (**Confirmed**).
- **More nodes, more surface.** A mesh is several computers, not one, so securing it means securing each; the Orbi flaws were across router and satellite [1] (**Confirmed**).
- **A bridge is an attack surface.** A Thread border router exists to join two networks, and the join is where a flaw like the NAT64 one sits [6] (**Confirmed**).
- **The owner's levers are updates, physical controls and placement.** Where the gateway study's owner could mostly only add a router in front, here the owner holds firmware updates, a mute switch and a wake-word indicator, and the choice of how many always-on devices to run. Read before you change: every defensive step here starts by reading the current state, and the change is the owner's to make (**Inferred**).

## Sources

All sources were opened on 25 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Cisco Talos (Christopher McBee and Dave McDaniel), "Vulnerability Spotlight: Netgear Orbi router vulnerable to arbitrary command execution", 21 March 2023, with advisories TALOS-2022-1595 to 1598, for the four Orbi flaws across router and satellite, the authentication requirement, the firmware tested, and the still-developing patch for one flaw | [blog.talosintelligence.com/vulnerability-spotlight-netgear-orbi-router-vulnerable-to-arbitrary-command-execution](https://blog.talosintelligence.com/vulnerability-spotlight-netgear-orbi-router-vulnerable-to-arbitrary-command-execution/) | 2026-11-25 | Confirmed |
| 2 | NVD, CVE-2022-37337 (NVD CVSS 3.1 8.8 primary; Cisco 9.1; CWE-78 from Cisco) and CVE-2022-38452, with CVE-2022-36429 and CVE-2022-38458 named in the Talos report, for the descriptions and the per-source scores | [nvd.nist.gov/vuln/detail/CVE-2022-37337](https://nvd.nist.gov/vuln/detail/CVE-2022-37337) | 2026-11-25 | Confirmed |
| 3 | MWR InfoSecurity, "Alexa, are you listening?", 1 August 2017 (write-up hosted by Reversec), for the physical debug-pad attack on the 2015 and 2016 Amazon Echo, the root shell and microphone streaming, the note that function is unaffected, the hotel-room example, and the 2017 edition not being vulnerable | [labs.reversec.com/posts/2017/08/alexa-are-you-listening](https://labs.reversec.com/posts/2017/08/alexa-are-you-listening) | 2026-11-25 | Confirmed |
| 4 | Sergio Esposito, Daniele Sgandurra and Giampaolo Bella, "Alexa versus Alexa" (ACM AsiaCCS 2022; project site ava-attack.org), for the self-issued-command definition, the skill and Bluetooth routes, the disclosure timeline, the fixed skill route and remaining Bluetooth route, the not-in-the-wild note, and the owner mitigations | [ava-attack.org](https://www.ava-attack.org/) | 2026-11-25 | Confirmed |
| 5 | NVD, CVE-2022-25809 (Alexa versus Alexa), for the description naming 3rd- and 4th-generation Amazon Echo Dot devices and the CVSS 3.1 9.8 primary score | [nvd.nist.gov/vuln/detail/CVE-2022-25809](https://nvd.nist.gov/vuln/detail/CVE-2022-25809) | 2026-11-25 | Confirmed |
| 6 | NVD, CVE-2026-8369 (OpenThread NAT64 translator), for the improper-input-validation description, the adjacent-IPv4-network packet injection into the Thread mesh, the OpenThread-before-commit-26a882d fix, and the CVSS 4.0 6.0 score assigned by Google rather than the NVD | [nvd.nist.gov/vuln/detail/CVE-2026-8369](https://nvd.nist.gov/vuln/detail/CVE-2026-8369) | 2026-11-25 | Confirmed |
| 7 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl` (ATT&CK v20.0), for the technique names and tactics in the mappings | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-25 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

## Related references

- [UPnP on the Home Network](/case-studies/UPNP_HOME_NETWORK.md), [Casting on the Home Network](/case-studies/CASTING_HOME_NETWORK.md), [The ISP-Supplied Gateway](/case-studies/ISP_GATEWAY_HOME_NETWORK.md)
- [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)
- [All case studies](/case-studies/README.md)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
