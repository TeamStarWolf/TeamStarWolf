# Structured Cabling and Physical Layer Reference

> OSI Layer 1 in the data center and the building: the copper and fiber that carry every link, the plant that organizes it, and the physical-layer attack surface it creates.

The logical network has no meaning until something carries the bits. This page covers the physical medium and the plant around it: the copper and fiber cable types, the connectors and transceivers that terminate them, the patch panels and pathways that route them, the standards that govern them, and the security exposure of a layer an attacker can reach with their hands. It is the companion to the [Data Center Infrastructure Reference](DATA_CENTER_INFRASTRUCTURE_REFERENCE.md), which covers the facility, racks, power, and cooling. Standards are named with their current edition and linked in [Sources](#sources); the paid standards are named for where a requirement is defined, not quoted, and engineering conventions that no single standard mandates are marked as common practice.

Related: [Data Center Infrastructure Reference](DATA_CENTER_INFRASTRUCTURE_REFERENCE.md), [Networking Fundamentals](NETWORKING_FUNDAMENTALS.md), [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md), [Physical Security Reference](PHYSICAL_SECURITY_REFERENCE.md), [Network Protocols Reference](NETWORK_PROTOCOLS_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network, cabling, and data-center engineers, and the physical-security readers who assess Layer 1

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 7 min (1,621 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are specifying or terminating copper and fiber in a data center or building, you are choosing a cable category, fiber class, or connector for a link, or you are assessing the physical-layer attack surface and how to detect a tap

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Copper](#copper), [Fiber](#fiber), [The security view](#the-security-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Data Center Infrastructure Reference](DATA_CENTER_INFRASTRUCTURE_REFERENCE.md), [Networking Fundamentals](NETWORKING_FUNDAMENTALS.md), [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md), [Physical Security Reference](PHYSICAL_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What this covers

Structured cabling is a planned, standardized cabling system rather than point-to-point runs: a hierarchy of backbone and horizontal cabling, terminated on patch panels and cross-connects, documented and labeled so any link can be traced and changed. This page walks the copper and fiber media, the components that terminate and extend them, the plant that administers them, and the security view of the physical layer. The active electronics that light the cable (switches, routers, NICs) belong to the logical-network references; this page stops at the transceiver.

## Standards and who publishes them

Three bodies set most of what follows, and their documents are the authority for any specific figure a reader needs:

- The **Telecommunications Industry Association (TIA)** publishes the **ANSI/TIA-568** set, described by TIA as covering cabling and components for "balanced twisted-pair, optical fiber, and coaxial cabling." Within the set, the balanced twisted-pair standard is now **ANSI/TIA-568.2-E** (published 5 November 2024, revising 568.2-D), and the optical fiber cabling standard is **ANSI/TIA-568.3-D**. TIA also publishes **ANSI/TIA-569** for "telecommunications pathways and spaces, including equipment rooms" and **ANSI/TIA-606** for "administration of telecommunications infrastructure, including labeling."
- The international counterpart is **ISO/IEC 11801** (Generic cabling for customer premises); Part 1, ISO/IEC 11801-1:2017, sets the general requirements, and the series defines the cabling classes and component categories used worldwide.
- The **IEEE** defines Ethernet over these media in the **IEEE 802.3** family, including Power over Ethernet; **IEEE 802.3bt-2018** adds, in IEEE's words, "Power over Ethernet over 4 pairs."

The cable categories, fiber classes, connector interfaces, and distance limits below are specified in these documents. Their full texts are paid and are not quoted here; the standard is named so a reader can go to the clause.

## Copper

Balanced twisted-pair copper remains the common medium for horizontal runs to a workstation, access point, or server management port. ANSI/TIA-568.2-E and ISO/IEC 11801 specify the performance **categories** (in TIA terms Category 5e, 6, 6A, and 8; ISO/IEC uses matching cabling classes), which differ in the bandwidth and data rate they support. As a long-standing structured-cabling convention, a horizontal copper channel is engineered to about 100 metres end to end; the higher categories trade distance for bandwidth at the top data rates, which is why a category is chosen against the rate and reach a link needs rather than taken as "the newest." Shielding (unshielded versus foil- or braid-shielded constructions) is selected for the electromagnetic environment.

**Power over Ethernet (PoE)** carries DC power to a device over the same twisted pairs that carry its data, which is how IP phones, cameras, access points, and sensors are powered from the switch. It is standardized in IEEE 802.3, where successive amendments (802.3af, 802.3at, and 802.3bt) raised the power available; 802.3bt-2018 delivers power over all four pairs at the higher tiers. PoE's power budget and heat are a design input for high-density cabling bundles.

## Fiber

Optical fiber carries the backbone, the high-rate links, and any run that is too long or too electrically hostile for copper. The two families are **single-mode** and **multimode**, and ISO/IEC 11801 and ANSI/TIA-568.3-D define the classes:

- **Multimode** fiber (the ISO/IEC OM classes, commonly OM3, OM4, and OM5, each a laser-optimized grade) carries shorter, lower-cost links inside and between buildings. The higher OM grades support higher rates over a given distance.
- **Single-mode** fiber (the OS classes, OS1 and OS2) carries the longest links and the highest rates, and is the default for anything beyond the multimode reach.

Fiber is terminated with connectors whose interfaces are standardized in the IEC 61754 series; the common types in a modern data center are, as a matter of practice, the small LC duplex connector for individual links and the multi-fiber MPO/MTP connector for high-density and parallel-optics trunks, with UPC or APC end-face polishes chosen for the return-loss the link needs. Loss budgets (how much optical loss a link may have and still work) are the governing design number for a fiber run.

## Transceivers and the active link

A transceiver converts between the switch or NIC's electrical signals and the light or line signal on the medium. The common pluggable form factors (SFP and SFP+ for 1 and 10 Gigabit, SFP28, QSFP+, QSFP28, and QSFP-DD for the higher and parallel rates) are defined by multi-source agreements coordinated through the SFF (Small Form Factor) specifications rather than by a single ISO or IEEE standard, so this page treats them as common industry form factors. Direct-attach copper (DAC) and active optical cables (AOC) are fixed transceiver-plus-cable assemblies for short rack-to-rack links. The transceiver is where this physical-layer page meets the active electronics covered elsewhere.

## The cabling plant

Beyond the cable itself, structured cabling is a managed system:

- **Termination and cross-connects**: horizontal and backbone cables land on **patch panels**; a **cross-connect** (an interconnect or a true cross-connect field) is where one cabling subsystem is patched to another, and in a carrier-neutral facility the **meet-me room** is the cross-connect point between tenants and providers. Keeping the permanent cabling terminated on panels and doing all change with patch cords is what makes the plant maintainable.
- **Pathways and spaces**: cable runs in the overhead or under-floor pathways and the rooms that ANSI/TIA-569 specifies, kept physically separated from power pathways to limit interference as a matter of installation practice.
- **Administration**: ANSI/TIA-606 sets the labeling and records scheme so every cable, panel port, and outlet has an identifier and a record tying one end to the other. Good administration is what lets an operator trace a link, and it is also a security record (see below).
- **Testing and certification**: a new link is tested against the standard it is built to, which in common practice means wire-map and transmission tests for copper and insertion-loss and, for longer or suspect fiber, optical time-domain reflectometer (OTDR) traces. The acceptance results are the baseline a later anomaly is measured against.

## The security view

Layer 1 is the one layer an attacker reaches physically rather than over the network, and it carries exposures the upper layers cannot see:

- **Cable tapping.** A copper link can be tapped by contact or by induction from its electromagnetic field, and a fiber link can be tapped without cutting it: bending the fiber past its critical angle (a macrobend, created with a clip-on coupler) leaks a small amount of light that a receiver can capture. Either tap can be passive and hard to notice. The countermeasures are physical: controlled pathways and spaces, conduit or armored cable on exposed runs, and, for the highest-sensitivity links, encryption so a captured copy is useless. The attack mechanics and physical-penetration context are in the [Physical Security Reference](PHYSICAL_SECURITY_REFERENCE.md).
- **Rogue patching and unauthorized cross-connects.** Because the plant is built to be re-patched, an attacker with floor access can move a patch cord to bridge segments, mirror a port, or insert an inline device. The defense is the administration record (ANSI/TIA-606): a labeled, documented plant where every cross-connect is known makes an unauthorized one visible, and port-to-patch records plus physical access control to the room are the controls.
- **Detection and integrity.** The acceptance tests above are a baseline: an unexplained change in a fiber's insertion loss or OTDR trace, or a copper link that no longer matches its wire-map record, is a physical-integrity signal. Periodic re-verification against the as-built records turns the cabling plant from an assumed-good substrate into one that can be checked.

The physical layer is often left out of a security program because it is "just cable." Treating pathways, the cross-connect fields, and the administration record as part of the attack surface, and keeping the as-built test baseline to measure against, is what brings it in.

## Sources

Standards and publisher pages, read 2026-11-25. The full texts of the TIA, ISO/IEC, and IEEE standards are paid and were not read; they are named for where a requirement is defined, not quoted.

- Telecommunications Industry Association, ANSI/TIA-568 set (balanced twisted-pair, optical fiber, and coaxial cabling): <https://tiaonline.org/standard/tia-568/>; ANSI/TIA-568.2-E (balanced twisted-pair, published 5 November 2024) announcement: <https://tiaonline.org/standardannouncement/tia-publishes-new-standards-ansi-tia-568-2-e-and-ansi-tia-568-5-1/>
- ANSI/TIA-569 (telecommunications pathways and spaces): <https://tiaonline.org/standard/tia-569/>; ANSI/TIA-606 (administration of telecommunications infrastructure): <https://tiaonline.org/standard/tia-606/>
- ISO/IEC 11801-1:2017, Information technology - Generic cabling for customer premises - Part 1: General requirements: <https://www.iso.org/standard/66182.html>
- IEEE 802.3bt-2018, Power over Ethernet over 4 pairs (an amendment to IEEE Std 802.3): <https://standards.ieee.org/ieee/802.3bt/6749/>
- Fiber connector interfaces are standardized in the IEC 61754 series; the SFP and QSFP transceiver form factors are defined by the SFF (Small Form Factor) multi-source specifications.

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Network security](/hubs/network-security.md)
- [Data Center Infrastructure Reference](/DATA_CENTER_INFRASTRUCTURE_REFERENCE.md)
- [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md)
- [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md)
- [Physical Security Reference](/PHYSICAL_SECURITY_REFERENCE.md)

<!-- related:end -->

---

*This reference summarizes publicly documented standards and industry practice from third parties (the Telecommunications Industry Association, ISO/IEC, IEEE, and IEC) as an independent practitioner summary; it is not affiliated with or endorsed by those organizations. Standards are revised; consult the linked originals for authoritative and current content.*
