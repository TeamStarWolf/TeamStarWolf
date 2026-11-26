# Data Center Infrastructure Reference

> The physical layer under every server: the racks, power, cooling, and facility systems of an enterprise data center, and the security that layer needs.

Most of this library describes software and the logical layer. This page describes the box it all runs in: the facility, the racks, and the power and cooling plant that keep an enterprise data center alive, written for the engineer who has to reason about the physical side of a system and the attack surface it carries. The wiring and cabling plant and the lights-out management interfaces that ride on this equipment are out of scope here; this page is the facility and the hardware it holds. Standards are named with their current edition and linked in [Sources](#sources); where a statement is common practice rather than a published requirement, it is marked as such.

Related: [Physical Security Reference](PHYSICAL_SECURITY_REFERENCE.md), [Enterprise Infrastructure Reference](ENTERPRISE_INFRASTRUCTURE.md), [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md), [Hardware Security Reference](HARDWARE_SECURITY_REFERENCE.md), [Cyber Resilience and BCDR Reference](CYBER_RESILIENCE_BCDR_REFERENCE.md), [ICS and OT Security Reference](ICS_OT_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Infrastructure, data-center, and security engineers who run or assess the physical layer under enterprise systems

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 12 min (2,830 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are racking or powering equipment in an enterprise data center, you are assessing a facility's resilience or its power and cooling redundancy, or you need to find the security exposure in the facility control layer

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Facility tiers and ratings](#facility-tiers-and-ratings), [Power](#power), [The security view](#the-security-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Physical Security Reference](PHYSICAL_SECURITY_REFERENCE.md), [Enterprise Infrastructure Reference](ENTERPRISE_INFRASTRUCTURE.md), [Hardware Security Reference](HARDWARE_SECURITY_REFERENCE.md), [Cyber Resilience and BCDR Reference](CYBER_RESILIENCE_BCDR_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What this covers

A data center is a controlled space whose purpose is to keep computing equipment powered, cooled, connected, and physically safe without interruption. The infrastructure that delivers it falls into a few domains that this page walks through in turn: how the industry rates a facility, how equipment is racked, how power reaches it, how heat leaves it, how the facility is monitored, how hardware is retired, and where the security exposure sits.

Two framing points carry through. First, availability is a security property, and the physical plant is where it is won or lost; power and environmental protection sit in a security control catalog, so they can be treated as controls rather than operations concerns alone (NIST SP 800-53 Rev. 5 places uninterruptible power under PE-11, fire protection under PE-13, and environmental controls under PE-14). Second, the facility runs on its own layer of networked controllers (power distribution units, environmental sensors, building management systems), and that control layer is an attack surface in its own right.

## Facility tiers and ratings

Two separate four-level classification systems describe how resilient a data center is, and they are routinely confused. They come from different bodies, use different words, and are not interchangeable.

The **Uptime Institute Tier Classification System** (Tier I through Tier IV) is, per Uptime Institute, a system it created "over 30 years ago." Uptime names the four levels **Tier I (Basic Capacity), Tier II (Redundant Capacity), Tier III (Concurrently Maintainable), and Tier IV (Fault Tolerant)**, and describes them in its own words:

- **Tier I, Basic Capacity**: dedicated site infrastructure beyond an office setting, with a UPS, dedicated cooling, and an engine generator; the site must shut down for maintenance.
- **Tier II, Redundant Capacity**: adds redundant power and cooling components such as UPS modules, chillers or pumps, and engine generators.
- **Tier III, Concurrently Maintainable**: adds a redundant delivery path for power and cooling, so it "requires no shutdowns for equipment replacement and maintenance."
- **Tier IV, Fault Tolerant**: individual equipment failures or distribution-path interruptions are "stopped short of the IT operations."

Uptime Institute says the Tiers are progressive, so each incorporates the requirements of the ones below, and that a Tier IV site is not "better" than a Tier II: the levels fit differing business operations. The Tier criteria are outcome-based; Uptime does not prescribe a specific redundancy design (an N-plus count) to reach a level. Uptime Institute is the body that certifies a site against its Tier Standard.

The **ANSI/TIA-942 Telecommunications Infrastructure Standard for Data Centers**, current edition **ANSI/TIA-942-C (April 2024)**, is a separate standard from the Telecommunications Industry Association (TIA). It defines its own four-level scale, written as **Rated-1 (Basic Site Infrastructure) through Rated-4 (Fault Tolerant Site Infrastructure)**, and TIA describes its scope as covering "the telecommunications infrastructure, the power infrastructure, the mechanical infrastructure, the architecture, the fire protection, security, and the monitoring of data centers." TIA-942 conformity is certified by TIA-licensed Certification Bodies under TIA's certification scheme. The practical point for a security or audit reader: an Uptime Tier and a TIA-942 Rated level are different measurements from different authorities, so a claim of "Tier 3" has to be read for which system is meant and who certified it. (A parallel international series, ISO/IEC 22237, published from the European EN 50600 series, defines its own availability and security classes.)

Neither system should be quoted as a fixed availability percentage. Uptime Institute states that in 2009 it removed all references to "expected downtime per year" and that its Tier Standard assigns no availability predictions to Tier levels; TIA's free materials likewise attach no percentage to a Rated level.

## Racks and cabinets

Equipment mounts in standardized frames. The common format is the **19-inch rack**, standardized by the Electronic Components Industry Association as **EIA/ECA-310-E** and internationally in the **IEC 60297-3-100** series, which fixes the mounting-rail dimensions of the 482.6 mm (19-inch) series. The vertical increment is the **rack unit (U)**, the long-standing **1.75-inch (44.45 mm)** increment attributed to the EIA-310 rack standard. Equipment height is quoted in U; in common practice a typical server is 1U or 2U, a blade chassis several U, and a full-height enterprise cabinet is 42U, with 45U to 48U also in use.

A few physical details, which are general data-center practice rather than a single published requirement, matter for both operations and security:

- **Mounting**: cabinets commonly use square-hole rails with cage nuts, set to depth for the equipment.
- **Airflow**: servers draw cool air from the front and exhaust hot air to the rear, and cabinets are arranged so fronts face fronts and rears face rears (the hot-aisle and cold-aisle layout below). Blanking panels fill empty U so hot exhaust does not recirculate to the intakes.
- **Power strips**: vertical rack power distribution units mount in the "0U" side channels so they do not consume usable U.
- **Density and loading**: power draw per rack is quoted in kilowatts. ASHRAE's technical committee documents rising device power, which drives the cooling choices below; fully loaded cabinets are heavy, so floor loading is a real constraint.

## Power

A data center takes utility power and delivers conditioned, redundant power to every device, with no interruption through faults or maintenance. The chain runs roughly: utility feed, transfer, backup generation, uninterruptible supply, distribution, and the device's own supplies.

- **Utility and transfer**: larger sites take feeds that can be backed by on-site generators (generator installation is governed by NFPA 110). In common practice an automatic transfer switch (ATS) moves the load from utility to generator on a mains failure, and a static transfer switch (STS) switches between two sources fast enough for sensitive loads. Generators cover a long outage; they need time to start and stabilize, which the battery layer bridges.
- **Uninterruptible power supply (UPS)**: the UPS maintains "continuity of load power in case of input power failure," carrying the load across the seconds between a utility loss and the generator coming up, and conditions the power. UPS topologies are classified in **IEC 62040-3:2021** (full text not read). An online double-conversion unit keeps the load on inverter power with no transfer gap and is used for critical loads; a line-interactive unit is simpler and suits smaller or less critical loads. Battery health and runtime are a monitored, finite resource.
- **Power distribution units (PDUs)**: distribution happens at several levels. Floor or row PDUs and remote power panels break the feed into branch circuits; rack PDUs deliver outlets inside the cabinet. Vendors commonly sell rack PDUs as basic (outlets only), metered (whole-unit or per-outlet current metering), and switched (per-outlet on and off control plus metering); the metered and switched units are networked, which is where the security note below applies.
- **A/B dual-corded feeds**: resilient racks are fed by two independent power paths, the "A" and "B" sides, from separate PDUs and ideally separate upstream distribution. Uptime's Tier IV requires fault-tolerant IT power, which in practice means dual power supplies, one cord to each side, so the loss of an entire path does not drop the load. Single-corded devices need a transfer switch to get the same protection.
- **Three-phase distribution**: at the density of a modern row, power is commonly distributed as three-phase and balanced across the phases to use the capacity efficiently.
- **Redundancy notation**: The Green Grid's glossary defines capacity in N notation, where "N represents the number of pieces to satisfy the normal conditions," and gives examples including "N+1, N+2, 2N, and 2(N+1)." **N** is exactly the capacity the load needs, with no spare; **N+1** adds one redundant module; **2N** is two complete, independent systems, each able to carry the full load alone; **2(N+1)** is two N+1 systems. Higher redundancy supports, but does not by itself define, the concurrently maintainable and fault tolerant outcomes above.

## Cooling and environment

Every watt of power a server draws becomes heat that has to be removed, so cooling capacity tracks power capacity. The room is a controlled thermal environment.

- **Air handling**: a CRAC (computer room air conditioner) and a CRAH (computer room air handler) are the two common room units; in general practice the CRAC is a direct-expansion unit with its own compressor and the CRAH uses chilled water from a central plant.
- **Hot aisle and cold aisle**: cabinets are laid out in alternating aisles so equipment fronts (intakes) face a cold aisle and rears (exhausts) face a hot aisle, which, in The Green Grid's words, serves "to minimize recirculation of the hot exhaust air with the cold supply air."
- **Containment**: physical barriers over an aisle separate hot and cold air as hot-aisle or cold-aisle containment, which raises the temperature difference the units can work across and lets the room run warmer; this is an established efficiency practice rather than a published requirement.
- **High-density cooling**: as per-rack kilowatts rise, air alone reaches its limits. In-row and rear-door heat exchangers bring cooling next to the load, and liquid cooling (direct-to-chip cold plates or full immersion) is increasingly used for dense AI and high-performance racks; ASHRAE's technical committee documents the emergence and expansion of liquid cooling, and TIA-942-C added an informative immersion-cooling annex.
- **Environmental envelope**: ASHRAE Technical Committee 9.9 publishes the **Thermal Guidelines for Data Processing Environments (5th edition, 2021, revised and expanded 2022)**, which defines recommended and allowable envelopes for equipment inlet conditions by equipment class (A1 to A4, and the high-density class added in the current edition); the specific temperature and humidity ranges are in that publication. Humidity is held within range, which in common practice avoids electrostatic discharge when too dry and condensation or corrosion when too damp.

## Monitoring and operations

A facility this interdependent is run from instrumentation, not by walking the floor.

- **DCIM (data center infrastructure management)** is, as a general definition, the software layer that tracks assets and their rack positions, models power and cooling capacity, reads telemetry, and drives change workflows. It is how an operator answers "what is in this rack, how much power and cooling is left, and what breaks if this circuit drops."
- **Environmental and power monitoring**: sensors for temperature, humidity, airflow, leak, and smoke feed alerts, and branch-circuit and PDU metering feed power dashboards. **PUE (Power Usage Effectiveness)**, which The Green Grid defines as "the total energy used by a data center divided by the energy used by ICT equipment in that data center," is the common efficiency yardstick and is now also standardized as ISO/IEC 30134-2.
- **Grounding and bonding**: a bonding and grounding system for telecommunications spaces is specified by **ANSI/TIA-607**; poor bonding shows up as noise, damage, and intermittent faults.
- **Fire detection and suppression**: IT-room fire protection is covered by **NFPA 75** (and NFPA 76 for telecommunications facilities), and gaseous clean-agent systems by **NFPA 2001**; clean agents suppress fire without the water damage of a wet system. Sprinkler types are defined in NFPA 13: a **pre-action** sprinkler keeps the pipe dry until a trigger fires, and the interlock type sets the trigger. Per NFPA's own explainer, a **single-interlock** pre-action system fills the pipe on operation of the detection system alone (and NFPA names computer rooms as a use), while a **double-interlock** system fills only when both the detection system and a sprinkler operate; a non-interlock system fills on either.
- **Cable pathways**: structured cabling runs in overhead ladder racks or under a raised floor, kept separate from power pathways to limit interference.

## Decommissioning and the hardware lifecycle

Hardware enters and leaves the facility, and both ends carry risk. On intake, receiving inspection and asset registration put every device into the inventory (NIST SP 800-53 Rev. 5 covers component inventory under CM-8 and controlled delivery and removal under PE-16), which is the baseline that later detects a device that should not be there. On exit, a device that held data must have its media sanitized before disposal or reuse (NIST SP 800-53 MP-6). **NIST SP 800-88 Revision 2 (September 2025)**, which supersedes Revision 1, defines the **clear, purge, and destroy** categories of sanitization and points to evolving industry standards, in particular **IEEE 2883**, for the media-specific techniques; it is a framework and policy document rather than the single source of every method. Revision 2 asks for a **certificate of sanitization for each item** that has been sanitized, whatever the method.

## The security view

The physical plant is in scope for security for three distinct reasons, on top of the physical-access controls (locks, badges, cameras, mantraps) that NIST SP 800-53 Rev. 5 places under PE-3 and that the [Physical Security Reference](PHYSICAL_SECURITY_REFERENCE.md) covers.

- **Power and cooling are availability controls.** Emergency power (PE-9, PE-11), fire protection (PE-13), and environmental controls (PE-14) are security controls, so the redundancy and monitoring above are part of the control set that keeps a service up; a cooling failure, a battery that has silently aged out, or a single-corded device on a failed power path is an outage waiting to happen. NIST SP 800-53 CP-4 calls for testing the contingency plan. Validating failover by deliberately failing a power path or a cooling unit is a sound practice but a disruptive one, so it is done under change control with the load's resilience confirmed first; it is a recommendation here, not a requirement.
- **The facility control layer is an attack surface.** PDUs with web and SNMP interfaces, smart UPS network cards, environmental controllers, and the building management system are networked computers. CISA and the Department of Energy warned in 2022 of threat actors reaching internet-connected UPS devices "often through unchanged default usernames and passwords," and advised removing their management interfaces from the internet; the same exposure applies in practice to other facility controllers. Placing these interfaces on an isolated management network rather than the production or corporate LAN follows that advice and the boundary-protection control (NIST SP 800-53 SC-7); the building-management side overlaps the operational-technology guidance in the [ICS and OT Security Reference](ICS_OT_SECURITY_REFERENCE.md).
- **Hardware supply chain and receiving.** Tampered firmware, implanted components, and counterfeit parts are introduced before a device is ever racked. NIST SP 800-53 Rev. 5 covers the countermeasures under the supply-chain-risk family: provenance (SR-4), tamper resistance and detection (SR-9), inspection of systems or components (SR-10), and component authenticity (SR-11); the firmware-integrity angle is developed in the [Hardware Security Reference](HARDWARE_SECURITY_REFERENCE.md).

Treating the data center floor as part of the attack surface, monitoring the facility control layer as any other management plane, and validating that power and cooling redundancy actually works rather than assuming the nameplate is the author's recommendation drawn from the controls above.

## Sources

Standards and publisher pages, read 2026-11-25. Full texts of the paid standards (TIA-942-C, EIA/ECA-310-E, IEC 60297-3-100, IEC 62040-3, the ASHRAE Thermal Guidelines, the NFPA codes, IEEE 2883, ISO/IEC 27001 and 22237) were not read; they are named for where a requirement is defined, not quoted from.

- Uptime Institute, Tier Classification System: <https://uptimeinstitute.com/tiers>; "Explaining Uptime Institute's Tier Classification System" (Uptime Institute Journal): <https://journal.uptimeinstitute.com/explaining-uptime-institutes-tier-classification-system/>
- Telecommunications Industry Association, ANSI/TIA-942-C (2024): data-center brochure <https://tiaonline.org/wp-content/uploads/2024/05/Data-Centers-Brochure_040124.pdf>; TIA-942 certification and scope <https://tiaonline.org/our-work/certifications/tia-942-certification/>; certifications and ratings (TIA-licensed Certification Bodies) <https://tiaonline.org/our-work/certifications/tia-942-certification/certifications-and-ratings/>
- EIA/ECA-310-E (ECIA): <https://www.ecianow.org/eia-technical-standards/>; IEC 60297-3-100: <https://webstore.iec.ch/en/publication/1283>
- IEC 62040-3:2021 (UPS classification): <https://webstore.iec.ch/en/publication/60140>
- The Green Grid glossary: redundancy (N, N+1, 2N, 2(N+1)) <https://www.thegreengrid.org/resources/glossary/R>; PUE <https://www.thegreengrid.org/resources/glossary/P>; UPS <https://www.thegreengrid.org/resources/glossary/U>; CRAC/CRAH <https://www.thegreengrid.org/resources/glossary/C>; hot aisle <https://www.thegreengrid.org/resources/glossary/H>. PUE as a standard: ISO/IEC 30134-2 <https://www.iso.org/standard/30134-2>
- ASHRAE Technical Committee 9.9, Thermal Guidelines for Data Processing Environments (5th ed., 2021/2022): <https://tc0909.ashraetcs.org>; liquid-cooling white paper <https://www.ashrae.org/file%20library/technical%20resources/bookstore/emergence-and-expansion-of-liquid-cooling-in-mainstream-data-centers_wp.pdf>
- NFPA sprinkler system types (pre-action interlocks): <https://www.nfpa.org/news-blogs-and-articles/blogs/2021/03/26/sprinkler-system-basics-types-of-sprinkler-systems>; NFPA 13 (sprinkler installation) <https://www.nfpa.org/product/nfpa-13-standard/p0013code>; NFPA 75 (IT equipment) <https://www.nfpa.org/product/nfpa-75-standard/p0075code>; NFPA 76 (telecommunications facilities) <https://www.nfpa.org/product/nfpa-76-standard/p0076code>; NFPA 2001 (clean agent) <https://www.nfpa.org/product/nfpa-2001-standard/p2001code>; NFPA 110 (emergency and standby power) <https://www.nfpa.org/product/nfpa-110-standard/p0110code>
- NIST SP 800-88 Rev. 2 (September 2025), Guidelines for Media Sanitization: <https://csrc.nist.gov/pubs/sp/800/88/r2/final>
- NIST SP 800-53 Rev. 5, Security and Privacy Controls (PE, SR, CM, MP, SC, CP families): <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>
- CISA and U.S. Department of Energy, "Mitigating Attacks Against Uninterruptible Power Supply Devices" (March 2022): <https://www.cisa.gov/news-events/alerts/2022/03/29/mitigating-attacks-against-uninterruptable-power-supply-devices>

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Network security](/hubs/network-security.md)
- [Physical Security Reference](/PHYSICAL_SECURITY_REFERENCE.md)
- [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md)
- [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md)
- [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md)

<!-- related:end -->

---

*This reference summarizes publicly documented standards and industry practice from third parties (Uptime Institute, the Telecommunications Industry Association, ECIA, IEC, ISO, ASHRAE, The Green Grid, NFPA, NIST, and CISA) as an independent practitioner summary; it is not affiliated with or endorsed by those organizations. Standards are revised and certifications change; consult the linked originals for authoritative and current content.*
