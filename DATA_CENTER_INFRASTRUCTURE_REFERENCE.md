# Data Center Infrastructure Reference

> The physical layer under every server: the racks, power, cooling, and facility systems of an enterprise data center, and the security that layer needs.

Most of this library describes software and the logical layer. This page describes the box it all runs in: the facility, the racks, and the power and cooling plant that keep an enterprise data center alive, written for the engineer who has to reason about the physical side of a system and the attack surface it carries. The wiring and cabling plant has its own page, and the lights-out management interfaces that ride on this equipment have theirs; this page is the facility and the hardware it holds.

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

About 11 min (2,439 words at 230 words a minute)

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

A data center is a controlled space whose whole purpose is to keep computing equipment powered, cooled, connected, and physically safe without interruption. Everything below is in service of one goal: the servers stay up. The infrastructure that delivers it falls into a few domains that this page walks through in turn - how the industry rates a facility, how equipment is racked, how power reaches it, how heat leaves it, how the facility is monitored, how hardware is retired, and where the security exposure sits.

Two framing points carry through. First, availability is a security property: the physical plant is where the availability leg of confidentiality, integrity, and availability is actually won or lost, so power and cooling are security controls, not just operations concerns. Second, the facility runs on its own layer of networked controllers - power distribution units, environmental sensors, building management systems - and that control layer is an attack surface in its own right.

## Facility tiers and ratings

Two separate four-level classification systems describe how resilient a data center is, and they are routinely confused. They come from different bodies, measure different things, and are not interchangeable.

The **Uptime Institute Tier Classification System** (Tier I through Tier IV, written in Roman numerals) is the older and more widely cited of the two. Uptime Institute describes the Tiers as progressive, so each Tier incorporates the requirements of the ones below it, and defines criteria for maintenance, power, cooling, and fault capability. In ascending order: Tier I is basic site capacity with a single distribution path and no redundant components; Tier II adds redundant capacity components on that single path; **Tier III is concurrently maintainable**, meaning any component or path can be taken out of service for maintenance without taking down the computing load; and **Tier IV is fault tolerant**, meaning the site can sustain an unplanned failure of a component or path and keep running. Uptime Institute is explicit that this is not a simple ranking: a Tier IV site is not automatically "better" than a Tier II, the levels fit different business needs, and Uptime Institute is the sole body that certifies a site against the standard.

The **ANSI/TIA-942 Telecommunications Infrastructure Standard for Data Centers** is a separate standard from the Telecommunications Industry Association. It defines its own four-level scale, written as **Rated-1 through Rated-4**, and covers four facets of the facility - telecommunications, architectural and structural, electrical, and mechanical - rather than power and cooling topology alone. TIA-942 conformity is certified through TIA and its accredited assessors. The practical point for a security or audit reader: an Uptime Tier and a TIA-942 Rated level are different measurements from different authorities, so a claim of "Tier 3" has to be read for which system is meant and who certified it.

Neither system should be quoted as a fixed availability percentage. Older material attaches specific uptime figures to each Tier; Uptime Institute has moved away from presenting the Tiers that way, and a resilience level is a statement about topology and maintainability, not a guaranteed number of nines.

## Racks and cabinets

Equipment mounts in standardized frames. The near-universal format is the **19-inch rack**, standardized as **EIA-310** (and internationally as **IEC 60297**), which fixes the mounting-rail spacing and the vertical increment. That increment is the **rack unit (U, or RU): one U is 1.75 inches, which is 44.45 mm**. Equipment height is quoted in U - a typical server is 1U or 2U, a blade chassis several U - and cabinets are sized in U, with 42U the common full-height enterprise cabinet and 45U to 48U also in use.

A few physical details matter for both operations and security:

- **Mounting**: modern cabinets use square-hole rails with cage nuts; rails are set to depth for the equipment. Rack ears, slide rails, and cable arms hold the gear.
- **Airflow**: servers pull cool air from the front and exhaust hot air to the rear. Cabinets are arranged so that fronts face fronts and rears face rears (the hot-aisle and cold-aisle layout below). **Blanking panels** fill empty U so hot exhaust cannot recirculate to the intakes, which is both a thermal and an efficiency control.
- **Power strips**: vertical rack power distribution units mount in the "0U" side channels so they do not consume usable U.
- **Density and loading**: power draw per rack is quoted in kilowatts and has climbed sharply with high-density and AI compute, which drives the cooling choices below. Fully loaded cabinets are heavy, so floor loading and, in raised-floor rooms, tile ratings are real constraints.

## Power

A data center takes utility power and delivers conditioned, redundant power to every device, with no interruption through faults or maintenance. The chain runs roughly: utility feed, transfer, backup generation, uninterruptible supply, distribution, and the device's own supplies.

- **Utility and transfer**: larger sites take feeds that can be backed by on-site generators. An **automatic transfer switch (ATS)** moves the load from utility to generator on a mains failure; a static transfer switch (STS) does the same between two sources fast enough for sensitive loads. Generators cover a long outage; they need time to start and stabilize, which is what the battery layer bridges.
- **Uninterruptible power supply (UPS)**: the UPS carries the load across the seconds between a utility loss and the generator coming up, and conditions the power. An **online double-conversion** UPS continuously rectifies incoming AC to DC and inverts it back, so the load is always on clean inverter power with no transfer gap when utility power drops; it is the norm for critical loads. A **line-interactive** UPS is simpler and cheaper, regulating voltage and switching to battery on loss, and suits smaller or less critical loads. Battery health and runtime are a monitored, finite resource.
- **Power distribution units (PDUs)**: distribution happens at several levels. Floor or row PDUs and remote power panels break the feed into branch circuits; rack PDUs deliver outlets inside the cabinet. Rack PDUs come as **basic** (outlets only), **metered** (whole-unit or per-outlet current metering, so a rack's draw is visible), and **switched** (per-outlet on and off control plus metering, for remote power cycling and load balancing). The metered and switched units are networked, which is where the security note below applies.
- **A/B dual-corded feeds**: resilient racks are fed by two independent power paths, the "A" and "B" sides, from separate PDUs and ideally separate upstream distribution. Dual-power-supply devices take one cord from each side, so the loss of an entire path does not drop the load. Single-corded devices need a transfer switch to get the same protection.
- **Three-phase distribution**: at the density of a modern row, power is distributed as three-phase and balanced across the phases to use the capacity efficiently.
- **Redundancy notation**: capacity is described with N notation. **N** is exactly the capacity the load needs, with no spare. **N+1** adds one redundant module (a spare UPS, generator, or cooling unit) so one unit can fail or be serviced. **2N** is two complete, independent systems, each able to carry the full load alone; **2N+1** adds a spare on top. Higher redundancy is what lets a site reach the concurrently maintainable and fault tolerant tiers above.

## Cooling and environment

Every watt of power a server draws becomes heat that has to be removed, so cooling capacity tracks power capacity. The room is a controlled thermal environment.

- **Air handling**: a **CRAC (computer room air conditioner)** is a direct-expansion unit with its own compressor; a **CRAH (computer room air handler)** uses chilled water supplied by a central plant. Both condition and move air; the choice depends on the facility's plant.
- **Hot aisle and cold aisle**: cabinets are laid out in alternating aisles so all equipment fronts (intakes) face a cold aisle and all rears (exhausts) face a hot aisle. This stops cold supply air and hot exhaust from mixing, which is the single biggest efficiency and capacity lever in air cooling.
- **Containment**: physical barriers (doors and roofs over an aisle) fully separate hot and cold air as **hot-aisle containment** or **cold-aisle containment**, raising the temperature difference the units can work across and letting the room run warmer and cheaper.
- **High-density cooling**: as per-rack kilowatts rise, air alone stops being enough. **In-row** and **rear-door** heat exchangers bring cooling next to the load; **liquid cooling**, whether **direct-to-chip** cold plates or full **immersion**, is now standard for dense AI and high-performance racks because it moves far more heat than air.
- **Environmental envelope**: temperature and humidity are held within an engineered range. **ASHRAE Technical Committee 9.9** publishes the widely used Thermal Guidelines for Data Processing Environments, which define recommended and allowable envelopes for equipment inlet conditions. Humidity is controlled to avoid both electrostatic discharge when too dry and condensation and corrosion when too damp.

## Monitoring and operations

A facility this interdependent is run from instrumentation, not by walking the floor.

- **DCIM (data center infrastructure management)** is the software layer that tracks assets and their rack positions, models power and cooling capacity, reads power and thermal telemetry, and drives change workflows. It is how an operator answers "what is in this rack, how much power and cooling is left, and what breaks if this circuit drops."
- **Environmental and power monitoring**: sensors for temperature, humidity, airflow, water or leak detection, and smoke feed alerts; branch-circuit and PDU metering feed power dashboards. **PUE (Power Usage Effectiveness)**, a metric from The Green Grid, expresses total facility energy over the energy delivered to IT equipment and is the common efficiency yardstick.
- **Grounding and bonding**: a common bonding network and proper equipment grounding protect both people and equipment and are part of the telecommunications infrastructure standards; poor bonding shows up as noise, damage, and intermittent faults.
- **Fire detection and suppression**: very early warning aspirating smoke detection samples air for the first products of combustion before flame; suppression is typically a clean agent (inert gas or a chemical agent) that puts out fire without soaking equipment, or a pre-action sprinkler system that keeps water out of the pipe until two independent triggers agree.
- **Cable pathways**: structured cabling runs in overhead ladder racks or under a raised floor, kept separate from power pathways to limit interference. The cabling plant itself, including media types, connectors, and the tapping exposure, is covered on the structured-cabling page.

## Decommissioning and the hardware lifecycle

Hardware enters and leaves the facility, and both ends carry risk. On intake, receiving inspection and asset registration put every device into the inventory or configuration management database (CMDB) with its identifiers and location, which is the baseline that later detects a device that should not be there. On exit, a device that held data cannot simply be unracked and shipped out: drives and other media must be sanitized before disposal or reuse, under a documented process with a chain of custody and, for destruction, a certificate. The authoritative method for erasing storage media is **NIST SP 800-88, Guidelines for Media Sanitization**, which defines the clear, purge, and destroy levels appropriate to the media and data sensitivity; a dedicated media-sanitization page will cover that process, and this page hands off to it at the point a device leaves the floor.

## The security view

The physical plant is in scope for security for three distinct reasons, on top of the physical-access controls (locks, badges, cameras, mantraps) covered in the [Physical Security Reference](PHYSICAL_SECURITY_REFERENCE.md).

- **Power and cooling are availability controls.** The redundancy, transfer, and monitoring above are the controls that keep a service up; a cooling failure, a battery that has silently aged out, or a single-corded device on a failed power path is an outage waiting to happen. Treating availability as an operations-only concern leaves the availability leg of security untested. Resilience testing (pulling a power path, failing a cooling unit) belongs in the same program as any other control validation.
- **The facility control layer is an attack surface.** PDUs with web and SNMP interfaces, smart UPS network cards, environmental controllers, and the building management system (BMS) that runs power and cooling are networked computers, and they are frequently left on default credentials, old firmware, and a flat network. An attacker who reaches them can cause physical impact (cut power or cooling to a row) or use them as a quiet foothold and pivot. These interfaces belong on an isolated management or facility network, not the production or corporate LAN; the out-of-band and lights-out management page covers that isolation in depth, and the building-management side overlaps the operational-technology guidance in the [ICS and OT Security Reference](ICS_OT_SECURITY_REFERENCE.md).
- **Hardware supply chain and receiving.** Tampered firmware, implanted components, and counterfeit parts are introduced before a device is ever racked. Receiving inspection, tamper-evident handling, buying from trusted and authorized suppliers, and recording provenance in the asset inventory are the countermeasures; the supply-chain and firmware-integrity angle is developed in the [Hardware Security Reference](HARDWARE_SECURITY_REFERENCE.md).

A mature program treats the data center floor as part of the attack surface, monitors the facility control layer as it would any other management plane, and validates that power and cooling redundancy actually works rather than assuming the nameplate.

## Resources

- Uptime Institute: Tier Classification System (uptimeinstitute.com/tiers) - the four-Tier topology standard and the certifying body.
- Telecommunications Industry Association: ANSI/TIA-942 Telecommunications Infrastructure Standard for Data Centers and its Rated-1 to Rated-4 certification (tiaonline.org).
- EIA-310 and IEC 60297: the 19-inch rack and rack-unit (1U = 1.75 in / 44.45 mm) dimensional standards.
- ASHRAE Technical Committee 9.9: Thermal Guidelines for Data Processing Environments (ashrae.org).
- The Green Grid: Power Usage Effectiveness (PUE) metric.
- NIST SP 800-88 Revision 1: Guidelines for Media Sanitization (csrc.nist.gov).

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Network security](/hubs/network-security.md)
- [Physical Security Reference](/PHYSICAL_SECURITY_REFERENCE.md)
- [Enterprise Infrastructure Reference](/ENTERPRISE_INFRASTRUCTURE.md)
- [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md)
- [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md)

<!-- related:end -->

---

*This reference summarizes publicly documented standards and industry practice from third parties (Uptime Institute, the Telecommunications Industry Association, EIA/IEC, ASHRAE, The Green Grid, and NIST) as an independent practitioner summary; it is not affiliated with or endorsed by those organizations. Standards are revised and certifications change; consult the linked originals for authoritative and current content.*
