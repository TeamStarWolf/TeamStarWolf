# Slide plan: VPNFilter 2018

- Study: case-studies/VPNFILTER_2018.md
- Cover title: VPNFilter 2018 / The Network Edge / As Intrusion Platform
- Subtitle: A staged router implant reached 500,000+ edge devices; this plan keeps disruption, eradication, capability and consequence distinct.
- Published: 18 November 2026
- Notes: The cover frames VPNFilter as the canonical edge-device botnet and signals a discipline of bounded claims over a dramatic narrative.

## CONTEXT | What VPNFilter was
- Disclosed May 2018: a botnet of SOHO routers and NAS devices.
- A staged, modular, persistent implant spanning many vendors.
- Carried collection, HTTP interception and destructive potential.
- The device carrying an organization's traffic became an adversary-controlled computer.
Caption: Evidence grade: Reported
Notes: Opens on the core blind spot, that the network edge is unmanaged, rarely patched and outside endpoint detection.

## DISCLOSURE | Talos discloses, May 23 2018
Stat: 500,000+ | infected devices estimated at disclosure
Stat: 54+ | countries with victims reported
Stat: May 23 | 2018 Talos public disclosure date
- Research was unfinished; the figure is a dated estimate, not a final census.
- May 8 and May 17 rises in Ukrainian victims drove early publication.
Caption: Evidence grade: Reported
Notes: Numbers stay tagged with their date and unit so a device estimate is never read as a hard total.

## STAGING | One persistent stage, several that are not
Left: Stage 1 (persistent)
- Survives reboot, the genuinely hard part.
- Re-establishes contact if later stages are dropped.
- Reboot alone does not remove it.
Right: Later stages (nonpersistent)
- Added packet capture and credential theft.
- Hosted the ssler and dstr modules.
- Cleared by reboot, so disruption was only partial.
Caption: Evidence grade: Confirmed
Notes: The stage split is why a quick reboot could help without finishing the job.

## MODULES | ssler, dstr and the industrial sniffer
Talos's June 6 analysis described distinct module behavior with clear limits.

| Module | What the sample showed | Boundary |
|---|---|---|
| ssler | Intercept and modify HTTP, support content injection | A capability, not proven endpoint compromise |
| dstr | Destructive device-wipe functionality | Potential, not a per-victim tally |
| Packet sniffer | Logged port-502 addressing, observe not modify | Did not validate the traffic as Modbus |
Caption: Evidence grade: Demonstrated
Notes: These are analyzed component capabilities, kept separate from demonstrated downstream consequences.

## ATTRIBUTION | From Sofacy to Sandworm, kept dated
Attribution is recorded by source and period rather than flattened into one synonym list.

| Source and date | Label applied | House boundary |
|---|---|---|
| Talos, May 23 2018 | BlackEnergy code overlap noted | Overlap is not definitive attribution |
| DOJ, May 23 2018 | Sofacy Group / APT28 | Broad historical alias list, not a modern taxonomy |
| NCSC, Feb 23 2022 | Sandworm, Russian GRU GTsST | Later evidence, kept visibly dated |
Caption: Evidence grade: Reported
Notes: Russia-linked attribution is bounded to the assessing body and its date, with Cyclops Blink held as a separate case.

## DISRUPTION | The domain seizure and the sinkhole
Stat: 1 | C2 domain seized under court order
Stat: 14,000 | unique sinkhole IPs seen per day
Stat: May 23 | 2018 DOJ disruption announced
- Seizure redirected certain stage-one traffic to an FBI-controlled server.
- The daily IP figure is a sinkhole metric, not a revised global device total.
Caption: Evidence grade: Confirmed
Notes: A population-level intervention can disrupt infrastructure and produce leads without inspecting every device.

## REBOOT | Interruption is not eradication
- Rebooting removed later stages but left persistent stage 1 in place.
- The FBI framed the reboot as an interruption, not a finished recovery.
- Name the intended outcome before selecting the procedure.
- Use current vendor recovery for the exact model, not a historical button sequence.
Caption: Evidence grade: Confirmed
Notes: The lesson generalizes: evaluate an action against the state it is meant to change.

## EDGE | The device as a trust boundary
- A gateway is a managed computer with software, credentials and a recovery path.
- Detection, authority and recoverability are complementary, separate capabilities.
- A good ownership record names service, custodian, provider contact and replacement.
- An indicator without a reachable owner is a problem found, not solved.
Caption: Evidence grade: Inferred
Notes: This organizational model is deliberately broader than malware detection.

## COUNTING | An estimate is not an IP count
- A device estimate and a daily unique-IP count answer different questions.
- One device can rotate addresses; one shared address can hide many systems.
- Do not subtract one headline number from another to claim a percent cleaned.
- Show unresolved assets explicitly, each with a follow-up owner.
Caption: Evidence grade: Inferred
Notes: Honest reporting keeps the metric's unit, window and source rather than manufacturing a rate.

## CAPABILITY | Capability is not consequence
Left: What a sample can do
- ssler can intercept and modify HTTP.
- The sniffer can log industrial addressing.
- dstr can render a device unusable.
Right: What that does not prove
- Not that all encryption was defeated.
- Not that industrial commands were changed.
- Not that every downstream endpoint was compromised.
Caption: Evidence grade: Demonstrated
Notes: A four-part record runs artifact, capability, evidence of presence, then demonstrated consequence, and stops where the chain stops.

## CHRONOLOGY | Event time is not knowledge time
A report's date describes when behavior was known, not when it began.

| Date | What the record establishes | Interpretation boundary |
|---|---|---|
| May 8 and 17 2018 | Rise in Ukrainian victims observed | Observation dates, not compromise dates |
| May 23 2018 | Talos disclosure and DOJ disruption | Disclosure is not the campaign's start |
| June 6 2018 | Expanded modules and device scope | New knowledge, not a capability born that day |
| Feb 23 2022 | NCSC attribution and successor context | Retrospective evidence stays dated |
Caption: Evidence grade: Confirmed
Notes: Merging event time and knowledge time creates false precision and distorts dwell-time estimates.

## MATRIX | Separate criteria for completion
An original response design, not a reconstruction of any affected organization.

| Workstream | Evidence of completion | What does not suffice |
|---|---|---|
| Asset ownership | Device mapped to service, custodian and location | A current IP address alone |
| Device recovery | Supported procedure completed, configuration reviewed | Internet connectivity restored |
| Account protection | Relevant identities assessed, decisions recorded | An unexplained blanket password reset |
| Closure | Residual risk accepted by an accountable owner | No new alerts for an arbitrary period |
Caption: Evidence grade: Inferred
Notes: Explicit handoffs stop one team's completion from erasing another team's outstanding obligation.

## LESSON | Build a better recovery system
- Preserve dates and units; separate potential from observed impact.
- Keep later attribution visibly distinct from initial assessment.
- Invest in identifiable devices, reachable owners and supported procedures.
- Closure is explicit residual-risk acceptance, not merely an absent alert.
Caption: Evidence grade: Inferred
Notes: These capabilities stay useful when the next incident has a different name, operator and mechanism.
