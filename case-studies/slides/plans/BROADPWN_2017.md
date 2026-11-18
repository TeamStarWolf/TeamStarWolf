# Slide plan: Broadpwn 2017: The Wi-Fi Chip as a Security Boundary

- Study: case-studies/BROADPWN_2017.md
- Cover title: Broadpwn 2017 / A Chip Is a Boundary / Not a Full Takeover
- Subtitle: Broadpwn reached the Broadcom Wi-Fi chip over the air, but kernel execution stayed out of scope; fixed upstream is not fixed on every device.
- Published: 18 November 2026
- Notes: The cover sets the frame: a reachable component boundary, not a proven whole-device takeover.

## EXECUTIVE SUMMARY | A component foothold is not whole-device compromise

- Broadpwn, associated with CVE-2017-9417, is about compromising a component versus proving the whole device fell.
- Artenstein's 2017 Exodus research reached the Broadcom BCM43xx Wi-Fi chip and described a propagation capability.
- A later scope statement set main-kernel execution outside the work, so the demonstrated capability stays bounded.
- No victim census, attacker identity, loss total or confirmed enterprise breach is established by this record.
Caption: Evidence grade: Confirmed disclosure; no incident attributed.
Notes: Executive-assessment framing from [1] and [2]; no exploit code run and no live radio testing.

## KEY FACTS | One CVE, two suppliers, one bounded demonstration

Stat: 2017-9417 | CVE assigned to Broadpwn
Stat: Jul 5 | Android bulletin, 2017
Stat: Jul 19 | iOS 10.3.3 and watchOS release
Stat: 47 | Deck page setting kernel out of scope
- Google placed CVE-2017-9417 in the Broadcom section of the complete 2017-07-05 patch level, rated critical remote code execution.
- The Android bulletin's dated statement reported no active customer exploitation of the newly reported issues.
- Apple records iOS 10.3.3 and watchOS 3.2.3 on 19 July 2017, describing code execution on the Wi-Fi chip within range.
Caption: Evidence grade: Confirmed, dated advisories.
Notes: Patch-level and exploitation statement from [3]; Apple scope from [4] and [7]; deck page 47 from [2].

## PART 1 | Vulnerability, exploit and incident are three claims

- A vulnerability is a potential failure; an exploit demonstration is a method that worked under stated conditions.
- An incident is actual use against a target; a reachable component, possible onward movement and a proven chain differ.
- These three evidentiary objects can coexist without contradiction only when each one's scope is stated.
- A slide title or marketing summary cannot replace the evidence needed for the final boundary-crossing step.
Caption: Evidence grade: Confirmed definitions; no exploitation in the wild claimed.
Notes: Evidence-level discipline from [1] and [2]; the three-object framing is original analysis.

## PART 1 | What the Black Hat deck does and does not establish

- The 48-page Black Hat deck's final technical slide, page 47, says the project does not run code in the main kernel.
- It points to separate Project Zero host-memory work and a route that would need an additional browser exploit chain.
- The blog's broad introduction is later narrowed: kernel execution deserves separate research, outside current scope.
- So this case does not present a verified universal takeover of both Android and iOS application processors.
Caption: Evidence grade: Demonstrated component reach; kernel execution out of scope.
Notes: Page 47 and the separate route from [2]; the scope narrowing from [1].

## PART 2 | Draw two boundaries, not one, around the chip

- FullMAC designs place substantial wireless protocol processing on a separate system-on-chip, adding a software environment.
- Model the problem as two boundaries: radio-origin input to the chip, and the chip to the main operating system.
- Review should ask what each boundary validates, what privileges cross it, and what proves the restriction holds.
- Strong application isolation can coexist with a weak peripheral; the question is the exact transition examined.
Caption: Evidence grade: Inferred model built on Confirmed architecture.
Notes: FullMAC and Nexus 6P context from [5]; the two-boundary model is original analysis.

## PART 2 | Related research is context, not borrowed proof

- Project Zero's two April 2017 articles examined host communication and hardware isolation on tested devices.
- They raised concerns about memory access from the Wi-Fi component on a Nexus 6P and a Galaxy S7 Edge.
- This context explains why a peripheral foothold deserves attention; it does not prove every device shares the path.
- A record supporting an architectural possibility belongs beside the claim it supports, not an unrelated incident count.
Caption: Evidence grade: Reported findings used as context, not proof.
Notes: Host-isolation findings and tested platforms from [5] and [6]; research streams kept separate.

## PART 2 | A length checked against the wrong assumption

- The flaw sits in WMM information-element handling during association, where WMM carries traffic-priority data.
- The parser copied an externally supplied length into a smaller fixed allocation without checking destination capacity.
- A length can be legal in a protocol field and still exceed the memory a particular implementation reserved.
- A fix must safely handle inconsistent input; asking users not to click links does not address the parser contract.
Caption: Evidence grade: Reported root cause; an interpretation, not a new code audit.
Notes: WMM allocation failure and tested Galaxy S5 and S7 platforms from [1]; no exploit steps reproduced.

## PART 2 | The diagram cannot supply the missing fourth link

- The architecture material shows separate RAM and ROM, an ARM Cortex-R4, a D11 component and PCIe and SDIO host interfaces.
- The mitigation slide reports no DEP, ASLR or writable-executable memory in the examined chip environment.
- These are historical observations about one researched component, not claims that modern phones lack OS hardening.
- The chain's fourth link, an identified host effect, cannot be supplied by drawing an arrow on a diagram.
Caption: Evidence grade: Confirmed component observations; the chain model is analysis.
Notes: Chip internals and absent mitigations from [2]; the four-link evidence chain is original analysis.

## PART 2 | Supplier scope: fixed upstream is not deployed

Keep supplier applicability separate from device-level deployment; each record carries its own limit.

| Record | Confirms | Does not establish |
|---|---|---|
| Android July 5 level | Correction available | Every device updated |
| iOS 10.3.3 | iPhone, iPad, iPod scope | Watch or non-Apple scope |
| watchOS 3.2.3 | Apple Watch models covered | Every Apple product affected |
| Project Zero work | Architectural possibility | Broadpwn end-to-end proof |
Caption: Evidence grade: Confirmed advisories; non-claims kept explicit.
Notes: Android level from [3], iOS from [4], watchOS from [7], Project Zero scope from [5] and [6].

## DEFENDER VIEW | Verify the remedy without a dangerous demonstration

- Verify the product remedy without requiring a dangerous production demonstration of the flaw.
- Connect the affected implementation, the supplier remedy, the delivered build and evidence the remedy is active.
- A connectivity fault alone cannot establish exploitation; an update record alone cannot establish no prior compromise.
- Hold any Wi-Fi dependency as a supported update path or a time-limited exception with a named owner.
Caption: Evidence grade: Inferred defensive guidance from the sources.
Notes: Closure model and decision rules from [1], [3] and [7]; distinct investigations kept distinct.

## FICTIONAL EXERCISE | Alder Mobile Survey turns claims into tasks

- Alder Mobile Survey is a fictional fleet of field phones, loan tablets and a small pool of specialist devices.
- An executive draft claiming complete takeover is corrected without removing the need for remediation.
- A supplier citing related research must still provide product-build applicability evidence, not a paper.
- An intermittent-connectivity report opens an evidence-based inquiry without premature attribution.
Caption: Evidence grade: Fictional exercise; no incident evidence added.
Notes: Exercise setup and injects from the study's sections 10 and 11; no real organization is represented.

## CROSS-CUTTING THEMES | What the record overstates versus understates

Left: Easy to overstate
- A component foothold read as universal device takeover.
- A patch announcement read as every device corrected.
- Related research treated as Broadpwn's missing end-to-end proof.
Right: Easy to understate
- A radio-reachable chip defect needing no user interaction is a real boundary.
- Supplier scope reached beyond phones to Apple Watch models.
- Fixed upstream and deployed to devices are different states.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated contrasts drawn across [1] through [7].

## CLOSE | Which processor, and what proves the next crossing

- Broadpwn forces a precise question: which processor was compromised, and what proves the next boundary crossing?
- Follow the actual processing path, not product labels, user permissions or update announcements.
- Separate availability of a fix from active correction on the real device, and demonstration from incident.
- Keep related work separate and let each source's specific scope constrain its broadest language.
Caption: Evidence grade: a conclusion synthesis.
Notes: Conclusion synthesis across the study; rests on [1] through [7].
