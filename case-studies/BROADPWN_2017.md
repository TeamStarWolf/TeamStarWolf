# Broadpwn: The Wi-Fi Chip as a Security Boundary

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Wireless Security Reference](/WIRELESS_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Mobile, wireless and firmware security owners, vulnerability-management leads and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 12 min (2,793 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a shorter, evidence-bounded account of Broadpwn, you need to separate a separate Wi-Fi processor from the application processor or related research from borrowed proof, or you are reasoning about chip-level security boundaries

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. What the presentation does and does not establish](#_3-what-the-presentation-does-and-does-not-establish), [8. Supplier scope extended beyond phones](#_8-supplier-scope-extended-beyond-phones)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Wireless Security Reference](/WIRELESS_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

Historical vulnerability study. Historical evidence, original defensive analysis, and a fictional exercise. No exploit instructions or live radio testing.

## Executive assessment

Broadpwn, associated with CVE-2017-9417, is a useful case study in the difference between compromising a component and proving compromise of an entire device. Nitay Artenstein's July 2017 Exodus Intelligence publication investigated Broadcom BCM43xx Wi-Fi chipsets and described a research propagation capability. Its introduction used broad main-processor execution language, but a later scope statement explicitly set kernel execution outside the current research. The accompanying conference presentation made that limitation particularly clear. [1][2]

That distinction does not make the finding unimportant. It changes how a responsible researcher should describe the result. A chip that processes externally supplied input can represent a serious security boundary even when the evidence stops short of demonstrating every possible consequence. A defender should neither inflate a component foothold into universal device takeover nor dismiss it because the familiar operating-system security features are still present.

The central argument of this study is that security assurance must follow the actual processing path. Product labels, user permissions, network membership, and update announcements each describe only part of that path. A useful response connects the affected implementation, the supplier's remedy, the delivered product build, and evidence that the remedy is active on the device. It also distinguishes a laboratory demonstration from an observed campaign.

This is not an account of a verified global Broadpwn outbreak. No victim census, attacker identity, financial loss total, or confirmed enterprise breach is established by the material reviewed here. The case is a vulnerability disclosure and architectural lesson, followed by an original response framework that an organization could use without reproducing the exploit.

## 1. Research scope and source discipline

The core records are the Exodus article, Artenstein's Black Hat presentation, Android's July 2017 bulletin, and Apple's iOS 10.3.3 security note. Two earlier Project Zero articles provide separately attributed architectural context. They are not silently merged into the Broadpwn demonstration or treated as the same vulnerability. Selected relevant passages were reviewed; this work is not a complete firmware audit or an independent reproduction of the researchers' experiments.

Primary sources can disagree in emphasis even when they concern the same research. A headline may describe the broad significance of an attack surface, a technical section may define what was actually built, and a supplier may describe the effect within its own product. A careful case study should preserve those scopes instead of selecting whichever wording sounds most dramatic.

The original analysis below is labeled through its function: proposed controls, review questions, decision rules, and the fictional exercise are not claims about actions taken by a named company in 2017. Historical versions are included to explain disclosure and correction. They are not a recommendation to install obsolete software today. Current remediation should use the device maker's supported release and maintenance guidance.

## 2. A compact chronology with bounded claims

Google's July bulletin was published on 5 July 2017. It placed CVE-2017-9417 in the Broadcom component section associated with the complete 2017-07-05 patch level, classified it as critical remote code execution, and described a proximate attack consequence. The bulletin also distinguished the partial July 1 level from the complete July 5 level. Its dated statement reported no active customer exploitation or abuse of the newly reported issues. [3]

Apple records iOS 10.3.3 as released on 19 July 2017. Its CVE-2017-9417 entry describes possible code execution on the Wi-Fi chip by an attacker within range and a correction to memory handling. The listed availability covers iPhone 5 and later, fourth-generation iPad and later, and sixth-generation iPod touch. The retrieved page also has a later publication metadata date, which is not the historical release date. [4]

The Exodus article is dated 26 July 2017. The Black Hat USA 2017 deck supplies the researcher's presentation record. These dates establish public documentation and supplier release milestones, not the date every affected device received or activated an update. The time from a supplier announcement to local correction remains a separate operational question.

## 3. What the presentation does and does not establish

The 48-page Black Hat deck's final technical slide, page 47 when counted from one, explicitly says the project does not include running code in the main kernel. It points to separate Project Zero work concerning host memory and describes another route that would require an additional browser exploit chain. [2]

This limitation is essential when reading the broad introductory language in the blog. The article itself later says kernel execution deserves separate research and is outside its current scope. Therefore, this case does not present the Broadpwn demonstration as a verified universal, complete takeover of both Android and iOS application processors. [1]

Original analytical conclusion: a claim about a reachable component, a claim about possible onward movement, and a demonstrated end-to-end chain are three different evidentiary objects. They can coexist without contradiction if their scope is stated. A slide title or marketing summary cannot replace the evidence needed for the final step. Equally, uncertainty at the final step does not erase the demonstrated exposure earlier in the chain.

## 4. Why a separate Wi-Fi processor matters

Project Zero's April 2017 architectural discussion explains FullMAC designs as placing substantial wireless protocol processing on a separate system-on-chip. Such offloading can simplify integration and reduce power consumption, while also introducing another complex software environment. The work examined a Nexus 6P and explicitly distinguished chip execution from subsequent host escalation. [5]

An original way to model the security problem is to draw two boundaries rather than one. The first is between radio-origin input and the processor handling it. The second is between that processor and the main operating system. Security review should ask what each boundary validates, what privileges cross it, and what evidence exists that the intended restrictions are effective.

This model avoids a common false choice between calling a device secure and calling it insecure. A platform can have strong application isolation while a peripheral component has a separate weakness. Conversely, a vulnerable component may be constrained by effective host isolation. The useful question is not whether protection exists somewhere, but whether the relevant protection applies to the exact transition under examination.

## 5. Related research is context, not borrowed proof

Project Zero's second April article examined host communication and hardware isolation separately. Its experiments included a Nexus 6P and a Galaxy S7 Edge and raised concerns about memory access from the Wi-Fi component in the tested systems. It also distinguished corrected software issues from the hardware-isolation state described at publication. [6]

Those findings help explain why a peripheral foothold deserves attention. They do not prove that every device, chipset revision, operating-system version, or later build shared the same path. This study therefore uses them as historical context rather than substituting them for missing Broadpwn-specific evidence. A complete claim would need the device, build, component, transition, and observed outcome to line up.

Original research discipline should retain that separation in a source register. A record supporting an architectural possibility belongs beside the claim it actually supports. It should not be attached to an unrelated incident count or an untested product. When combining research streams, explicitly identify the point at which the argument becomes an inference and what observation would be required to confirm it.

## 6. Case-specific failure: a length checked against the wrong assumption

The original Exodus analysis locates the flaw in WMM information-element handling during association. WMM provides traffic-priority information. The parser copied an externally supplied length into a smaller fixed allocation without validating destination capacity. The researchers worked on Galaxy S5 and S7 devices, chiefly the latter for exploit development. These are tested-platform statements, not proof of identical behavior on every listed product. [1]

The important root-cause distinction is between the validity of a representation and the validity of a destination write. A length can be representable in a protocol field and still exceed the memory reserved by a particular implementation. Knowing that a message contains a legal length field is therefore not equivalent to proving that a copy is safe. This is an analytical interpretation of the reported mismatch, not a new code audit.

That interpretation narrows the remedy question. A repair must make the implementation reject or safely handle inconsistent input before it overruns the relevant allocation. Simply asking users not to click links does not address that parser contract. Conversely, identifying a missing check does not by itself establish every later stage needed for reliable remote execution. This study omits malformed values, payload layouts, memory-corruption techniques, and reproduction steps.

## 7. What the chip diagram contributes

The Black Hat architecture material depicts separate RAM and ROM, an ARM Cortex-R4, a D11 wireless-processing component, and host interfaces including PCIe and SDIO. Its mitigation slide reports the absence of DEP/ASLR and writable/executable memory in the examined chip environment. These are historical observations about the researched component, not claims that modern phones lack operating-system hardening. [2]

The original architectural inference is that security properties need a processor and execution context attached to them. Application-processor memory randomization cannot simply be credited to unrelated firmware. Equally, the absence of a particular protection on a peripheral does not prove that every host-isolation mechanism fails. The two claims must be tested independently.

A useful evidence chain has four distinct links: radio-facing parsing reaches the component; a component defect changes its execution; the component has some interface to the host; and an identified boundary failure permits a particular host effect. The Broadpwn source limitation matters because the fourth link cannot be supplied merely by drawing an arrow on an architecture diagram. Related Project Zero work can motivate that question without completing Broadpwn's missing end-to-end proof.

## 8. Supplier scope extended beyond phones

Apple's watchOS 3.2.3 record also lists CVE-2017-9417. It dates the release to July 19, 2017, lists all Apple Watch models then covered by the release, and describes nearby execution on the Wi-Fi chip. The retained page's November 2023 publication metadata is not a second release date. This is an additional supplier-confirmed product family, not a researcher demonstration on every Watch. [7]

A phone-only inventory would consequently be too narrow for a historical review of Apple's published applicability. However, an unqualified statement that all Apple products were affected would be too broad. The correct expansion follows the explicit product bulletin. This review does not extrapolate the Watch entry to every television, laptop, accessory, or later product carrying a similar brand or chip family.

The Android bulletin's July 5 complete patch level and Apple's named operating-system releases are different systems of identifying correction. They should not be forced into a common calendar label such as the July patch. An original closure record should connect the actual product and supplier advisory to the maintained installed build. The historical release is evidence of correction availability; it is not a present-day recommendation to install obsolete software.

## 9. Research outcomes and unanswered questions

This review separates a reported component-execution capability, reported propagation research, supplier-confirmed applicability, and a documented incident. The sources support the first three kinds of evidence. They do not establish a named Broadpwn victim, an outbreak census, a financial-loss figure, or a confirmed adversary campaign. None of those missing quantities is estimated here.

There are also narrower technical gaps. This study does not independently compare every supplier's fixed firmware with its vulnerable predecessor. It does not measure the effective radio range of the demonstration, audit every hardware-isolation configuration, or verify that every model in a broad research inventory has an identical exploitable path. Those are specific research questions, not a reason to replace uncertainty with a universal takeover claim.

For a defensive reader, the original decision rule is to verify the product remedy without requiring a dangerous production demonstration. Supplier applicability, a supported release mapping, and evidence of the active device state can support remediation closure. A connectivity fault alone cannot establish exploitation; an update record alone cannot establish that a previous compromise never occurred. These are different investigations.

The fictional exercise below remains separate from the historical case. It tests the two errors made especially plausible by this record: overstating the processor boundary crossed and understating the products that require an applicability check. It supplies no additional incident evidence.

## 10. Fictional exercise: Alder Mobile Survey

Alder Mobile Survey is a fictional organization with field phones, loan tablets, and a small pool of specialist devices. No real organization, employee, compromise, or customer is represented. The exercise begins when the security coordinator receives a supplier bulletin and a management request to confirm that the fleet is protected by the end of the week.

The first evidence packet contains a count of enrolled devices but no record of the loan pool. A second packet says the July update was approved, but does not distinguish deployment from active installation. A third states that a specialist supplier has received an upstream correction but has not confirmed a product release. Participants must turn these statements into separate tasks rather than accepting them as closure.

The first discussion should produce an evidence map: known device groups, missing ownership, supplier dependencies, and the specific observation needed for each closure decision. The exercise is not scored on how quickly someone says everything is safe. It is scored on whether uncertainty becomes actionable without being concealed or exaggerated.

## 11. Exercise injects and expected decisions

The first inject is an executive draft saying the vulnerability proves complete takeover of every affected phone. Participants should correct the claim boundary and explain why that correction does not remove the need for remediation. The second inject is a supplier answer citing separate research without identifying the actual product build. Participants should request applicability evidence rather than treating any related paper as a product assurance statement.

The third inject reveals that disabling Wi-Fi would interrupt an approved field workflow on one device class. The team must choose an authorized alternative, a supported update path, or a time-limited exception with a named owner. It should not ignore the dependency, and it should not use the dependency as a reason to leave the issue permanently unresolved.

The final inject is a report of intermittent connectivity. Participants should open an evidence-based investigation while avoiding premature attribution. A successful answer distinguishes service restoration from forensic certainty and records any tradeoff involved in restarting or updating the device. No exploit payload, radio manipulation, or unauthorized data collection forms part of the exercise.

## 12. Conclusion

Broadpwn is valuable because it forces a precise question: which processor was compromised, and what evidence establishes the next boundary crossing? The primary records support a serious wireless-component security case while also containing explicit limits that a responsible account must preserve. The most useful lesson is not a universal takeover headline, but a better method for reading technical claims and turning them into justified action.

For defenders, the original response model is straightforward: identify the real device, follow the supplier's scope, separate availability from active correction, verify safely, and keep exceptions accountable. For designers and buyers, ask how peripheral authority is constrained and how corrections remain deliverable throughout the product's useful life.

For researchers, the enduring discipline is equally important. Keep related work separate, distinguish demonstration from incident, and let a source's specific scope constrain its broadest language. That produces a case study that remains useful after the headline fades and after the original patch versions become historical artifacts.

## Sources and reading scope

[1] Nitay Artenstein, Exodus Intelligence, Broadpwn, 26 July 2017. Introduction, WMM allocation failure, tested-platform scope, limitation, and propagation discussion reviewed; operational exploit material is not reproduced. https://blog.exodusintel.com/2017/07/26/broadpwn/

[2] Nitay Artenstein, Black Hat USA 2017, Broadpwn presentation. Architecture, mitigation and concluding scope slides reviewed, including page 47; not an independent demonstration or a full line-by-line deck audit. https://blackhat.com/docs/us-17/thursday/us-17-Artenstein-Broadpwn-Remotely-Compromising-Android-And-iOS-Via-A-Bug-In-Broadcoms-Wifi-Chipsets.pdf

[3] Android Open Source Project, Android Security Bulletin, July 2017, published 5 July and updated 26 September 2017. CVE placement, patch-level semantics, and dated exploitation statement. https://source.android.com/docs/security/bulletin/2017-07-01

[4] Apple, About the security content of iOS 10.3.3. Historical release 19 July 2017; CVE-2017-9417 Wi-Fi entry and supported-device availability. Retrieved regional records carry later page metadata; this is distinguished from release timing. https://support.apple.com/en-euro/103803

[5] Gal Beniamini, Project Zero, Over The Air: Exploiting Broadcom's Wi-Fi Stack, Part 1, 4 April 2017. Architectural context and separately scoped research, not the Broadpwn proof. https://projectzero.google/2017/04/over-air-exploiting-broadcoms-wi-fi_4.html

[6] Gal Beniamini, Project Zero, Over The Air: Exploiting Broadcom's Wi-Fi Stack, Part 2, 11 April 2017. Selected host-isolation findings and tested-platform context; historical configuration evidence is not generalized to every later device. https://projectzero.google/2017/04/over-air-exploiting-broadcoms-wi-fi_11.html

[7] Apple, About the security content of watchOS 3.2.3. July 19, 2017 release; Wi-Fi CVE-2017-9417; all Apple Watch models in the historical release scope. Page publication metadata November 3, 2023. https://support.apple.com/en-us/103535
