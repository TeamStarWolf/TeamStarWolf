# Slide plan: BlueBorne: Bluetooth Exposure Beyond the Pairing Prompt

- Study: case-studies/BLUEBORNE_2017.md
- Cover title: BlueBorne / Bluetooth Exposure / Beyond the Pairing Prompt
- Subtitle: Not accepting a pairing prompt did not insulate a device from hostile Bluetooth input, so one shared name still demanded component-specific evidence.
- Published: 15 November 2026
- Notes: House style; faithful to the study; evidence grades preserved; no invented victim count or attacker.

## EXECUTIVE SUMMARY | Pairing approval was not the whole Bluetooth boundary

Armis described eight implementation vulnerabilities across major operating-system families, reachable without discoverability or prior pairing.

- The attacks reached processing below the user interaction many treated as the boundary.
- Impact varied by product: information disclosure, code execution or interception.
- Supplier assessments narrowed risk; the path from upstream fix to shipped device differed.
- The study invents no victim count, names no attacker, and claims no global outbreak.
Caption: Evidence grade: Reported by Armis; impact Confirmed to vary by supplier.
Notes: Executive assessment and the scope and evidence method. [1][2][3][4]

## KEY FACTS | One name covered eight distinct flaws with different severities

Stat: 8 | Implementation vulnerabilities (Armis)
Stat: 4 | Android CVEs in the Sept 2017 bulletin
Stat: 2 | Linux CVEs: userspace and kernel
Stat: 12 Sep | CERT/CC note VU#240311, 2017
- Android labeled CVE-2017-0781/-0782 critical RCE, -0783 high and -0785 moderate disclosure.
- Linux split CVE-2017-1000250 (BlueZ userspace) from -1000251 (kernel L2CAP).
- Apple CVE-2017-14315 and Windows CVE-2017-8628 sat in the same collection.
Caption: Evidence grade: Confirmed from supplier bulletins and coordination notes.
Notes: What the BlueBorne name represented; Android, Linux, Apple, Windows. [2][3][4][7]

## PART 1 | A shared name was not a shared defect

- CERT/CC VU#240311 grouped Bluetooth issues across Windows, iOS and Linux-derived systems.
- A common name implies no shared patch, identical prerequisites or equal post-exploit control.
- Keep each vulnerability ID beside the campaign name so one fix does not close others.
- Do not assign the worst effect to every member, or let a lower-severity issue vanish.
Caption: Evidence grade: Confirmed (CERT/CC catalog); grouping is communication, not one defect.
Notes: What the BlueBorne name represented. [2]

## PART 2 | Radio proximity is not internet reachability

- Red Hat: the target needed Bluetooth hardware and service enabled, attacker within range.
- Hostile input can arrive without physical access, yet this is not an internet-reachable service.
- A nearby radio channel can cross an org boundary even with no routed network between devices.
- Network diagrams need accurate wireless interfaces; the study gives no range-extension method.
Caption: Evidence grade: Confirmed prerequisites (Red Hat); no universal radius invented.
Notes: Radio proximity and remote access. [5]

## PART 3 | Discovery and authorization answer different questions

- Armis showed the attacks reached vulnerable processing without the pairing approval step.
- Turning off discoverability alone was explicitly rejected as sufficient protection.
- A device may parse peer input before deciding to accept, reject or authenticate it.
- A no-paired-device screenshot does not prove the vulnerable code was unreachable.
Caption: Evidence grade: Demonstrated by Armis; pairing and safe input handling differ.
Notes: Discovery, pairing and input processing. [1]

## PART 4 | Supplier bulletin, not advisory date, set the Android remedy

- Android's bulletin set 2017-09-01 and 2017-09-05 patch levels; the later covered all its issues.
- CERT/CC and JPCERT/CC instead cite a September 9 Android patch level.
- The study preserves the discrepancy and uses the supplier bulletin for the exact remedy.
- Android reported no customer exploitation of the new issues, a bounded, dated statement.
Caption: Evidence grade: Confirmed (supplier bulletin); date conflict preserved, not normalized.
Notes: Android evidence and the patch-date discrepancy. [2][3][7]

## PART 5 | A userspace package update was not an active kernel fix

- Ubuntu split CVE-2017-1000250 (BlueZ daemon memory) from -1000251 (kernel L2CAP).
- Stack protection changed the kernel issue's expected impact from code execution to a crash.
- BlueZ commit 9e009647 added a continuation-bounds check; a cache object is not a valid range.
- Kernel commit e860d2c9 bounded output construction, not only incoming-message validation.
- USN-3413-1 (12 Sept, userspace) and USN-3420-1 (18 Sept, kernel, reboot) were separate milestones.
Caption: Evidence grade: Confirmed (Ubuntu, upstream commits); a six-day gap is not an exposure interval.
Notes: Linux user space and the kernel. [4][9][10][11][12]

## PART 6 | Host-stack exposure was not the radio vendor's firmware

- Microchip located the issues in the host Bluetooth stack, not its device firmware or driver.
- Its ATWILC3000 firmware measure was a planned future date, not verified shipped evidence.
- Red Hat rated CVE-2017-1000251 Important and flagged PPC64 configs without stack protection.
- JPCERT noted Apple CVE-2017-14315 (fixed in iOS 10) and Windows CVE-2017-8628 spoofing.
Caption: Evidence grade: Confirmed component scoping; a plan is not a shipped release.
Notes: Red Hat, Apple and Windows, host software versus radio hardware. [6][7][8]

## DEFENDER VIEW | A closed response needs evidence of the corrected state

Left: Record and map
- Record platform, Bluetooth stack, enabled functions and business owner.
- Map each applicable CVE to the supplier's remedy; keep unknowns as verification tasks.
Right: Verify and report
- Verify with supported config and package evidence plus legitimate workflow checks, no exploit.
- Report verified, temporarily restricted and still-awaiting counts; keep exception age visible.
Caption: Evidence grade: Original analysis; safe verification without production exploit tests.
Notes: Bounded defensive evidence model and closure metrics. [3][4]

## MITRE MAPPINGS | The study assigns no ATT&CK technique IDs, by design

The study maps suppliers and CVEs, not ATT&CK techniques, to avoid overstating demonstrated capability as observed adversary behavior.

| Behavior in the study | ATT&CK mapping |
|---|---|
| Pre-pairing radio access | Not mapped; no technique ID claimed |
| Code execution on some targets | Not mapped; impact varies by product |
| Disclosure or interception | Not mapped; severity differs by issue |
| Malware propagation idea | Not mapped; capability, not observed use |
Caption: Evidence grade: the boundary preserved; demonstrated capability is not observed use.
Notes: Severity interpretation and incident claims. [1][2]

## CROSS-CUTTING THEMES | What the study refused to overstate or drop

Left: Not overstated
- No victim census, no named attacker, no confirmed self-propagating outbreak.
- No universal radius, no single patch, no worst-effect label for every member.
Right: Not understated
- A mitigated crash still matters to an essential service; the flaw still needs fixing.
- Configuration-based non-exposure needs an owner and reassessment when it changes.
Caption: Evidence grade: Three categories kept apart: demonstrated, observed and accomplished.
Notes: Capability versus incident claims and evidence limits. [1][6]

## CLOSE | No single layer is a safe proxy for the others

- Pairing, radio discovery, host software and vendor hardware are related, not interchangeable.
- Identify which component processes the input and what condition prevents the harmful behavior.
- Researcher findings establish the class; supplier records refine applicability and maintenance.
- The Cedar Field Services exercise tests coordination and evidence, not exploitation skill.
Caption: Evidence grade: a conclusion plus a fictional training exercise; no real entity represented.
Notes: The fictional exercise, closure metrics and conclusion. [1][2][3][4]
