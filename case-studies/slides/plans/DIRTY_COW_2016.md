# Slide plan: Dirty COW 2016: A Kernel Race and the Work of Proving a Fix

- Study: case-studies/DIRTY_COW_2016.md
- Cover title: Dirty COW 2016 / A Kernel Race / and Proving a Fix
- Subtitle: A long-lived Linux copy-on-write race became a local privilege-escalation primitive; installing a fix and activating protection are different events.
- Published: 18 November 2026
- Notes: The cover sets the frame: a local privilege boundary failed, and remediation has several distinct states.

## EXECUTIVE SUMMARY | Local privilege escalation, not remote code execution

- Dirty COW is CVE-2016-5195, a race in the Linux memory subsystem's copy-on-write handling.
- An unprivileged local user could gain write access that should have been unavailable and raise privileges.
- This is local privilege escalation, not an unauthenticated remote-code-execution vulnerability.
- Installing an update is only part of proving a system has stopped running vulnerable code.
Caption: Evidence grade: Confirmed vulnerability with Reported in-the-wild misuse.
Notes: Executive framing from [1]; the local versus remote boundary is held throughout, no exploit run.

## KEY FACTS | One CVE, mid-to-late October 2016 disclosure window

Stat: 2016 | Year of disclosure
Stat: 4 | Remediation states to track
Stat: ~11 yr | Age of a prior attempted fix
- CVE-2016-5195 is a copy-on-write race for private read-only mappings.
- Red Hat identifies public disclosure on 19 October 2016; Debian published its update the same day.
- The oss-security message of 21 October says the issue reached linux-distros on 13 October.
Caption: Evidence grade: Confirmed, dated advisories.
Notes: Disclosure and distro dates from [1][5][4]; the prior-fix lineage from [3].

## PART 1 | Local does not mean physical presence

- Copy-on-write defers copying shared memory until a change requires it.
- The flaw let a permitted private change become an unauthorized change to read-only material.
- "Local" means an adversary can run lower-privileged code in the environment, not that they are at the keyboard.
- Dirty COW should not be credited with creating every initial-access path that might precede it.
Caption: Evidence grade: Confirmed mechanism; the access framing is original analysis.
Notes: Boundary description and local-escalation status from [2]; the two-stage authority model is the study's.

## PART 1 | A race condition is a security problem

- Correctness depended on the ordering of operations that can interleave differently.
- A security check reasonable in isolation can fail if its state changes before the operation completes.
- Later memory-management changes made the race easier to trigger, per the fix message.
- A repair must preserve the intended invariant across all security-relevant schedules, not one stable run.
Caption: Evidence grade: Demonstrated reasoning from the repair record.
Notes: Race explanation and the state-validation point from [3]; no vulnerable sequence reproduced.

## PART 1 | Age proves neither safety nor exploitability

- A prior attempted fix roughly eleven years earlier had been reverted over another architecture.
- A defect's age does not establish its practical exploitability in every historical environment.
- A component's long service does not prove its invariants were examined under modern conditions.
- Changes elsewhere can alter timing, assumptions or reachable behavior.
Caption: Evidence grade: Confirmed lineage; the caution is original analysis.
Notes: Prior-fix and architecture detail from [3]; the long-code-lineage lesson is the house angle.

## PART 1 | A commit, a release and a deployment prove different things

A maintenance ticket must keep these artifacts connected, each answering its own question.

| Artifact | What it establishes | Does not establish |
|---|---|---|
| Upstream commit | What maintainers changed | Any vendor shipped it |
| Vendor notice | Which product build has the remedy | Any machine installed it |
| Deployment record | What an operator installed | Which kernel is running |
| Runtime evidence | Code the machine actually uses | That recovery media match |
Caption: Evidence grade: Confirmed, repository and advisory records.
Notes: Repair credited to Phil Oester and Linus Torvalds in [3]; the artifact model is the study's.

## PART 2 | Disclosure dates need explicit attribution

- The oss-security post of 21 October says the issue became public "yesterday."
- Red Hat names 19 October as disclosure; Debian's DSA-3696-1 is dated 19 October.
- These reflect different publication contexts and should not be flattened into one precise event.
- A page's last-modified timestamp may describe later editorial maintenance, not the security event.
Caption: Evidence grade: Confirmed source dates, kept separate.
Notes: Date records from [4][1][5]; measuring delay from ambiguous metadata is warned against.

## PART 2 | A version string is a clue, not a verdict

- Debian's DSA-3696-1 lists 3.16.36-1+deb8u2 as corrected for stable Jessie.
- Ubuntu's record lists 4.4.0-45.66 for its 16.04 LTS linux package.
- Distributions apply corrections while keeping an older base version, so upstream-only comparison misleads.
- The evidence should name release, exact build, package source and advisory, then reconcile the running kernel.
Caption: Evidence grade: Confirmed, product-specific historical records.
Notes: Package builds from [5][2]; these are not universal minimum kernel versions.

## PART 2 | An installed fix can remain inactive

Separate the states of remediation; the final state is not inferred from the earlier ones.

| State | Evidence it needs | Risk if assumed final |
|---|---|---|
| Remedy identified | Authoritative product advisory | Wrong package chosen |
| Remedy acquired | Package or firmware obtained | Nothing yet installed |
| Remedy installed | Successful transaction record | Kernel not activated |
| Protection verified | Post-reboot runtime check | Residual exposure hidden |
Caption: Evidence grade: Confirmed; USN-3104-1 requires a reboot.
Notes: Reboot and kernel-ABI caveats from [6]; the four-state model is the study's.

## PART 2 | Mitigation is not durable correction

- Red Hat describes SystemTap measures as a stopgap, specific to the running kernel.
- The generated module does not survive a reboot, and a changed kernel needs a compatible approach.
- "The server uses live patching" does not establish coverage for this CVE on this kernel.
- Every temporary mitigation needs an explicit expiry condition and a replacement action.
Caption: Evidence grade: Confirmed vendor mechanisms, bounded in scope.
Notes: SystemTap and kpatch caveats from [1]; commands are intentionally not reproduced.

## PART 2 | A month name is not a patch level

- The November 2016 Android bulletin defines a supplemental 2016-11-06 level including CVE-2016-5195.
- The entry rates the kernel issue Critical and describes possible permanent local compromise.
- "The November update" can refer to several patch levels with different contents.
- A bulletin defines a level's meaning; it does not prove every device received an update.
Caption: Evidence grade: Confirmed bulletin; device coverage separate.
Notes: Supplemental level and severity from [7]; device-level evidence stays its own question.

## PART 2 | A "resolved" label still needs the fixed build

- Synology's 2 November 2016 advisory acknowledges the issue and describes a planned DSM 6.0 update.
- The archived page carries a resolved status alongside forward-looking body text.
- An archived page can retain old prose after a later status change, so locate the release notes.
- An appliance still has an owner even when administrators cannot rebuild its kernel.
Caption: Evidence grade: Confirmed response exists; exact fixed build not established.
Notes: Status and body limitations preserved from [8]; guess a firmware version is warned against.

## DEFENDER VIEW | Assess exposure without running exploit code

- Begin with assets and maintenance ownership; separate servers, hosted infrastructure, mobile and appliances.
- A public privilege-escalation program is a poor default production scanner and can alter system state.
- Record the execution context available to less-trusted users, jobs or workloads.
- Keep unknowns actionable; "unknown" should not become "not affected" because a scanner has no answer.
Caption: Evidence grade: Original defensive analysis.
Notes: Assessment discipline follows the study; distribution lists are not counts of vulnerable systems.

## DEFENDER VIEW | Keep remediation and incident response distinct

- Patching removes future opportunity; it does not reverse unauthorized changes already made.
- An in-the-wild exploit was identified from an HTTP capture, attributed to Phil Oester.
- That does not make Dirty COW remote code execution or establish one universal intrusion chain.
- Distinguish confirmed misuse from attempted execution and from a file merely associated with an exploit.
Caption: Evidence grade: Reported exploitation; no victim roster or attribution established.
Notes: Attributed capture account from [9]; confidence levels and dual workstreams from the study.

## CLOSE | Verify the state that matters, preserve the uncertainty

- A fix in a repository, an installed package and a generic update label are all useful observations.
- None should be substituted for proof the running environment has the required protection.
- Keep vulnerability, exploit and incident distinct; keep installed distinct from activated.
- Open gaps: no global victim count, no worm, no single attributed campaign in the record.
Caption: Evidence grade: case-specific conclusions, bounded to the sources.
Notes: Conclusion synthesis across [1] through [9]; precision over a manufactured cleaner story.
