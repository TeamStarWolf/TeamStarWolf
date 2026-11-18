# Slide plan: XcodeGhost 2015: A Compromised Build Tool

- Study: case-studies/XCODEGHOST_2015.md
- Cover title: XcodeGhost 2015 / A Compromised Build Tool / Behind Trusted Apps
- Subtitle: A compromised build tool produced trusted apps; signed is not safe, and distribution breadth is not targeting breadth.
- Published: 18 November 2026
- Notes: The cover sets the frame: a supply-chain build-tool compromise, with evidence kept bounded to its source.

## EXECUTIVE SUMMARY | A compromised build tool, not a hacked store

- Malicious material entered through unofficial copies of Xcode, so developers shipped code they did not write.
- Distribution through an official store did not by itself reveal the earlier contamination.
- Counts of apps, versions, DNS queries, source IPs and customers measure different things and cannot be swapped.
- The account separates researcher observations from hypotheses, and a litigant's proposal from a court's finding.
Caption: Evidence grade: Confirmed mechanism; no single victim count established.
Notes: Executive-assessment framing; sources [1] through [11], with no sample executed and no live infrastructure contacted.

## KEY FACTS | Dated reports, different counts, one build-tool origin

Stat: 6.1-6.4 | Xcode versions in the initial report
Stat: ~20 | Unofficial Xcode packages Tencent tested
Stat: 76 | Apps in Tencent top 5,000 survey
Stat: 39 | Apps named in Palo Alto follow-up
- Palo Alto published September 17; Tencent's own narrative dates to September 19.
- The payload collected device and app metadata and sent it to remote infrastructure.
- App, version, DNS-query, source-IP and customer counts are not interchangeable units.
Caption: Evidence grade: Confirmed dated reports.
Notes: Version range and sampled-app facts from [1]; the survey and package-testing counts from [2].

## PART 1 | The attack entered before the application existed

- Palo Alto's September 17 report found added material failing signature validation in Xcode 6.1-6.4.
- The payload was a Mach-O object tied to a misleading CoreServices location, linked in during the build.
- "The App Store was hacked" implies backend tampering the reviewed evidence does not establish.
- "Compiler malware" overstates it; developers built with altered tools and submitted through normal channels.
Caption: Evidence grade: Confirmed mechanism; stronger framings unsupported.
Notes: Injection point, payload and the two imprecise summaries from [1]; NetEase Cloud Music 2.8.3 was the confirmed sampled app.

## PART 1 | Download convenience became a trust decision

- Unofficial copies spread through developer forums and Baidu links, chosen for faster local downloads.
- Once adopted, the same untrusted input can influence many future products.
- Risk is not proportional to how many people downloaded the original package.
- The decision was whether origin and integrity were established before producing trusted output.
Caption: Evidence grade: Confirmed context; not a judgment on all developers.
Notes: Distribution route and the convenience framing from [1]; source-repository history alone would miss an injection point outside the repo.

## PART 2 | Different counts measured different populations

These counts answered different questions and cannot be substituted for one another.

| Source | Count | Population measured |
|---|---|---|
| Tencent, Sep 19 | 76 apps | Top 5,000 App Store apps, Sep 16 |
| Palo Alto, Sep 18 | 39 apps | Named apps and specific versions |
| Fox-IT | Separate list | Network observations |
Caption: Evidence grade: Reported counts; denominators differ.
Notes: Survey denominator from [2]; the 39-app list and the attributed Fox-IT list from [3], which stays attributed, not re-confirmed here.

## PART 2 | Names alone were no longer enough

- Palo Alto's follow-up named WeChat 6.2.5, with 6.2.6 described as removing the malicious code.
- A September 21 correction kept CamCard 6.5.1 in the Chinese store distinct from the unaffected 5.5.2 in the U.S. store.
- An app title can name different binaries across times and markets, so title-only action can overstate or understate.
- A binary a researcher examined and an identity inferred from traffic are different proofs with different failure modes.
Caption: Evidence grade: Confirmed correction; two evidence types kept separate.
Notes: Version, storefront precision and the two forms of evidence from [3]; popularity language is an exposure ceiling, not a device count.

## PART 2 | The capability correction is central to the case

- An early remote-control analysis described alerts, URL handling and clipboard access.
- The September 21 update says the examined code could not directly phish iCloud passwords as first claimed.
- The inspected alert implementation lacked the input-form setting needed for that particular password prompt.
- HTTP command exchange had inadequate protection; server shutdown did not remove residual risk from installed apps.
Caption: Evidence grade: Demonstrated, then corrected; carry the correction forward.
Notes: Original claim and its correction from [4]; the alert-setting and HTTP-protection detail from [5]. Metadata collection, a URL action, a deceptive alert and a completed theft are different observations.

## PART 2 | Technical control did not require a jailbreak narrative

- The mechanism operated within applications produced through the compromised environment.
- The reports do not establish a universal jailbreak, a kernel compromise or access to every other app's storage.
- The code had the host app's normal opportunities; it need not defeat every platform protection.
- A URL-opening capability is not proof that any particular handler vulnerability was exploited.
Caption: Evidence grade: Confirmed scope; stronger iOS claims not imported.
Notes: Scope limits and the URL-handling caveat from [5]; command schemas and interception recipes are omitted because the historical inference does not need them.

## PART 2 | The response was a sequence across separate owners

Coordinated actions touched different resources; none alone remediated every installed copy.

| Actor | Action | What it did not do |
|---|---|---|
| Apple | Removed apps from Sep 18, told devs to rebuild | Rewrite every build environment |
| Amazon | Disabled observed servers | Remove code already shipped |
| Baidu | Removed the altered installers | Clean existing builds |
Caption: Evidence grade: Confirmed actions; some listings remained at observation time.
Notes: Removal, rebuild guidance and infrastructure actions from [5]; coordinated cleanup can be real and still incomplete at a given observation time.

## DEFENDER VIEW | Platform guidance and a supplier's own answer

Left: Platform guidance (Apple, Sep 22)
- Directs developers to official channels and explains Gatekeeper signature checking.
- Tells invalid-copy holders to obtain clean tools and rebuild before resubmission; QA1900 shares the date.
- Addresses the producer: a signed output can still carry untrusted build input, so signed is not safe.
Right: Supplier statement (QNAP, Sep 22)
- Says its iOS apps were built with official Xcode and none were affected.
- Primary evidence for QNAP's public position, not independent proof produced here.
- A platform-wide warning is a reason to investigate, not a verdict on every vendor.
Caption: Evidence grade: Confirmed guidance; Reported supplier statement.
Notes: Apple notice and QA1900 from [6]; QNAP advisory from [7]. No setting was changed and no validation was run on the user's computer.

## DEFENDER VIEW | Read the network layer through its measurement rules

Stat: 14,147 | Daily unique IPs, Hong Kong, Oct wk 1
Stat: 7,151 | Daily unique IPs, Hong Kong, Oct wk 4
- Verisign's October 1 account analyzes authoritative DNS and warns that caching shapes the visible graph.
- Shorter negative-cache behavior can raise query volume after removal even as impacted users fall.
- Observations via Google's public resolvers do not establish infection inside Google's corporate network.
- HKCERT reads the decline as consistent with store action and updates, with residual devices still at risk.
Caption: Evidence grade: Reported telemetry; IPs are not deduplicated people.
Notes: DNS caveats and the resolver point from [8]; the Hong Kong weekly figures and interpretation from [9], kept attached to their period and unit.

## CROSS-CUTTING THEMES | Distribution breadth is not targeting breadth

- November 3: Symantec reports a new variant in unofficial Xcode 7 copies tied to iOS 9 development.
- That shows the September response was not the permanent end of this attack class.
- Epic's May 28, 2021 proposed findings cite 128 million customers and more than 2,500 apps (printed pp. 409-410).
- It is a party's proposal, not a court finding; a customer figure, an app count and a query count are different units.
Caption: Evidence grade: Reported variant; a litigation claim with identified provenance.
Notes: New variant from [10]; the scale figures and their evidentiary status from [11]. The FireEye follow-up was not retrievable, so its enterprise totals are not reproduced.

## CROSS-CUTTING THEMES | Where the record is overstated versus understated

Left: Easy to overstate
- "The App Store was hacked" or "compiler malware" as the mechanism.
- A completed iCloud credential theft the corrected analysis did not support.
- One takedown date standing in for complete remediation.
Right: Easy to understate
- A real upstream injection that ordinary signing faithfully delivered.
- How many apps shipped the tainted library versus what the payload actually did.
- Post-disruption DNS traffic consistent with residual installed components.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated framings from [1] and [4]; the distribution-versus-targeting and residual-traffic points from [3], [5] and [8].

## CLOSE | Precision about origin beats a single resolved status

- Application trust depends on more than a legitimate developer and distribution channel.
- A compromised build input can reach users through otherwise ordinary production steps.
- Keep signed distinct from safe, and distribution breadth distinct from targeting breadth.
- The record leaves the final operator, an audited loss and complete global remediation unestablished.
Caption: Evidence grade: case-specific conclusions, scope bounded.
Notes: Conclusion synthesis across [1] through [11]; the capability correction, version distinctions and telemetry caveats are kept, not smoothed away.
