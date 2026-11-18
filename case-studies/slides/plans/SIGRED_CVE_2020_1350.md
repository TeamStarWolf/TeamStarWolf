# Slide plan: SIGRed 2020: A 17-Year DNS Flaw and Emergency Mitigation

- Study: case-studies/SIGRED_CVE_2020_1350.md
- Cover title: SIGRed 2020 / Windows DNS parsing / Emergency mitigation
- Subtitle: A critical Windows DNS Server flaw with an emergency registry workaround beside the patch; wormable was a classification, not a completed worm.
- Published: 18 November 2026
- Notes: The cover sets the frame: a privileged DNS parser, an interim workaround and a patch, with evidence kept in separate categories.

## EXECUTIVE SUMMARY | A critical DNS Server flaw, not a DNS-wide failure

- SIGRed, CVE-2020-1350, was a critical flaw in Microsoft's Windows DNS Server role, disclosed July 2020.
- It was not a failure of DNS as a protocol, nor a flaw in every device performing a DNS lookup.
- Microsoft classified it as wormable and said it knew of no active attacks at publication.
- CISA later added it to Known Exploited Vulnerabilities on 3 November 2021; the record changed.
Caption: Evidence grade: Confirmed disclosure; no incident attributed.
Notes: Executive-assessment framing from [1]; later classification from [3]; no exploit code reproduced.

## KEY FACTS | Wormable and 10.0, with no known attacks at disclosure

Stat: 10.0 | CVSS base score, wormable label
Stat: 17 yr | Code lineage back to Server 2003
Stat: Jul 14 | 2020 Microsoft fix released
Stat: 255 | Bytes between the two TCP caps
- Check Point credits Sagi Tzadik; report to Microsoft May 19, CVE June 18, fix July 14, 2020.
- The 17-year label is vulnerability age, not 17 years of documented hostile exploitation.
- Microsoft assigned CVSS 10.0 and the wormable label; it reported no known active attacks at disclosure.
- CISA's cisagov catalog lists CVE-2020-1350 with a 3 November 2021 addition date.
Caption: Evidence grade: Confirmed CVE and dated records.
Notes: Timeline and age from [2]; score and wormable from [1]; catalog date from [3].

## PART 1 | Keep vulnerability, exploit and incident distinct

- A wormability classification is a judgment about potential, not a record of propagation.
- The discoverer demonstrated a memory-corruption path but had not completed a full exploit chain.
- "Patch available", "patch deployed" and "verified remediated" are three separate states.
- Keep exploitable-in-theory distinct from exploited-in-the-wild, each dated to its source.
Caption: Evidence grade: Confirmed statements; no epidemic claimed.
Notes: Three-proposition discipline from [1,2]; exploit-completion limit stated in [2].

## PART 1 | Discovery timeline, research versus public fix

Check Point's disclosure timeline separates research milestones from the public correction.

| Date | Milestone | Meaning |
|---|---|---|
| May 19, 2020 | Report to Microsoft | Research disclosure milestone |
| Jun 18, 2020 | CVE-2020-1350 issued | Identifier assigned |
| Jul 9, 2020 | Wormability acknowledged | Critical severity classified |
| Jul 14, 2020 | Microsoft fix released | Public correction milestone |
Caption: Evidence grade: Confirmed, dated timeline.
Notes: Dates from [2]; July 14 is the public correction, May 19 a research milestone, not one patch-delay measure.

## PART 1 | DNS Server and DNS Client are different surfaces

- Microsoft locates the flaw in the DNS Server role; dns.exe differs from the Windows DNS client.
- A workstation resolving names is not automatically an instance of the vulnerable server role.
- A Windows Server inventory needs role data before it becomes an exposure inventory.
- Counting every endpoint overstates scope; counting only public name servers can miss internal DNS.
Caption: Evidence grade: Confirmed role scope.
Notes: Role location from [1]; server and client distinction from [2].

## PART 1 | The fault was a size-calculation failure

- Check Point identifies an integer overflow in the SIG-record path, SigWireRead, leading to heap overflow.
- Allocation-size arithmetic narrowed to sixteen bits; SIG and RRSIG records share the parser.
- A transport-level ceiling does not guarantee every derived representation fits the reserved region.
- The invariant: validate the size actually stored, with arithmetic that preserves the range.
Caption: Evidence grade: Demonstrated memory-corruption path; no exploit recipe.
Notes: Root cause from [2]; exploit construction deliberately omitted.

## PART 1 | A negative result keeps the scope precise

- Check Point found NsecWireRead combined similar sizes, but its final range check prevented the flaw.
- The DNS client's Sig_RecordRead carried a size check before its allocator call.
- These were bounded comparisons in the analyzed routines, not a guarantee for every DNS parser.
- The lesson is narrower than "DNS compression is dangerous"; it depends on the caller's arithmetic.
Caption: Evidence grade: Reported analysis of inspected routines.
Notes: Variant analysis and client comparison from [2]; not a review of Microsoft's private fix.

## PART 2 | TCP was a legitimate transport, not an anomaly

- RFC 7766 (March 2016) makes TCP a required part of a full DNS implementation.
- TCP framing includes a two-octet message-length field bounding the encoded message.
- Transport size and in-memory size deserve separate labels; the bound is on the wire, not the decode.
- Treating all large DNS-over-TCP responses as attacks would create an inaccurate detection premise.
Caption: Evidence grade: Confirmed normative standard.
Notes: Transport requirement and framing from [4]; the vulnerability arose in handling data, not the connection.

## PART 2 | Wormable was a classification, not a completed worm

- Microsoft assigned CVSS 10.0 and described propagation without user interaction between systems.
- The same July 14 announcement said active attacks were not then known.
- Check Point said it had the necessary primitives but had not completed the full chain.
- A plausible route to automation can justify urgency before a weaponized implementation appears.
Caption: Evidence grade: Confirmed statements held together.
Notes: Score and wormable label from [1]; exploit-completion limit from [2]; no worm is claimed to have occurred.

## PART 2 | Local System impact and domain-controller context

- CERT-EU describes successful code execution in the Local System account context.
- Australia's advisory notes DNS is commonly installed on domain controllers.
- Privileged execution on a host and administrative authority over a domain are not interchangeable.
- Final impact depends on the host's actual role and the attacker's actions, not a universal outcome.
Caption: Evidence grade: Confirmed privilege; proximity reported.
Notes: Local System context from [6]; domain-controller placement from [7].

## PART 2 | The temporary size limit was narrowly defined

The workaround trades a narrow compatibility range for protection while the patch is arranged.

Stat: 65,280 | Temporary inbound TCP cap (bytes)
Stat: 65,535 | Default maximum response (bytes)
Stat: 255 | Difference between the two bounds
- KB4569509 sets a temporary cap of 65,280 bytes (FF00) on inbound TCP DNS responses.
- Oversized responses are silently dropped; uncommon legitimate queries may consequently fail.
- The setting does not affect DNS zone transfers; it is not turning off DNS or blocking all TCP.
- Pasting FF00 into the wrong entry type can yield decimal 4,325,120, not 65,280.
Caption: Evidence grade: Confirmed vendor guidance.
Notes: Cap, default, drop behavior, zone transfers and the numeric-entry warning from [8].

## PART 2 | Restart is not reboot; activation is its own step

- The registry change requires a DNS-service restart to take effect, not a full server reboot.
- NSA states the patch requires a server reboot; the workaround needs the DNS service restarted.
- Writing a configuration value and having the service enforce it are different events.
- A record of successful registry distribution can leave the protected state unproven.
Caption: Evidence grade: Confirmed activation boundary.
Notes: Service restart from [8]; patch-reboot distinction from [5].

## PART 2 | Directive 20-03 separated interim and final states

Emergency Directive 20-03 (July 16) encoded two deadlines and a reconnection rule.

| Deadline | Requirement | Scope note |
|---|---|---|
| 2 p.m. Jul 17 | Patch or workaround DNS-role servers | Immediate exposure reduced |
| 2 p.m. Jul 24 | July update to all Windows Servers | Permanent baseline completed |
| Before connect | Cover new or reconnected servers | Avoids a one-time snapshot gap |
Caption: Evidence grade: Confirmed directive; compliance not audited.
Notes: Deadlines and reconnection rule from [9]; it excluded defense and intelligence systems and did not bind private organizations.

## DEFENDER VIEW | Later classification changes the retrospective

- The cisagov catalog lists CVE-2020-1350 with a dateAdded of 3 November 2021.
- That addition date is a record-management milestone, not an attack-onset timestamp.
- Elastic's detection article records a July 17, 2020 release but is dated November 22, 2022; it supplies hypotheses, not proof.
- Remove the workaround after patching to retire the nonstandard limit; keep the software fix as the protection.
Caption: Evidence grade: Confirmed catalog date; detection reported.
Notes: Catalog date from [3]; detection discussion and milestone from [10]; removal guidance from [5,8].

## CLOSE | Separate the states, keep the dates with their sources

- Encoded-message limits cannot substitute for safe handling of expanded data and internal arithmetic.
- Configured protection, active protection and permanent correction are three different states.
- Wormability, research demonstrations and observed exploitation belong in separate evidence categories.
- The record does not establish a worldwide outbreak, a loss total or a uniform domain-takeover outcome.
Caption: Evidence grade: case-specific conclusions, scope bounded.
Notes: Synthesis across the final assessment; conclusions rest on [1] through [10].
