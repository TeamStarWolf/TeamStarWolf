# Slide plan: SMBGhost 2020: Compression Arithmetic and Client Exposure

- Study: case-studies/SMBGHOST_CVE_2020_0796.md
- Cover title: SMBGhost 2020 / Compression Arithmetic / Client Exposure
- Subtitle: An integer-overflow in SMBv3 decompression reached clients and servers on specific Windows 10 builds; mitigation and patch status stay distinct.
- Published: 18 November 2026
- Notes: The cover sets the frame: an implementation flaw and its scope, not an attributed outbreak.

## EXECUTIVE SUMMARY | A vulnerability disclosure, not an attributed incident

- SMBGhost (CVE-2020-0796) was a Windows SMB 3.1.1 implementation vulnerability disclosed in March 2020, not an incident.
- The flaw crossed a trust boundary processing compressed network data before authentication, affecting servers and clients.
- CERT/CC describes possible arbitrary code execution with SYSTEM privileges; the sources support no victim count or attribution.
- The lesson is distinctions summaries erase: compressed versus allocated size, server workaround versus client protection, crash versus code execution.
Caption: Evidence grade: Confirmed disclosure; no incident attributed.
Notes: Executive-assessment framing from [1] and [2]; no exploit code reproduced.

## KEY FACTS | One dialect, specific builds, a March 2020 patch

Stat: 3.1.1 | Affected SMB dialect
Stat: 2 | Windows 10 versions: 1903 and 1909
Stat: Mar 12 | 2020 patch, KB4551762
Stat: 2022 | Added to CISA KEV catalog
- CVE-2020-0796, nicknamed SMBGhost, was an SMB 3.1.1 implementation flaw disclosed in March 2020.
- KB4551762 identified builds 18362.720 and 18363.720; that package later expired. [2]
- CERT-EU scope covers Windows 10 1903 and 1909, plus Windows Server 1903 and 1909 Server Core. [3]
- CISA recorded the entry on February 10, 2022, marking ransomware campaign use as known. [11]
Caption: Evidence grade: Confirmed CVE and dated advisories.
Notes: Builds and servicing from [2]; product scope from [3]; catalog classification from [11].

## PART 1 | Vulnerability, exploit and incident stay distinct

- A vulnerability is a potential failure; an exploit demonstration worked only under stated conditions.
- An incident is actual use against a target; the three levels must not be collapsed.
- Keep wormable or exploitable-in-theory separate from exploited-in-the-wild.
- A proof of concept is not an observed campaign, and a crash is not proven control of a host.
Caption: Evidence grade: Confirmed definitions; no exploitation-in-the-wild detail invented.
Notes: Evidence-level discipline from the study's assessment and [1]; demonstration limits from [5].

## PART 1 | An affected implementation, not the whole protocol

Trellix traced separate server and client driver paths reaching related decompression processing.

| Network role | Driver path | Reported evidence |
|---|---|---|
| Server receiving SMB | srv2.sys | Crash in decompression [9] |
| Client initiating SMB | mrxsmb.sys | Crash in decompression [9] |
| Historical scope | Windows 10 and Server Core 1903, 1909 | Narrower than all SMB [3] |
Caption: Evidence grade: Confirmed paths and product scope.
Notes: Server and client driver paths from [9]; explicit product list from [3], used over broader detection-article wording.

## PART 1 | Compression created a size-consistency obligation

- The archived analysis describes allocation from a compressed message's size and offset, then decompression whose bounds could disagree. [9]
- Microsoft's account attributes the behavior to network-derived length and offset parsing. [7]
- It describes an out-of-bounds write with an overflowing size calculation and an out-of-bounds read in source-length handling. [7]
- The repair centered on checked arithmetic such as RtlULongAdd and RtlULongSub, not merely disabling a feature. [9]
Caption: Evidence grade: Confirmed root-cause from vendor and patch comparison.
Notes: Allocation mechanism and checked helpers from [9]; write and read conditions from [7]; the integer-overflow was in SMBv3 decompression, not the compression algorithm itself.

## PART 1 | A checked helper is only part of a safe repair

- Synacktiv's comparison shows checked addition before allocation, an error branch, a size comparison and checked subtraction. [4]
- Inserting a checked helper is only part of a safe repair; the caller must honor its failure status. [4]
- RtlULongAdd returns STATUS_INTEGER_OVERFLOW on an out-of-range result, leaving the output invalid. [15]
- An arithmetic result that fits the integer type must still fit the message and the destination allocation.
Caption: Evidence grade: Confirmed patch comparison; one operand label is a guess, not a verified symbol.
Notes: Checked control flow from [4]; helper contract from [15]; representability versus consistency is the study's analysis.

## PART 2 | Client exposure changed the mitigation problem

Left: Server path
- CERT/CC's compression workaround needed no reboot but did not protect SMB clients. [1]
- A server configuration change is evidence about the server path, not the whole host.
Right: Client path
- A vulnerable machine could initiate a connection and be reached through the response it receives. [1]
- NHS Digital repeated the server-only limit and suggested inbound and outbound TCP 445 review. [10]
Caption: Evidence grade: Confirmed directional guidance.
Notes: Two network situations and workaround scope from [1]; perimeter and host advice from [10]; the registry workaround stays distinct from the patch.

## PART 2 | Patch available and patch deployed are separate

Separate product availability from an organization's remediation; each row carries what it does not establish.

| Date | Supported event | Does not establish |
|---|---|---|
| Mar 12, 2020 | KB4551762 released | Universal installation |
| Aug 5, 2021 | KB marked expired | That the 2020 fix never shipped |
| Later | Successor quality updates | A named victim's deployment log |
Caption: Evidence grade: Confirmed servicing dates; non-claims explicit.
Notes: Build numbers and expiration notice from [2]; availability versus remediation is the study's distinction, not a claim about any unexamined organization.

## PART 2 | Crash, privilege escalation and remote execution

- The March 31 research demonstrated local privilege escalation from a medium-integrity starting context. [5]
- It explicitly distinguished that result from an achieved remote code-execution proof of concept. [5]
- A crash shows disrupted availability; local privilege escalation crosses a local authority boundary under stated conditions.
- Remote code execution is a different completion claim; the phrases must not be used interchangeably.
Caption: Evidence grade: Demonstrated LPE under stated conditions; RCE not claimed for SMBGhost alone.
Notes: Demonstration and its medium-integrity boundary from [5]; urgent response was still justified at disclosure.

## PART 2 | SMBleed was related, not another name for SMBGhost

- A June 9 writeup describes SMBleed as CVE-2020-1206, a separate uninitialized-memory disclosure. [8]
- Combining it with unpatched SMBGhost was reported to enable pre-authentication remote code execution. [8]
- That is not the March patch failing to fix CVE-2020-0796; a neighboring bug and a chain are different claims.
- The nickname SMBleedingGhost describes combined research, not one merged vulnerability identity.
Caption: Evidence grade: Reported chaining result; two CVEs kept distinct.
Notes: Separate CVE and the combined outcome from [8]; chain construction omitted.

## PART 2 | Detection and catalog claims had a defined scope

- Microsoft's April 6 post announced detection of crafted packets against unpatched domain controllers. [6]
- An attempted exploit, a matching packet and a compromised host are different evidentiary states. [6]
- The CISA entry was added February 10, 2022 and marks ransomware campaign use as known. [11]
- It names no campaign, victim count or first exploitation date; the June 2020 alert was inaccessible. [11]
Caption: Evidence grade: Confirmed detection scope and catalog classification.
Notes: Detection target and observation scope from [6]; catalog addition and classification from [11]; no campaign attribution inferred.

## DEFENDER VIEW | Model the endpoint by the roles it performs

- Model an endpoint by the network roles it performs, not by an asset label like desktop or file server.
- A machine can accept file-sharing in one connection and initiate it in another, consuming external data either way. [9]
- State a mitigation's scope by the role and connection direction it covers, not as whole-host safety.
- Validate with the actual OS release and servicing state and controlled tests, not reproduced exploit code.
Caption: Evidence grade: Inferred defensive guidance drawn from the sources.
Notes: Role modeling and dual driver paths from [9]; directional scope from [1]; no reproduction performed.

## CROSS-CUTTING THEMES | What the record overstates vs understates

Left: Overstated in the retelling
- A spreading worm or a victim count; the record shows a crash on tested platforms. [14]
- "Fixed on March 12" read as universal installation rather than product availability. [2]
- A later chain or demonstration backdated into the earlier March publications.
Right: Understated and worth keeping
- Client exposure, not server-only, on specific Windows 10 builds. [1][3]
- The workaround and the patch were different corrective actions. [1][2]
- SMBGhost and SMBleed are two identifiers with two disclosure contexts. [8]
Caption: Evidence grade: editorial corrections the case requires.
Notes: Worm and crash scope from [14]; servicing from [2]; CVE separation from [8].

## CLOSE | Keep the four dates and the two scopes distinct

- Every arithmetic relationship governing privileged network parsing must stay safe for inconsistent inputs.
- A mitigation's scope must be stated by the actual role and connection direction it covers.
- Keep publication, product correction, demonstration and catalog dates as separate events.
- The record supports a serious pre-authentication flaw and a later known-exploitation classification, not a fabricated outbreak.
Caption: Evidence grade: a conclusion synthesis.
Notes: Final-assessment synthesis across [1] through [15]; no live exposure assessment offered.
