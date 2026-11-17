# Selecting AES: How Rijndael Became a Standard Without Becoming a Complete Security System

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [Post-Quantum Migration Reference](/POST_QUANTUM_MIGRATION_REFERENCE.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Cryptography practitioners, application and platform engineers, and security historians

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 11 min (2,641 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a shorter, evidence-bounded account of the 2000 AES selection, you need to separate a selection decision from a final standard or a cipher from a complete secure-message format, or you want why losing finalists were not broken

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. Five finalists were not five failures waiting to be ranked](#_3-five-finalists-were-not-five-failures-waiting-to-be-ranked), [9. A block cipher is not a complete secure-message format](#_9-a-block-cipher-is-not-a-complete-secure-message-format)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [Post-Quantum Migration Reference](/POST_QUANTUM_MIGRATION_REFERENCE.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- The October 2000 Rijndael announcement was a selection decision, not the final publication of the federal standard. ([Executive assessment](#executive-assessment))
- This is an advancement case: a public competition became a precise, interoperable specification weighing security with efficiency. ([Executive assessment](#executive-assessment))
- Selection did not prove the losing finalists were broken or that every implementation of the winner was secure. ([Executive assessment](#executive-assessment))
- In the three AES variants the numbers 128, 192 and 256 describe key lengths, while all use 128-bit blocks. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

## Executive assessment

On October 2, 2000, NIST announced Rijndael as its proposed Advanced Encryption Standard. The winning design came from Belgian cryptographers Joan Daemen and Vincent Rijmen. The announcement was a selection decision, not the final publication of the federal standard: further public review and approval still lay ahead. [1]

AES is an advancement case rather than a breach narrative. Its importance lies in how a public technical competition became a precise interoperable specification. The process considered security together with implementation efficiency and flexibility. It did not establish that losing finalists were broken, that every implementation of the winner was secure, or that encryption alone supplied all the properties a secure application needs.

The formal FIPS 197 publication followed on November 26, 2001. Its three AES variants all use 128-bit blocks; the numbers 128, 192 and 256 in their names describe key lengths. NIST's May 2023 update made editorial improvements without changing the algorithm. [2]

This case separates the competition's chronology, the engineering judgment behind selection, the standard's technical boundary, and the later responsibilities of implementers. That separation avoids a common historical shortcut: treating a famous algorithm name as proof of the security of an entire product.

## 1. Evidence and reading scope

The account uses NIST's development archive, dated announcements, selected sections of the October 2000 development report, the AES3 conference report, the FIPS 197 specification, and related NIST publications. The original selection and standardization records are the evidence for historical decisions. Later pages establish the maintenance history, not what participants could have known in 2000.

The selection report is lengthy. The passages reviewed for this study include process background, qualitative versus quantitative evaluation, the number-of-algorithms decision, implementation comparisons, and the conclusion. This is not a claim that every cited cryptanalytic paper or every candidate implementation was independently reproduced.

The SP 800-38D publication landing page timed out twice, but its official NIST PDF was retrieved. That PDF is used only to explain the distinction between an underlying block cipher and authenticated-encryption modes. No current product recommendation or complete survey of modern AES cryptanalysis is offered.

No cryptographic benchmark was run. No proprietary product was certified, and no deployed system's encryption configuration was inspected. The article concerns a standards decision and the limits of the assurance that follows from it.

## 2. The development effort began before the winner was known

NIST's archive dates the initiation announcement to January 2, 1997 and the formal call for algorithms to September 12. The call sought a publicly disclosed, royalty-free symmetric block cipher, with specified minimum block and key sizes. Fifteen candidates were announced August 20, 1998. Public analysis continued through a second candidate conference in March 1999, followed by the first-round comment deadline on April 15. [3]

These milestones show that the requirements preceded the final choice. That matters because a standards competition can otherwise be narrated backward, as though the winner's existing characteristics were the only properties ever considered.

Public disclosure also had a technical purpose beyond publicity. Researchers needed a shared specification to analyze, implement, compare, and criticize. A confidential design with unexplained assurances would not have supplied the same basis for reproducible external evaluation.

The process did not make agreement automatic. It created a documented setting in which competing claims could be examined. The distinction between open evidence and unanimous preference remains important throughout the case.

## 3. Five finalists were not five failures waiting to be ranked

NIST announced the finalists August 9, 1999: MARS, RC6, Rijndael, Serpent, and Twofish. Its announcement stated that initial analysis had found no significant security vulnerabilities in those finalists. It described evaluation across computers and constrained devices, with contributions from public papers, conference discussion, submitted comments, and NIST's own testing. [4]

The implication is narrower than "all finalists were mathematically proven secure." The assessment reflected the analysis available at that point. It justified further scrutiny rather than terminating scrutiny.

It is equally wrong to infer that selecting Rijndael classified the other four as unsafe. Standardization can prefer one candidate among several credible designs because their practical advantages differ. A competition winner need not be the only acceptable design, and a non-selection need not represent a discovered flaw.

The first-round report's publication record describes further study before selecting one or more algorithms. That wording preserves an uncertainty that later summaries often erase: even the number of final algorithms had not been fixed at the finalist stage. [5]

## 4. AES3 made the practical tradeoffs visible

The third candidate conference took place April 13-14, 2000 in New York. Morris Dworkin's report records 230 registered participants from at least 26 countries and 24 papers. Sessions covered FPGA and ASIC implementations, platform-specific performance, cryptographic analysis, and debate over whether the standard should contain more than one algorithm. [6]

Those subjects explain why the decision was not simply a contest to produce the longest key or the fastest desktop encryption loop. Hardware area, software behavior, memory limits, and deployment flexibility could matter differently in different environments.

For a constrained device, memory use may be as consequential as throughput. For a hardware design, a highly parallel implementation may consume more area than a compact serial one. For an application that changes keys frequently, setup cost may matter differently from bulk encryption speed. These are engineering interpretations of the kinds of evaluations represented in the conference, not newly measured performance results.

The public discussion also made the single-winner question substantive. Multiple algorithms could offer diversity, but diversity would introduce implementation and interoperability obligations. The conference record is evidence that this was debated, not that everyone shared one view from the beginning.

## 5. NIST chose a qualitative judgment, not a universal numeric score

The October 2000 development report explains that NIST considered a weighted quantitative approach but judged many criteria too subjective for defensible numerical scoring. It also records the decision to select one algorithm and no designated backup, weighing interoperability and implementation concerns against diversity arguments. Its conclusion favored Rijndael's overall performance across environments, low memory needs, strong setup behavior, and amenability to defenses against timing and power analysis. [7]

The report did not claim one candidate dominated every comparison. Its conclusion treated all five as credible and selected the best overall fit.

This is an important form of technical judgment. A single score can appear objective even when the weights encode disputed assumptions. A qualitative decision is not automatically weaker if it makes those tradeoffs visible and supplies the evidence that informed them.

Nor does the choice of one standard imply that future cryptanalytic discoveries were impossible. It made interoperability and implementation costs part of the decision under uncertainty. A retrospective should explain that uncertainty rather than replace it with hindsight certainty about the eventual winner.

The article does not reproduce the report's benchmark tables as current performance comparisons. Processor generations, software techniques, hardware support, and implementation goals change. A historical measurement remains useful evidence of a historical choice without becoming a current buying guide.

## 6. Statistical testing was evidence, not a security proof

NISTIR 6483, published in April 2000, examined statistical properties of the finalists with 192-bit and 256-bit keys. Its publication abstract says the results supported the appearance of randomness for all five candidates. [8]

That result should not be promoted into proof that an adversary cannot recover a key or distinguish a construction through a more specialized attack. Statistical testing asks whether examined output behaves as expected under chosen tests. Cryptanalysis can ask questions those tests do not capture.

This distinction also explains why the competition used multiple forms of analysis. A favorable statistical result does not settle implementation cost, side-channel resistance, or the consequences of a particular mode of operation. The tests contributed to the record without replacing the rest of it.

The case therefore rejects a simplistic selection story in which Rijndael won because its ciphertext "looked the most random." The retrieved abstract actually reported favorable results for all five finalists. A conclusion that singles out one candidate on that basis would contradict the source.

## 7. Selection, publication, and deployment had different dates

The October 2, 2000 announcement called Rijndael the proposed AES and anticipated a further public-comment process. NIST's development archive records a draft FIPS in February 2001, a ninety-day comment period, and publication of FIPS 197 on November 26, 2001. [1,3]

The December 4, 2001 Commerce announcement then described AES as an official standard and discussed preparations for validation of implementations. It also said non-federal organizations were invited, rather than universally required, to adopt it. [9]

These distinctions prevent three common mistakes. The 2000 selection is not the 2001 final specification. The publication of a specification is not proof that every product immediately implemented it. And a federal standard's existence is not a universal mandate covering every private user.

The staged process also gave implementers a stable target. A competition candidate is a proposal under evaluation. A final standard defines exactly which behavior implementations must match. Validation then assesses conformance against that target. Those activities build on one another but should not be collapsed into a single announcement.

## 8. What AES actually specifies

FIPS 197 specifies three configurations: AES-128, AES-192, and AES-256. Their keys are 128, 192, and 256 bits; their blocks are always 128 bits. They use ten, twelve, and fourteen rounds respectively. The standard defines a key expansion and transformations called SubBytes, ShiftRows, MixColumns, and AddRoundKey, with the final round omitting MixColumns. It explicitly limits conformance to the specified Rijndael configurations. [10]

The distinction between key size and block size matters in technical writing. Calling AES-256 a "256-bit block cipher" is incorrect if that phrase is intended to describe the block width. A larger AES key does not turn the state into a larger block.

The relationship with Rijndael also needs precision. AES is a standardized selection from that cipher family, not permission to label every possible Rijndael parameter combination AES. Interoperability depends on using the specified configurations rather than merely invoking a familiar family name.

This article does not present a hand-rolled implementation. Naming the transformations explains the specification's structure; it does not recommend implementing cryptography from a prose case study.

## 9. A block cipher is not a complete secure-message format

NIST's December 2001 SP 800-38A defines confidentiality modes such as CBC, CFB, OFB and CTR for underlying block ciphers, alongside ECB. The publication's scope is the mode of operation, not the selection of AES itself. [11]

The separate document makes an architectural boundary visible. A block cipher transforms a fixed-size block under a key. Applications usually need to protect messages with lengths, structure, and operational constraints that go beyond one block. Their mode and surrounding protocol determine additional properties.

NIST's November 2007 SP 800-38D specifies GCM for authenticated encryption with associated data and GMAC for authentication of data that is not encrypted. It separately addresses IV uniqueness and implementation considerations. [12]

That separation explains why the phrase "uses AES" cannot establish message integrity, correct nonce handling, key management, or secure storage of key material. Those properties belong to the construction and implementation around the primitive. An algorithm can remain sound while a product using it fails at a different boundary.

The 2007 mode document is later context, not an ingredient retroactively inserted into the 2000 selection. This study uses it to show what the selection did not, and could not, specify by itself.

## 10. Validation and implementation security

The December 2001 announcement discussed testing through accredited laboratories and validation of implementations. That work addresses whether the complex specification has been implemented correctly; it is not equivalent to selecting the algorithm. [9]

A conforming implementation and a secure deployment remain different objects. A system may correctly compute an encryption primitive while mishandling a key, exposing plaintext elsewhere, or selecting an unsuitable surrounding construction. That is a logical boundary of what conformance can establish, not a finding about any named validated product.

Implementation attacks also should not be confused with a mathematical break of AES. The selection report considered power and timing defenses as implementation issues. A report about leakage from a particular implementation must identify that scope rather than imply that all AES ciphertext has become readable. [7]

No current side-channel survey is claimed here. The historical importance is that implementation constraints were already part of the evaluation, rather than an entirely separate concern discovered only after standardization.

## 11. The 2023 update did not create a new cipher

NIST announced an editorial update to FIPS 197 on May 9, 2023. It improved terminology, formatting, explanatory material, and key-schedule diagrams without technical changes to the algorithm. The announcement records an initial review call in May 2021 and a December 2022 draft-update proposal. [13]

A revised publication date can otherwise be misread as evidence that the cipher was replaced or repaired. In this case NIST explicitly says the algorithm was unchanged. That does not eliminate the value of clearer documentation: precision in notation and explanation can matter to readers and implementers even when the mathematical transformation remains the same.

The update also illustrates how a standard can be maintained without staging another competition. Selection, specification clarity, implementation validation, and continuing review are related but distinct activities across the life of a cryptographic standard.

This case does not infer eternal security from that editorial decision. NIST's original official-standard announcement itself cautioned that nobody could know indefinitely how long an algorithm would remain secure. Historical confidence should not be rewritten as a guarantee without limits. [9]

## 12. Case conclusion

The AES selection combined an openly examined design space with a documented judgment about practical suitability. The result was a precise standard, not a claim that every competing design had failed or that every later AES-based product would be safe.

Its lasting analytical lesson is to keep the levels separate. The competition assessed candidate algorithms. FIPS 197 specified the selected configurations. Modes added ways of applying a primitive. Validation checked implementation conformance. Deployments still had to protect keys and use constructions correctly.

The evidence supports a major standards advancement, but not a single quantified global benefit or a complete account of every subsequent cryptanalytic result. This focused history preserves what the sources establish: the dates, alternatives, technical boundaries, and maintenance decisions that made AES a standard.

## Sources and reading scope

[1] NIST, Commerce Department Announces Winner of Global Information Security Competition, 2 October 2000. Proposed selection, designers and next review stage. https://www.nist.gov/news-events/news/2000/10/commerce-department-announces-winner-global-information-security

[2] NIST, FIPS 197 publication record, original 26 November 2001, updated 9 May 2023. Variant naming and no-technical-change notice. https://csrc.nist.gov/pubs/fips/197/final

[3] NIST, AES Development archive. Selected chronology from 1997 initiation through 2001 publication. https://csrc.nist.gov/Projects/Cryptographic-Standards-and-Guidelines/Archived-Crypto-Projects/AES-Development

[4] NIST, NIST Announces Encryption Standard Finalists, 9 August 1999. Finalist names and initial evaluation scope. https://www.nist.gov/news-events/news/1999/08/nist-announces-encryption-standard-finalists

[5] NIST, Status Report on the First Round, publication record dated 1 October 1999. Abstract and future-selection wording; full first-round paper not independently reproduced. https://csrc.nist.gov/pubs/journal/1999/10/first-round-status-report-on-aes-development/final

[6] Morris Dworkin, NIST, Third AES Candidate Conference report, 13-14 April 2000. Participation, sessions and multiple-winner discussion. https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/aes-development/aes3report.pdf

[7] Nechvatal and colleagues, NIST, Report on the Development of AES, dated 2 October 2000. Selected methodology, implementation comparison and conclusion passages; no current benchmark claim. https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=151226

[8] Soto and Bassham, NISTIR 6483 publication abstract, April 2000. Statistical-testing scope and qualified results. https://www.nist.gov/publications/randomness-testing-advanced-encryption-standard-finalist-candidates

[9] NIST, Commerce Secretary Announces New Standard for Global Information Security, 4 December 2001. Official status, voluntary non-federal adoption, validation and longevity caveat. https://www.nist.gov/news-events/news/2001/12/commerce-secretary-announces-new-standard-global-information-security

[10] NIST, FIPS 197 updated specification, May 2023, especially section 5 and Table 3. Fixed block width, key lengths, rounds and transformations. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

[11] NIST, SP 800-38A publication record, December 2001. Confidentiality-mode scope; not current deployment advice. https://csrc.nist.gov/pubs/sp/800/38/a/final

[12] NIST, SP 800-38D, November 2007. Abstract, scope and IV-uniqueness context; official PDF retrieved after landing-page timeouts. https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

[13] NIST, NIST Updates FIPS 197, 9 May 2023. Editorial changes and review chronology. https://www.nist.gov/news-events/news/2023/05/nist-updates-fips-197-advanced-encryption-standard-aes
