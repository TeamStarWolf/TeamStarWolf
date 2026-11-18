# Slide plan: Selecting AES as a standard

- Study: case-studies/NIST_AES_2000.md
- Cover title: Open competition / Public cryptanalysis / A durable standard
- Subtitle: How NIST ran a public 1997 to 2000 contest to replace DES and selected Rijndael as AES through openness rather than secret design.
- Published: 18 November 2026
- Notes: The cover frames AES as a standards and process case, where transparency built trust and selection was a decision rather than a final guarantee.

## PROCESS | A competition before its winner
NIST documented each milestone in sequence before Rijndael was chosen.

| Date | Milestone |
| --- | --- |
| 2 January 1997 | Development effort initiated |
| 12 September 1997 | Formal call for algorithms |
| 20 August 1998 | Fifteen candidates announced |
| 9 August 1999 | Five finalists announced |
| 2 October 2000 | Rijndael selected as proposed AES |
Caption: Evidence grade: Confirmed (NIST development archive and dated announcements)
Notes: The dated chronology shows the requirements preceded the final choice, so the contest cannot be narrated backward from the winner.

## OPENNESS | Public disclosure was the point
- The call sought a publicly disclosed, royalty-free symmetric block cipher with specified minimum block and key sizes.
- Researchers needed a shared specification to analyze, implement, compare, and criticize.
- A confidential design with unexplained assurances could not supply the same basis for reproducible external evaluation.
- The process created a documented setting for examining competing claims, not automatic agreement.
Caption: Evidence grade: Confirmed (call for algorithms, NIST development archive)
Notes: Open specifications made external cryptanalysis possible, which is the mechanism this case treats as the source of trust.

## FINALISTS | Five credible designs, not five failures
NIST announced the finalists on 9 August 1999 and reported no significant security vulnerabilities found at that point.

| Finalist | Status |
| --- | --- |
| MARS | Credible design, not selected |
| RC6 | Credible design, not selected |
| Rijndael | Selected October 2000 |
| Serpent | Credible design, not selected |
| Twofish | Credible design, not selected |
Caption: Evidence grade: Confirmed (NIST finalist announcement, 9 August 1999)
Notes: Selecting one candidate among several credible designs did not classify the other four as broken or unsafe.

## AES3 | The conference that showed tradeoffs
Stat: 230 | Registered participants at AES3
Stat: 26 | Countries represented
Stat: 24 | Papers presented
- Sessions covered FPGA and ASIC implementations, platform performance, and cryptographic analysis.
- Participants debated whether the standard should contain more than one algorithm.
Caption: Evidence grade: Reported (Third AES Candidate Conference report)
Notes: The conference record shows the single-winner question and the hardware and software tradeoffs were actively debated.

## JUDGMENT | A qualitative decision, not one score
- NIST considered a weighted quantitative approach but judged many criteria too subjective for defensible numerical scoring.
- It selected one algorithm with no designated backup, weighing interoperability and implementation concerns against diversity.
- The conclusion favored Rijndael's overall performance, low memory needs, strong setup behavior, and side-channel defenses.
- The report treated all five finalists as credible and chose the best overall fit, not a universal winner.
Caption: Evidence grade: Confirmed (Report on the Development of AES, 2 October 2000)
Notes: A visible qualitative judgment made the disputed weights explicit rather than hiding them inside one apparently objective number.

## EVIDENCE | Statistical randomness is not a proof
Left: What the testing reported
- NISTIR 6483 examined statistical properties of the finalists with 192-bit and 256-bit keys.
- The abstract reported results consistent with the appearance of randomness for all five candidates.
Right: What it did not settle
- Favorable statistics do not prove an adversary cannot recover a key or distinguish a construction.
- The result did not settle implementation cost, side-channel resistance, or mode of operation.
Caption: Evidence grade: Reported (NISTIR 6483 publication abstract, April 2000)
Notes: Because all five finalists tested favorably, no selection story can rest on one candidate's ciphertext looking the most random.

## DATES | Selection, publication and deployment
The announcement, the specification, and the official standard each carried a distinct date.

| Stage | Date |
| --- | --- |
| Rijndael named proposed AES | 2 October 2000 |
| FIPS 197 published | 26 November 2001 |
| Official standard announced | 4 December 2001 |
Caption: Evidence grade: Confirmed (NIST development archive and Commerce announcements)
Notes: Separating these dates prevents treating a 2000 selection as the final specification or as a universal mandate on every private user.

## SPEC | What FIPS 197 actually defines
FIPS 197 specifies three configurations whose keys differ while every block stays 128 bits.

| Variant | Key bits | Block bits | Rounds |
| --- | --- | --- | --- |
| AES-128 | 128 | 128 | 10 |
| AES-192 | 192 | 128 | 12 |
| AES-256 | 256 | 128 | 14 |
Caption: Evidence grade: Confirmed (FIPS 197 specification, section 5 and Table 3)
Notes: The numbers name key lengths, so calling AES-256 a 256-bit block cipher misstates the fixed 128-bit block width.

## BOUNDARY | A cipher is not a message format
Left: The primitive
- A block cipher transforms a fixed-size block under a key.
- SP 800-38A defines confidentiality modes such as CBC, CFB, OFB, and CTR.
Right: The surrounding construction
- SP 800-38D specifies GCM and GMAC for authenticated encryption with associated data.
- Integrity, nonce handling, key management, and storage belong to the construction.
Caption: Evidence grade: Confirmed (SP 800-38A, December 2001; SP 800-38D, November 2007)
Notes: The phrase "uses AES" cannot establish message integrity or safe key handling, since those properties sit around the primitive.

## VALIDATION | Conformance is not secure deployment
- Accredited laboratories validate whether the complex specification was implemented correctly.
- A conforming implementation can still mishandle a key, expose plaintext elsewhere, or use an unsuitable construction.
- Implementation attacks are a different matter from a mathematical break of the algorithm.
- Power and timing defenses were already treated as implementation issues during the selection.
Caption: Evidence grade: Confirmed (Commerce announcement, 4 December 2001; development report)
Notes: Validation checks conformance against the specified target and cannot by itself certify that a whole deployment is secure.

## MAINTENANCE | The 2023 update changed words
- NIST announced an editorial update to FIPS 197 on 9 May 2023.
- It improved terminology, formatting, explanatory material, and key-schedule diagrams.
- NIST states the update made no technical changes to the algorithm.
- The review chronology records an initial call in May 2021 and a December 2022 draft proposal.
Caption: Evidence grade: Confirmed (NIST FIPS 197 update announcement, 9 May 2023)
Notes: A revised publication date reflects clearer documentation, not a replaced or repaired cipher.

## TRUST | Why openness outperformed secrecy
Left: Open public process
- Shared specifications let outside researchers test and criticize each candidate.
- Documented criteria and conference debate exposed the tradeoffs behind the choice.
Right: Secret design
- Unexplained assurances offer no basis for reproducible external evaluation.
- Confidence rests on authority rather than examined evidence.
Caption: Evidence grade: Inferred (contrast drawn from the documented open process)
Notes: Transparency functioned as the trust mechanism because confidence came from public analysis rather than from hidden design.

## BOUNDS | A durable baseline, not eternal proof
- Selection reflected the best public analysis available at that time, not a guarantee for all time.
- NIST itself cautioned that nobody could know indefinitely how long an algorithm would stay secure.
- Confidence is maintained by continuing review, not by a one-time decision.
- A standard is a durable, stable target for implementers rather than a permanent proof.
Caption: Evidence grade: Confirmed (Commerce announcement longevity caveat, 4 December 2001)
Notes: Keeping assurances bounded preserves the distinction between an openly chosen standard and an unlimited promise of security.

## LESSON | Keep the levels separate
- The competition assessed candidate algorithms against documented criteria.
- FIPS 197 specified the selected configurations precisely.
- Modes of operation add ways of applying the primitive to real messages.
- Validation checks conformance, while deployments still must protect keys and use constructions correctly.
Caption: Evidence grade: Confirmed (case synthesis of NIST selection and standardization records)
Notes: The lasting lesson is to keep selection, specification, modes, validation, and deployment distinct rather than collapse them into one name.
