# Slide plan: The Binance Hot-Wallet Theft of October 2026: A Case Study

- Study: case-studies/BINANCE_HEIST_2026.md
- Cover title: The Binance Hot-Wallet Theft / of October 2026 / A Case Study
- Subtitle: A five-month intrusion through three engineers, and most of $6.34 billion gone in minutes
- Published: 12 November 2026
- Notes: Slide plan for the deck of the study case-studies/BINANCE_HEIST_2026.md, published 12 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Three engineers were the way in

- June 2026: a wallet developer downloaded a tampered Homebrew installer; it was caught, but roles and colleagues were exposed.
- September: a second engineer's fake job assignment swapped a pyenv component, and endpoint tools missed it.
- 20 October: an internal AI tool gave the attackers two more devices and a container deployment token.
- 29 October: about $6.34 billion left hot wallets on ten chains, most of it within about 20 minutes.
- The FBI named North Korea's TraderTraitor on 31 October; Binance cites the FBI rather than its own finding.
Caption: Evidence grade: Confirmed as Binance and the FBI state; the 20-minute figure is Reported.
Notes: Intrusion chain [1][2]. Loss and start [1][3]. 20 minutes [9]. FBI alert [28]. Binance cites the FBI [2].

## KEY FACTS | A record theft with no CVE

Stat: $6.34B | Loss in Binance's post-mortem
Stat: $2.85B | Frozen or intercepted
Stat: 628 | Laundering addresses the FBI published
Stat: 98% | Assets replenished by 31 October
- Theft window: about 20:05 UTC on 29 October to the last transfer at 23:56 UTC.
- Estimates run from $5.8 billion to $6.43 billion; Binance's figure leads.
- No CVE applies: the exposure was people, tokens and internal tools.
Notes: Loss [1]; range [16][19]. Frozen [1][14]. Addresses [28]. Replenishment [1]. Window [1][3]. No CVE [1][23].

## PART 1 | Five months from installer to hot wallet

| Date (UTC) | Event |
|---|---|
| June 2026 | Tampered Homebrew installer; device replaced, credentials rotated |
| September 2026 | Fake job process; assignment swaps a pyenv component |
| 20 Oct | Internal AI tool takes over Engineers A and C's devices |
| 29 Oct | Container deployed with the stolen token; signing service abused |
| 29 Oct 20:05 | Hot wallets on ten chains start sending to attacker addresses |
| 29 Oct 23:56 | Final unauthorized transfer, 2,961.9 ETH |
| 30 Oct 00:10 | Binance clears the EIP-7702 delegation |
| 1 Nov | Phase-one withdrawals resume on 15 networks |
Caption: Binance gives the container window as 17:15 to 19:56; whether that is UTC or UTC+8 was not checked.
Notes: June and September [1][2]. Lateral movement [1]. Container [2]. Theft times [1][3]. Delegation [1][2]. Withdrawals [4].

## PART 2 | Two footholds, then a lateral path

- The June installer was detected; the device was replaced and credentials rotated.
- The engineer's role and colleague information were already exposed.
- In September a fictitious company ran two interview rounds, then sent an "assignment" repository.
- Its install script replaced a pyenv component; endpoint tools did not detect it.
- On 20 October the attackers used an internal AI tool to control two colleagues' devices.
Caption: Chainalysis ties the fake interview to a playbook refined over dozens of smaller attacks (Reported).
Notes: June foothold [1][2]. September foothold [1]; job-platform detail [13]. Lateral movement [1][2]. Teng on permissions [17].

## PART 2 | Why pausing withdrawals did not stop it

Left: What the attackers used
- The internal wallet signing service started the first transactions.
- On Ethereum, 50 signed EIP-7702 authorizations delegated execution to an attacker contract.
- The MPC hot wallet had no single key that could revoke them.
Right: What Binance found
- No evidence that wallet private keys leaked.
- The delegations sat outside the withdrawal system and outlived the pause.
- A special revocation at 00:10 UTC on 30 October ended the theft.
Caption: The signing service could start transactions outside the withdrawal flow (Inferred).
Notes: Signing service [2][21]. EIP-7702 [1]. No key leak [3]. Pause and revocation [1][2].

## DISCREPANCIES | The numbers differ by source

| Measure | Range in the record |
|---|---|
| Loss | $5.8B early tracking to $6.43B (Elliptic) |
| Frozen | About $2.7B (TRM) to about $3B (Update #2) |
| Chains | Ten (TRM) or 11 (Elliptic) |
| Start time | 20:05 UTC (Binance) or about 20:20 UTC (Chainalysis) |
| Replenished | 98% of token assets or 95% of the impacted amount |
Caption: This study leads with Binance's own figures; the two replenishment figures measure different things.
Notes: Loss [16][3][1][9][12][14][19]. Frozen [9][3][12][1][14]. Chains [9][14][19]. Start [1][3][9][12][14]. Replenishment [1][4].

## PART 3 | Analytics firms named the actor first

| Who | When | What |
|---|---|---|
| Chainalysis | 30 Oct 04:30 UTC | TraderTraitor, from commingling with Bitget proceeds |
| Elliptic | 30 Oct | North Korea likely, before the FBI |
| FBI, USSS, IRS-CI | 31 Oct | North Korea responsible; TraderTraitor |
| Binance | 3 Nov | Cites the FBI; names no actor itself |
| North Korea | 2 Nov | Kim Yo Jong calls the accusation absurd |
Caption: Analytics attributions and the denial are Reported; the FBI alert is Confirmed from the alert itself.
Notes: Chainalysis [12]. Elliptic [14]. FBI [28]. Binance [2]. Denial [21]. Public doubt in press [24].

## PART 4 | Freezes held 44%, mostly stablecoins

Stat: 44% | Of the theft frozen or seized
Stat: 94% | Of the frozen value in stablecoins
Stat: $786M | Stablecoins converted before freezes landed
Stat: $2.4B | ETH and BTC left with the attacker
- Binance bore the loss from its SAFU fund and treasury; deposits stayed open.
- Laundering ran through a self-minted TRON token, lending receipts and chained cross-chain swaps.
- The FBI asked node operators, exchanges and other VASPs to block 628 addresses.
Notes: Elliptic's figures [14]. Attacker holdings and laundering [10]. SAFU [3]. FBI request [28].

## PART 4 | Containment, recovery and remediation

- Deposits stayed open; more than $6.34 billion was set aside on 30 October.
- About 80% was replenished by 30 October and 98% by 31 October.
- Ten major assets were fully backed when withdrawals resumed on 1 November.
- Binance rebuilt the wallet system and the AI tool with new access controls.
- Devices replaced, credentials and tokens retired, every employee device scanned.
Caption: Binance plans an independent third-party review.
Notes: Set-aside and 80% [3]. 98% [1]. Withdrawals and backing [4]. Remediation [2].

## DEFENDER VIEW | The controls this record argues for

Left: Before the theft
- Isolated, disposable machines for interview assignments and unsolicited code.
- Verify developer-tool installers; watch toolchain components such as pyenv.
- Short-lived, scoped, device-bound deployment tokens.
Right: At the wallet
- Access control and logging on internal AI tools that act on endpoints.
- A signing service that signs only what the withdrawal flow approved.
- Monitor on-chain delegations and rehearse MPC revocation.
Caption: A program that ranks work by CVE or KEV would have seen nothing here (Inferred).
Notes: Assignments [1][13]. Installer and pyenv [1]. Token [1]. AI tool [1][2]. Signing and delegations [2]. The recommendations are Inferred.

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- Coverage that has Binance blaming TraderTraitor; Binance cites the FBI.
- The "compromised DevOps laptop" framing of the first days.
- "$6.3 billion lost" once about $2.85 billion was frozen.
Right: Understated
- About $2.4 billion stayed with the attacker.
- Pausing withdrawals did not stop delegated on-chain authorizations.
- Binance says it blocked 57 suspected North Korea-linked incidents in 2026.
Notes: Binance's position [2]. Laptop framing [17] against [1]. Frozen [1]. Attacker holdings [10]. Pause [2]. 57 incidents [1][2].

## MITRE MAPPINGS | Eleven techniques, no group bound

| Id | Technique | Tie to Binance |
|---|---|---|
| T1566.003 | Spearphishing via Service | The fake job approach |
| T1204.002 | Malicious File | Installer and assignment script run |
| T1036.005 | Match Legitimate Resource Name or Location | The swapped pyenv component |
| T1072 | Software Deployment Tools | The internal AI tool |
| T1550.001 | Application Access Token | The stolen deployment token |
| T1610 | Deploy Container | The 29 October container |
| T1657 | Financial Theft | The hot-wallet theft |
Caption: ATT&CK v20.0; also T1591.004, T1608.001, T1552 and T1070. CAPEC-163, CAPEC-616, CAPEC-593. No TraderTraitor object exists.
Notes: Techniques [1][2][13][20][21] with [27]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The hiring channel is an access channel

- **Recruiting lures reach privileged staff.** AA22-108A warned of this audience in 2022.
- **Developer tooling is supply chain.** A tampered installer did the work a vendor CVE does elsewhere.
- **Internal AI tools are privileged systems.** One moved the attackers between machines.
- **Freezes work only for some assets.** Stablecoins froze; ETH and BTC largely did not.
- **Attribution runs at blockchain speed.** Analytics firms named the actor within hours.
Notes: AA22-108A [5]. Installer [1]. AI tool [1]. Freezes [14][10]. Attribution [12][28]. The themes are Inferred from the record.
