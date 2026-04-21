# Blockchain & Web3 Security

Blockchain and Web3 security encompasses the practices, tools, and controls required to secure blockchain protocols, smart contracts, DeFi protocols, NFT platforms, Web3 applications, and cryptocurrency infrastructure. It is a growing specialized discipline combining traditional web application security and cryptography skills with protocol-level analysis unique to decentralized systems. Unlike conventional software, smart contracts are immutable once deployed — bugs cannot be patched after the fact, making pre-deployment security review the only reliable defense. A single vulnerability in a widely-used DeFi protocol can result in nine-figure losses within a single transaction.

The discipline sits at the intersection of cryptography, distributed systems, and software security. Practitioners must understand not only code-level vulnerabilities like reentrancy and integer overflow, but also protocol-level attack surfaces including flash loans, oracle manipulation, bridge exploits, and MEV (Miner/Maximum Extractable Value). The historical record is stark: The DAO hack ($60M, 2016), Ronin bridge ($625M, 2022), and Wormhole bridge ($320M, 2022) represent a pattern of high-consequence exploits against systems securing real economic value with no recovery mechanism.

---

## Where to Start

Begin with Solidity and smart contract fundamentals before studying vulnerability classes. Understanding how the EVM executes code, how storage slots work, and what the call stack looks like at the bytecode level makes every vulnerability class more concrete. Ethernaut CTF and Damn Vulnerable DeFi are the hands-on starting points — working through them in order covers the majority of real-world exploit patterns.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Solidity basics, EVM execution model, how transactions and gas work, common vulnerability classes (reentrancy, integer overflow, access control failures), reading Etherscan | [CryptoZombies](https://cryptozombies.io/) (free Solidity tutorial), [Ethernaut CTF](https://ethernaut.openzeppelin.com/) (OpenZeppelin), Capture the Ether, Solidity documentation, Remix IDE |
| Practitioner | DeFi protocol mechanics (AMMs, lending, flash loans), oracle design and manipulation, bridge security, running Slither and Mythril on real contracts, reading audit reports from Trail of Bits and OpenZeppelin | [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/), Secureum Epoch 0, Trail of Bits public audit reports, rekt.news postmortems, Foundry testing framework |
| Advanced | Formal verification with Certora Prover, fuzzing with Echidna, MEV and front-running research, cross-chain bridge architecture, protocol-level governance attacks, conducting full audit engagements | Secureum Bootcamp, Smart Contract Auditing Heuristics (Patrickd), Spearbit audit reports, DeFiHackLabs PoC repository |

---

## Smart Contract Vulnerability Classes

### Reentrancy
The most famous smart contract vulnerability class. When a contract sends ETH (or calls an external contract) before updating its own state, the receiving contract can call back into the sender and withdraw again before the balance is decremented.

**The DAO (2016, $60M)**: The DAO's `splitDAO()` function sent ETH to a "child DAO" before updating the balance. An attacker deployed a malicious contract whose fallback function recursively called back into `splitDAO()`, draining 3.6M ETH before the balance ever decreased. This led to the Ethereum hard fork.

**Reentrancy pattern**:
```
1. Victim contract checks balance (OK)
2. Victim sends ETH to attacker
3. Attacker fallback() fires → calls back into victim withdraw()
4. Victim checks balance again (still unchanged — state not yet updated)
5. Victim sends ETH again → repeat until drained
6. Victim finally updates balance (too late)
```
**Fix**: Checks-Effects-Interactions pattern (update state before external calls) or ReentrancyGuard mutex.

### Integer Overflow / Underflow
Solidity <0.8.0 arithmetic wraps silently. A `uint256` at 0 minus 1 becomes `2^256 - 1`. Attackers exploit this to bypass balance checks or manufacture large token balances. Fixed in Solidity 0.8+ with built-in overflow reversion; older contracts should use SafeMath.

### Access Control Failures
Functions that should be restricted (owner-only, admin-only) are left `public` or lack proper role checks. The Parity multisig wallet (2017, $30M) was drained because the `initWallet()` function had no access control and could be called by anyone to re-initialize ownership.

### Front-Running / MEV (Miner Extractable Value)
Miners and MEV bots can observe pending transactions in the mempool and insert their own transactions with higher gas to execute first. DEX sandwich attacks extract value by front-running a large trade (buying before it, selling after), moving the price against the victim. Commit-reveal schemes and private mempools (Flashbots Protect) mitigate but do not eliminate MEV.

### Flash Loan Attacks
Flash loans allow borrowing millions of tokens within a single transaction at zero cost — the loan must be repaid by the end of the transaction or everything reverts. Attackers use flash loans to manipulate DeFi protocol state temporarily: borrow enormous sums, manipulate an oracle or liquidity pool, exploit the manipulated state in another protocol, repay the loan, keep the profit — all in one transaction.

**Cream Finance (2021, $130M)**: Attacker used a flash loan to borrow large amounts, manipulate the price oracle used by Cream Finance's lending market, and drain the protocol's reserves by borrowing against artificially inflated collateral.

### Oracle Manipulation
DeFi protocols rely on price oracles to determine asset values. On-chain oracles derived from DEX spot prices can be manipulated by large trades. When a protocol uses a spot price as a collateral value, an attacker can temporarily manipulate that price to borrow far more than they should be able to, then let the price return to normal.

### Bridge Vulnerabilities
Cross-chain bridges lock assets on one chain and mint representations on another. The locking/minting logic represents one of the highest-value attack surfaces in crypto.

- **Ronin Bridge ($625M, March 2022)**: Lazarus Group (North Korea) compromised 5 of 9 Ronin validator keys (4 via a single entity running multiple validators), enabling them to forge withdrawal approvals and drain the bridge over several days before discovery.
- **Wormhole Bridge ($320M, February 2022)**: A signature verification flaw in the Solana side of the bridge allowed an attacker to mint 120,000 wETH without depositing any ETH — a pure arithmetic/logic exploit in the verification code.

### Rug Pulls
Malicious project developers retain privileged contract functions (unlimited mint, drain liquidity, upgrade proxy) and use them to steal funds after building up significant liquidity and community trust. Unlike exploits, rug pulls are intentional fraud by the deployers.

---

## Free Training

- [Ethernaut CTF (OpenZeppelin)](https://ethernaut.openzeppelin.com/) — The foundational smart contract security CTF; 20+ progressively difficult challenges covering reentrancy, delegatecall abuse, storage layout, and access control
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/) — DeFi-focused CTF covering flash loan attacks, oracle manipulation, lending protocol exploits, and governance attacks; the practical complement to Ethernaut
- [Capture the Ether](https://capturetheether.com/) — Smart contract security challenges covering integer overflow, lotteries, accounts, and math vulnerabilities
- [Secureum Epoch 0](https://secureum.substack.com/) — Comprehensive free smart contract security curriculum covering Solidity, EVM, security pitfalls, and audit methodology
- [Trail of Bits Blog](https://blog.trailofbits.com/) — Free technical blog from one of the top smart contract audit firms
- [rekt.news](https://rekt.news/) — Postmortem analysis of major DeFi exploits; one of the fastest ways to understand real-world attack patterns
- [Smart Contract Security Best Practices](https://consensys.github.io/smart-contract-best-practices/) — Community-maintained reference covering known vulnerability classes and secure development patterns
- [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) — Foundry-based reproductions of major DeFi hacks; learn attack mechanics hands-on

---

## Tools & Repositories

### Static Analysis
- [crytic/slither](https://github.com/crytic/slither) — Most widely used open-source Solidity static analyzer from Trail of Bits; detects reentrancy, access control issues, and 80+ other vulnerability classes; fast and CI/CD-ready
- [ConsenSys/mythril](https://github.com/ConsenSys/mythril) — Symbolic execution tool for EVM bytecode; detects integer overflows, reentrancy, and other vulnerabilities by exploring all code paths; operates on bytecode without source
- [Certora Prover](https://www.certora.com/) — Formal verification platform; proves correctness properties hold for all possible inputs; used by Aave, Compound, and other major protocols
- [trailofbits/manticore](https://github.com/trailofbits/manticore) — Symbolic execution tool for EVM and native binaries; supports complex multi-contract analysis

### Fuzzing & Testing
- [crytic/echidna](https://github.com/crytic/echidna) — Property-based fuzzer for Ethereum smart contracts from Trail of Bits; tests user-defined invariants by generating random transaction sequences; the standard for smart contract fuzzing
- [foundry-rs/foundry](https://github.com/foundry-rs/foundry) — Modern smart contract development and testing framework; Forge (testing + fuzz), Cast (chain interaction), Anvil (local node); fastest test execution for Solidity
- [trufflesuite/hardhat](https://github.com/NomicFoundation/hardhat) — Ethereum development environment; task runner, testing framework, and network forking for security testing; widely used in existing audit workflows alongside Foundry
- [OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) — The standard audited base library for Solidity; secure implementations of ERC tokens, access control, and proxy patterns; using it reduces custom vulnerability surface

### Runtime Monitoring
- [forta-network/forta-core-go](https://github.com/forta-network/forta-core-go) — Decentralized threat detection network; community-run bots monitoring on-chain activity for exploits and anomalous transactions
- [OpenZeppelin Defender](https://www.openzeppelin.com/defender) — Smart contract operations platform with automated monitoring, incident response, and upgrade management
- [Tenderly](https://tenderly.co/) — Smart contract monitoring, alerting, and simulation platform; transaction simulation before on-chain execution

### Blockchain Analytics
- [Etherscan](https://etherscan.io/) — Primary Ethereum block explorer; essential for investigating transactions, tracing fund flows, reading verified contract source
- [SunWeb3Sec/DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) — PoC exploit reproductions for major DeFi hacks in Foundry; study real attack implementations
- [Breadcrumbs](https://www.breadcrumbs.app/) — Blockchain address tracking and visualization; maps fund flows across addresses for attribution

---

## Commercial Platforms

| Platform | Strength |
|---|---|
| **Trail of Bits** | Most technically rigorous smart contract audit firm; deep expertise in formal verification, fuzzing, and custom tooling; public reports are valuable free learning resources |
| **OpenZeppelin** | Smart contract audits plus the standard secure base library; Defender platform for operational security |
| **CertiK** | High-volume audit firm with on-chain security score tracking; broad coverage across EVM-compatible chains |
| **Halborn** | Blockchain security covering smart contract audits, Web3 infrastructure pentesting, and protocol advisory |
| **Immunefi** | Dominant bug bounty platform for Web3; bounty programs with payouts reaching $10M+; primary market for white-hat smart contract researchers |
| **Chainalysis** | Blockchain analytics and investigation; transaction tracing, compliance screening used by exchanges and law enforcement |
| **Elliptic** | Blockchain analytics competitor; crypto asset risk scoring, transaction monitoring, and sanctions screening |

---

## NIST 800-53 Control Alignment

| Control | ID | Blockchain & Web3 Relevance |
|---|---|---|
| Developer Testing and Evaluation | SA-11 | Pre-deployment smart contract security testing — static analysis (Slither), symbolic execution (Mythril), fuzzing (Echidna), formal verification (Certora) — is the primary preventive control given immutability |
| Vulnerability Scanning | RA-5 | Continuous static analysis of contract code, runtime monitoring via Forta and OpenZeppelin Defender, and regular audit engagements constitute the vulnerability scanning program |
| Protection of Information at Rest | SC-28 | Private key management via HSMs, hardware wallets, and multi-signature schemes protects cryptographic credentials controlling contract ownership and treasury funds |
| Access Enforcement | AC-3 | Smart contract access control — owner patterns, role-based access via OpenZeppelin AccessControl, multi-signature governance — enforces authorization for privileged functions |
| Software and Information Integrity | SI-7 | Smart contract bytecode verification on Etherscan, immutable deployment addresses, and formal verification of critical invariants provide integrity assurance |
| Configuration Management | CM-2, CM-6 | Immutable contract deployment as a baseline; proxy upgrade patterns must be documented and controlled; timelock mechanisms enforce change management delays |
| Audit and Accountability | AU-2, AU-9 | On-chain event logs (emitted events) are immutable and auditable; monitoring for unexpected privileged function calls detects unauthorized access attempts |
| Supply Chain Risk Management | SR-3 | npm dependency auditing for Web3 frontends, pinning OpenZeppelin library versions, and verifying contract bytecode against audited source prevents supply chain compromise |

---

## ATT&CK Coverage

| Technique | ID | Web3 Security Control |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Pre-deployment audits, Slither static analysis, Echidna fuzzing, and formal verification address smart contract vulnerabilities; runtime monitoring detects active exploitation |
| Unsecured Credentials | T1552 | Hardware wallet adoption, HSM-based key management, multi-signature schemes, and eliminating private keys in code or environment variables prevent key exposure |
| Financial Theft | T1657 | Multi-signature treasury controls, timelocks on administrative functions, circuit breakers (pause mechanisms), and real-time Forta monitoring reduce financial theft impact |
| Supply Chain Compromise | T1195 | npm dependency auditing for Web3 frontends, pinning library versions, and verifying bytecode against audited source prevents supply chain attacks |
| Phishing | T1566 | Web3 phishing targets wallet seed phrases and private keys; hardware wallets, browser extension security, and transaction simulation reduce phishing impact on assets |
| Resource Hijacking | T1496 | Gas limit analysis and monitoring for unexpected resource consumption detects griefing attacks against smart contracts |
| Adversary-in-the-Middle | T1557 | Front-running and MEV extraction intercept transactions; private mempools (Flashbots Protect), commit-reveal schemes, and slippage controls mitigate |
| Exploitation for Privilege Escalation | T1068 | Reentrancy, integer overflow, and access control failures enable attackers to gain unauthorized control of contract funds or admin roles |

---

## Certifications

There is no single dominant certification for smart contract security — the discipline is young enough that demonstrated skills outweigh credentials. The recognized pathway is:

- **Portfolio-Based Recognition** — The Web3 security community weights demonstrated audit findings, public CTF results (Ethernaut, Damn Vulnerable DeFi), Immunefi bug bounty payouts, and Code4rena audit competition rankings above formal certifications
- **Smart Contract Auditor Pathway**: Ethernaut → Damn Vulnerable DeFi → Secureum Epoch 0 → real audit contest participation (Code4rena, Sherlock, Cantina) → private engagements or internal audit roles
- **CBSP** (Certified Blockchain Security Professional — EC-Council) — The most recognized formal blockchain security certification; covers blockchain fundamentals, smart contract vulnerabilities, and DeFi security
- **CSSLP** (Certified Secure Software Lifecycle Professional — ISC2) — Secure SDLC credential applicable to smart contract development practices
- **OSCP** (Offensive Security Certified Professional) — Offensive methodology provides the attacker mindset essential for smart contract auditing; many top auditors hold OSCP for its offensive reasoning foundation

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Ethernaut CTF](https://ethernaut.openzeppelin.com/) | Free CTF | Foundational smart contract security CTF; 20+ challenges covering core vulnerability classes |
| [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/) | Free CTF | DeFi attack challenges covering flash loans, oracle manipulation, and governance exploits |
| [Secureum Substack](https://secureum.substack.com/) | Free curriculum | Comprehensive structured smart contract security curriculum |
| [rekt.news](https://rekt.news/) | Free postmortems | Ranked postmortems of DeFi exploits; essential reading for real attack patterns |
| [Trail of Bits Public Audits](https://github.com/trailofbits/publications) | Free audit reports | High-quality audit reports covering real protocol vulnerabilities |
| [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) | Free PoC repo | Foundry-based reproductions of major DeFi hacks |
| [Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/) | Free reference | Consensys Diligence reference covering known vulnerability patterns and mitigations |
| [Foundry Book](https://book.getfoundry.sh/) | Free reference | Complete Foundry documentation; fuzz testing, fork testing, and cheatcodes for security testing |

---

## Related Disciplines

- [Application Security](application-security.md)
- [Cryptography & PKI](cryptography-pki.md)
- [Bug Bounty](bug-bounty.md)
- [Offensive Security](offensive-security.md)
- [Supply Chain Security](supply-chain-security.md)
