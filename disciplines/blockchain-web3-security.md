# Blockchain & Web3 Security

Blockchain and Web3 security encompasses the practices, tools, and controls required to secure blockchain protocols, smart contracts, DeFi protocols, NFT platforms, Web3 applications, and cryptocurrency infrastructure. It is a growing specialized discipline that combines traditional web application security and cryptography skills with protocol-level analysis unique to decentralized systems. Unlike conventional software, smart contracts are immutable once deployed — bugs cannot be patched after the fact, making pre-deployment security review the only reliable defense. A single vulnerability in a widely-used DeFi protocol can result in nine-figure losses within a single transaction.

The discipline sits at the intersection of cryptography, distributed systems, and software security. Practitioners must understand not only how to identify code-level vulnerabilities like reentrancy and integer overflow but also how to reason about protocol-level attack surfaces including flash loans, oracle manipulation, bridge exploits, and MEV (Miner Extractable Value). The historical record is stark: The DAO hack ($60M, 2016), Ronin bridge ($625M, 2022), and Wormhole bridge ($320M, 2022) represent a pattern of high-consequence exploits against systems securing real economic value with no recovery mechanism.

---

## Where to Start

Begin with Solidity and smart contract fundamentals before studying vulnerability classes. Understanding how the EVM executes code, how storage slots work, and what the call stack looks like at the bytecode level makes every vulnerability class more concrete. The Ethernaut CTF and Damn Vulnerable DeFi are the hands-on starting points — working through them in order covers the majority of real-world exploit patterns.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Solidity basics, EVM execution model, how transactions and gas work, common vulnerability classes (reentrancy, integer overflow, access control), reading Etherscan | CryptoZombies (free Solidity tutorial), Ethernaut CTF (OpenZeppelin), Capture the Ether, Solidity documentation, Remix IDE for experimentation |
| Practitioner | DeFi protocol mechanics (AMMs, lending, flash loans), oracle design and manipulation, bridge security, running Slither and Mythril on real contracts, reading audit reports from Trail of Bits and OpenZeppelin | Damn Vulnerable DeFi (v3/v4), Secureum Epoch 0 material, Trail of Bits public audit reports, rekt.news postmortems, Foundry testing framework |
| Advanced | Formal verification with Certora Prover, fuzzing with Echidna, MEV and front-running research, cross-chain bridge architecture, protocol-level governance attacks, conducting full audit engagements | Secureum Bootcamp, Smart Contract Auditing Heuristics (Patrickd), Spearbit audit reports, DeFiHackLabs PoC repository, academic cryptography foundations |

---

## Free Training

- [Ethernaut CTF (OpenZeppelin)](https://ethernaut.openzeppelin.com/) — The foundational smart contract security CTF; 20+ progressively difficult challenges covering reentrancy, delegatecall abuse, storage layout, and access control; every serious Web3 security practitioner works through this first
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/) — DeFi-focused CTF covering flash loan attacks, oracle manipulation, lending protocol exploits, and governance attacks; the practical complement to Ethernaut for DeFi security
- [Capture the Ether](https://capturetheether.com/) — Smart contract security challenges covering integer overflow, lotteries, accounts, and math vulnerabilities; good complement to Ethernaut for foundational vulnerability coverage
- [Secureum Epoch 0](https://secureum.substack.com/) — Comprehensive free smart contract security curriculum from the Secureum community; covers Solidity, EVM, security pitfalls, and audit methodology in structured modules
- [Trail of Bits Blog](https://blog.trailofbits.com/) — Free technical blog from one of the top smart contract audit firms; covers vulnerability research, tool releases, and protocol analysis at practitioner and research depth
- [Consensys Diligence Blog](https://consensys.io/diligence/blog/) — Smart contract security research and audit insights from Consensys; good practitioner-level coverage of common vulnerability patterns
- [rekt.news](https://rekt.news/) — Postmortem analysis of major DeFi exploits; reading these in order is one of the fastest ways to understand real-world attack patterns and protocol-level thinking
- [Smart Contract Security Best Practices](https://consensys.github.io/smart-contract-best-practices/) — Community-maintained reference covering known vulnerability classes, secure development patterns, and recommendations for Solidity developers

---

## Tools & Repositories

### Static Analysis
- [crytic/slither](https://github.com/crytic/slither) — The most widely used open-source Solidity static analyzer from Trail of Bits; detects reentrancy, access control issues, uninitialized storage, and 80+ other vulnerability classes; fast and produces machine-readable output for CI/CD integration
- [ConsenSys/mythril](https://github.com/ConsenSys/mythril) — Symbolic execution tool for EVM bytecode from Consensys Diligence; detects integer overflows, reentrancy, and other vulnerabilities by exploring all code paths; operates on bytecode so works without source
- [Certora Prover](https://www.certora.com/) — Formal verification platform for smart contracts; proves correctness properties hold for all possible inputs using mathematical verification; used by Aave, Compound, and other major protocols; free academic access available
- [trailofbits/manticore](https://github.com/trailofbits/manticore) — Symbolic execution tool for EVM and native binaries from Trail of Bits; more flexible than Mythril for custom analysis; requires more setup but supports complex multi-contract analysis

### Fuzzing & Testing
- [crytic/echidna](https://github.com/crytic/echidna) — Property-based fuzzer for Ethereum smart contracts from Trail of Bits; tests user-defined invariants by generating random transaction sequences; the standard for smart contract fuzzing
- [foundry-rs/foundry](https://github.com/foundry-rs/foundry) — The modern smart contract development and testing framework; Forge (testing with fuzz capabilities), Cast (chain interaction), and Anvil (local node); the fastest test execution environment for Solidity
- [trufflesuite/truffle](https://github.com/trufflesuite/truffle) — Established smart contract development framework; testing, deployment scripts, and network management; widely used in existing codebases though largely superseded by Foundry for new projects
- [trufflesuite/ganache](https://github.com/trufflesuite/ganache) — Local Ethereum blockchain for development and testing; deterministic accounts, instant mining, and fork mode for testing against mainnet state locally

### Runtime Monitoring & Threat Detection
- [forta-network/forta-core-go](https://github.com/forta-network/forta-core-go) — Decentralized threat detection network for blockchain; community-run detection bots monitoring on-chain activity for exploits, rug pulls, and anomalous transactions in real time
- [OpenZeppelin Defender](https://www.openzeppelin.com/defender) — Smart contract operations platform with automated monitoring, incident response, and upgrade management; monitors contracts for anomalous behavior and automates incident response workflows
- [Tenderly](https://tenderly.co/) — Smart contract monitoring, alerting, and simulation platform; transaction simulation and debugging before on-chain execution; widely used for pre-deployment testing and production monitoring

### Blockchain Analytics
- [Etherscan](https://etherscan.io/) — The primary Ethereum block explorer; essential for investigating transactions, tracing fund flows, reading verified contract source code, and analyzing on-chain events during incident response
- [Breadcrumbs](https://www.breadcrumbs.app/) — Free blockchain address tracking and visualization tool; maps fund flows across addresses and exchanges for wallet analysis and attribution during investigations
- [SunWeb3Sec/DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) — Repository of PoC exploit reproductions for major DeFi hacks written in Foundry; hands-on study of real attack implementations including flash loans, oracle manipulation, and reentrancy

---

## Commercial & Enterprise Platforms

| Platform | Strength |
|---|---|
| **Trail of Bits** | One of the most technically rigorous smart contract audit firms; deep expertise in formal verification, fuzzing, and custom tooling; public audit reports are valuable free learning resources |
| **OpenZeppelin** | Smart contract audit services plus the OpenZeppelin Contracts library (the standard secure base library for Solidity development); Defender platform for operational security |
| **CertiK** | High-volume smart contract audit firm with on-chain security score tracking; broad coverage across EVM-compatible chains and Layer 2 protocols |
| **Halborn** | Blockchain security firm covering smart contract audits, penetration testing of Web3 infrastructure, and security advisory for major protocols and exchanges |
| **Immunefi** | The dominant bug bounty platform for Web3; hosts bounty programs for major DeFi protocols with payouts reaching $10M+; the primary market for white-hat smart contract researchers |
| **Chainalysis** | Blockchain analytics and investigation platform; transaction tracing, compliance screening, and investigation tools used by exchanges, law enforcement, and financial institutions |
| **Elliptic** | Blockchain analytics competitor to Chainalysis; crypto asset risk scoring, transaction monitoring, and sanctions screening for financial institutions and exchanges |

---

## NIST 800-53 Control Alignment

| Control | ID | Blockchain & Web3 Relevance |
|---|---|---|
| Developer Testing and Evaluation | SA-11 | Pre-deployment smart contract security testing — static analysis (Slither), symbolic execution (Mythril), fuzzing (Echidna), and formal verification (Certora) — is the primary preventive control given smart contract immutability |
| Development Standards | SA-15 | Secure Solidity development standards, use of audited libraries (OpenZeppelin Contracts), and mandatory audit requirements before deployment implement development security standards |
| Software and Information Integrity | SI-7 | Smart contract bytecode verification on Etherscan, immutable deployment addresses, and formal verification of critical invariants provide integrity assurance for deployed contracts |
| Protection of Information at Rest | SC-28 | Private key management using hardware security modules (HSMs), hardware wallets, and multi-signature schemes protects cryptographic credentials that control contract ownership and treasury funds |
| Access Enforcement | AC-3 | Smart contract access control — owner patterns, role-based access control via OpenZeppelin AccessControl, and multi-signature governance — enforces authorization for privileged contract functions |
| Vulnerability Scanning | RA-5 | Continuous static analysis of contract code, monitoring of deployed contracts via Forta and OpenZeppelin Defender, and regular audit engagements constitute the vulnerability scanning program for Web3 assets |

---

## ATT&CK Coverage

| Technique | ID | Web3 Security Control |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Pre-deployment audits, static analysis (Slither), fuzzing (Echidna), and formal verification address smart contract vulnerabilities before deployment; runtime monitoring detects active exploitation |
| Unsecured Credentials | T1552 | Hardware wallet adoption, HSM-based key management, multi-signature schemes, and eliminating private key storage in code or environment variables prevent key exposure |
| Financial Theft | T1657 | Multi-signature treasury controls, timelocks on administrative functions, circuit breakers (pause mechanisms), and real-time monitoring via Forta reduce the impact of financial theft attempts |
| Resource Hijacking | T1496 | Smart contract gas limit analysis and monitoring for unexpected resource consumption patterns detects cryptomining abuse and griefing attacks |
| Supply Chain Compromise | T1195 | Dependency auditing for npm packages in Web3 frontends, pinning OpenZeppelin library versions, and verifying contract bytecode against audited source prevents supply chain attacks on Web3 projects |

---

## Certifications

- **CBSP** (Certified Blockchain Security Professional — EC-Council) — The most recognized formal blockchain security certification; covers blockchain fundamentals, smart contract vulnerabilities, cryptographic attack surfaces, and DeFi security; the credential for practitioners moving into formal Web3 security roles
- **CSSLP** (Certified Secure Software Lifecycle Professional — ISC2) — Secure software development lifecycle credential applicable to smart contract development; covers security requirements, design, implementation, and testing practices that transfer directly to Web3 security
- **GWEB** (GIAC Web Application Penetration Tester) — Web application security skills covering API security and JavaScript vulnerabilities directly applicable to Web3 frontend and wallet security; useful complement to smart contract-specific skills
- **OSCP** (Offensive Security Certified Professional) — Offensive methodology and exploitation skills provide the attacker mindset essential for smart contract auditing; many top smart contract auditors hold OSCP for its offensive reasoning foundation
- **Portfolio-based recognition** — The Web3 security community heavily weights demonstrated audit findings, public CTF results (Ethernaut, Damn Vulnerable DeFi), published vulnerability research, and Immunefi bug bounty payouts over formal certifications

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Ethernaut CTF](https://ethernaut.openzeppelin.com/) | Free CTF | OpenZeppelin's foundational smart contract security CTF; 20+ challenges covering core vulnerability classes |
| [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/) | Free CTF | DeFi attack challenges covering flash loans, oracle manipulation, and governance exploits |
| [Secureum Substack](https://secureum.substack.com/) | Free curriculum | Comprehensive structured smart contract security curriculum from the Secureum community |
| [rekt.news](https://rekt.news/) | Free postmortems | Ranked postmortems of DeFi exploits; essential reading for understanding real attack patterns |
| [Trail of Bits Public Audits](https://github.com/trailofbits/publications) | Free audit reports | High-quality audit reports covering real protocol vulnerabilities; practitioner-level depth |
| [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) | Free PoC repo | Foundry-based reproductions of major DeFi hacks; learn attack mechanics hands-on |
| [Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/) | Free reference | Consensys Diligence reference covering known vulnerability patterns and mitigations |
| [Foundry Book](https://book.getfoundry.sh/) | Free reference | Complete Foundry framework documentation; fuzz testing, fork testing, and cheatcodes for security testing |

---

## Related Disciplines

- [Application Security](application-security.md) — Web3 frontends, wallet interfaces, and exchange platforms are web applications; traditional AppSec skills covering XSS, API security, and authentication are directly applicable to Web3 attack surfaces
- [Cryptography & PKI](cryptography-pki.md) — Smart contracts and blockchain protocols are built on cryptographic primitives; understanding hash functions, digital signatures, and elliptic curve cryptography is foundational for Web3 security
- [Bug Bounty](bug-bounty.md) — Immunefi and code4rena operate the largest Web3 bug bounty and competitive audit platforms; bug bounty methodology applies directly to smart contract vulnerability research
- [Offensive Security](offensive-security.md) — Attack simulation and exploitation methodology applied to smart contracts and DeFi protocols; offensive skills drive the auditor mindset required for finding non-obvious vulnerabilities
- [Supply Chain Security](supply-chain-security.md) — npm dependency attacks on Web3 frontends, malicious Solidity libraries, and compromised development tooling represent supply chain risks specific to the Web3 ecosystem
