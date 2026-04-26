# Blockchain Security Reference

> Comprehensive reference for blockchain security, smart contract vulnerabilities, DeFi attacks, auditing tools, and incident response. Maintained as part of the TeamStarWolf cybersecurity library.

---

## Table of Contents

1. [Blockchain Security Fundamentals](#1-blockchain-security-fundamentals)
2. [Smart Contract Vulnerabilities](#2-smart-contract-vulnerabilities)
3. [DeFi Attack Case Studies](#3-defi-attack-case-studies)
4. [Smart Contract Auditing Tools](#4-smart-contract-auditing-tools)
5. [Solidity Security Patterns](#5-solidity-security-patterns)
6. [Blockchain Network Security](#6-blockchain-network-security)
7. [Exchange and Wallet Security](#7-exchange-and-wallet-security)
8. [NFT and Token Security](#8-nft-and-token-security)
9. [Regulatory and Compliance](#9-regulatory-and-compliance)
10. [Incident Response for Blockchain](#10-incident-response-for-blockchain)

---

## 1. Blockchain Security Fundamentals

### 1.1 Consensus Mechanism Security

#### Proof of Work (PoW) — 51% Attack Mathematics

A 51% attack occurs when a single entity controls the majority of a network's hash rate, enabling double-spend attacks and chain reorganizations.

**Attack feasibility formula:**

```
Attack cost (USD/hr) = (Network hashrate × 51%) / Attacker ASIC efficiency × Electricity cost per kWh
```

**Double-spend probability:**
```
P(attacker catches up) = 1 - Σ(k=0 to z) [ (λ^k × e^-λ) / k! × (1 - (q/p)^(z-k)) ]

Where:
  p = honest miner fraction
  q = attacker fraction (must be > 0.5 for guaranteed success)
  z = number of confirmations to wait
  λ = z × (q/p)
```

**Bitcoin 51% attack cost estimates (2024):**
- 1-hour attack: ~$1.4 billion in hardware + operational cost
- Requires sustained >500 EH/s hashrate
- Major exchanges require 6+ confirmations (~60 min)

**Historical 51% attacks:**
| Network | Date | Hashrate Rented | Blocks Reorged | Estimated Loss |
|---|---|---|---|---|
| Ethereum Classic | Jan 2019 | NiceHash GPU miners | 400 blocks | $1.1M |
| Ethereum Classic | Aug 2020 | NiceHash GPU miners | 4,000 blocks | $5.6M |
| Bitcoin Gold | May 2018 | Rented hashrate | 22 blocks | $18M |
| Vertcoin | Dec 2018 | Rented hashrate | 310 blocks | Unknown |

**Defenses against PoW 51% attacks:**
- Delayed finality (more confirmations)
- Checkpointing (PoA hybrid)
- Merge mining with larger chain (auxiliary PoW)
- ASIC-resistant algorithms reduce rental-market attacks

---

#### Proof of Stake (PoS) — Long-Range Attacks

Long-range attacks (also called "history revision attacks") exploit the fact that private keys from the genesis era remain valid.

**Attack types:**

**1. Simple Long-Range Attack:**
- Attacker acquires old private keys (purchased, stolen, or from validators who exited)
- Uses them to rewrite history from genesis
- Countermeasure: **Weak subjectivity checkpoints** — new nodes must obtain a recent trusted state from a known-good source

**2. Stake Bleeding Attack:**
- Attacker forks from a past point when they held significant stake
- Collects block rewards on the fork to grow their stake share
- Eventually overtakes the honest chain
- Countermeasure: **Forward-secure key derivation** (keys are deleted after signing)

**3. Nothing-at-Stake Problem:**
- Validators have no economic cost to sign on multiple forks
- Pure PoS without slashing conditions: rational validators sign all forks
- Countermeasure: **Slashing conditions** (Ethereum Casper FFG slashes equivocating validators)

**Ethereum Casper FFG Slashing Conditions:**
```
Condition 1 (Double vote): A validator signs two different checkpoints at the same epoch
Condition 2 (Surround vote): A validator signs checkpoint A→B surrounding existing vote C→D
Penalty: Full 32 ETH stake burned + forced exit
```

**Long-range attack mitigation in Ethereum:**
```python
# Weak subjectivity period calculation (approximate)
# Source: Ethereum research
def weak_subjectivity_period(validator_count, eth_staked):
    # Safety decay constant
    safety_decay = 10  # percent
    avg_active_validator_balance = eth_staked / validator_count
    # Period in epochs
    period = (safety_decay * avg_active_validator_balance * 1e18) / (
        2 * 10**4 * 2**25 * 10**9
    )
    return period

# Modern Ethereum weak subjectivity checkpoint: ~27 days
```

---

#### PBFT — Byzantine Fault Tolerance

Practical Byzantine Fault Tolerance (PBFT) is used in permissioned blockchains (Hyperledger Fabric, Tendermint).

**BFT Theorem:** A system with `n` nodes can tolerate at most `f` Byzantine (malicious) nodes where:
```
n ≥ 3f + 1
```

This means:
- 4 nodes → tolerates 1 Byzantine node
- 7 nodes → tolerates 2 Byzantine nodes
- 10 nodes → tolerates 3 Byzantine nodes

**PBFT message complexity:** O(n²) — scales poorly, impractical beyond ~100 validators

**PBFT protocol phases:**
```
1. REQUEST:    Client → Leader (request)
2. PRE-PREPARE: Leader → All replicas (propose block)
3. PREPARE:    Each replica → All replicas (vote to prepare)
4. COMMIT:     Each replica → All replicas (vote to commit)
5. REPLY:      All replicas → Client (result)

Requires 2f+1 matching PREPARE messages to advance
Requires 2f+1 matching COMMIT messages to finalize
```

**Tendermint vs. PBFT differences:**
| Property | PBFT | Tendermint |
|---|---|---|
| Safety | Guaranteed with f < n/3 | Guaranteed with f < n/3 |
| Liveness | Not guaranteed under network partition | Not guaranteed under async conditions |
| Leader rotation | Manual view-change | Automatic round-robin |
| Complexity | O(n²) messages | O(n²) messages |
| Finality | Immediate | Immediate |

---

### 1.2 Cryptographic Primitives

#### secp256k1 ECDSA (Elliptic Curve Digital Signature Algorithm)

Bitcoin and Ethereum both use the `secp256k1` elliptic curve for key generation and signing.

**Curve parameters:**
```
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
     (prime defining the field)
a  = 0  (curve coefficient)
b  = 7  (curve coefficient)
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
     (order of the generator point G)
```

**Key generation:**
```python
import secrets
from cryptography.hazmat.primitives.asymmetric import ec

# Generate private key (256-bit random integer in [1, n-1])
private_key = ec.generate_private_key(ec.SECP256K1())
private_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')

# Public key = private_key × G (elliptic curve point multiplication)
public_key = private_key.public_key()
public_point = public_key.public_numbers()
public_bytes_uncompressed = bytes([0x04]) + public_point.x.to_bytes(32,'big') + public_point.y.to_bytes(32,'big')
```

**ECDSA signature generation:**
```
1. Generate random nonce k ∈ [1, n-1]  ← CRITICAL: must be truly random
2. Compute R = k × G
3. r = R.x mod n
4. s = k⁻¹(hash(msg) + r × privateKey) mod n
5. Signature = (r, s)
```

**CRITICAL VULNERABILITY — Nonce reuse:**
If the same `k` is used for two different messages, the private key can be recovered:
```
k_recovered = (hash1 - hash2) × (s1 - s2)⁻¹ mod n
private_key = (s1 × k - hash1) × r⁻¹ mod n
```

**Real-world nonce reuse attack:** PlayStation 3 (2010) — Sony used constant k=0 for firmware signing, allowing full key extraction.

**Bitcoin/Ethereum signing mitigation:**
- RFC 6979: Deterministic k generation using HMAC-DRBG with private key + message hash
- Prevents both weak-RNG and nonce-reuse attacks

---

#### Keccak-256

Ethereum uses Keccak-256 (NOT standard SHA-3, which differs in padding). This distinction matters for interoperability.

```python
from Crypto.Hash import keccak

def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

# Ethereum address derivation
def eth_address(public_key_bytes_64: bytes) -> str:
    hash_bytes = keccak256(public_key_bytes_64)  # hash of 64-byte uncompressed pubkey (no 0x04 prefix)
    return '0x' + hash_bytes[-20:].hex()
```

**Keccak-256 vs SHA-3-256:**
```
Input: "" (empty string)
Keccak-256: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
SHA3-256:   a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
```

---

#### Merkle Tree Proofs

Merkle trees enable efficient, cryptographically-verified inclusion proofs.

**Structure:**
```
              Root Hash
             /         \
        Hash(AB)       Hash(CD)
        /    \          /    \
   Hash(A)  Hash(B) Hash(C) Hash(D)
      |        |       |       |
     Tx_A    Tx_B    Tx_C    Tx_D
```

**Proof of inclusion for Tx_C:**
```python
proof = [Hash(D), Hash(AB)]  # sibling hashes from leaf to root

def verify_merkle_proof(leaf_hash, proof, root):
    current = leaf_hash
    for sibling in proof:
        # Ordering: convention determines left/right
        if current < sibling:
            current = keccak256(current + sibling)
        else:
            current = keccak256(sibling + current)
    return current == root
```

**Merkle proof complexity:** O(log n) proof size, O(log n) verification

**Merkle tree vulnerabilities:**
- **Second preimage attack on naive implementations:** Concatenating leaf-level and internal nodes using same hash without domain separation allows forging proofs. Mitigation: prefix leaf nodes with `0x00` and internal nodes with `0x01` before hashing (Bitcoin approach).
- **CVE-2012-2459 (Bitcoin):** Duplicate transaction in coinbase allowed creating two blocks with the same Merkle root.

**Merkle Sum Trees (proof of reserves):**
```
Each node stores: (hash, balance_sum)
Proves: total user balances ≤ exchange holdings
Without: revealing individual user balances
Used by: Binance, OKX, Kraken post-FTX collapse
```

---

### 1.3 Key Management

#### HD Wallets — BIP32/39/44

**BIP39 — Mnemonic Generation:**
```
1. Generate 128–256 bits of entropy (CSPRNG)
2. Append SHA-256 checksum (entropy_bits/32 bits)
3. Split result into 11-bit groups
4. Map each 11-bit value to word in 2048-word wordlist
5. 128-bit entropy → 12 words; 256-bit entropy → 24 words

Security: 128-bit entropy = 2^128 guesses to brute force
BIP39 wordlist: https://github.com/trezor/python-mnemonic/blob/master/src/mnemonic/wordlist/english.txt
```

**BIP39 seed derivation:**
```python
import hashlib, hmac

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    # PBKDF2-HMAC-SHA512, 2048 iterations
    mnemonic_bytes = mnemonic.encode('utf-8')
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, salt, 2048)
# Returns 512-bit (64-byte) seed
```

**BIP32 — Hierarchical Deterministic Key Derivation:**
```python
def derive_child_key(parent_key: bytes, parent_chain_code: bytes, index: int) -> tuple:
    if index >= 0x80000000:  # hardened derivation
        data = b'\x00' + parent_key + index.to_bytes(4, 'big')
    else:                    # normal derivation
        data = parent_pubkey + index.to_bytes(4, 'big')

    I = hmac.new(parent_chain_code, data, 'sha512').digest()
    child_key = (int.from_bytes(I[:32], 'big') + int.from_bytes(parent_key, 'big')) % CURVE_ORDER
    child_chain_code = I[32:]
    return child_key.to_bytes(32, 'big'), child_chain_code
```

**BIP44 — Multi-Account Hierarchy:**
```
m / purpose' / coin_type' / account' / change / address_index

Examples:
  m/44'/0'/0'/0/0   → Bitcoin, account 0, external, address 0
  m/44'/60'/0'/0/0  → Ethereum, account 0, external, address 0
  m/44'/195'/0'/0/0 → Tron, account 0, external, address 0

Apostrophe (') = hardened derivation (index + 2^31)
Hardened derivation: child private key CANNOT be derived from parent public key alone
```

**BIP44 coin type registry (partial):**
| Coin Type | Symbol | Network |
|---|---|---|
| 0' | BTC | Bitcoin |
| 60' | ETH | Ethereum |
| 195' | TRX | Tron |
| 501' | SOL | Solana |
| 637' | APT | Aptos |

---

#### Hardware Wallets (Ledger, Trezor)

Hardware wallets store private keys in a secure element or microcontroller that never exposes keys to the host machine.

**Ledger architecture:**
```
Host (PC/phone)
     ↕ USB/BT (APDU commands)
Ledger Secure Element (ST33 — CC EAL5+ certified)
     ↕ Internal SPI
STM32 MCU (manages display, buttons)
```

**Trezor architecture:**
```
Host (PC/phone)
     ↕ USB/WebUSB
STM32 MCU (open-source firmware, no secure element)
     ↕ GPIO
OLED display + buttons
```

**Security comparison:**
| Property | Ledger | Trezor |
|---|---|---|
| Secure Element | Yes (ST33, CC EAL5+) | No |
| Firmware | Proprietary (BOLOS) | Open source |
| Supply chain attack resistance | Higher | Lower |
| Physical extraction | Harder | Possible with expertise |
| PIN brute-force | Wipes after 3 attempts (Ledger) | Increasing delays |

**Known hardware wallet attacks:**
- **Ledger data breach (2020):** ~272,000 customer shipping addresses leaked from e-commerce database (not key compromise, but enabled targeted physical attacks)
- **Trezor One voltage glitching:** Physical attacks can bypass PIN protection by injecting voltage glitches during verification — requires hands-on access
- **Supply chain interdiction:** Evil maid attacks via malicious firmware pre-flash
- **Malicious companion app:** Fake Ledger Live apps have stolen seeds by prompting "recovery" phrases

**Ledger Recover (2023 controversy):**
- Optional service to shard and back up seed phrase using identity verification
- Architecture: Seed → 3 encrypted shards → Coincover, EscrowTech, Ledger
- Security concern: Demonstrates seed can leave device, eroding trust model

---

#### MPC Wallets

Multi-Party Computation (MPC) wallets split the private key into shares across multiple parties. No single share reveals the key.

**Threshold Signature Scheme (TSS):**
```
t-of-n setup: any t parties can sign; fewer than t learn nothing about the key

Protocols:
  - GG18/GG20 (Gennaro-Goldfeder): Most widely deployed for secp256k1
  - ECDSA-MPC: Fireblocks, ZenGo, Coinbase Prime use variants
  - Schnorr MPC: More efficient; used in BIP340 (Bitcoin Taproot)
```

**MPC vs. Multisig:**
| Property | MPC/TSS | On-chain Multisig |
|---|---|---|
| On-chain footprint | Single signature | Multiple signatures on chain |
| Gas cost | Lower (1 sig) | Higher (n sigs) |
| Privacy | Private — looks like single sig | Public threshold visible |
| Key reconstruction | Never required | N/A |
| Auditability | Off-chain | On-chain |
| Protocol complexity | High | Low |

**MPC wallet providers:**
- Fireblocks (institutional — most deployed in crypto exchanges)
- ZenGo (consumer — keyless wallet using MPC + biometrics)
- Coinbase Prime (enterprise MPC custody)
- Qredo (decentralized MPC custody network)

---

### 1.4 Private Key Security

#### Entropy Generation

Private key security is only as strong as the entropy used to generate it.

**CSPRNG sources by platform:**
```python
# Python — uses OS CSPRNG
import secrets
private_key_bytes = secrets.token_bytes(32)  # 256 bits

# JavaScript (Node.js)
const crypto = require('crypto');
const privateKey = crypto.randomBytes(32);

# Solidity — NO on-chain RNG is secure
# block.timestamp, blockhash, and block.prevrandao are all manipulable by miners/validators
# Use Chainlink VRF for on-chain randomness
```

**Weak entropy sources (NEVER use for key generation):**
- `Math.random()` (not cryptographically secure)
- `time.time()` as seed
- Predictable sequences (consecutive integers, patterns)
- Low-entropy PRNG seeds

**Real-world weak entropy attack:**
- **Blockchain.info Android bug (2013):** Java SecureRandom improperly seeded on Android, leading to k-value reuse in ECDSA signatures. ~55 BTC stolen. Root cause: `SecureRandom` not properly seeded before use.

---

#### Seed Phrase Storage

**Best practices for seed phrase storage:**

```
1. WRITE IT DOWN (paper/metal) — never type into a computer
2. NEVER store seed phrase in:
   - Cloud storage (iCloud, Google Drive, Dropbox)
   - Email (any provider)
   - Password managers (compromise reveals all)
   - Screenshots or photos
   - Text messages / messaging apps

3. Physical storage options:
   - Metal backup plates (Cryptosteel, Bilodl) — fireproof/waterproof
   - Multiple geographic locations (primary + backup)
   - Safety deposit box (jurisdiction risk)
   - Fireproof safe at home

4. Passphrase (BIP39 25th word):
   - Adds additional factor beyond seed phrase
   - Different passphrase = different wallet derivation path
   - Store passphrase separately from seed phrase
   - Loss of passphrase = permanent loss of funds
```

---

#### Shamir's Secret Sharing (SSS)

Shamir's Secret Sharing splits a secret (e.g., seed phrase) into `n` shares where any `t` shares can reconstruct the secret.

**Mathematical basis (Lagrange interpolation):**
```
Secret S is encoded as f(0) where f is a degree t-1 polynomial:
f(x) = S + a1*x + a2*x² + ... + a(t-1)*x^(t-1)  (mod prime p)

Share i = (i, f(i)) for i = 1, 2, ..., n

Recovery: Given any t shares (xi, yi), recover S using Lagrange interpolation:
S = Σ yi × Π[(xj)/(xj - xi)]  for j ≠ i

Properties:
  - Any t shares reconstruct S exactly
  - Fewer than t shares provide ZERO information about S (information-theoretic security)
```

**Implementation: SLIP39 (Trezor's Shamir backup standard):**
```
SLIP39 encodes shares as mnemonic words
Example: 3-of-5 scheme
  Share 1: "duckling enlarge academic academic agency disaster "
  Share 2: "duckling enlarge academic academic always swimming "
  ...
  Any 3 of 5 shares reconstruct the master secret
```

**SSSS vs. multisig:**
- SSS: Secret must be reconstructed at a single point (temporary key exposure)
- Multisig: Secret is never reconstructed; each party signs independently (preferred for operational security)

---

### 1.5 Address Types

#### Bitcoin Address Types

| Type | Prefix | Script Type | Encoding | Introduced |
|---|---|---|---|---|
| Legacy | 1... | P2PKH | Base58Check | Bitcoin genesis |
| Script | 3... | P2SH | Base58Check | BIP16 (2012) |
| Native SegWit | bc1q... | P2WPKH/P2WSH | Bech32 | BIP84 (2017) |
| Taproot | bc1p... | P2TR | Bech32m | BIP341 (2021) |

**P2PKH (Pay to Public Key Hash):**
```
ScriptPubKey: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
ScriptSig:    <sig> <pubKey>
Address:      Base58Check(0x00 || RIPEMD160(SHA256(pubKey)))
```

**P2SH (Pay to Script Hash):**
```
ScriptPubKey: OP_HASH160 <scriptHash> OP_EQUAL
RedeemScript: <m> <pubKey1> <pubKey2> ... <pubKeyN> <n> OP_CHECKMULTISIG
ScriptSig:    OP_0 <sig1> <sig2> <redeemScript>
Address:      Base58Check(0x05 || RIPEMD160(SHA256(redeemScript)))
```

**Bech32 / Bech32m error detection:**
```
Bech32 can detect:
  - All 1-char substitution errors
  - All insertion/deletion errors up to distance
  - More than 99.9% of longer errors

Format: bc1 <version> <witness program>
  bc1q = version 0 (SegWit v0)
  bc1p = version 1 (Taproot/SegWit v1)
```

#### Ethereum Address Types

**EOA (Externally Owned Account):**
```
Controlled by private key
No code
Can initiate transactions
Address = last 20 bytes of keccak256(pubkey)
EIP-55 checksum: Mixed-case hex where each nibble > 8 sets uppercase
  Valid: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
```

**Contract Address:**
```
Deterministic: keccak256(RLP([deployer_address, nonce]))[-20:]
CREATE2:        keccak256(0xff || deployer || salt || keccak256(initcode))[-20:]
No private key — controlled by code
Can receive ETH but cannot initiate transactions alone
```

**EIP-1167 Minimal Proxy (Clone) Contracts:**
```
Bytecode: 3d602d80600a3d3981f3 363d3d373d3d3d363d73 <implementation_address> 5af43d82803e903d91602b57fd5bf3
Delegates all calls to implementation
Used extensively in DeFi to deploy cheap clones
```

---

## 2. Smart Contract Vulnerabilities

### 2.1 Reentrancy Attacks

Reentrancy is the most famous smart contract vulnerability class. It occurs when an external call is made before state changes are finalized, allowing the callee to re-enter the caller.

#### The DAO Hack ($60M, June 2016)

The DAO was an Ethereum-based venture fund. A reentrancy vulnerability allowed an attacker to drain ~3.6M ETH (~$60M at the time).

**Vulnerable code pattern (simplified):**
```solidity
// VULNERABLE — Classic reentrancy
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // BUG: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // Attacker re-enters here before this line executes
        balances[msg.sender] -= amount;  // ← Never reached during attack
    }
}

// ATTACKER CONTRACT
contract Attacker {
    VulnerableBank public target;
    uint256 public attackAmount = 1 ether;

    constructor(address _target) {
        target = VulnerableBank(_target);
    }

    function attack() external payable {
        target.deposit{value: attackAmount}();
        target.withdraw(attackAmount);
    }

    // Fallback triggered when target sends ETH
    receive() external payable {
        if (address(target).balance >= attackAmount) {
            target.withdraw(attackAmount);  // Re-enter!
        }
    }
}
```

**Fixed version using Checks-Effects-Interactions + ReentrancyGuard:**
```solidity
// SAFE — OpenZeppelin ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureBank is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // nonReentrant modifier sets a lock before execution, reverts if already locked
    function withdraw(uint256 amount) external nonReentrant {
        // CHECK
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // EFFECT (state change BEFORE external call)
        balances[msg.sender] -= amount;

        // INTERACTION (external call LAST)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

// ReentrancyGuard internals (simplified):
// uint256 private _status = NOT_ENTERED (1);
// modifier nonReentrant:
//   require(_status != ENTERED)
//   _status = ENTERED
//   _;
//   _status = NOT_ENTERED
```

#### Cross-Function Reentrancy

```solidity
// VULNERABLE — Cross-function reentrancy
contract CrossFunctionVulnerable {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[to] += amount;
        balances[msg.sender] -= amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        // External call before balance update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
    // Attacker: in receive() calls transfer() to move "double balance" to accomplice
    // Then withdraw() sets balance to 0 but funds already transferred
}
```

#### Cross-Contract Reentrancy

Occurs when multiple contracts share state and an attacker can manipulate that shared state:
```solidity
// Contract A reads price from B
// Contract B calls user-supplied callback
// User callback manipulates price in B before A reads it
// Common in AMM price oracle manipulation
```

---

### 2.2 Integer Overflow and Underflow

Prior to Solidity 0.8.0, all arithmetic was unchecked. Values would silently wrap around.

**Classic overflow example:**
```solidity
// Solidity < 0.8.0 — VULNERABLE
contract OverflowVulnerable {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // If balances[msg.sender] = 0 and amount = 1:
        // 0 - 1 wraps to 2^256 - 1 (huge number)
        require(balances[msg.sender] - amount >= 0);  // Always true due to wrapping!
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
```

**Safe Math library (pre-0.8.0):**
```solidity
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }
}
```

**Solidity 0.8+ built-in overflow protection:**
```solidity
// Solidity >= 0.8.0 — Safe by default
contract SafeByDefault {
    function sub(uint256 a, uint256 b) external pure returns (uint256) {
        return a - b;  // Reverts with Panic(0x11) if b > a
    }

    // Explicit unchecked block for gas optimization (only when overflow is impossible)
    function efficientLoop(uint256 n) external pure returns (uint256 sum) {
        for (uint256 i = 0; i < n; ) {
            sum += i;
            unchecked { ++i; }  // Safe: i can't overflow uint256 in practice
        }
    }
}
```

**BEANstalk finance (April 2022):** Integer arithmetic manipulation via governance flash loan enabled attacker to pass a malicious proposal and drain $182M.

---

### 2.3 Access Control Flaws

#### tx.origin vs. msg.sender

```solidity
// VULNERABLE — tx.origin phishing
contract VulnerableWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transfer(address payable to, uint256 amount) external {
        // tx.origin = original EOA that initiated the transaction
        // If victim calls MaliciousContract which calls this → tx.origin = victim
        require(tx.origin == owner, "Not owner");  // VULNERABLE
        to.transfer(amount);
    }
}

// Attack: Trick victim into calling this contract
contract MaliciousContract {
    VulnerableWallet public target;
    address payable public attacker;

    function phish() external {
        // When victim calls phish(), tx.origin = victim
        target.transfer(attacker, address(target).balance);
    }
}

// SAFE — use msg.sender instead
function transfer(address payable to, uint256 amount) external {
    require(msg.sender == owner, "Not owner");  // msg.sender is the direct caller
    to.transfer(amount);
}
```

#### Unprotected Initializers — Parity Wallet Hack (July 2017)

The Parity multi-signature wallet library contract had an unprotected `initWallet` function:
```solidity
// VULNERABLE — Parity Wallet Library (simplified)
contract WalletLibrary {
    address public owner;

    // initWallet was NEVER protected with a modifier to prevent re-initialization
    // Anyone could call this on the deployed library contract and become owner
    function initWallet(address[] memory _owners, uint256 _required) public {
        owner = _owners[0];  // Takeover!
    }

    function kill(address _to) external onlyOwner {
        selfdestruct(payable(_to));
    }
}
// Impact: Attacker called initWallet on the shared library, became owner,
// then called kill() — permanently destroying the library.
// ~$280M of ETH locked in wallets using that library became permanently inaccessible.
```

**Fix — use OpenZeppelin Initializable:**
```solidity
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract SecureWallet is Initializable {
    address public owner;

    // initializer modifier ensures this can only be called once
    function initialize(address _owner) external initializer {
        owner = _owner;
    }
}
```

---

### 2.4 Front-Running and MEV

#### Sandwich Attacks

```
Block ordering by validators enables sandwich attacks on DEX trades:

1. Victim submits swap: 100 ETH → USDC at Uniswap (max slippage 1%)
2. Attacker sees mempool, submits:
   Front-run tx (higher gas): Buy USDC with ETH (pushes price up)
   Victim tx:                  Victim buys USDC at higher price
   Back-run tx (lower gas):    Sell USDC back to ETH (at profit)

Attacker profit = victim's slippage loss - gas costs
MEV bots extract ~$1M+ per day from Ethereum mainnet
```

**Time-Bandit Attacks:**
```
Scenario: Block N contains a profitable transaction (e.g., $10M arbitrage)
Time-bandit attacker: Reorg back to N-1, include their version of N with the profit captured
Profitable when: reorg reward > block rewards given up

Ethereum defense: Finality via Casper FFG — finalized blocks cannot be reorganized
```

**Commit-Reveal Scheme (front-running mitigation):**
```solidity
contract CommitRevealAuction {
    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public bids;

    // Phase 1: Commit (hide bid)
    function commit(bytes32 commitment) external {
        commitments[msg.sender] = commitment;
    }

    // Phase 2: Reveal (after commit phase ends)
    function reveal(uint256 bidAmount, bytes32 nonce) external {
        bytes32 expected = keccak256(abi.encodePacked(bidAmount, nonce, msg.sender));
        require(commitments[msg.sender] == expected, "Invalid reveal");
        bids[msg.sender] = bidAmount;
    }
}
```

---

### 2.5 Oracle Manipulation

Price oracles are critical infrastructure in DeFi. On-chain spot price oracles (reading directly from AMM reserves) are manipulable within a single transaction.

**Harvest Finance Attack (October 2020, ~$34M):**
```
1. Attacker takes flash loan of USDC/USDT
2. Manipulates Curve.fi stablecoin pool price (depeg USDC)
3. Deposits into Harvest vault (vault uses Curve pool price for share valuation)
4. Vault mints shares at artificially low USDC price (attacker gets more shares)
5. Restores Curve pool price (repay flash loan)
6. Redeems shares at correct price — profit
Root cause: Harvest used spot price from single AMM pool as oracle
```

**Mango Markets Attack (October 2022, ~$116M):**
```
1. Attacker opens large MNGO perpetual long position
2. Simultaneously manipulates MNGO spot price on thin Serum DEX
3. Unrealized profits on perpetual inflate borrowing capacity
4. Attacker borrows all protocol assets against inflated collateral
5. "Negotiated" return of $67M, kept $49M as "bug bounty"
Root cause: Used manipulable spot oracle for collateral valuation
```

**Oracle security best practices:**
```solidity
// Use time-weighted average price (TWAP) instead of spot
interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external view returns (int56[] memory tickCumulatives, uint160[] memory);
}

function getTWAP(address pool, uint32 twapInterval) external view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval;
    secondsAgos[1] = 0;

    (int56[] memory tickCumulatives, ) = IUniswapV3Pool(pool).observe(secondsAgos);
    int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
    int24 timeWeightedTick = int24(tickDiff / int56(uint56(twapInterval)));

    return TickMath.getSqrtRatioAtTick(timeWeightedTick);  // Less manipulable
}

// Or use Chainlink price feeds (off-chain aggregated, requires trust in node operators)
AggregatorV3Interface priceFeed = AggregatorV3Interface(0x...);
(, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
require(block.timestamp - updatedAt < 1 hours, "Stale price");
```

---

### 2.6 Flash Loan Attacks

Flash loans allow borrowing arbitrary amounts with zero collateral, provided the loan is repaid within the same transaction. This amplifies economic attacks.

**Euler Finance Hack (March 2023, $197M):**
```
Root cause: Flawed donation mechanism in eToken contract
1. Attacker takes flash loan of 30M DAI
2. Deposits DAI into Euler → receives eDAI (collateral token)
3. Exploits vulnerability: calling donateToReserves() with leveraged position
   - The function did not check health factor after donation
   - Attacker created artificially large dToken (debt) without proportional collateral check
4. Liquidates their own leveraged position at profit
5. Repays flash loan
Notable: Euler received $200M in fund returns after attacker communicated with team
```

**bZx Protocol Attacks (February 2020, $1M + $600K):**
```
Attack 1 (Feb 14):
1. Flash loan 10,000 ETH from dYdX
2. Borrow 5,500 ETH from Compound (collateral: 10K flash loan)
3. Short ETH via bZx (opening 1,300 ETH short on Fulcrum)
4. Use remaining ETH to crash ETH/BTC price on Uniswap
5. bZx oracle used Uniswap spot price → underwater position opened
6. Profit ~318K USD

Attack 2 (Feb 18):
1. Flash loan 7,500 ETH
2. Pump sUSD price on Kyber (thin liquidity)
3. Borrow 6,796 ETH from bZx using overvalued sUSD as collateral
4. Profit ~$600K
```

**Flash loan attack mitigation:**
```solidity
// 1. Use TWAP instead of spot prices
// 2. Add slippage guards
// 3. Implement price deviation checks
function getPrice(address token) internal returns (uint256) {
    uint256 spotPrice = getSpotPrice(token);
    uint256 twapPrice = getTWAP(token, 30 minutes);
    // Revert if price deviation > 5%
    require(
        abs(spotPrice - twapPrice) * 100 / twapPrice < 5,
        "Price deviation too high"
    );
    return twapPrice;
}
```

---

### 2.7 Timestamp Dependence

`block.timestamp` can be manipulated by validators within a ~12-second window.

```solidity
// VULNERABLE — random number via timestamp
function random() internal view returns (uint256) {
    return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
    // Validator can choose to include transaction in a block with favorable timestamp
}

// VULNERABLE — time-based deadline
function isExpired() external view returns (bool) {
    return block.timestamp > deadline;
    // Validator can delay or advance by ~12 seconds
}

// SAFER — use blockhash for randomness (still manipulable but less so)
// BEST — use Chainlink VRF for verifiable on-chain randomness
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
```

---

### 2.8 Delegatecall and Storage Collision

`delegatecall` executes external code in the calling contract's storage context. Storage slot collisions between proxy and implementation contracts can lead to critical vulnerabilities.

**Parity Multisig Wallet Hack #1 (July 2017, $30M):**
```solidity
// Simplified vulnerable proxy pattern
contract WalletProxy {
    address public owner;          // slot 0
    address public libraryAddress; // slot 1

    fallback() external payable {
        // Delegates ALL calls including initWallet to library
        libraryAddress.delegatecall(msg.data);
    }
}

contract WalletLibrary {
    address public owner;  // slot 0 — maps to PROXY's owner slot!

    function initWallet(address _owner) public {
        owner = _owner;  // Writes to proxy's slot 0 = overwrites proxy owner!
    }
}
// Attack: Call proxy.initWallet(attacker) → sets proxy.owner = attacker
```

**Storage collision in upgradeable proxies:**
```solidity
// BAD: Implementation variable at slot 0 collides with proxy's admin at slot 0
contract BadProxy {
    address public implementation;  // slot 0

    fallback() external {
        implementation.delegatecall(msg.data);
    }
}

contract BadImplementation {
    address public owner;  // slot 0 — COLLISION with proxy.implementation!
}

// GOOD: EIP-1967 uses pseudo-random storage slots
// implementation slot: keccak256("eip1967.proxy.implementation") - 1
bytes32 constant IMPLEMENTATION_SLOT =
    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
```

---

### 2.9 Signature Replay Attacks

Without proper domain separation and nonce management, valid signatures can be replayed on different contracts or chains.

**EIP-712 Structured Data Signing:**
```solidity
// Domain separator binds signature to specific contract + chain
bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256(bytes("MyProtocol")),
    keccak256(bytes("1")),
    block.chainid,      // prevents cross-chain replay
    address(this)       // prevents cross-contract replay
));

// Type hash for the signed message
bytes32 constant PERMIT_TYPEHASH = keccak256(
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
);

mapping(address => uint256) public nonces;  // prevents replay within same contract

function permit(
    address owner, address spender, uint256 value,
    uint256 deadline, uint8 v, bytes32 r, bytes32 s
) external {
    require(deadline >= block.timestamp, "Permit expired");

    bytes32 digest = keccak256(abi.encodePacked(
        "\x19\x01",
        DOMAIN_SEPARATOR,
        keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))
    ));

    address recoveredOwner = ecrecover(digest, v, r, s);
    require(recoveredOwner == owner && owner != address(0), "Invalid signature");

    _approve(owner, spender, value);
}
```

---

### 2.10 Gas Griefing and Denial of Service

**DoS via unbounded loops:**
```solidity
// VULNERABLE — gas cost grows unbounded
contract VulnerableDistribution {
    address[] public recipients;

    function distribute() external {
        for (uint i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(1 ether);  // Each transfer uses gas
            // If array grows large enough → hits block gas limit → reverts
        }
    }
}

// SAFE — pull payment pattern
contract SafeDistribution {
    mapping(address => uint256) public pendingWithdrawals;

    function claim() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
```

**DoS via external call revert:**
```solidity
// VULNERABLE — one recipient can block all withdrawals
function distribute(address[] calldata recipients) external {
    for (uint i = 0; i < recipients.length; i++) {
        // If ANY recipient is a contract that reverts → entire function reverts
        payable(recipients[i]).transfer(amount);
    }
}
// FIX: Use call() and track failures instead of reverting
```

**Return bomb / gas griefing:**
```solidity
// VULNERABLE — malicious contract returns huge return data, wasting caller gas
(bool success, bytes memory returnData) = target.call(data);
// If target returns 1MB of data → copies to memory → expensive

// FIX: Cap return data with assembly
assembly {
    success := call(gasLimit, target, value, add(data, 0x20), mload(data), 0, 0)
}
```

---

### 2.11 Uninitialized Storage Pointers

In older Solidity versions, local storage pointer variables would default to storage slot 0 if not initialized.

```solidity
// Solidity < 0.5.0 — VULNERABLE
contract Vulnerable {
    address public owner;    // slot 0
    uint256 public lockTime; // slot 1

    struct Locker {
        uint256 amount;
        address depositor;
    }

    function setLock(uint256 time) external {
        Locker storage locker;  // Uninitialized — defaults to slot 0!
        locker.amount = time;   // Overwrites owner (slot 0) with 'time'!
    }
}
// Fixed in Solidity 0.8.0+ — compiler disallows uninitialized storage
```

---

### 2.12 Short Address Attacks

ERC-20 `transfer(address to, uint256 amount)` ABI encoding assumes fixed 32-byte parameters. If `to` is missing 1 byte (31 bytes), the ABI decoder right-pads with zero bytes from the next parameter, effectively left-shifting the amount.

```
Normal call:  transfer(0xABCD...ABCD, 100)
Encoded:      [4-byte selector] [32-byte address padded] [32-byte amount]

Attack call:  transfer(0xABCD...AB, 100)  ← 31-byte address
Encoded:      [4-byte selector] [31-byte address][1 zero byte from amount] [31-byte amount + "00"]
Effect:       amount = 100 << 8 = 25600 (amount × 256)
```

**Mitigation:**
```solidity
// Check calldata length at contract level (historical pattern)
modifier validPayload(uint size) {
    require(msg.data.length >= size + 4, "Short address");
    _;
}

// Modern fix: Validate at exchange/wallet level — verify calldata is correct length
// Ethereum clients now enforce correct encoding — attack is largely historical
```

---

## 3. DeFi Attack Case Studies

### 3.1 Poly Network Hack ($611M, August 2021)

**Largest DeFi hack at time of occurrence. Attacker returned most funds.**

**Root cause:** The cross-chain bridge's `EthCrossChainManager` contract had a `verifyHeaderAndExecuteTx` function that could be tricked into calling arbitrary contract methods.

```
Attack chain:
1. Cross-chain message included arbitrary calldata targeting the KeysManager contract
2. Called putCurEpochConPubKeyBytes() — a function intended only for internal use
   that sets trusted public keys for cross-chain verification
3. Attacker replaced trusted public keys with their own keys
4. Now attacker could forge any cross-chain message
5. Drained ETH, BSC, Polygon chains of bridged assets

Key flaw: _executeCrossChainTx() called a user-supplied _toContract.call(_method, _args)
without restricting which contracts or methods could be called
```

**Recovery:**
- Attacker communicated via on-chain transaction messages
- Claimed hack was "for fun" and to expose vulnerability
- Returned ~$610M over several weeks
- $33M of USDT was frozen by Tether before return

**Bridge security lesson:** Cross-chain message execution must strictly whitelist allowed target contracts and methods.

---

### 3.2 Ronin Network Bridge ($625M, March 2022)

**Largest crypto hack in history at time of occurrence.**

**Architecture:**
```
Ronin is an Ethereum sidechain for Axie Infinity (Sky Mavis)
Bridge uses 9 validator nodes: requires 5-of-9 signatures to authorize withdrawals
```

**Attack:**
```
1. Attacker (Lazarus Group / DPRK) compromised 4 Sky Mavis validator nodes
   via spear-phishing (fake job offer PDF with malware)
2. Discovered that Sky Mavis had previously granted Axie DAO permission
   to sign on their behalf (for gas-free transactions in Nov 2021)
3. This permission was NEVER revoked (5 months later)
4. Axie DAO node = 5th signature → attacker now had 5/9
5. Two fraudulent withdrawals: 173,600 ETH + 25.5M USDC
6. Not detected for 6 days (only discovered when user tried to withdraw)
```

**Key failures:**
- No monitoring for large unauthorized withdrawals
- Stale access permissions never revoked
- Insufficient validator decentralization (4 nodes controlled by one entity)

**Post-hack:**
- Sky Mavis raised $150M to reimburse users
- U.S. Treasury sanctioned attacker addresses
- Upgraded to 9-of-9 validator requirement

---

### 3.3 Wormhole Bridge ($320M, February 2022)

**Wormhole bridges assets between Solana, Ethereum, BSC, and other chains.**

**Root cause:** Signature verification bypass in Solana program.

```solidity
// Vulnerable Solana program (simplified concept)
// The verify_signatures instruction used a sysvar account
// Attacker passed a FAKE sysvar account address that was pre-populated with valid-looking data

// Normal flow:
//   1. Guardian network observes event on chain A
//   2. Guardians sign a VAA (Verified Action Approval)
//   3. 13/19 guardian signatures required
//   4. Wormhole program verifies signatures against sysvar
//   5. Mints wrapped tokens on destination chain

// Attack:
//   1. Attacker crafted a fake VAA with their address as the recipient
//   2. Called verify_signatures with a spoofed sysvar account
//      (account held valid-looking but fake signature data)
//   3. Wormhole program accepted the fake VAA
//   4. Minted 120,000 wETH on Solana (~$320M at the time)
//   5. Bridged wETH back to Ethereum as real ETH
```

**Root cause technical detail:**
- Wormhole used `load_current_index` from an account that should have been a known sysvar
- The program did not verify the account was the actual sysvar program address
- Attacker passed an attacker-controlled account with crafted data

**Jump Trading (Wormhole backer) replenished the 120,000 ETH within 24 hours.**

---

### 3.4 Nomad Bridge ($190M, August 2022)

**Unusual hack: Open to anyone. Became a "free-for-all" copy-paste attack.**

**Root cause:** A routine upgrade introduced a critical bug.

```
During upgrade, the trusted root was initialized to 0x00 (zero hash)

Nomad's message verification:
  - Message validity: proven[root] must be True
  - proved[0x00] was set to True during initialization
  - Any message with root=0x00 would pass verification

Attack:
1. First attacker discovered a successful fraudulent withdrawal transaction
2. Copied the transaction calldata, changed only the recipient address
3. Rebroadcast — succeeded because 0x00 root always validates
4. Hundreds of copycat attackers joined within hours (watched mempool)
5. $190M drained in a few hours, with ~300 unique attacker addresses

This was the first time a major hack was replicated by dozens of independent actors
copying and modifying the original exploit transaction.
```

---

### 3.5 Common Bridge Vulnerability Patterns

| Pattern | Description | Example |
|---|---|---|
| Validator key compromise | Social engineering or malware to steal signing keys | Ronin ($625M) |
| Message validation bypass | Insufficient verification of cross-chain messages | Wormhole ($320M), Poly Network |
| Logic bugs in state verification | Incorrect root/proof validation | Nomad ($190M) |
| Unsafe deserialization | Trusting user-supplied data for execution | Poly Network |
| Centralized validator set | Too few validators, too concentrated | Ronin (4 of 9 controlled) |
| Stale permissions | Access rights not revoked when no longer needed | Ronin |
| Unlimited minting | No supply cap enforcement on wrapped tokens | Multiple incidents |
| Oracle/price manipulation | Bridge using manipulable prices for asset valuation | Smaller exploits |

**Bridge security best practices:**
```
1. Decentralize validator set (20+ validators across independent organizations)
2. Require time-locks on large withdrawals (1-3 day delay above threshold)
3. Implement withdrawal rate limits (max X ETH per day)
4. Real-time anomaly detection and circuit breakers
5. Formal verification of core bridge logic
6. Regular security audits of every upgrade
7. Bug bounty programs with $1M+ rewards for critical findings
8. Multi-sig on bridge admin keys with hardware wallets
```

---

## 4. Smart Contract Auditing Tools

### 4.1 Slither — Static Analyzer

Slither is a Python-based static analysis framework for Solidity. It detects ~80+ vulnerability classes.

**Installation:**
```bash
pip install slither-analyzer
# or with solc-select for version management
pip install solc-select slither-analyzer
solc-select install 0.8.19 && solc-select use 0.8.19
```

**Basic usage:**
```bash
# Analyze a single contract
slither contracts/Vault.sol

# Analyze entire project
slither .

# Target specific detectors
slither contracts/ --detect reentrancy-eth,unprotected-upgrade --json results.json

# Exclude informational findings
slither . --exclude informational

# Print inheritance graph
slither . --print inheritance-graph

# Print call graph
slither . --print call-graph

# List all available detectors
slither . --list-detectors
```

**Detector categories:**
| Category | Examples | Severity |
|---|---|---|
| Reentrancy | reentrancy-eth, reentrancy-no-eth, reentrancy-benign | High/Medium |
| Access Control | unprotected-upgrade, suicidal, arbitrary-send-eth | High |
| Arithmetic | divide-before-multiply, incorrect-equality | Medium |
| Shadowing | shadowing-state, shadowing-local | Medium/Low |
| Optimization | costly-loop, cache-array-length | Optimization |
| ERC compliance | erc20-interface, erc721-interface | Informational |

**Slither CI integration:**
```yaml
# .github/workflows/slither.yml
name: Slither Analysis
on: [push, pull_request]

jobs:
  slither:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: crytic/setup-action@v1
        with:
          solc-version: 0.8.19
      - uses: crytic/slither-action@v0.3.0
        id: slither
        with:
          ignore-compile: true
          slither-args: "--filter-paths node_modules --detect reentrancy-eth,unprotected-upgrade"
          fail-on: high
```

**Slither output JSON structure:**
```json
{
  "success": true,
  "results": {
    "detectors": [
      {
        "check": "reentrancy-eth",
        "impact": "High",
        "confidence": "Medium",
        "description": "Vault.withdraw() (contracts/Vault.sol#45-52) sends ETH to arbitrary user...",
        "elements": [
          {
            "type": "function",
            "name": "withdraw",
            "source_mapping": {"filename_relative": "contracts/Vault.sol", "lines": [45, 52]}
          }
        ]
      }
    ]
  }
}
```

---

### 4.2 Mythril — Symbolic Execution

Mythril analyzes EVM bytecode using symbolic execution to find security vulnerabilities.

**Installation:**
```bash
pip install mythril
# Or via Docker
docker pull mythril/myth
```

**Usage:**
```bash
# Analyze a Solidity file
myth analyze contracts/Vault.sol --solv 0.8.19 -o json

# Analyze deployed contract
myth analyze -a 0x1234...ABCD --rpc https://mainnet.infura.io/v3/YOUR_KEY

# Set analysis depth (higher = more thorough, slower)
myth analyze contracts/Vault.sol --execution-timeout 300 --max-depth 22

# Output as JSON for CI
myth analyze contracts/Vault.sol --solv 0.8.19 -o json > mythril-results.json

# Docker usage
docker run mythril/myth analyze /path/to/contract.sol
```

**Mythril vulnerability classes detected:**
- Integer overflow/underflow (SWC-101)
- Reentrancy (SWC-107)
- Unprotected Ether withdrawal (SWC-105)
- Arbitrary JUMP (SWC-127)
- Delegatecall to user-supplied address (SWC-112)
- Unprotected selfdestruct (SWC-106)
- State change after external call (SWC-107)

**SWC Registry:** https://swcregistry.io — standardized vulnerability classification for smart contracts

---

### 4.3 Echidna — Property-Based Fuzzer

Echidna is a Haskell-based fuzzer for EVM smart contracts using property-based testing.

**Installation:**
```bash
# Binary release
wget https://github.com/crytic/echidna/releases/latest/download/echidna-test-linux-x86_64.tar.gz
tar xvf echidna*.tar.gz && mv echidna /usr/local/bin/

# Docker
docker pull ghcr.io/crytic/echidna/echidna
```

**Writing Echidna properties:**
```solidity
// EchidnaTest.sol
contract EchidnaVaultTest is Vault {
    // Echidna calls functions randomly, then checks invariants
    // Invariants must be functions starting with "echidna_"

    // Invariant: total balance should never exceed deposits
    function echidna_balance_invariant() public view returns (bool) {
        return address(this).balance <= totalDeposits;
    }

    // Invariant: user balance should never exceed their deposits
    function echidna_user_balance_invariant() public view returns (bool) {
        return balances[msg.sender] <= deposits[msg.sender];
    }

    // Invariant: contract should never be drained to zero if deposits > 0
    function echidna_not_drained() public view returns (bool) {
        return totalDeposits == 0 || address(this).balance > 0;
    }
}
```

**Running Echidna:**
```bash
# Basic fuzzing
echidna-test contracts/EchidnaVaultTest.sol --contract EchidnaVaultTest

# With config file
echidna-test . --contract EchidnaVaultTest --config echidna.yaml

# echidna.yaml
# testMode: assertion
# testLimit: 100000
# seqLen: 100
# shrinkLimit: 5000
# workers: 8
```

---

### 4.4 Foundry Forge — Fuzzing and Fork Testing

Foundry is the modern smart contract development framework with built-in fuzzing, fork testing, and invariant testing.

**Installation:**
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

**Fuzz testing:**
```solidity
// test/VaultFuzz.t.sol
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultFuzzTest is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
    }

    // Forge will automatically fuzz 'amount' with various inputs
    function testFuzz_deposit(uint256 amount) public {
        vm.assume(amount > 0 && amount < 1e18);  // Bound inputs
        vm.deal(address(this), amount);

        vault.deposit{value: amount}();
        assertEq(vault.balances(address(this)), amount);
    }

    // Bounded input using bound() helper (preferred over vm.assume)
    function testFuzz_withdraw(uint256 depositAmount, uint256 withdrawAmount) public {
        depositAmount = bound(depositAmount, 1, 1e18);
        withdrawAmount = bound(withdrawAmount, 1, depositAmount);

        vm.deal(address(this), depositAmount);
        vault.deposit{value: depositAmount}();
        vault.withdraw(withdrawAmount);
        assertEq(vault.balances(address(this)), depositAmount - withdrawAmount);
    }
}
```

**Fork testing against mainnet:**
```solidity
function testFork_existingProtocol() public {
    // Fork mainnet at specific block
    vm.createSelectFork("https://mainnet.infura.io/v3/KEY", 18_000_000);

    // Impersonate a whale
    address whale = 0x28C6c06298d514Db089934071355E5743bf21d60;
    vm.startPrank(whale);

    IERC20 usdc = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    vault.deposit(usdc, 1_000_000e6);
    vm.stopPrank();
}
```

**Invariant testing:**
```solidity
contract VaultInvariantTest is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
        targetContract(address(vault));
    }

    // Called after every sequence of function calls
    // forge test --match-test invariant_
    function invariant_totalAssetsMatchDeposits() public {
        assertEq(vault.totalAssets(), vault.totalDeposits());
    }

    function invariant_noUnderflow() public {
        assertTrue(vault.totalAssets() >= 0);
    }
}
```

**Running Foundry tests:**
```bash
forge test                           # All tests
forge test --match-test testFuzz_    # Only fuzz tests
forge test --match-test invariant_   # Only invariant tests
forge test -vvvv                     # Verbose output
forge coverage                       # Coverage report
forge snapshot                       # Gas snapshots
```

---

### 4.5 Certora Prover — Formal Verification

Certora Prover uses formal verification to mathematically prove or disprove properties of smart contracts. Rules are written in CVL (Certora Verification Language).

**CVL specification example:**
```javascript
// Vault.spec
methods {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
    function balances(address) external returns (uint256) envfree;
    function totalDeposits() external returns (uint256) envfree;
}

// Rule: withdraw cannot increase user balance
rule withdrawDecreasesBalance(uint256 amount) {
    address user;
    uint256 balanceBefore = balances(user);
    env e;
    require e.msg.sender == user;

    withdraw(e, amount);

    uint256 balanceAfter = balances(user);
    assert balanceAfter <= balanceBefore, "Balance increased after withdraw";
}

// Invariant: sum of all balances equals contract balance
invariant totalBalancesMatchContractBalance()
    totalDeposits() == nativeBalances[currentContract];
```

**Running Certora:**
```bash
certoraRun contracts/Vault.sol --verify Vault:specs/Vault.spec   --solc solc-0.8.19 --msg "Initial vault verification"
```

---

### 4.6 OpenZeppelin Defender

OpenZeppelin Defender provides automated security monitoring, relayers, and incident response for smart contracts.

**Key capabilities:**
```
Monitor:    Alert on specific on-chain events, unusual transaction patterns
Relayer:    Managed transaction signing with key rotation
Autotask:   Serverless functions triggered by monitor alerts or schedule
Sentinel:   Automated response — pause contract, notify team
```

**Example Defender Autotask (emergency pause):**
```javascript
const { ethers } = require("ethers");
const { DefenderRelayProvider, DefenderRelaySigner } = require("defender-relay-client/lib/ethers");

exports.handler = async function(event) {
    const provider = new DefenderRelayProvider(event);
    const signer = new DefenderRelaySigner(event, provider, { speed: 'fast' });

    const vault = new ethers.Contract(VAULT_ADDRESS, VAULT_ABI, signer);

    // Triggered when: transfer event > 1000 ETH in single tx
    const tx = await vault.pause();
    console.log(`Emergency pause tx: ${tx.hash}`);
    return { txHash: tx.hash };
};
```

---

## 5. Solidity Security Patterns

### 5.1 Checks-Effects-Interactions (CEI) Pattern

```solidity
function withdraw(uint256 amount) external {
    // 1. CHECKS — validate inputs and state
    require(amount > 0, "Amount must be positive");
    require(balances[msg.sender] >= amount, "Insufficient balance");
    require(!paused, "Contract paused");

    // 2. EFFECTS — update state BEFORE external calls
    balances[msg.sender] -= amount;
    totalDeposits -= amount;
    emit Withdrawal(msg.sender, amount);

    // 3. INTERACTIONS — external calls LAST
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "ETH transfer failed");
}
```

### 5.2 Pull Payment (Withdrawal) Pattern

```solidity
contract PullPayment {
    mapping(address => uint256) private _payments;

    // PUSH (vulnerable to DoS if recipient is malicious contract)
    function badDistribute(address[] calldata payees) external {
        for (uint i = 0; i < payees.length; i++) {
            payable(payees[i]).transfer(amount);  // Can revert, blocking all payments
        }
    }

    // PULL (safe — each user claims their own payment)
    function creditPayment(address payee, uint256 amount) internal {
        _payments[payee] += amount;
    }

    function withdrawPayments() external {
        uint256 payment = _payments[msg.sender];
        _payments[msg.sender] = 0;
        payable(msg.sender).transfer(payment);
    }
}
```

### 5.3 Rate Limiting and Circuit Breakers

```solidity
contract RateLimitedVault {
    uint256 public constant MAX_DAILY_WITHDRAWAL = 100 ether;
    uint256 public constant WINDOW = 1 days;

    uint256 public windowStart;
    uint256 public withdrawnInWindow;
    bool public circuitBreakerTripped;

    modifier rateLimit(uint256 amount) {
        if (block.timestamp >= windowStart + WINDOW) {
            windowStart = block.timestamp;
            withdrawnInWindow = 0;
        }
        require(withdrawnInWindow + amount <= MAX_DAILY_WITHDRAWAL, "Rate limit exceeded");
        withdrawnInWindow += amount;
        _;
    }

    modifier notTripped() {
        require(!circuitBreakerTripped, "Circuit breaker active");
        _;
    }

    function withdraw(uint256 amount) external rateLimit(amount) notTripped {
        // Automatic circuit breaker: if >50% drained in single block
        if (address(this).balance < initialBalance / 2) {
            circuitBreakerTripped = true;
            emit CircuitBreakerTripped(block.number);
            revert("Circuit breaker: unusual drain detected");
        }
        // ... withdrawal logic
    }
}
```

### 5.4 Emergency Pause (OpenZeppelin Pausable)

```solidity
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract PausableVault is Pausable, AccessControl {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UNPAUSER_ROLE = keccak256("UNPAUSER_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
    }

    // Only PAUSER_ROLE can pause — can be granted to monitoring systems
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    // UNPAUSER_ROLE requires stricter multisig control
    function unpause() external onlyRole(UNPAUSER_ROLE) {
        _unpause();
    }

    function deposit() external payable whenNotPaused {
        // Deposits blocked when paused
    }

    function withdraw(uint256 amount) external whenNotPaused {
        // Withdrawals also blocked — prevents attacker draining during incident
    }

    // Emergency withdraw — available even when paused (only owner)
    function emergencyWithdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

### 5.5 Upgradeable Contract Security

**Transparent Proxy Pattern:**
```solidity
// Admin calls go to proxy, user calls delegatecall to implementation
// ProxyAdmin.sol controls upgrades

// Storage gap — prevents storage collisions in inherited contracts
abstract contract VersionA {
    uint256 public valueA;
    uint256[49] private __gap;  // Reserve 49 slots for future variables
}

abstract contract VersionB is VersionA {
    uint256 public valueB;  // Uses slot 50 (after gap)
    uint256[48] private __gap;  // Adjusted gap
}
```

**UUPS (Universal Upgradeable Proxy Standard, EIP-1822):**
```solidity
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract VaultV1 is UUPSUpgradeable, OwnableUpgradeable {
    mapping(address => uint256) public balances;

    function initialize(address _owner) external initializer {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
    }

    // Required by UUPS — restricts who can upgrade
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        // Add delay requirement, timelock, or multisig here
    }
}
```

**UUPS vs. Transparent Proxy:**
| Property | Transparent Proxy | UUPS |
|---|---|---|
| Upgrade logic location | ProxyAdmin contract | Implementation contract |
| Gas cost (calls) | Slightly higher | Lower |
| Bricking risk | Lower (proxy always upgradeable) | Higher (bad implementation disables upgrades) |
| Admin collision | Handled via ProxyAdmin | N/A |

### 5.6 OpenZeppelin Role-Based Access Control

```solidity
import "@openzeppelin/contracts/access/AccessControl.sol";

contract ManagedProtocol is AccessControl {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    constructor(address admin, address[] memory guardians) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);  // Admin manages all roles
        for (uint i = 0; i < guardians.length; i++) {
            _grantRole(GUARDIAN_ROLE, guardians[i]);
        }
        // Set role hierarchy: GUARDIAN_ROLE is administered by DEFAULT_ADMIN
        _setRoleAdmin(GUARDIAN_ROLE, DEFAULT_ADMIN_ROLE);
    }

    function sensitiveOperation() external onlyRole(OPERATOR_ROLE) {
        // ...
    }

    function emergencyPause() external onlyRole(GUARDIAN_ROLE) {
        // Guardians can pause without admin
    }
}
```

### 5.7 Multi-Signature Requirements (Gnosis Safe)

Gnosis Safe is the most widely deployed multi-signature wallet in DeFi ($100B+ under management).

```
Gnosis Safe 3-of-5 cold wallet setup for exchange:
  Signers: 5 hardware wallets (Ledger/Trezor) held by different executives
  Threshold: 3 signatures required to approve transactions
  Hardware: Different brands (Ledger + Trezor) to reduce supply chain risk
  Geography: Distributed across 3+ physical locations

Transaction flow:
  1. Propose transaction in Safe web UI
  2. Collect 3 signatures (each signer uses their hardware wallet)
  3. Execute transaction

Security properties:
  - Single key compromise cannot steal funds
  - Two key compromises cannot steal funds
  - Single key loss does not lock funds (3-of-5 → 2 keys can be lost)
```

### 5.8 Timelock Controllers for Governance

```solidity
import "@openzeppelin/contracts/governance/TimelockController.sol";

// Deploy with 2-day delay minimum
TimelockController timelock = new TimelockController(
    2 days,           // minDelay
    proposers,        // Can propose (governance contract, multisig)
    executors,        // Can execute after delay (anyone, or specific address)
    admin             // Can admin (address(0) for no admin)
);

// Governance action flow:
// 1. Proposer calls schedule() — starts 2-day clock
// 2. Community can review pending action
// 3. If malicious: cancel before execution
// 4. After 2 days: anyone can call execute()

// Emergency bypass: cancel is always available (to CANCELLER_ROLE)
// Audits: All pending and completed actions visible on-chain
```

---

## 6. Blockchain Network Security

### 6.1 Node Security

**Ethereum node attack surface:**

```
Exposed services (default ports):
  30303 TCP/UDP  — P2P (devp2p / libp2p) — MUST be public for sync
  8545 TCP       — HTTP RPC — NEVER expose to internet
  8546 TCP       — WebSocket RPC — NEVER expose to internet
  8551 TCP       — Engine API (consensus ↔ execution) — localhost only
  9000 TCP/UDP   — Lighthouse/Prysm P2P — must be public
```

**Geth hardening:**
```bash
# Never expose RPC to 0.0.0.0 without authentication
geth --http.addr 127.0.0.1      --http.port 8545      --http.api eth,net,web3 \           # Minimal API exposure
     --http.vhosts localhost \           # Only allow localhost
     --authrpc.addr 127.0.0.1 \         # Engine API localhost only
     --authrpc.jwtsecret /path/jwt.hex \ # JWT auth for consensus client
     --ws.addr 127.0.0.1      --maxpeers 50 \                     # Limit peer connections
     --nat extip:YOUR_STATIC_IP      --metrics      --pprof.addr 127.0.0.1             # Profiling localhost only
```

**API key management for node providers:**
```
Infura / Alchemy / QuickNode best practices:
  1. Create separate API keys per application
  2. Set domain/IP allowlists for each key
  3. Rate limit keys individually
  4. Monitor for unusual usage patterns
  5. Rotate keys periodically or on compromise
  6. Never commit API keys to git repositories

Use .env files + git-secret or HashiCorp Vault for key management
```

---

### 6.2 Eclipse Attacks

An eclipse attack isolates a node by controlling all of its peer connections.

```
Normal node: Connected to 25 random peers across the network
Eclipse attack: Attacker fills all 25 peer slots with attacker-controlled nodes

Effects:
  - Node only sees attacker's version of chain
  - Can be shown stale or fake blocks
  - Enables 0-confirmation double spends against the eclipsed victim
  - Can selectively censor transactions

Defenses (Bitcoin/Ethereum):
  - Peer diversity requirements (no more than X peers per /24 subnet)
  - Random peer rotation
  - Kademlia-based peer discovery (makes targeting harder)
  - Feeler connections to test new peer candidates
  - Inbound connection limits separate from outbound
```

---

### 6.3 BGP Hijacking Impact

BGP (Border Gateway Protocol) route hijacking allows ASes to announce false routes, redirecting internet traffic.

**Impact on crypto exchanges:**
```
2018 Amazon Route 53 BGP Hijack:
  - Attacker hijacked MyEtherWallet's DNS traffic via BGP
  - Redirected users to phishing server with fake SSL cert
  - Stole ~$17M in ETH

2014 CryptoWall BGP Hijack:
  - Botnet operators redirected mining pool traffic
  - Stole mining rewards by redirecting hashrate

Defenses:
  - RPKI (Resource Public Key Infrastructure) — cryptographic BGP route validation
  - DNSSEC — signs DNS responses
  - DNS-over-HTTPS (DoH) — prevents DNS interception
  - Certificate Transparency (CT) — detect fraudulent TLS certs
  - HSTS preloading — prevents SSL stripping
```

---

### 6.4 MEV Infrastructure Security

Maximal Extractable Value (MEV) infrastructure has become critical Ethereum security infrastructure.

```
PBS (Proposer-Builder Separation) flow:
  1. Builders collect transactions + MEV opportunities
  2. Builders construct blocks and bid to proposers via relays
  3. Proposer selects highest-bid block from trusted relays
  4. Relay verifies block validity before revealing to proposer

Relay trust model:
  - Proposer trusts relay won't release block without payment
  - Builder trusts relay won't steal their block
  - Relay is the trusted intermediary (centralization risk)

MEV-Boost relay censorship (2022-2023):
  - OFAC-compliant relays refused to include certain addresses (Tornado Cash)
  - At peak, ~70% of blocks censored at relay level
  - Countermeasure: MEV-Boost with multiple relays, including uncensored

Security risks:
  - Relay compromise → proposer receives invalid/malicious block
  - All major relays operated by small number of entities
  - Flashbots open-sourced MEV-Boost to allow community operation
```

---

## 7. Exchange and Wallet Security

### 7.1 Hot/Cold Wallet Architecture

```
Exchange cold storage best practice:

  Total user funds: $500M
  ├── Cold storage: $450M (90%) — offline, multi-sig, air-gapped
  │   └── 3-of-5 Gnosis Safe with hardware wallet signers
  ├── Warm storage: $45M (9%) — online, multi-sig, auto-rebalance
  │   └── 2-of-3 multi-sig, hardware wallets + HSM
  └── Hot wallet: $5M (1%) — single-sig, HSM-secured, rate-limited
      └── Auto-refilled from warm when below $2M
      └── Daily withdrawal limit: $2M max

Automated cold→hot rebalancing:
  - Triggered when hot wallet < 0.5% of AUM
  - Requires 2-of-3 warm wallet approvals
  - Audit trail: every rebalancing operation logged with justification
  - Human review for any transfer > $1M
```

### 7.2 Withdrawal Security Controls

```python
# Withdrawal security pipeline (pseudocode)

class WithdrawalRequest:
    def validate(self):
        # 1. KYC/AML check
        if not user.is_kyc_verified():
            raise ValidationError("KYC required for withdrawals")

        # 2. Withdrawal allowlist
        if address not in user.allowed_addresses:
            raise ValidationError("Address not in allowlist")

        # 3. Velocity limits
        daily_amount = get_24h_withdrawal_amount(user)
        if daily_amount + amount > user.daily_limit:
            raise ValidationError("Daily limit exceeded")

        # 4. Risk scoring
        risk_score = aml_engine.score_address(address)
        if risk_score > 80:  # Chainalysis/Elliptic risk score
            queue_for_manual_review(self)
            return

        # 5. Travel rule (FATF) — for transfers > $1000
        if amount_usd >= 1000:
            if not has_travel_rule_data(address):
                request_travel_rule_info()
                return

        # 6. Sanctions check
        if sanctions_engine.is_sanctioned(address):
            block_and_report(self)
            return

        # 7. 2FA confirmation for large withdrawals
        if amount_usd >= 5000:
            require_2fa_confirmation(user)

        # 8. Email confirmation for new addresses
        if address.first_seen < 24_hours_ago:
            send_confirmation_email(user)
```

### 7.3 HSM Integration for Exchange Key Management

Hardware Security Modules (HSMs) protect signing keys in tamper-resistant hardware.

```
HSM usage in exchanges:
  Vendor examples: Thales Luna, AWS CloudHSM, YubiHSM 2

  Hot wallet signing flow:
    Application → HSM API (PKCS#11 / JCE) → HSM signs transaction
    Private key NEVER leaves HSM
    Audit log: every signing operation logged with requester identity

  HSM access controls:
    - M-of-N authentication required to activate HSM
    - Role separation: key custodians vs. operators
    - Time-based access controls (business hours only for non-emergency)
    - Geographic access restrictions
    - Automatic key backup to secondary HSM

  AWS CloudHSM example:
    - FIPS 140-2 Level 3 certified
    - Customer-managed keys (AWS cannot access)
    - Multi-AZ deployment for HA
    - CloudTrail audit of all HSM operations
```

### 7.4 Proof of Reserves

Post-FTX collapse, exchanges adopted cryptographic proof of reserves to demonstrate solvency.

```
Merkle Sum Tree (Plasma-style PoR):

  User leaves: (user_id_hash, balance)
  Each internal node: (hash(left || right), sum_left + sum_right)
  Root: (root_hash, total_user_balances)

  User verification:
  1. Exchange provides Merkle proof for user's leaf
  2. User verifies their balance is included correctly
  3. User checks root_balance = total_user_balances
  4. Exchange signs root with hot wallet address
  5. User verifies on-chain balance of hot + cold wallets ≥ root_balance

  Privacy: User learns only their sibling hash sums, not individual balances

  Limitations:
  - Does not prove liabilities (exchange could have hidden debts)
  - Does not prevent fractional reserve between audits
  - Requires trusting auditor for completeness

Tools: Summa (a16z), Chainalysis PoR, custom implementations (Binance)
```

### 7.5 Exchange Hack Case Studies

**Mt. Gox ($450M BTC, 2011-2014):**
```
Multiple incidents:
  2011: Auditor accidentally set BTC price to $0.01 → 2,000 BTC stolen
  2011: 650,000 BTC stolen from hot wallet over time
  2014: Exchange collapsed — 850,000 BTC missing (200K later recovered)

Root causes:
  - No separation between hot and cold storage
  - No real-time monitoring of wallet balances
  - Single point of failure: CEO (Mark Karpelès) had sole control
  - Poor accounting: took 3 years to notice 650K BTC missing
  - No multi-signature for any wallets
```

**FTX Collapse ($8B, 2022):**
```
Not a hack — fraud/mismanagement:
  - Customer funds commingled with Alameda Research
  - FTT token used as collateral for Alameda loans from FTX
  - $8B+ customer funds missing when withdrawal run occurred
  - No segregation of customer assets from trading desk

Security failures:
  - $370M stolen by insider/hacker on night of bankruptcy
  - Extremely poor key management (keys stored in unencrypted S3 buckets)
  - No multi-signature requirements
  - Single employee had admin access to entire infrastructure
```

**Binance Bridge Hack ($570M, October 2022):**
```
BSC Token Hub bridge exploit:
  Attacker forged proof of deposit on Binance Chain
  Bridge verified Merkle proofs for BNB Chain messages
  Vulnerability: Proof verification bug allowed forging inclusion proofs
  Impact: 2M BNB minted fraudulently
  Mitigation: BNB Chain validators froze $432M, attacker kept ~$110M

Key lesson: Bridge proof verification must be formally verified
```

---

## 8. NFT and Token Security

### 8.1 ERC-20 Token Vulnerabilities

**Approval attack / infinite approval phishing:**
```solidity
// Victim approves malicious contract for unlimited spending
IERC20(tokenAddress).approve(maliciousContract, type(uint256).max);
// Attacker calls transferFrom at any time, draining victim's balance

// Safer: Use EIP-2612 permit() — approval with expiry and signature
// Or: Approve only exact amount needed per transaction
```

**ERC-20 Permit phishing (EIP-2612):**
```
Attack flow:
1. Victim signs a "gasless approval" permit message (off-chain)
2. Signature creates approval without on-chain transaction
3. Attacker submits permit + transferFrom in one tx
4. No on-chain approval event visible to victim before theft

Defense:
  - Wallets should clearly display permit signature requests
  - Use Revoke.cash to check and revoke approvals
  - Hardware wallet prompts show permit details
```

**Common ERC-20 implementation bugs:**
```solidity
// Rebasing tokens (AMPL, stETH) — balance changes every block
// Direct balance caching breaks DeFi integrations

// Fee-on-transfer tokens (SAFEMOON-like)
// Amount received < amount sent — breaks protocols assuming amount == received

// Non-standard transfer (USDT return value bug)
// USDT transfer() doesn't return bool — use SafeERC20.safeTransfer()
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;
token.safeTransfer(recipient, amount);  // Handles non-standard returns
```

### 8.2 ERC-721/1155 Security

```solidity
// ERC-721 safeTransferFrom reentrancy
// Calls onERC721Received() on recipient if it's a contract
// This is an external call — reentrancy possible!

function safeTransferFrom(address from, address to, uint256 tokenId) external {
    // Transfer first (state change)
    _transfer(from, to, tokenId);
    // Then call recipient
    if (to.code.length > 0) {
        // EXTERNAL CALL — potential reentrancy
        IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, "");
    }
}

// ERC-1155 batch transfers also call onERC1155BatchReceived
// Always apply CEI pattern and reentrancy guards in contracts receiving NFTs
```

### 8.3 OpenSea Wyvern Exploit (January 2022)

```
Vulnerability in Wyvern Protocol (OpenSea's order book):
  Attacker sent phishing emails with "OpenSea migration" link
  Link prompted MetaMask signature for an order with blank callTarget
  Wyvern allowed delegatecall to attacker-controlled contract
  32 users signed the fraudulent transaction
  ~254 ETH ($750K) worth of NFTs stolen

Root cause:
  - Users did not understand what they were signing
  - Order format allowed arbitrary delegatecall targets
  - No transaction simulation shown to users

Fix:
  - OpenSea migrated to Seaport protocol (open source, audited)
  - Seaport uses a more restrictive order format
  - MetaMask added transaction simulation (via Tenderly integration)
```

### 8.4 Token Approval Management

```
Revoke.cash pattern for managing approvals:

1. Connect wallet to revoke.cash (or etherscan token approvals)
2. View all active approvals across all ERC-20/721 tokens
3. Revoke any suspicious or unlimited approvals
4. Set approvals to 0 rather than type(uint256).max

On-chain events to monitor:
  event Approval(address indexed owner, address indexed spender, uint256 value);

Best practices:
  - Never approve infinite amounts to unaudited contracts
  - Check contract audit status before approving
  - Use hardware wallet for approval transactions (shows destination)
  - Periodically audit approvals (monthly)
  - Use Revoke.cash, Etherscan, or DeBank to view active approvals
```

---

## 9. Regulatory and Compliance

### 9.1 FATF Travel Rule

The FATF Travel Rule (Recommendation 16) requires Virtual Asset Service Providers (VASPs) to share originator and beneficiary information for transfers above $1,000/€1,000.

**IVMS 101 (InterVASP Messaging Standard):**
```json
{
  "originator": {
    "originatorPersons": [{
      "naturalPerson": {
        "name": [{
          "nameIdentifier": [{
            "primaryIdentifier": "Smith",
            "secondaryIdentifier": "John",
            "nameIdentifierType": "LEGL"
          }]
        }],
        "dateAndPlaceOfBirth": {
          "dateOfBirth": "1990-01-15",
          "placeOfBirth": "New York"
        },
        "nationalIdentification": {
          "nationalIdentifier": "123-45-6789",
          "nationalIdentifierType": "SSIN"
        }
      }
    }],
    "accountNumber": ["0x742d35Cc6634C0532925a3b8D4C9B9b8d1E5Ab1C"]
  },
  "beneficiary": {
    "beneficiaryPersons": [{
      "naturalPerson": {
        "name": [{"nameIdentifier": [{"primaryIdentifier": "Jones", "secondaryIdentifier": "Mary"}]}]
      }
    }],
    "accountNumber": ["0x1234...ABCD"]
  },
  "transferAmount": {
    "value": "1000.00",
    "currency": "USDC"
  }
}
```

**Travel Rule technology vendors:**
- Notabene (most widely deployed)
- Sygna Bridge (used in Asia)
- TRP (Travel Rule Protocol — HSBC, Standard Chartered)
- VerifyVASP
- Shyft Network

**Unhosted wallet (self-hosted wallet) challenges:**
- Travel Rule typically only applies VASP-to-VASP
- EBA/FATF guidance varies by jurisdiction for unhosted wallet transfers
- MiCA (EU): Enhanced due diligence for transfers to unhosted wallets > €1,000

---

### 9.2 Blockchain Analytics for AML

**Leading platforms:**
| Platform | Owned By | Specialties |
|---|---|---|
| Chainalysis | Private | Investigations, compliance, KYT |
| Elliptic | Private | VASP compliance, enterprise |
| CipherTrace | Mastercard | Government, investigations |
| TRM Labs | Private | Fraud, compliance, sanctions |
| Merkle Science | Private | APAC focus, DeFi coverage |

**Transaction monitoring concepts:**
```
Risk scoring factors:
  - Direct exposure: funds came directly from flagged address
  - Indirect exposure: funds passed through N hops from flagged address
  - Counterparty type: exchange, mixer, darknet, ransomware wallet
  - Jurisdiction: sanctions considerations

Heuristics used:
  - Common input ownership (Bitcoin: inputs in same tx likely same owner)
  - Change address detection
  - Peeling chains (single output sent through multiple addresses)
  - Dust attacks (track wallet consolidation)

Limitations:
  - Privacy coins (Monero, Zcash shielded) largely unanalyzable
  - CoinJoin (Wasabi Wallet) significantly reduces tracing confidence
  - Cross-chain bridges break address linkage between chains
  - Layer 2 (Lightning Network, zkSync) reduces on-chain footprint
```

---

### 9.3 Sanctions Screening

```
OFAC SDN List screening for blockchain:

  Direct match:
    Any transaction to/from an OFAC-designated wallet address
    Examples: Tornado Cash smart contracts (sanctioned Aug 2022)
              North Korean Lazarus Group wallets
              Iranian exchange wallets

  Indirect exposure:
    Funds that recently passed through sanctioned addresses
    Time window and hop count vary by compliance policy

  Implementation:
    if chainalysis.get_risk_score(address).includes("OFAC SDN"):
        block_transaction()
        file_SAR() if US_nexus else file_locally()

  Tornado Cash precedent:
    First time US sanctions applied to immutable smart contract code
    Court case (Van Loon v. Treasury) partially ruled in favor of sanctions
    Ongoing legal uncertainty for DeFi protocols
```

---

### 9.4 MiCA (EU Crypto Regulation)

Markets in Crypto-Assets Regulation (MiCA) — effective June 2024 for stablecoins, December 2024 for CASPs.

**Key security requirements:**
```
Crypto-Asset Service Providers (CASPs):
  1. Custody requirements:
     - Segregate client assets from own assets
     - Cold storage for majority of client assets
     - Cover losses from security failures

  2. Cybersecurity requirements:
     - Implement ICT risk management framework (DORA aligned)
     - Penetration testing requirements
     - Incident reporting within 24 hours of major incidents

  3. Stablecoin issuers (ART/EMT):
     - 2/3 reserve in custody at credit institutions
     - Regular redemption stress tests
     - Interoperability requirements

  4. DeFi (largely out of scope for now):
     - Guidance expected post-2025 review
     - Fully decentralized protocols may be exempt
```

---

### 9.5 SEC Digital Asset Custody

SEC Staff Bulletin 2022-8 (SAB 121):
```
Accounting treatment for crypto custody:
  - Entities holding customer crypto MUST record a liability on balance sheet
  - Corresponding asset (crypto) also recorded at fair value
  - Unprecedented: traditional custodians don't record client assets on own balance sheet
  - Purpose: protect investors if custodian fails

SAB 122 (2025): Reversed SAB 121 for most entities
  - Banks meeting prudential standards can use traditional off-balance-sheet treatment

Qualified Custodian definition (Investment Advisers Act):
  - Banks, savings institutions, broker-dealers, futures commission merchants
  - Many crypto custodians argue they qualify
  - SEC has not approved any crypto-native custodian as qualified custodian
```

---

## 10. Incident Response for Blockchain

### 10.1 On-Chain Transaction Monitoring

**Setting up real-time monitoring:**
```python
# Using web3.py to monitor for suspicious transactions
from web3 import Web3
from web3.middleware import geth_poa_middleware

w3 = Web3(Web3.WebsocketProvider('wss://mainnet.infura.io/ws/v3/YOUR_KEY'))

VAULT_ADDRESS = '0xYourVaultAddress'
ALERT_THRESHOLD = w3.to_wei(100, 'ether')

def handle_new_block(block_hash):
    block = w3.eth.get_block(block_hash, full_transactions=True)
    for tx in block.transactions:
        if tx['to'] == VAULT_ADDRESS:
            if tx['value'] > ALERT_THRESHOLD:
                send_alert(f"Large inbound tx: {tx['hash'].hex()} value={tx['value']}")

        # Check for unusual function calls
        if tx['to'] == VAULT_ADDRESS and len(tx['input']) >= 4:
            selector = tx['input'][:4].hex()
            if selector in SUSPICIOUS_SELECTORS:
                send_alert(f"Suspicious function call: {selector}")

w3.eth.subscribe('newBlockHeaders', handle_new_block)
```

**Monitoring services:**
- OpenZeppelin Defender Sentinel
- Tenderly Alerts
- Forta Network (decentralized threat detection)
- Chainalysis KYT (Know Your Transaction)
- Nansen Smart Alerts

**Forta threat detection bots:**
```javascript
// Example Forta bot for reentrancy detection
function handleTransaction(txEvent) {
    const findings = [];
    const reentrancyPattern = txEvent.traces
        .filter(t => t.action.callType === 'call')
        .reduce((acc, trace) => {
            const key = `${trace.action.from}-${trace.action.to}`;
            acc[key] = (acc[key] || 0) + 1;
            return acc;
        }, {});

    for (const [pair, count] of Object.entries(reentrancyPattern)) {
        if (count > 5) {
            findings.push(Finding.fromObject({
                name: 'Potential Reentrancy',
                description: `Repeated call pattern: ${pair} (${count}x)`,
                severity: FindingSeverity.High,
                type: FindingType.Exploit
            }));
        }
    }
    return findings;
}
```

---

### 10.2 Emergency Pause Procedure

```
DeFi protocol emergency response runbook:

TRIGGER CONDITIONS:
  - Unexpected large outflow (>10% TVL in single block)
  - Anomalous function call sequence detected by monitoring
  - External report from security researcher or white hat
  - Price oracle divergence > 20% from reference
  - Community report of unusual behavior

IMMEDIATE RESPONSE (0-15 minutes):
  1. PAUSE: Execute emergency pause via Guardian multisig
     gnosis safe tx: vault.pause()
     Required: 2-of-3 guardian keys

  2. ASSESS: Review suspicious transactions on-chain
     Dune Analytics / Etherscan / Tenderly

  3. COMMUNICATE:
     Internal: Emergency Slack/Signal channel
     External: Twitter "We are investigating an incident. All funds are PAUSED."
     Do NOT confirm exploit or amount until confirmed

  4. PRESERVE: Take snapshots
     Block number at pause
     User balances at that block
     Transaction hash of suspicious activity

  5. ESCALATE:
     Notify security auditors (24/7 contact on file)
     Notify legal counsel
     Notify insurance (Nexus Mutual, InsurAce, etc.)

INVESTIGATION (15 min - 4 hours):
  1. Trace attack transactions via Tenderly debug
  2. Identify root cause: which contract, which function, which condition
  3. Calculate impact: total assets drained
  4. Determine if ongoing (contract still vulnerable while paused)

RECOVERY DECISION (4-24 hours):
  Option A: Deploy fix and resume
    - Audit fix
    - Deploy with timelock (waived in emergency)
    - Gradual unpause with rate limits

  Option B: Migration
    - Deploy new contracts
    - Snapshot user balances at attack block
    - Manual recovery / airdrop

  Option C: White hat negotiation
    - Send on-chain message offering bug bounty
    - Set deadline (24-48 hours)
    - Coordinate with law enforcement if no response
```

---

### 10.3 Post-Exploit Fund Tracing

```
Tracing stolen crypto funds:

Step 1: Identify attack transactions
  - Find entry point (flash loan, initial deposit)
  - Trace fund flow through subsequent transactions

Step 2: Cluster attacker addresses
  - All addresses used in attack
  - Deposit addresses at exchanges
  - Intermediary wallets

Tools:
  Etherscan: Manual tracing
  Metasleuth: Automated attack tracing (free tier available)
  Breadcrumbs: Visual blockchain investigation
  Chainalysis Reactor: Professional investigation platform

Step 3: Monitor exchange deposits
  - Report attacker addresses to major exchanges
  - Exchanges can freeze deposits from flagged addresses
  - Coordinate with Chainalysis/Elliptic for VASP notifications

Step 4: Bridge and chain hop detection
  - Attackers often bridge to other chains within hours
  - Cross-chain tracing tools: Metasleuth, Breadcrumbs support multi-chain
  - Common bridges used post-hack: Stargate, Synapse, Hop Protocol

Step 5: Tornado Cash / mixer usage
  - If funds enter Tornado Cash: tracing becomes probabilistic
  - Statistical analysis of deposit/withdrawal timing can link addresses
  - Blockchain analytics tools maintain partial Tornado Cash deposit/withdrawal matching

Timeline of typical large hack:
  Hour 0:   Exploit executed
  Hour 1-2: Funds bridged to multiple chains
  Hour 4-8: Exchanges contacted, some addresses frozen
  Hour 24:  Funds entered mixers or DEX swaps
  Day 3-7:  Attempted cash-out at less-regulated exchanges
```

---

### 10.4 Bug Bounty Programs

**Immunefi Platform:**
```
Largest blockchain bug bounty platform
Total payouts: $100M+ to researchers
Severity tiers:

Critical:
  - Direct theft of user funds
  - Permanent freezing of funds
  - Minting tokens without authorization
  Payout: $10,000 - $10,000,000

High:
  - Theft requiring user interaction
  - Temporary freezing of significant funds
  - Governance manipulation
  Payout: $5,000 - $100,000

Medium:
  - DoS of protocol (temporary)
  - Griefing attacks with no profit motive
  Payout: $1,000 - $20,000

Low:
  - Informational/best practices
  Payout: $500 - $5,000

Notable bounties paid:
  - $10M: Wormhole (undisclosed researcher, 2022)
  - $6M: Aurora bridge (security researcher pwning.eth, 2022)
  - $2M: Polygon (undisclosed, 2021)
  - $1M: Optimism (Jay Freeman/@saurik, 2022)
```

**Running a bug bounty program:**
```yaml
# Sample Immunefi bug bounty scope definition

scope:
  in_scope:
    - "https://github.com/protocol/contracts/blob/main/src/Vault.sol"
    - "https://github.com/protocol/contracts/blob/main/src/Bridge.sol"
    - Deployed contracts on mainnet: [0x123..., 0x456...]

  out_of_scope:
    - Test networks (Goerli, Sepolia)
    - Frontend/UI issues
    - Third-party dependencies (OpenZeppelin contracts)
    - Centralized infrastructure (website, APIs)
    - Known issues listed in audit reports

response_sla:
  acknowledgment: 48 hours
  triage: 5 business days
  payout: 30 days after fix deployed

rules:
  - No public disclosure until fix deployed
  - No testing on mainnet with real user funds
  - Proof of concept required for critical/high
  - No social engineering, phishing, or DDoS
```

---

### 10.5 MITRE ATT&CK for Blockchain

While MITRE has not released an official Blockchain ATT&CK framework, security researchers have mapped common attack patterns.

**Blockchain attack pattern mapping:**

| ATT&CK Tactic | Blockchain Equivalent | Example Technique |
|---|---|---|
| Initial Access | Wallet compromise, phishing | Seed phrase theft, malicious transaction signing |
| Execution | Smart contract exploitation | Reentrancy, flash loan execution |
| Persistence | Governance takeover | Malicious proposal installation |
| Privilege Escalation | Access control bypass | Unprotected initializer, tx.origin bypass |
| Defense Evasion | Fund obfuscation | Tornado Cash, bridge hopping, DEX swaps |
| Credential Access | Private key theft | Hardware wallet attack, hot wallet compromise |
| Discovery | On-chain reconnaissance | Smart contract code analysis, TVL mapping |
| Lateral Movement | Cross-chain attacks | Bridge exploitation, cross-contract reentrancy |
| Collection | Front-running/MEV | Transaction monitoring, sandwich attacks |
| Exfiltration | Fund withdrawal | Rapid withdrawal, exchange cash-out |
| Impact | Protocol damage | Oracle manipulation, governance attack |

**Community resources for blockchain threat modeling:**
- OWASP Smart Contract Top 10: https://owasp.org/www-project-smart-contract-top-10/
- SWC Registry: https://swcregistry.io
- DeFiHackLabs: https://github.com/SunWeb3Sec/DeFiHackLabs (PoC exploits for 300+ hacks)
- Rekt.news: https://rekt.news (post-mortems for major DeFi incidents)
- BlockThreat Newsletter: Weekly blockchain security threat intelligence
- Immunefi Bug Bounty: https://immunefi.com
- Trail of Bits Building Secure Smart Contracts: https://github.com/crytic/building-secure-contracts

---

## Quick Reference: Vulnerability → Tool Mapping

| Vulnerability Class | Slither | Mythril | Echidna | Certora |
|---|---|---|---|---|
| Reentrancy | ✓ (reentrancy-eth) | ✓ | ✓ (invariant) | ✓ (rule) |
| Integer overflow | ✓ | ✓ | ✓ | ✓ |
| Access control | ✓ | ✓ | Limited | ✓ |
| Unprotected initializer | ✓ | Limited | Limited | ✓ |
| Flash loan economic | ✗ | ✗ | ✓ (with setup) | ✓ (rules) |
| Oracle manipulation | ✗ | ✗ | ✓ (fork mode) | ✓ |
| Storage collision | ✓ | Limited | ✗ | ✓ |
| Signature replay | Limited | Limited | ✗ | ✓ |

## Essential Audit Checklist

```
Pre-audit:
  [ ] Codebase freeze and version pinning
  [ ] Identify all external calls and integrations
  [ ] Document all trust assumptions
  [ ] Map all privilege roles and their powers
  [ ] List all invariants (what should always be true)

Smart contract review:
  [ ] All external calls follow CEI pattern
  [ ] ReentrancyGuard on all state-changing functions with external calls
  [ ] Access control on all sensitive functions
  [ ] Input validation (zero amounts, zero addresses, array bounds)
  [ ] Integer arithmetic safety (Solidity 0.8+ or SafeMath)
  [ ] Oracle price validation (freshness, deviation limits)
  [ ] Signature validation (EIP-712, replay protection, expiry)
  [ ] Upgrade safety (storage gaps, initialization guards)
  [ ] Event emission for all state changes
  [ ] Gas limit considerations for loops

Testing:
  [ ] 100% branch coverage
  [ ] Fuzz testing for core financial functions
  [ ] Invariant testing for protocol invariants
  [ ] Fork testing against mainnet state
  [ ] Formal verification for critical paths

Post-audit:
  [ ] All findings remediated or acknowledged
  [ ] Re-audit of changed code
  [ ] Bug bounty program live before deployment
  [ ] Monitoring and alerting configured
  [ ] Incident response plan documented
  [ ] Emergency pause tested on testnet
```

---

*Part of the TeamStarWolf Cybersecurity Reference Library. For contributions, see [CONTRIBUTING.md](.github/CONTRIBUTING.md).*
