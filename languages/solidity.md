# Solidity

Solidity is a statically typed, contract-oriented language for writing smart contracts that run on the Ethereum Virtual Machine (EVM) and compatible blockchains. It was proposed in 2014 and first released in 2015, with a syntax influenced by JavaScript, C++, and Python. Code compiles to EVM bytecode, where execution costs gas, storage is persistent and expensive, and a deployed contract is effectively public and hard to change. It is used for tokens, decentralized finance, and other on-chain applications.

| Attribute | Value |
|---|---|
| Paradigm | Contract-oriented, object-oriented, imperative |
| Typing | Static, strong |
| First appeared | 2015 (proposed 2014) |
| Memory model | EVM: persistent `storage`, transient `memory`, read-only `calldata`; no garbage collector; gas-metered |
| Reference compiler | [solc](https://github.com/ethereum/solidity) |
| Typical uses | Smart contracts: tokens, decentralized finance, governance, NFTs |
| Governance | [Ethereum Foundation Solidity team](https://soliditylang.org/) |

Related: [Vyper](/languages/vyper.md), [Move](/languages/move.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Solidity was proposed by Gavin Wood and developed by a team that included Christian Reitwiessner at the Ethereum Foundation. It became the main language for Ethereum smart contracts. The language changes quickly and is not always backward compatible; the 0.8.0 release in late 2020 was a notable milestone because it made arithmetic overflow checks the default. A `pragma solidity` line pins the compiler version a source file expects, because behavior can differ across versions.

A smart contract, once deployed, runs exactly as written for anyone who calls it, holds funds, and usually cannot be patched in place. That immutability and the direct link to money make correctness and security unusually consequential compared with ordinary application code.

## Paradigm and type system

Solidity is organized around contracts, which resemble classes: they hold persistent state variables, functions, events, and modifiers, and they support inheritance. Typing is static and strong, with sized integers (`uint256` down to `uint8`), `address`, fixed-size and dynamic arrays, `mapping`, `struct`, and `enum`. Function visibility (`public`, `external`, `internal`, `private`) and state mutability (`view`, `pure`, `payable`) are part of the signature.

Data location matters: `storage` is persistent on-chain state, `memory` is temporary during a call, and `calldata` is the read-only argument region. Getting the location wrong changes both cost and semantics.

```solidity
mapping(address => uint256) public balances;

function deposit() external payable {
    balances[msg.sender] += msg.value;  // reverts on overflow since 0.8.0
}
```

## Toolchain and ecosystem

- Compiler: [solc](https://github.com/ethereum/solidity) produces EVM bytecode and an ABI (application binary interface).
- Development frameworks: [Foundry](https://getfoundry.sh/) (the `forge`, `cast`, and `anvil` tools) and [Hardhat](https://hardhat.org/) build, test, and deploy; [Remix](https://remix.ethereum.org/) is a browser IDE.
- Libraries: [OpenZeppelin Contracts](https://www.openzeppelin.com/contracts) provides reviewed implementations of token standards, access control, and safety utilities.
- Analysis: [Slither](https://github.com/crytic/slither) is a static analyzer; [Mythril](https://github.com/Consensys/mythril) does symbolic execution; [solhint](https://github.com/protofire/solhint) lints style and security patterns.

```bash
forge init my_project
forge build
forge test
```

## Syntax tour

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Escrow {
    address public immutable payer;
    address public immutable payee;
    uint256 public amount;

    event Deposited(uint256 amount);
    event Released(address to, uint256 amount);

    constructor(address _payee) {
        payer = msg.sender;
        payee = _payee;
    }

    // Only the payer may call; `payable` lets the call carry value
    function deposit() external payable {
        require(msg.sender == payer, "not payer");
        amount += msg.value;
        emit Deposited(msg.value);
    }

    function release() external {
        require(msg.sender == payer, "not payer");
        uint256 toSend = amount;
        amount = 0;                      // effects before interaction
        (bool ok, ) = payee.call{value: toSend}("");
        require(ok, "transfer failed");
        emit Released(payee, toSend);
    }
}
```

## Idioms and different approaches

- Follow the checks-effects-interactions order: validate inputs, update state, and only then call external addresses, so a reentrant call finds state already updated.
- Prefer reviewed libraries (OpenZeppelin) for token standards, access control, and upgrade patterns rather than reimplementing them.
- Use `require` for input and precondition checks with revert reasons, `revert` with custom errors to save gas, and `assert` only for invariants that should never fail.
- Emit events for state changes so off-chain systems can follow them; on-chain code cannot read past events.
- Minimize and batch storage writes, since `storage` is the dominant gas cost.

## Design principles

Solidity aims to make Ethereum contracts writable in a familiar, high-level style while mapping onto the EVM's cost and execution model. Explicit visibility and mutability, required data locations, and (since 0.8.0) checked arithmetic reflect a shift toward catching dangerous mistakes at compile time, learned from early high-value exploits. The language leaves gas cost visible because it is a first-order concern, not an implementation detail.

## Standard library and notable packages

Solidity has a small built-in surface rather than a large standard library: global objects (`msg`, `block`, `tx`), member functions on `address` (`transfer`, `send`, `call`), units (`wei`, `ether`, `days`), and ABI encoding helpers (`abi.encode`, `abi.decode`). Practical reuse comes from community libraries, chiefly [OpenZeppelin Contracts](https://www.openzeppelin.com/contracts) for ERC-20, ERC-721, access control, pausing, and safe upgrade proxies, and [Solmate](https://github.com/transmissions11/solmate) for gas-lean building blocks.

## Testing and packaging

Testing is done in the development framework. Foundry lets you write tests in Solidity itself, including fuzz tests that throw random inputs at a function, and Hardhat tests in JavaScript or TypeScript. There is no central package registry for the language; dependencies are usually pulled in as git submodules (Foundry) or npm packages (Hardhat).

```solidity
// Foundry test
import "forge-std/Test.sol";

contract EscrowTest is Test {
    function testDepositIncreasesAmount() public {
        Escrow e = new Escrow(address(0xBEEF));
        e.deposit{value: 1 ether}();
        assertEq(e.amount(), 1 ether);
    }
}
```

## Performance and concurrency

The EVM runs one transaction at a time against a contract's state; there is no in-contract concurrency to manage. Performance is measured in gas, the metered cost of each operation, which users pay and which is capped per block. The evaluation model has direct consequences:

- Storage reads and especially writes dominate cost; keep state small, pack variables into slots, and cache values in memory within a call.
- Loops over unbounded, caller-influenced arrays can exceed the block gas limit and make a function permanently uncallable, which is also a denial-of-service risk.
- External calls hand control to another contract, which can call back in (reentrancy) before the current call finishes; the execution model, not parallelism, is the hazard.

Because a deployed contract is usually immutable, there is no later tuning pass: cost and correctness are fixed at deployment unless an upgrade proxy was built in.

## Common pitfalls

- Reentrancy: calling an external address before updating state lets the callee re-enter and drain funds; follow checks-effects-interactions and consider a reentrancy guard.
- Unchecked low-level calls: `call`, `send`, and `delegatecall` return a success boolean that must be checked; ignoring it continues as if the call succeeded.
- Access-control gaps: a missing `onlyOwner`-style check, or a public function that should be internal, lets anyone call privileged logic.
- `tx.origin` for authorization: it can be spoofed through an intermediary contract; use `msg.sender`.
- Assuming pre-0.8.0 arithmetic is safe: before 0.8.0, overflow wrapped silently; older code needs SafeMath.

## Secure coding

Smart contracts hold funds and are usually immutable, so these weaknesses carry outsized consequences:

- Reentrancy ([CWE-841](https://cwe.mitre.org/data/definitions/841.html)): an external call can re-enter the contract before state is updated, as in the 2016 DAO incident. Apply checks-effects-interactions, use a reentrancy guard (OpenZeppelin `ReentrancyGuard`), and prefer pull-over-push payment patterns.
- Integer overflow and underflow ([CWE-190](https://cwe.mitre.org/data/definitions/190.html)): arithmetic wraps unless checked. Solidity 0.8.0 and later revert on overflow by default; for older code use SafeMath, and use `unchecked` blocks only where overflow is provably impossible.
- Access-control errors ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)): missing or wrong authorization on privileged functions, or misuse of `delegatecall`, lets attackers mint tokens, withdraw funds, or take ownership. Gate privileged functions with a vetted access-control library and test every path.
- Unchecked external calls ([CWE-252](https://cwe.mitre.org/data/definitions/252.html)): the return value of low-level calls must be checked, and the callee must be treated as untrusted, since it can fail, revert, or re-enter.
- Supply chain: imported contracts and libraries run with the contract's authority; pin and review dependencies. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: run [Slither](https://github.com/crytic/slither) for static analysis and [Mythril](https://github.com/Consensys/mythril) for symbolic checks, add fuzz and invariant tests in Foundry, and obtain an independent audit before deploying value-bearing contracts. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Solidity documentation](https://docs.soliditylang.org/), the language reference and security considerations chapter.
- [OpenZeppelin Contracts](https://docs.openzeppelin.com/contracts/), reviewed building blocks and patterns.
- [Foundry Book](https://book.getfoundry.sh/), for the testing and deployment workflow.

## Related pages

- [Vyper](/languages/vyper.md)
- [Move](/languages/move.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
