# Vyper

Vyper is a statically typed, contract-oriented language for the Ethereum Virtual Machine (EVM) with Python-like syntax. It was created to make smart contracts easier to audit than Solidity by deliberately leaving out features that make code hard to reason about, such as inheritance, modifiers, inline assembly, and unbounded recursion. Code compiles to EVM bytecode, so like Solidity it runs gas-metered, holds funds, and is usually immutable once deployed. It is used for decentralized finance and other contracts where auditability is a priority.

| Attribute | Value |
|---|---|
| Paradigm | Contract-oriented, imperative; intentionally restricted |
| Typing | Static, strong |
| First appeared | 2017 |
| Memory model | EVM: persistent `storage`, transient `memory`, read-only `calldata`; no garbage collector; gas-metered |
| Reference compiler | [vyper](https://github.com/vyperlang/vyper) |
| Typical uses | Smart contracts, decentralized finance, audited on-chain logic |
| Governance | [Vyper project](https://vyperlang.org/) (community, formerly under the Ethereum Foundation) |

Related: [Solidity](/languages/solidity.md), [Move](/languages/move.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Vyper grew out of the Ethereum community as an alternative to Solidity, with a stated goal of auditability and security over expressiveness. Its syntax resembles Python, which makes contracts approachable to read, but the two languages are unrelated at the semantic level. The compiler and language are still evolving and, like Solidity, not always backward compatible across versions, so a contract is pinned to a compiler version with a `# pragma version` line.

The project treats restriction as a feature: by omitting constructs that enable surprising behavior, it aims to make the gap between what code says and what it does small enough for a human auditor to close. Vyper contracts run on the same EVM as Solidity, so the same immutability and direct link to funds apply.

## Paradigm and type system

A Vyper file is a single contract (no inheritance), with state variables, external and internal functions, events, and interfaces. Typing is static and strong, with sized integers (`uint256`, `int128`), `address`, `bool`, fixed-size byte strings, bounded dynamic arrays and strings (`DynArray[uint256, 10]`, `String[64]`), `struct`, and `HashMap`. Many types carry an explicit upper bound, which keeps gas use predictable and loops finite.

Functions are decorated to state visibility and mutability (`@external`, `@internal`, `@view`, `@pure`, `@payable`). There are no modifiers; access checks are written inline as plain statements, which the project argues is easier to audit.

```vyper
balances: public(HashMap[address, uint256])

@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value  # reverts on overflow
```

## Toolchain and ecosystem

- Compiler: [vyper](https://github.com/vyperlang/vyper) produces EVM bytecode and an ABI (application binary interface); it can be installed from PyPI.
- Development frameworks: [Titanoboa](https://github.com/vyperlang/titanoboa) is the project's own testing and scripting tool; [Ape](https://github.com/ApeWorX/ape) and [Foundry](https://getfoundry.sh/) (through a plugin) also build and test Vyper contracts.
- Interoperability: Vyper contracts expose a standard ABI, so they work with the same wallets, explorers, and client libraries as Solidity contracts.
- Analysis: the Vyper compiler emits warnings; static-analysis support is less extensive than Solidity's, so manual audit and testing carry more weight.

```bash
pip install vyper
vyper contract.vy            # compile to bytecode
```

## Syntax tour

```vyper
# pragma version ^0.4.0

payer: public(address)
payee: public(address)
amount: public(uint256)

event Deposited:
    amount: uint256

event Released:
    to: address
    amount: uint256

@deploy
def __init__(_payee: address):
    self.payer = msg.sender
    self.payee = _payee

@external
@payable
def deposit():
    assert msg.sender == self.payer, "not payer"
    self.amount += msg.value
    log Deposited(msg.value)

@external
def release():
    assert msg.sender == self.payer, "not payer"
    to_send: uint256 = self.amount
    self.amount = 0                      # effects before interaction
    send(self.payee, to_send)
    log Released(self.payee, to_send)
```

## Idioms and different approaches

- Write access checks as explicit `assert` statements at the top of a function, since there are no modifiers to hide them.
- Keep the checks-effects-interactions order: validate, update state, then make external calls or sends.
- Use bounded types (`DynArray[...]`, `String[n]`) so loops terminate and gas stays predictable.
- Favor many small, single-purpose external functions over deep call chains, since there is no inheritance to spread logic across.
- Pin the compiler version and rebuild deliberately when upgrading, because semantics can shift between versions.

## Design principles

Vyper's guiding principle is auditability: code should be hard to write in a way that misleads a reader. To that end it omits inheritance, function and operator overloading, inline assembly, recursive calls, and unbounded loops, and it bounds array and string lengths. Overflow and bounds checks are on by default. The trade is expressiveness for a smaller surface in which a reviewer can hold the whole contract in mind.

## Standard library and notable primitives

Vyper exposes built-in state and environment objects (`msg`, `block`, `tx`, `self`) and built-in functions for hashing (`keccak256`), sending value (`send`, `raw_call`), ABI encoding (`abi_encode`, `abi_decode`), and bounds-safe helpers. Rather than a large library ecosystem, the language leans on these built-ins and on patterns the compiler can verify. Standard token interfaces (ERC-20, ERC-721) are commonly written directly or adapted from reference implementations, since there is no inheritance-based library layer comparable to Solidity's.

## Testing and packaging

Testing uses Titanoboa, Ape, or Foundry, typically driving contracts from Python or Solidity test code and asserting on results, with fuzz testing to explore inputs. The compiler ships on PyPI, so it installs with `pip`; contracts themselves are distributed as source and deployed bytecode rather than through a language package registry.

```python
# Titanoboa (Python) test sketch
import boa

def test_deposit():
    c = boa.load("escrow.vy", boa.env.eoa)
    with boa.env.prank(boa.env.eoa):
        c.deposit(value=10**18)
    assert c.amount() == 10**18
```

## Performance and concurrency

The EVM executes one transaction at a time against contract state, so there is no in-contract concurrency. Performance is gas: the metered, user-paid cost of each operation, capped per block. The evaluation model drives the same concerns as other EVM languages, with Vyper's restrictions aimed at keeping them bounded:

- Bounded arrays and the absence of unbounded recursion keep worst-case gas analyzable, which reduces the risk of a function becoming uncallable because it exceeds the block gas limit.
- Storage writes dominate cost; minimize and batch them.
- External calls and `raw_call` hand control to another contract that can re-enter; the hazard is the execution model, not parallelism.

As with Solidity, a deployed contract is usually immutable, so gas cost and behavior are fixed at deployment.

## Common pitfalls

- Assuming Python semantics: Vyper only looks like Python; integer sizes, division, and typing follow EVM rules, not Python's.
- Reentrancy through `raw_call` or `send` before state updates; keep checks-effects-interactions and use the built-in reentrancy guard where available.
- Compiler-version drift: a contract compiled with a different version can behave differently; pin the version and retest after upgrades.
- Relying on a feature that was removed or changed between major versions (the language has reorganized decorators and syntax across releases).
- Expecting broad static-analysis tooling; coverage is thinner than for Solidity, so tests and audits matter more.

## Secure coding

Vyper contracts hold funds and are usually immutable, so the same high-consequence weaknesses as other smart-contract languages apply, even though the language restricts some of them by design:

- Reentrancy ([CWE-841](https://cwe.mitre.org/data/definitions/841.html)): external calls can re-enter before state is updated. Follow checks-effects-interactions and use the reentrancy-guard decorator. A 2023 compiler defect in the reentrancy lock of specific Vyper versions contributed to exploits of several pools, a reminder that the compiler is part of the trust base and that pinning to a reviewed version matters.
- Integer overflow and underflow ([CWE-190](https://cwe.mitre.org/data/definitions/190.html)): arithmetic and bounds are checked by default and revert on violation; keep those checks on rather than reaching for unchecked escape hatches.
- Access-control errors ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)): since there are no modifiers, every privileged function needs an explicit `assert` on the caller; a missing check exposes privileged logic to anyone.
- Unchecked external calls ([CWE-252](https://cwe.mitre.org/data/definitions/252.html)): the result of `raw_call` and sends must be handled, and the callee treated as untrusted.
- Supply chain: the compiler version is a dependency with security weight; pin it, track advisories, and rebuild deliberately. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: rely on the compiler's warnings, extensive unit and fuzz tests in Titanoboa or Foundry, and an independent audit before deploying value-bearing contracts, given the thinner static-analysis ecosystem. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Vyper documentation](https://docs.vyperlang.org/), the language reference and security notes.
- [Titanoboa](https://github.com/vyperlang/titanoboa), the project's testing and scripting tool.
- [Vyper by Example](https://docs.vyperlang.org/en/stable/vyper-by-example.html), worked contract patterns.

## Related pages

- [Solidity](/languages/solidity.md)
- [Move](/languages/move.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
