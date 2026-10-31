# Move

Move is a statically typed language for writing smart contracts, built around resource types that the type system guarantees cannot be copied or silently discarded. It was created at Facebook (later Meta) for the Diem blockchain project and now powers the Aptos and Sui networks. By modeling digital assets as linear resources, Move makes properties such as "this coin cannot be duplicated or lost" enforceable by the compiler and a bytecode verifier rather than by convention. It is used for on-chain assets, decentralized finance, and other contracts where asset safety is central.

| Attribute | Value |
|---|---|
| Paradigm | Resource-oriented, imperative; linear and affine types |
| Typing | Static, strong, with abilities (`copy`, `drop`, `store`, `key`) |
| First appeared | 2019 (Diem project; public networks from 2022) |
| Memory model | No garbage collector: resources have a single owner and an explicit lifetime; a bytecode verifier enforces the rules |
| Reference toolchain | [Move compiler and Move Prover](https://github.com/move-language/move); platform toolchains for [Aptos](https://aptos.dev/) and [Sui](https://docs.sui.io/) |
| Typical uses | Smart contracts, on-chain assets and tokens, decentralized finance |
| Governance | Platform maintainers (Aptos Labs, Mysten Labs) and the Move community |

Related: [Solidity](/languages/solidity.md), [Vyper](/languages/vyper.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Move was designed by the team behind Facebook's Diem (originally Libra) blockchain, with a 2019 white paper describing a language whose central idea is the resource: a value that behaves like physical property, with exactly one owner, that cannot be copied or dropped unless the type explicitly allows it. When Diem wound down, the language carried on through the Aptos and Sui networks, which each adapted it: Aptos stays close to the original account-and-module model, while Sui introduced an object-centric variant.

Because the two main platforms diverge in their storage and object models, a Move contract is written against a specific platform's framework and standard library. The core language and its safety guarantees are shared, but the surrounding APIs are not interchangeable.

## Paradigm and type system

Move code is organized into modules that declare types and functions, and scripts that call them. The type system is static and strong, and its distinctive feature is abilities: each type carries a set drawn from `copy` (may be duplicated), `drop` (may be discarded), `store` (may be held inside other data in global storage), and `key` (may be a top-level item in global storage). A resource type typically has neither `copy` nor `drop`, so the compiler forbids duplicating or silently losing it; the value must be moved, stored, or explicitly destroyed.

```move
module example::coin {
    // No `copy` and no `drop`: a Coin cannot be duplicated or discarded
    struct Coin has store { value: u64 }

    public fun value(c: &Coin): u64 { c.value }
}
```

This linear treatment of values is what lets the type system prove asset-safety properties that other contract languages enforce only at run time, if at all.

## Toolchain and ecosystem

- Compiler and verifier: Move source compiles to bytecode that a verifier checks before execution, rejecting programs that violate type, resource, or reference-safety rules.
- Platform command-line tools: the [Aptos CLI](https://aptos.dev/tools/aptos-cli/) and [Sui CLI](https://docs.sui.io/references/cli) build, test, and publish modules for their respective networks.
- Formal verification: the [Move Prover](https://github.com/move-language/move) checks user-written specifications (preconditions, postconditions, and invariants) against the code statically.
- Package management: modules are organized into packages with a `Move.toml` manifest that declares dependencies and named addresses.

```bash
aptos move compile
aptos move test
aptos move publish
```

## Syntax tour

```move
module example::escrow {
    use std::signer;

    struct Escrow has key {
        payer: address,
        payee: address,
        amount: u64,
    }

    // `signer` proves the caller authorized the transaction
    public entry fun create(payer: &signer, payee: address, amount: u64) {
        let addr = signer::address_of(payer);
        move_to(payer, Escrow { payer: addr, payee, amount });
    }

    public fun amount(at: address): u64 acquires Escrow {
        borrow_global<Escrow>(at).amount
    }
}
```

## Idioms and different approaches

- Model assets as resources without `copy` or `drop`, so the compiler guarantees they are conserved; destroy them only through explicit functions that unpack their fields.
- Use the `signer` type to establish authorization: a function that needs the account owner's consent takes a `&signer`, which only the transaction sender can provide.
- Keep state in resources stored under account addresses (Aptos) or in objects (Sui) and reach them through `borrow_global` or object references, declaring `acquires` where required.
- Write specifications for the Move Prover on functions that guard value, so critical invariants are checked statically rather than only tested.
- Target one platform's framework at a time; do not assume Aptos and Sui APIs match.

## Design principles

Move's central principle is that scarce digital assets should be first-class values whose conservation the type system enforces, not an accounting discipline the programmer must maintain. Abilities make the permitted operations on each type explicit. The bytecode verifier means these guarantees hold even for code that arrives as compiled modules, so a chain can safely run modules it did not compile itself. The language also favors being analyzable: it omits dynamic dispatch and unbounded constructs that would make static verification and the Move Prover harder.

## Standard library and notable modules

Each platform ships a framework and standard library. A shared `std` layer provides vectors, options, strings, and hashing. On Aptos, the `aptos_framework` modules provide accounts, coins (the `coin` and fungible-asset modules), events, and timestamps; on Sui, the `sui_framework` provides objects, coins, and the transfer primitives built around the object model. Because the frameworks differ, the "standard library" a contract uses depends on its target network.

## Testing and packaging

Move has unit testing built into the toolchain: functions annotated `#[test]` run with the platform CLI, and `#[expected_failure]` marks tests that should abort. Packages declare dependencies and named addresses in `Move.toml`, and dependencies are commonly pulled from git or the platform's framework. The Move Prover supplements tests with static proofs of specified properties.

```move
#[test]
fun test_amount_is_stored() {
    // set up a signer and call create, then assert on amount(...)
}
```

## Performance and concurrency

A blockchain executes transactions against shared state, and the evaluation model here has a few notable features:

- Execution is metered (gas on Aptos, a comparable cost model on Sui), so operations and especially storage have a cost the user pays; there is no unbounded loop or recursion that could run without limit.
- Sui's object model lets the runtime execute transactions that touch disjoint objects in parallel, because ownership is explicit; transactions on shared objects are ordered. Aptos uses a parallel execution engine that runs transactions optimistically and resolves conflicts. In both cases the parallelism is provided by the runtime, not expressed in Move itself.
- The bytecode verifier runs before execution, so invalid modules are rejected rather than caught at run time.

As with other on-chain code, published modules are typically hard to change, so cost and correctness are largely fixed at publication, subject to each platform's upgrade rules.

## Common pitfalls

- Treating Aptos and Sui as interchangeable; their storage models (global resources under addresses versus owned objects) and frameworks differ, so code and idioms do not port directly.
- Forgetting `acquires` annotations or mismanaging references, which the borrow checker rejects; the fix is to follow the ownership and borrowing rules the verifier enforces.
- Assuming a resource can be ignored: a value without `drop` must be consumed, moved, or stored, or the code will not compile.
- Over-granting abilities: adding `copy` or `drop` to a type that represents an asset defeats the conservation guarantee.
- Relying on authorization other than `signer`; address arguments alone do not prove the caller controls that account.

## Secure coding

Move's type system removes some classes of smart-contract bug by construction, but the high-consequence weaknesses of on-chain code still require care:

- Access-control errors ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)): authorization must be tied to a `&signer` or an owned object capability, not to an address passed as data. A function that mutates value without checking the right signer or capability exposes privileged logic. This is the most common Move-specific class.
- Integer overflow ([CWE-190](https://cwe.mitre.org/data/definitions/190.html)): Move's integer operations abort on overflow by default rather than wrapping, which prevents silent overflow; still validate ranges so the abort does not become an unexpected denial of service.
- Reentrancy ([CWE-841](https://cwe.mitre.org/data/definitions/841.html)): Move does not permit dynamic dispatch to arbitrary external code in the way EVM languages do, which structurally limits classic reentrancy; do not reintroduce the hazard through patterns that call back into mutable shared state.
- Unchecked external calls ([CWE-252](https://cwe.mitre.org/data/definitions/252.html)): check the results and abort codes of calls into other modules, and treat composed modules as part of your trust boundary.
- Supply chain: depended-upon modules and frameworks run with your module's assumptions; pin versions and review third-party packages. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: use the built-in unit tests and the [Move Prover](https://github.com/move-language/move) to prove invariants on value-guarding functions, rely on the bytecode verifier as a baseline, and obtain an independent audit before publishing value-bearing modules. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The Move Book](https://move-language.github.io/move/) and the [Move white paper](https://github.com/move-language/move), for the language and its model.
- [Aptos developer documentation](https://aptos.dev/), for the account-and-module platform.
- [Sui documentation](https://docs.sui.io/), for the object-centric platform.

## Related pages

- [Solidity](/languages/solidity.md)
- [Vyper](/languages/vyper.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
