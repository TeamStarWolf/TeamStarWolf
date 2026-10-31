# Erlang

Erlang is a dynamically typed, functional language built for concurrent, distributed, fault-tolerant systems, created at Ericsson in the 1980s and released as open source in 1998. Its runtime, the BEAM, runs large numbers of isolated processes that communicate by message passing and recover from failure through supervision. It is used in telecommunications, messaging platforms, databases, and other systems that need high availability.

| Attribute | Value |
|---|---|
| Paradigm | Functional, concurrent, process-oriented, distributed |
| Typing | Dynamic, strong |
| First appeared | 1986 at Ericsson; open-sourced in 1998 |
| Memory model | Automatic: per-process garbage collection on the BEAM |
| Reference implementation | [Erlang/OTP](https://github.com/erlang/otp) running on the BEAM |
| Typical uses | Telecommunications, messaging, databases, high-availability services |
| Governance | [Erlang/OTP](https://www.erlang.org/) maintained by the OTP team at Ericsson with community contributors |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Elixir](/languages/elixir.md), [languages index](/languages/README.md).

## Overview and history

Erlang was developed at Ericsson to program telephone exchanges, where the requirements were concurrency on a massive scale, tolerance of hardware and software faults, and the ability to upgrade running systems without downtime. These requirements shaped the language and its runtime more than any single paradigm did. Ericsson released Erlang as open source in 1998, and it is distributed together with the Open Telecom Platform (OTP), a set of libraries and design patterns for building reliable systems.

The runtime is the BEAM, a virtual machine that schedules processes preemptively and isolates their memory. Erlang's design is often summarized by the phrase "let it crash": rather than defending against every error inline, a process fails fast and a supervisor restarts it into a known-good state.

## Paradigm and type system

Erlang is functional with immutable data and single assignment: a variable is bound once within its scope. It is dynamically typed, and pattern matching drives both binding and control flow. Concurrency follows the actor model: processes are the unit of isolation, each with its own heap, and they interact only by sending and receiving messages.

```erlang
-module(area).
-export([of_shape/1]).

of_shape({circle, R}) -> math:pi() * R * R;
of_shape({rect, W, H}) -> W * H.
```

Function clauses, guards, and the `receive` expression let a program branch on the shape and content of data and of incoming messages. There is no static type checker in the language itself; the Dialyzer tool infers types separately through success typing.

## Toolchain and ecosystem

- Runtime and shell: `erl` starts the runtime and an interactive shell; `escript` runs scripts.
- Build tool: [rebar3](https://rebar3.org/) builds projects, manages dependencies, and runs tasks; [Hex](https://hex.pm/) serves packages shared with Elixir.
- Design framework: OTP provides behaviours such as `gen_server`, `supervisor`, and `application` that encode proven patterns for servers and supervision trees.
- Release tooling: `rebar3 release` (often with `relx`) assembles a self-contained release.

```bash
rebar3 new app my_app
cd my_app
rebar3 compile
rebar3 eunit
rebar3 shell
```

## Syntax tour

```erlang
-module(tree).
-export([insert/2, to_list/1]).

%% Build a binary search tree from tagged tuples
insert(X, nil) -> {node, nil, X, nil};
insert(X, {node, L, V, R}) when X < V -> {node, insert(X, L), V, R};
insert(X, {node, L, V, R}) when X > V -> {node, L, V, insert(X, R)};
insert(_, T) -> T.

%% In-order traversal
to_list(nil) -> [];
to_list({node, L, V, R}) -> to_list(L) ++ [V] ++ to_list(R).

%% A simple process loop that answers messages
loop(State) ->
    receive
        {add, N, From} ->
            From ! {ok, State + N},
            loop(State + N);
        stop ->
            ok
    end.
```

## Idioms and different approaches

- Match on the shape of data with function clauses and guards instead of writing conditional ladders.
- Structure systems as supervision trees so that a failing process is restarted by its supervisor rather than corrupting shared state; design each process to do one job.
- Return tagged tuples such as `{ok, Value}` and `{error, Reason}` and match on them; let unexpected shapes crash so a supervisor can recover.
- Use OTP behaviours rather than hand-written process loops for anything long-lived, so that code tracing, upgrades, and supervision work as expected.

## Design principles

Erlang's design puts reliability first: isolate state in processes, detect failure quickly, and recover through supervision rather than trying to handle every error where it occurs. Immutability and share-nothing concurrency make it safe to run millions of processes without data races. The runtime supports soft real-time latency and, through OTP, hot code loading so that long-running systems can be upgraded in place. These properties come from the telecommunications setting the language was built for.

## Standard library and notable packages

The OTP distribution ships the standard modules: `lists`, `maps`, and `ets` for data, `gen_server` and `supervisor` for the process framework, `inets` and `ssl` for networking, and `crypto` for cryptographic primitives (built on OpenSSL). Notable systems written in Erlang include the [RabbitMQ](https://www.rabbitmq.com/) message broker, the [ejabberd](https://www.ejabberd.im/) messaging server, and the [Riak](https://riak.com/) and [CouchDB](https://couchdb.apache.org/) databases. Packages are shared with the Elixir community through Hex.

## Testing and packaging

Erlang ships two test frameworks: EUnit for unit tests and Common Test for larger, system-level suites. rebar3 runs both.

```erlang
-include_lib("eunit/include/eunit.hrl").

add_test() ->
    ?assertEqual(5, 2 + 3).
```

A project describes itself in `rebar.config` and an application resource file (`.app.src`); `rebar3 release` assembles a runnable release, and packages publish to Hex with `rebar3 hex publish`.

## Performance and concurrency

The BEAM is built for concurrency: it runs one scheduler per core by default, preempts processes so none can monopolize a scheduler, and garbage-collects each process heap independently, which keeps pause times short and bounded. Processes are cheap, so a system can run hundreds of thousands of them. Distribution is built in: nodes connect and exchange messages with the same send and receive primitives used locally. Single-threaded arithmetic throughput is modest compared with native-compiled languages, so CPU-bound inner loops are often moved into NIFs (native implemented functions) or ports, with care because a misbehaving NIF can crash or block the whole node.

## Common pitfalls

- Atom table exhaustion: atoms are never garbage-collected and the table has a fixed limit, so converting untrusted input with `list_to_atom/1` or `binary_to_atom/2` can crash the node; use the `..._to_existing_atom` variants.
- Unbounded mailboxes: a process that cannot keep up with incoming messages grows its mailbox until memory runs out; apply back pressure and use selective receive carefully.
- Large terms sent between processes are copied, so repeatedly passing big data structures is expensive.
- NIFs that run too long or block stall the scheduler they run on; keep native calls short or use dirty schedulers.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Unsafe deserialization: `binary_to_term/1` reconstructs arbitrary Erlang terms from bytes and, without protection, can create new atoms and large structures from attacker-controlled input; always pass `binary_to_term(Bin, [safe])`, and prefer not to decode untrusted data into terms at all, using a schema-checked format instead. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Atom exhaustion: creating atoms from untrusted input exhausts the fixed atom table and halts the node; use `binary_to_existing_atom/2` and validate against a known set. This is resource exhaustion, [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- Input validation at the boundary: dynamic typing leaves external data unchecked until you match or validate it; validate message and request shapes explicitly, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Command and code execution: do not pass untrusted strings to `os:cmd/1`, and avoid evaluating runtime-constructed code; treat the distribution cookie as a secret, since a shared cookie grants a remote node code-execution access.
- Dependency supply chain: pin dependency versions in `rebar.config`, commit the lock file, and review new dependencies; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [Dialyzer](https://www.erlang.org/doc/apps/dialyzer/dialyzer_chapter.html) performs static discrepancy analysis through success typing and finds type errors, dead code, and some unsafe patterns; `xref` checks cross-references between modules. Run both in continuous integration.

## Learning resources

- [Erlang/OTP documentation](https://www.erlang.org/docs), the reference for the language and OTP.
- [Learn You Some Erlang for Great Good](https://learnyousomeerlang.com/), a free introductory book.
- [Erlang Reference Manual](https://www.erlang.org/doc/reference_manual/introduction.html), the language definition.

## Related pages

- [Elixir](/languages/elixir.md)
- [Gleam](/languages/gleam.md)
- [Haskell](/languages/haskell.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
