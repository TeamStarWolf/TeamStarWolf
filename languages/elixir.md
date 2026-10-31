# Elixir

Elixir is a dynamically typed, functional language that runs on the Erlang virtual machine (the BEAM), first released in 2012 and created by Jose Valim. It brings a modern syntax, metaprogramming through macros, and a build tool and package manager to the Erlang runtime, inheriting that runtime's model of lightweight processes, message passing, and supervised fault tolerance. It is used for web back ends, real-time systems, distributed services, and data-ingestion pipelines.

| Attribute | Value |
|---|---|
| Paradigm | Functional, concurrent, process-oriented |
| Typing | Dynamic, strong (with an opt-in set-theoretic type system in progress) |
| First appeared | 2012 |
| Memory model | Automatic: per-process garbage collection on the BEAM |
| Reference implementation | [Elixir](https://github.com/elixir-lang/elixir) compiling to BEAM bytecode |
| Typical uses | Web back ends, real-time and distributed systems, data pipelines |
| Governance | Core team led by Jose Valim; development on GitHub |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Erlang](/languages/erlang.md), [languages index](/languages/README.md).

## Overview and history

Elixir was created to pair a productive, extensible syntax with the strengths of the Erlang runtime, which has run telecommunications systems with long uptimes since the 1990s. Elixir compiles to BEAM bytecode and interoperates directly with Erlang modules, so Elixir code can call Erlang libraries and vice versa without a foreign-function boundary.

The language reached version 1.0 in 2014 and has kept source compatibility within the 1.x line since. Recent releases have added work toward a gradual, set-theoretic type system that checks code at compile time while keeping the dynamic runtime. The [Phoenix](https://www.phoenixframework.org/) web framework, including its LiveView model for server-rendered interactive pages, is a major reason for the language's adoption.

## Paradigm and type system

Elixir is functional: data is immutable, and functions transform values rather than mutating them. It is dynamically typed, with run-time type checks and pattern matching that both binds variables and asserts structure. Concurrency follows the actor model inherited from Erlang: isolated processes hold their own state and communicate only by sending messages.

```elixir
defmodule Area do
  def of({:circle, r}), do: :math.pi() * r * r
  def of({:rect, w, h}), do: w * h
end

Area.of({:circle, 2.0})
```

Pattern matching with the `=` match operator, multiple function clauses, and guard clauses (`when`) replace much of the branching that other languages write with conditionals. The in-progress type system adds compile-time checks without requiring annotations on every function.

## Toolchain and ecosystem

- Compiler and runtime: `elixir` and `iex` (the interactive shell) run on the BEAM installed with the Erlang/OTP distribution.
- Build tool: [Mix](https://hexdocs.pm/mix/Mix.html) creates projects, compiles, runs tasks, and manages dependencies.
- Packages publish to [Hex](https://hex.pm/); documentation is generated with [ExDoc](https://github.com/elixir-lang/ex_doc).
- Formatting and linting: `mix format` applies the standard layout, and [Credo](https://github.com/rrrene/credo) reports style and consistency issues.

```bash
mix new my_app
cd my_app
mix deps.get
mix test
iex -S mix
```

## Syntax tour

```elixir
defmodule Tree do
  # Structs and recursion over tagged tuples
  def insert(x, nil), do: {nil, x, nil}

  def insert(x, {l, v, r} = t) do
    cond do
      x < v -> {insert(x, l), v, r}
      x > v -> {l, v, insert(x, r)}
      true  -> t
    end
  end

  def to_list(nil), do: []
  def to_list({l, v, r}), do: to_list(l) ++ [v] ++ to_list(r)
end

# The pipe operator threads a value through transformations
result =
  [5, 3, 8, 1, 4]
  |> Enum.reduce(nil, &Tree.insert/2)
  |> Tree.to_list()

IO.inspect(result)  # [1, 3, 4, 5, 8]

# Pattern matching on function return
case Integer.parse("42") do
  {n, ""} -> n
  _ -> 0
end
```

## Idioms and different approaches

- Thread data through transformations with the pipe operator `|>` and the `Enum` and `Stream` modules rather than manual loops.
- Prefer multiple function clauses and pattern matching over nested conditionals; let the shape of the data select the branch.
- Return tagged tuples such as `{:ok, value}` and `{:error, reason}` and match on them, reserving exceptions for programmer errors.
- Structure concurrent and fault-tolerant systems with OTP behaviours (`GenServer`, `Supervisor`) rather than ad hoc processes, so that failures are contained and restarted.

## Design principles

Elixir keeps the Erlang runtime's model of isolated, supervised processes and adds a syntax designed for extension through macros, so that frameworks can define their own constructs while compiling down to ordinary function calls. Immutability and message passing make concurrent state easier to reason about, because no two processes share memory. The language aims for a productive developer experience with good tooling and documentation while staying compatible with the broad Erlang/OTP library base.

## Standard library and notable packages

The standard library provides `Enum` and `Stream` for collections, `String` for Unicode text, `Task` and `GenServer` for concurrency, and `File` and `IO` for input and output. Widely used packages on Hex include [Phoenix](https://hex.pm/packages/phoenix) for the web, [Ecto](https://hex.pm/packages/ecto) for database access and validation, [Plug](https://hex.pm/packages/plug) for composable web middleware, [Broadway](https://hex.pm/packages/broadway) for data pipelines, and [Nx](https://hex.pm/packages/nx) for numerical computing.

## Testing and packaging

ExUnit is the built-in test framework, run with `mix test`; [StreamData](https://hex.pm/packages/stream_data) adds property-based testing.

```elixir
defmodule MathTest do
  use ExUnit.Case

  test "addition" do
    assert 2 + 3 == 5
  end
end
```

A package declares its metadata and dependencies in `mix.exs` and publishes to Hex with `mix hex.publish`, which also builds the documentation.

## Performance and concurrency

The BEAM schedules large numbers of lightweight processes across operating-system threads, preempting them so that one busy process cannot starve others. Each process has its own heap and is garbage-collected independently, which keeps pauses short. Processes communicate only by asynchronous message passing, and distribution across nodes uses the same primitives, so a system can scale from one machine to a cluster with the same model. For CPU-bound numeric work, native code can be called through NIFs or ports, and libraries such as Nx offload to optimized backends. Raw single-threaded throughput is lower than that of native-compiled languages; the runtime's strength is concurrency, soft real-time latency, and fault tolerance.

## Common pitfalls

- Atom creation from untrusted input: atoms are not garbage-collected and the atom table is bounded, so `String.to_atom/1` on attacker-controlled strings can exhaust the table and crash the node; use `String.to_existing_atom/1`.
- Unbounded process mailboxes: a process that receives faster than it handles grows its mailbox until memory is exhausted; apply back pressure or selective receive.
- Large messages between processes are copied, not shared, so passing big data structures repeatedly costs memory and time.
- Thinking in objects: state lives in processes and immutable data, not mutable objects, so model it with `GenServer` and message passing.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Atom exhaustion: converting untrusted input to atoms with `String.to_atom/1` or `List.to_atom/1` can fill the fixed atom table and bring the node down; prefer `String.to_existing_atom/1` and validate against a known set. This is a form of resource exhaustion, [CWE-400](https://cwe.mitre.org/data/definitions/400.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Unsafe deserialization: `:erlang.binary_to_term/1` on attacker-controlled data can create arbitrary terms, including new atoms and executable constructs, and can be abused to exhaust resources; pass the `[:safe]` option, and better, avoid decoding external data this way and use a schema-checked format such as JSON. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- Input validation at the boundary: dynamic typing means external data is unchecked until you check it; validate and cast with Ecto changesets or explicit guards, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Injection: build SQL through Ecto's parameterized queries rather than string interpolation, and avoid passing untrusted input to `:os.cmd/1` or `System.cmd/3` as a shell string. See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Dependency supply chain: pin versions in `mix.exs`, commit `mix.lock`, and review new dependencies; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [Credo](https://github.com/rrrene/credo) reports style and consistency issues, [Sobelow](https://github.com/nccgroup/sobelow) scans Phoenix applications for common web vulnerabilities, and [Dialyzer](https://www.erlang.org/doc/apps/dialyzer/dialyzer_chapter.html) (through the `dialyxir` wrapper) finds type discrepancies by success typing.

## Learning resources

- [Elixir official guides](https://elixir-lang.org/getting-started/introduction.html), the introductory documentation.
- [HexDocs](https://hexdocs.pm/), API documentation for the standard library and packages.
- [Phoenix framework documentation](https://hexdocs.pm/phoenix/overview.html), for building web applications.

## Related pages

- [Erlang](/languages/erlang.md)
- [Gleam](/languages/gleam.md)
- [Haskell](/languages/haskell.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
