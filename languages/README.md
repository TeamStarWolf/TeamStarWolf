# Programming languages

In-depth reference pages for programming and scripting languages. Each page covers the language's history and design, its type system and paradigm, the toolchain and ecosystem, a syntax tour with runnable examples, idioms and alternative approaches, performance and concurrency, common pitfalls, and a secure-coding section tied to the library's [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) and the relevant CWE weaknesses.

These pages describe the languages themselves. For building software securely across languages, start at the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md); for the discipline, see the [Application Security](/disciplines/application-security.md) learning path.

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Reference Index](/INDEX.md).

---

## Foundations

| Topic | Summary |
|---|---|
| [Programming paradigms](/paradigms/README.md) | The dedicated paradigms section: imperative, procedural, structured, object-oriented, functional, logic, declarative, concurrent, reactive, and more, each in depth with a bibliography |

## Systems and low-level

| Language | Summary |
|---|---|
| [C](/languages/c.md) | Procedural systems language; portable, manual memory, the foundation of operating systems and embedded code |
| [C++](/languages/cpp.md) | Multi-paradigm systems language with RAII, templates, and zero-overhead abstractions |
| [Rust](/languages/rust.md) | Memory-safe systems language with ownership and borrow checking, no garbage collector |
| [Go](/languages/go.md) | Compiled, garbage-collected language with goroutines for concurrent network services |
| [Zig](/languages/zig.md) | Low-level systems language (pre-1.0) with explicit allocators and compile-time code, a C alternative |
| [Nim](/languages/nim.md) | Statically typed, compiled language with Python-like syntax and macros |
| [D](/languages/d.md) | Systems language with optional garbage collection, templates, and compile-time function evaluation |
| [Ada](/languages/ada.md) | Statically typed language for safety-critical and real-time systems, with strong contracts |
| [Crystal](/languages/crystal.md) | Statically typed, compiled language with Ruby-like syntax and type inference |
| [V](/languages/vlang.md) | Simple compiled language (pre-1.0) aiming for fast builds and no hidden control flow |
| [x86-64 Assembly](/languages/assembly-x86.md) | The AMD64 instruction set: registers, addressing, and calling conventions |
| [ARM Assembly](/languages/assembly-arm.md) | The ARM and AArch64 instruction set, registers, and the AAPCS calling convention |

## JVM languages

| Language | Summary |
|---|---|
| [Java](/languages/java.md) | Statically typed, class-based language on the JVM, used across server back ends and Android |
| [Kotlin](/languages/kotlin.md) | Statically typed JVM language with null safety and coroutines, preferred for Android |
| [Scala](/languages/scala.md) | Hybrid object-functional language on the JVM with a strong type system |
| [Groovy](/languages/groovy.md) | Dynamic JVM language used for scripting and build tooling such as Gradle |
| [Clojure](/languages/clojure.md) | A Lisp dialect on the JVM with immutable data and software transactional memory |

## .NET languages

| Language | Summary |
|---|---|
| [C#](/languages/csharp.md) | Statically typed, object-oriented .NET language for applications, web, and games |
| [F#](/languages/fsharp.md) | Functional-first .NET language with type inference and pattern matching |
| [Visual Basic .NET](/languages/visual-basic-net.md) | Object-oriented .NET language with an approachable, verbose syntax |

## Apple and mobile

| Language | Summary |
|---|---|
| [Swift](/languages/swift.md) | Statically typed, memory-safe language for Apple platforms and server-side work |
| [Objective-C](/languages/objective-c.md) | C-based object-oriented language, the historical language of macOS and iOS |
| [Dart](/languages/dart.md) | Client-optimized language that powers the Flutter cross-platform UI toolkit |

## Scripting and dynamic languages

| Language | Summary |
|---|---|
| [Python](/languages/python.md) | Dynamically typed, readable, multi-paradigm; automation, data science, web, and security tooling |
| [Ruby](/languages/ruby.md) | Dynamic, object-oriented language known for the Rails web framework and developer ergonomics |
| [Perl](/languages/perl.md) | Dynamic text-processing language with strong regular-expression support |
| [Raku](/languages/raku.md) | The redesigned Perl-family language (formerly Perl 6) with gradual typing and grammars |
| [PHP](/languages/php.md) | Server-side scripting language that drives a large share of the web |
| [Lua](/languages/lua.md) | Small, embeddable scripting language common in games and configuration |
| [Tcl](/languages/tcl.md) | Embeddable scripting language with a simple string-based syntax, paired with the Tk GUI toolkit |

## Web languages

| Language | Summary |
|---|---|
| [JavaScript](/languages/javascript.md) | The dynamic language of the web browser and, through Node.js, servers |
| [TypeScript](/languages/typescript.md) | JavaScript with static types that compile away, for larger codebases |
| [CoffeeScript](/languages/coffeescript.md) | An early JavaScript-transpiled language with terse syntax, now largely historical |
| [WebAssembly](/languages/webassembly.md) | A portable binary instruction format run in browsers and standalone runtimes |
| [Elm](/languages/elm.md) | A typed functional language for reliable browser front ends |
| [PureScript](/languages/purescript.md) | A Haskell-like typed functional language that compiles to JavaScript |

## Functional, Lisp, and ML languages

| Language | Summary |
|---|---|
| [Haskell](/languages/haskell.md) | A pure, lazily evaluated functional language with a strong static type system |
| [OCaml](/languages/ocaml.md) | A practical functional language with a module system and a fast native compiler |
| [Standard ML](/languages/standard-ml.md) | A formally specified functional language used in teaching and verification |
| [Elixir](/languages/elixir.md) | A functional language on the Erlang VM for concurrent, fault-tolerant systems |
| [Erlang](/languages/erlang.md) | A functional language built for concurrency, distribution, and fault tolerance |
| [Common Lisp](/languages/common-lisp.md) | A multi-paradigm Lisp with macros and a mature ANSI standard |
| [Scheme](/languages/scheme.md) | A minimalist Lisp dialect emphasizing clean semantics and tail calls |
| [Racket](/languages/racket.md) | A Scheme-derived language and platform for building languages |
| [Gleam](/languages/gleam.md) | A statically typed language on the Erlang VM with a friendly type system |

## Data, scientific, and numeric languages

| Language | Summary |
|---|---|
| [R](/languages/r.md) | A language and environment for statistics, data analysis, and visualization |
| [Julia](/languages/julia.md) | A high-level language for numerical and scientific computing with a just-in-time compiler |
| [MATLAB](/languages/matlab.md) | A numerical computing environment and matrix-oriented language |
| [GNU Octave](/languages/octave.md) | An open-source numerical language largely compatible with MATLAB |
| [Fortran](/languages/fortran.md) | The original scientific-computing language, still used in high-performance code |
| [SAS](/languages/sas.md) | A statistical analysis system and language used in regulated industries |
| [Wolfram Language](/languages/wolfram.md) | The symbolic, knowledge-based language behind Mathematica |
| [APL](/languages/apl.md) | An array-oriented language that uses a special symbol set |
| [J](/languages/j.md) | An ASCII array language in the APL tradition |
| [K and Q](/languages/k-q.md) | Terse array languages used with the kdb+ time-series database |

## Query languages

| Language | Summary |
|---|---|
| [SQL](/languages/sql.md) | The standard query language for relational databases |
| [PL/SQL](/languages/plsql.md) | Oracle's procedural extension to SQL |
| [T-SQL](/languages/tsql.md) | Microsoft SQL Server's procedural extension to SQL |
| [GraphQL](/languages/graphql.md) | A query language and runtime for APIs with a typed schema |
| [SPARQL](/languages/sparql.md) | The query language for RDF graph data on the semantic web |
| [Datalog](/languages/datalog.md) | A declarative logic query language used in analysis and databases |

## Shell and automation

| Language | Summary |
|---|---|
| [Bash](/languages/bash.md) | The common Unix shell and scripting language |
| [PowerShell](/languages/powershell.md) | Microsoft's object-oriented shell and scripting language, cross-platform |
| [Zsh](/languages/zsh.md) | A feature-rich Unix shell, the default on current macOS |
| [fish](/languages/fish.md) | A user-friendly Unix shell with sane defaults |
| [Windows Batch (cmd)](/languages/batch.md) | The legacy Windows command-script language |
| [Nushell](/languages/nushell.md) | A modern shell with structured, typed data pipelines |
| [AWK](/languages/awk.md) | A pattern-action language for text and data extraction |
| [Make](/languages/make.md) | A build-automation language driven by dependency rules |

## Legacy and historical languages

| Language | Summary |
|---|---|
| [COBOL](/languages/cobol.md) | A business-oriented language still running core mainframe systems |
| [Pascal](/languages/pascal.md) | A structured teaching language that influenced many successors |
| [Delphi (Object Pascal)](/languages/delphi.md) | An object-oriented Pascal with a rapid Windows application toolchain |
| [BASIC](/languages/basic.md) | The family of beginner-oriented languages from the 1960s onward |
| [Visual Basic (classic)](/languages/visual-basic.md) | Microsoft's rapid application development language for Windows before .NET |
| [Prolog](/languages/prolog.md) | A logic-programming language based on facts and rules |
| [Smalltalk](/languages/smalltalk.md) | A pure object-oriented language with a live image environment |
| [Forth](/languages/forth.md) | A stack-based, extensible language used in firmware and embedded systems |
| [ALGOL](/languages/algol.md) | The influential algorithmic language that shaped modern syntax |
| [PL/I](/languages/pli.md) | An IBM language combining scientific and business features |
| [RPG (IBM)](/languages/rpg.md) | A business language for the IBM i platform |
| [Logo](/languages/logo.md) | An educational language known for turtle graphics |
| [Eiffel](/languages/eiffel.md) | An object-oriented language built around design by contract |

## Hardware description languages

| Language | Summary |
|---|---|
| [VHDL](/languages/vhdl.md) | A hardware description language for digital circuit design and simulation |
| [Verilog](/languages/verilog.md) | A hardware description language widely used in chip design |
| [SystemVerilog](/languages/systemverilog.md) | An extension of Verilog for design and hardware verification |

## Smart-contract languages

| Language | Summary |
|---|---|
| [Solidity](/languages/solidity.md) | The main language for Ethereum smart contracts |
| [Vyper](/languages/vyper.md) | A Python-like, security-focused language for Ethereum contracts |
| [Move](/languages/move.md) | A resource-oriented language for safe digital assets on newer chains |

## Infrastructure and configuration languages

| Language | Summary |
|---|---|
| [HCL](/languages/hcl.md) | HashiCorp's configuration language, used by Terraform |
| [Nix](/languages/nix.md) | The language of the Nix package manager and reproducible builds |
| [Puppet](/languages/puppet.md) | A declarative language for configuration management |

## Other and emerging languages

| Language | Summary |
|---|---|
| [Ballerina](/languages/ballerina.md) | A language for cloud-native integration and network services |
| [GDScript](/languages/gdscript.md) | The scripting language of the Godot game engine |
| [Haxe](/languages/haxe.md) | A cross-platform language that compiles to many targets |
| [Mojo](/languages/mojo.md) | A Python-family language (pre-1.0) for AI and systems performance |
