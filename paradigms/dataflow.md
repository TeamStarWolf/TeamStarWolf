# Dataflow Programming

Dataflow programming models a program as a directed graph of operations in which data travels along edges and a node fires when its inputs are ready. It is declarative about dependencies: you state what each node needs, not the order in which to run nodes. This matters because the graph exposes parallelism directly and makes recomputation on changing inputs natural.

## Core idea

In the dataflow model, computation is driven by the availability of data rather than by a sequential instruction pointer. Each node is a small function. Edges carry values from one node's output to another's input. A node executes exactly when all of its required inputs have arrived.

Because order is implied by dependencies rather than written by hand, independent nodes may run in any order or at the same time. This is the structural reason dataflow maps well onto parallel and pipelined hardware. The programmer describes connections; the scheduler decides timing.

A second property is recomputation. When an input value changes, only the nodes downstream of that change need to fire again. This is the model behind spreadsheets, where editing a cell recomputes exactly the dependent cells and nothing else.

## How it works

Consider the graph as nodes with typed ports. A node with two input ports and one output port waits for both inputs, computes, and emits. Tokens, meaning individual data values, flow along edges. In token-based dataflow a node may fire each time a fresh token sits on every input edge, which turns the graph into a pipeline.

A spreadsheet is the dataflow program most people already use. Here is the same dependency structure expressed in formula form:

```text
A1 = 10
B1 = 5
C1 = A1 + B1      # fires when A1 and B1 are known -> 15
D1 = C1 * 2       # fires when C1 is known         -> 30
```

Change `A1` to `20` and the engine recomputes `C1` then `D1`, following edges in dependency order. `B1` is untouched because nothing it depends on changed. The engine computes a topological order so each node runs after its inputs are current.

Synchronous dataflow (SDF) is a restricted form with strong guarantees. Each node consumes a fixed number of tokens per input and produces a fixed number per output, all known at compile time. From those fixed rates a scheduler can compute a static firing order and bounded buffer sizes before the program runs. SDF underpins much digital signal processing, where predictable timing and memory are requirements.

```text
# Synchronous dataflow rates on each edge (tokens per firing)
source --2--> fft --1--> scale --1--> sink
```

With rates fixed, a tool can prove the graph runs without deadlock and size every buffer exactly. That static analysis is what distinguishes SDF from the general dynamic case, where firing patterns depend on data and buffers may need runtime management.

Visual dataflow tools make the graph the primary artifact. In LabVIEW, programs are wiring diagrams: you draw nodes and connect their terminals, and the block executes when its wired inputs are present. This suits instrumentation and control, where engineers already think in signal diagrams. The visual form and the textual form share one semantics: availability of data triggers execution.

Dataflow relates closely to reactive programming and to stream processing. Reactive systems propagate change along a dependency graph, which is dataflow with an emphasis on time-varying inputs. Stream processors such as pipeline frameworks run long-lived dataflow graphs over unbounded data, partitioning nodes across machines and moving tokens between them as network messages.

## Strengths and trade-offs

The model surfaces parallelism without explicit threads, because independent nodes are independent by construction. Incremental recomputation follows from the same structure, which is why spreadsheets feel immediate. Static variants like SDF give compile-time guarantees on scheduling and memory.

The trade-offs center on control and dynamism. Expressing data-dependent control flow, loops with irregular termination, and shared mutable state is awkward in a pure graph. Large graphs can be hard to read, and debugging token flow differs from stepping through statements. General dynamic dataflow can deadlock or grow buffers without care.

## Languages and tools

Confirmed language links are weak for this paradigm, so the main examples are named in plain text. Spreadsheets, including Excel and Google Sheets, are the most widespread dataflow engines in daily use. LabVIEW and its G language are the best-known visual dataflow environment for instrumentation and measurement.

Stream processors express dataflow at cluster scale: systems such as Apache Flink, Apache Beam, and similar pipeline runtimes execute operator graphs over streaming data. Signal-processing tools like Pure Data and Max/MSP apply dataflow to audio. Many build systems are dataflow engines too, since a dependency graph of targets recomputes only what a change affects.

## Secure-coding considerations

Unbounded or data-dependent buffers between nodes are a resource risk. A graph that lets producers outrun consumers can exhaust memory, which maps to CWE-400 (Uncontrolled Resource Consumption). Size buffers deliberately and prefer bounded or synchronous rates where latency budgets allow.

Nodes that evaluate externally supplied formulas or expressions are dangerous. A spreadsheet or pipeline that interprets untrusted input as a formula can enable injection, which relates to CWE-94 (Improper Control of Generation of Code). Treat every incoming token as untrusted data and validate it at the graph's boundary. See /SECURE_CODING_REFERENCE.md for validation and resource-limit practices.

## Resources

- Gilles Kahn, *The Semantics of a Simple Language for Parallel Programming*, 1974, IFIP Congress
- Edward A. Lee and David G. Messerschmitt, *Synchronous Data Flow*, 1987, Proceedings of the IEEE
- Wesley M. Johnston, J. R. Paul Hanna, and Richard J. Millar, *Advances in Dataflow Programming Languages*, 2004, ACM Computing Surveys

## Related pages

- /paradigms/README.md
- /SECURE_CODING_REFERENCE.md
- /paradigms/reactive.md
- /paradigms/declarative.md
- /paradigms/concurrent.md
- /paradigms/functional.md
