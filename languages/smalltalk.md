# Smalltalk

Smalltalk is a dynamically typed, object-oriented language and live programming environment developed at Xerox PARC in the 1970s, with Smalltalk-80 defining the model that most later systems follow. Everything is an object, computation happens by sending messages between objects, and the language runs inside a persistent image that holds the running program and its tools together. It is used in research, education, live-system development, and some financial and enterprise applications.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented (pure, message-passing) |
| Typing | Dynamic, strong |
| First appeared | 1972 (Smalltalk-80 published the model; ANSI standard in 1998) |
| Memory model | Automatic: garbage collection within a persistent object image |
| Reference implementation | No single reference; [Pharo](https://pharo.org/) and [Squeak](https://squeak.org/) are common open-source systems, Cincom VisualWorks is commercial |
| Typical uses | Research, education, live systems, some financial and enterprise software |
| Governance/standard | [ANSI INCITS 319-1998](https://www.incits.org/) (Smalltalk) |

Related: [Eiffel](/languages/eiffel.md), [Logo](/languages/logo.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Smalltalk was created by Alan Kay, Dan Ingalls, Adele Goldberg, and colleagues at Xerox PARC, where it also drove early work on graphical user interfaces and overlapping windows. Smalltalk-80 was the version released beyond PARC and became the basis for the ANSI standard and for later systems. Its defining idea is uniform object orientation: there are no primitive non-objects in the model, control flow is expressed with messages and blocks, and the development tools are themselves Smalltalk objects you can inspect and change while the system runs.

There is no single reference implementation. Squeak and its descendant Pharo are active open-source systems with modern libraries and tooling; GNU Smalltalk offers a more file-oriented, scripting style; Cincom VisualWorks and Instantiations VA Smalltalk are commercial systems used in production. Programs are developed and shipped as images, snapshots of the live object memory.

## Paradigm and type system

Smalltalk is purely object-oriented and dynamically but strongly typed. Every value, including integers, booleans, and classes, is an object, and the only operation is sending a message to an object, which looks up a method in the receiver's class. Conditionals and loops are messages to objects with block closures as arguments, not special syntax.

```smalltalk
"Everything is a message send; blocks are objects"
| max |
max := [:a :b | a > b ifTrue: [a] ifFalse: [b]].
Transcript showln: (max value: 3 value: 7) printString.  "7"
```

Types are checked at run time: sending a message an object does not understand raises `doesNotUnderstand:`, which the object can even intercept to implement proxies.

## Toolchain and ecosystem

- Environment: Pharo and Squeak are self-contained IDEs and runtimes; you browse and edit classes in a live image and save the image to persist work.
- Package manager: Pharo uses [Metacello](https://github.com/Metacello/metacello) with the Monticello versioning system and loads packages from repositories.
- Source control: code can be exported to files and tracked in Git through tools such as Iceberg in Pharo.

```smalltalk
"In a Pharo workspace, load a package"
Metacello new
  baseline: 'MyProject';
  repository: 'github://user/MyProject';
  load.
```

## Syntax tour

```smalltalk
Object subclass: Circle [
    | radius |
    radius: aNumber [ radius := aNumber ]
    area [ ^ radius * radius * Float pi ]
]

"Create an instance and send messages"
| c |
c := Circle new.
c radius: 2.
Transcript showln: c area printString.

"Collections with blocks"
#(1 2 3 4 5)
    select: [:n | n odd]
    thenCollect: [:n | n * n].   "#(1 9 25)"
```

## Idioms and different approaches

- Express control flow by sending messages (`ifTrue:ifFalse:`, `whileTrue:`, `do:`) with blocks, rather than looking for statement keywords.
- Keep methods short and name them so a message send reads as a sentence (`aCollection detect: [:x | x > 0]`).
- Develop live: write a method, run it from a workspace, inspect the resulting objects, and refine in place.
- Use the collection protocol (`collect:`, `select:`, `inject:into:`) instead of manual index loops.
- Override `printOn:` so objects describe themselves in inspectors and the transcript.

## Design principles

Smalltalk's design goal was a uniform, learnable system in which a small number of ideas (objects, messages, classes, blocks) compose without exception, and in which the environment is live and malleable. Alan Kay's conception centered on objects as independent entities that communicate by messages, an idea that shaped later object-oriented languages. The persistent image reflects a view of programming as cultivating a running system rather than compiling and restarting it.

## Standard library and notable packages

The base image provides a layered class library: magnitudes and numbers, a rich collection hierarchy (`Array`, `OrderedCollection`, `Dictionary`, `Set`), streams, exceptions, and reflection. Pharo adds frameworks for web development (Seaside, Teapot), object persistence, graphics (Morphic), and data access. Because the environment is reflective, the libraries, the compiler, and the tools are all ordinary classes available to programs.

## Testing and packaging

SUnit, the original xUnit framework, originated in Smalltalk and ships with Pharo and Squeak. Tests are methods on a `TestCase` subclass. Code is packaged as loadable packages (Monticello or Tonel file format) and described for dependency loading with Metacello baselines; a deliverable is often a configured image.

```smalltalk
TestCase subclass: CircleTest [
    testArea [
        | c |
        c := Circle new radius: 1.
        self assert: (c area - Float pi) abs < 1e-9
    ]
]
```

## Performance and concurrency

Modern Smalltalk systems compile methods to bytecode and run them on a virtual machine with a just-in-time compiler, so general object code performs reasonably, though number-crunching trails native languages. Concurrency uses green processes scheduled by the virtual machine, with `Process`, `Semaphore`, and `SharedQueue` for coordination; some systems add operating-system threads. Because the image is shared mutable state, concurrent code must synchronize access to shared objects explicitly.

## Common pitfalls

- Treating the image as the only copy of code: without exporting to files and version control, work lives only in a binary snapshot.
- `doesNotUnderstand:` errors surfacing late because typing is dynamic; a mistyped selector is found only when the message is sent.
- Shared mutable state in the global image causing surprising interactions between unrelated code.
- Overusing reflection and `become:` in ways that make behavior hard to follow.
- Blocking the UI process with long computations instead of forking a separate process.

## Secure coding

Smalltalk's reflective, image-based model concentrates its security-relevant risks in dynamic evaluation and persistence:

- Dynamic evaluation: `Compiler evaluate:` and similar methods compile and run source at run time, so evaluating untrusted text executes arbitrary code. Never evaluate external input as source; parse it into data instead. This maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Unsafe deserialization: loading objects from untrusted serialized data (image segments or object-serialization formats) can reconstruct unexpected objects and trigger behavior; restrict and validate what is loaded, which maps to [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- Input validation: dynamic typing means external data is unchecked until the program checks it; validate structure and range at the boundary, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Resource exhaustion: recursion or collection growth sized by untrusted input can exhaust memory; bound input, which maps to [CWE-400](https://cwe.mitre.org/data/definitions/400.html).

Dedicated security analyzers are scarce. Pharo and Squeak provide code critics and lint rules (the Refactoring Browser's rules, SmallLint) that flag some risky patterns; manual review of any `evaluate:` and deserialization is the primary control. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Pharo by Example](https://books.pharo.org/), a free introduction to a modern Smalltalk.
- [Pharo documentation](https://pharo.org/documentation), guides and references for the environment.
- [Squeak documentation](https://squeak.org/documentation/), for the related open-source system.

## Related pages

- [Eiffel](/languages/eiffel.md)
- [Logo](/languages/logo.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
