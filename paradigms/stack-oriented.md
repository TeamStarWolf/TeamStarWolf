# Stack-Oriented and Concatenative Programming

Stack-oriented programming computes by pushing values onto an operand stack and popping them with operators, so most instructions take their arguments implicitly from the stack top. It is an imperative style at the machine level and a concatenative one at the language level, where writing two programs next to each other composes them. It matters because it underlies Forth, PostScript, and the bytecode stacks of the JVM and WebAssembly.

## Core idea

A single operand stack holds the working values. Pushing a literal places it on top. Applying an operator removes its operands from the top and pushes the result. Because operands are already present when an operator runs, operators need no named parameters.

This gives postfix order, also called reverse Polish notation. You write the operands first and the operator last, so `3 4 +` leaves `7` on the stack. Postfix needs no parentheses and no precedence rules, since evaluation order follows the text exactly.

Concatenative languages take a further step: every program denotes a function from stack to stack, and juxtaposition means function composition. Joining two snippets runs the first, then the second, with no glue syntax. Factoring out a common phrase is literal cut and paste, because a sub-sequence of words is itself a valid program.

## How it works

Forth organizes a program as a dictionary of words. A word is a named routine that acts on the stack, and defining a word with `:` and `;` adds it to the dictionary for later use. The interpreter reads whitespace-separated tokens, pushes numbers, and executes words it finds, so the language has almost no fixed syntax.

Stack manipulation words rearrange the top without arithmetic. `dup` copies the top value, `swap` exchanges the top two, `drop` discards the top, and `over` copies the second item to the top. Mastering these is most of the skill, because data flow is expressed by shuffling the stack rather than by naming variables.

This Forth session defines a word that squares the top of the stack, then uses it.

```forth
: square ( n -- n*n )  dup * ;
5 square .   \ prints 25
```

The comment `( n -- n*n )` is a stack effect, the standard way to document what a word consumes and produces. `dup` duplicates the `5`, `*` multiplies the two copies, and `.` prints and pops the result. Nothing is named; the value simply moves through the stack.

PostScript applies the same model to page description. A print job is a stack program whose operators set coordinates, build paths, and paint, so `72 72 moveto` consumes two numbers and moves the current point. The document is literally code that a printer or viewer executes.

Stack machines dominate language runtimes for a different reason: they are simple to generate code for and compact to encode. The JVM and WebAssembly both specify a virtual operand stack, so a bytecode instruction like integer add pops two values and pushes their sum. A compiler can emit such code with a straightforward tree walk, and a just-in-time stage later maps the stack onto registers.

Factor is a modern concatenative language that keeps the stack model while adding a module system, a static-checked stack effect, and a large standard library. It shows that the paradigm scales past small embedded words to general application code, with tooling that verifies stack effects at compile time.

## Strengths and trade-offs

Implementations are small, which is why Forth runs on tiny microcontrollers and why bytecode stacks are easy to target. Postfix evaluation needs no precedence table or parenthesis matching, so the parser is trivial. Concatenative composition makes refactoring mechanical, since any contiguous run of words can be named and reused without rewiring arguments.

The trade-offs center on readability. Deep stack juggling with `dup`, `swap`, and `rot` becomes hard to follow, and a wrong stack effect produces silent corruption rather than a type error in untyped Forth. Because values are positional, a routine that expects three items but receives two reads whatever lies beneath, so discipline about stack effects is essential. Typed concatenative languages such as Factor recover some safety, at the cost of the extreme minimalism that makes classic Forth appealing.

## Languages and tools

[Forth](/languages/forth.md) is the canonical stack-oriented language and the usual entry point, especially in embedded and firmware work. PostScript and its descendant PDF use the same operand-stack model for rendering, and Factor carries the concatenative idea into a modern general-purpose language.

The style also lives inside systems you may not call stack languages. The JVM, the CPython evaluation loop, and WebAssembly all execute stack-based bytecode, so understanding operand stacks helps when you read disassembly or write a code generator.

## Secure-coding considerations

The operand stack has no bounds enforcement in classic Forth, so a word that pops more than was pushed reads adjacent memory or underflows. This maps to CWE-124 (Buffer Underwrite) and, for over-pushing without checks, to stack-exhaustion faults. Verify stack depth at entry to words that process untrusted input, and prefer runtimes that check effects.

Forth also exposes direct memory words such as fetch and store, which trust the address on the stack. An address computed from external data can read or write anywhere, so treat such values as you would raw pointers in C. See /SECURE_CODING_REFERENCE.md for memory-safety guidance that applies to direct stack and address manipulation.

## Resources

- Leo Brodie, *Starting Forth*, 1981, Prentice Hall
- Leo Brodie, *Thinking Forth*, 1984, Prentice Hall
- Manfred von Thun, *Joy: Forth's Functional Cousin*, 2001 (the Joy language papers)

## Related pages

- /paradigms/README.md
- /SECURE_CODING_REFERENCE.md
- /paradigms/imperative.md
- /paradigms/functional.md
- /paradigms/procedural.md
- /paradigms/metaprogramming.md
