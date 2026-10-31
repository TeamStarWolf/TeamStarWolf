# Logo

Logo is a dynamically typed, interpreted language created in 1967 at Bolt, Beranek and Newman by Wally Feurzeig, Seymour Papert, and Cynthia Solomon to teach programming and mathematical thinking to children. It derives much of its design from Lisp, but is best known for turtle graphics: commands move a turtle around the screen, drawing as it goes. Logo is used mainly in education, and its ideas carried into later learning environments.

| Attribute | Value |
|---|---|
| Paradigm | Procedural and functional (Lisp-derived), educational |
| Typing | Dynamic |
| First appeared | 1967 |
| Memory model | Automatic: garbage-collected |
| Reference implementation | No single reference; [UCBLogo (Berkeley Logo)](https://people.eecs.berkeley.edu/~bh/logo.html) is a common one, [FMSLogo](http://fmslogo.sourceforge.net/) targets Windows |
| Typical uses | Teaching programming and geometry, turtle graphics, early computer-science education |
| Governance/standard | No formal standard; dialect-driven |

Related: [Smalltalk](/languages/smalltalk.md), [Prolog](/languages/prolog.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Logo was designed as a learning language grounded in a constructionist view of education: children learn by building and debugging their own programs. Seymour Papert, who had worked with Jean Piaget, argued that programming a turtle to draw shapes gives learners a concrete way to reason about geometry and procedures. The turtle began as a floor robot and became an on-screen cursor. The 1980 book Mindstorms set out the educational philosophy.

There is no single reference implementation and no formal standard; many dialects exist. UCBLogo (Berkeley Logo) is a widely used free implementation with a documented language; FMSLogo is a Windows implementation descended from it. Logo's turtle-graphics model influenced later educational tools, including the turtle module in other languages and block-based environments such as Scratch, which came from the same research tradition.

## Paradigm and type system

Logo is dynamically typed and draws on Lisp: its core data structures are words and lists, and programs are built from procedures. It reads as command words followed by their inputs, which makes simple programs look like instructions in near-English. Procedures are defined with `to ... end` and can be recursive, which Logo uses heavily for drawing fractal and repeating figures.

```logo
to square :size
  repeat 4 [ forward :size right 90 ]
end
```

Values are words (atoms and numbers) and lists; variables are introduced with `make` and referenced with a colon prefix. Because it is dynamically typed, type mismatches surface at run time.

## Toolchain and ecosystem

- Interpreter: UCBLogo and FMSLogo provide an interactive interpreter with a turtle-graphics window.
- Interaction: development is interactive; you type commands at the prompt and see the turtle respond immediately, then collect commands into procedures.
- Ecosystem: Logo has no package manager; dialects ship their own built-in command sets, and shared code is distributed as source procedure files.

```bash
# UCBLogo: start the interpreter, then type commands
logo
? repeat 36 [ fd 100 rt 170 ]
```

## Syntax tour

```logo
; Recursive drawing: a spiral
to spiral :length :angle
  if :length > 200 [ stop ]
  forward :length
  right :angle
  spiral (:length + 5) :angle
end

; Clear the screen and draw
clearscreen
spiral 10 92

; Working with lists and words
make "nums [1 2 3 4 5]
print first :nums        ; 1
print count :nums        ; 5
```

## Idioms and different approaches

- Build a drawing from small named procedures (a `square`, a `petal`) and compose them, rather than one long command sequence.
- Use `repeat` for fixed iteration and recursion for figures that grow or branch.
- Keep turtle state predictable: have a procedure leave the turtle where it started so procedures compose cleanly.
- Use lists and the word and list operations (`first`, `butfirst`, `fput`) for data, reflecting the Lisp heritage.
- Name inputs clearly with the colon convention so a procedure reads as an instruction.

## Design principles

Logo was designed for learning: immediate feedback, a low threshold for a first program, and room to grow into recursion and list processing. The turtle gives an embodied way to think about geometry and state, what Papert called "body syntonic" reasoning. The language favors approachability and exploration over performance or scale, and its Lisp-derived core means the same ideas (procedures, recursion, lists) that make it a teaching tool also connect to general computer science.

## Standard library and notable packages

Logo's built-in vocabulary covers turtle graphics (`forward`, `back`, `right`, `left`, `penup`, `pendown`), control (`repeat`, `if`, `stop`, `output`), and word and list processing (`first`, `last`, `butfirst`, `sentence`, `fput`, `lput`). Dialects add their own commands for sound, multiple turtles, file access, and graphics. There is no central package ecosystem; each implementation provides its own commands, and reusable procedures are shared as source files.

## Testing and packaging

Logo has no standard test framework, consistent with its educational focus; checking a program usually means running it and watching the turtle or printing results. There is no packaging system; programs are shared as source files of procedure definitions that a learner loads into the interpreter. In a classroom, the deliverable is typically the running program itself rather than a distributable artifact.

## Performance and concurrency

Performance is not a design goal: Logo implementations are interpreters aimed at interactive, educational use, so they are slow relative to compiled languages, which rarely matters for the drawings and exercises Logo is used for. Concurrency is generally not part of the language, though some dialects support multiple turtles that appear to move together under one program's control. Standard Logo programs are single-threaded, and parallelism is not a reason the language is used.

## Common pitfalls

- Turtle state left in an unexpected position or heading, so a procedure that worked alone misbehaves when composed with others.
- Recursion without a base case (a missing `stop` or `if` guard), causing a runaway drawing or stack exhaustion.
- Confusing a variable's name (`"x`) with its value (`:x`), a common beginner error.
- Dialect differences: command names and features vary between UCBLogo, FMSLogo, and others, so programs may not port unchanged.
- Dynamic typing surprises, such as passing a list where a number is expected, which fails only at run time.

## Secure coding

Logo runs almost entirely in classroom and self-contained settings, so it has little exposure to untrusted input, but the general weaknesses still apply where a Logo program processes external data or text:

- Dynamic evaluation: Logo's `run` command executes a list as instructions, so running text assembled from untrusted input executes arbitrary commands. Do not `run` external input; treat it as data. This maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Input validation: values read from input or files are unchecked until the program checks them; validate before use, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- File and system access: dialects that provide file or shell access should not pass untrusted input to those commands, which relates to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Resource exhaustion: unbounded recursion driven by input can exhaust the stack, which maps to [CWE-400](https://cwe.mitre.org/data/definitions/400.html).

There is no dedicated security tooling for Logo, reflecting its educational scope and low exposure. Where a Logo program does handle external input, apply the general practices of validating input and never evaluating it as code. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Berkeley Logo (UCBLogo) manual](https://people.eecs.berkeley.edu/~bh/usermanual), the reference for a common implementation.
- [Computer Science Logo Style by Brian Harvey](https://people.eecs.berkeley.edu/~bh/v1-toc2.html), a free text using Logo to teach computing.
- [Seymour Papert, "Mindstorms"](https://archive.org/details/mindstormschildr0000pape), the book setting out Logo's educational philosophy.

## Related pages

- [Smalltalk](/languages/smalltalk.md)
- [Prolog](/languages/prolog.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
