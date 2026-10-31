# Symbolic Programming

Symbolic programming treats programs and data as manipulable symbolic structures rather than as fixed sequences of machine operations. It is cross-cutting: a style that overlays functional, logic, and metaprogramming work rather than a single control model. It matters because it underlies computer algebra, program transformation, and the classic artificial intelligence tradition, where the thing being computed is itself an expression.

## Core idea

The defining concept is that symbols and the structures built from them are first-class values. A variable, an operator, or a whole expression like `(+ x (* 2 y))` is data you can build, inspect, transform, and evaluate. The program reasons about expressions, not just numbers and strings.

Homoiconicity is the sharpest expression of this idea. In a homoiconic language, code is represented in the language's own primary data structure, so a program is a data structure that other programs can read and rewrite. Lisp represents code as nested lists, called s-expressions, which are the same lists the language manipulates at runtime.

This distinguishes symbolic programming from numeric and object-oriented styles. The unit of work is a term or expression, and computation often means rewriting one expression into another according to rules. The boundary between program and data is deliberately thin.

## How it works

The core data structure in the Lisp tradition is the s-expression: an atom, or a parenthesized list of s-expressions. Because source code is written as s-expressions, a Lisp program can take another program as a list and transform it. `quote` suppresses evaluation so you can treat code as data, and `eval` turns data back into a running program.

```scheme
; A list that is also valid code.
(define expr '(+ 1 (* 2 3)))
(car expr)        ; => +      (the operator symbol)
(eval expr)       ; => 7      (evaluate the same list as code)
```

Macros use this property to transform code at compile time. A macro receives unevaluated code as a data structure, computes a new structure, and the compiler then evaluates the result. This lets you add control constructs that look built in. The macro runs over the program text, not over runtime values.

```scheme
; A macro that evaluates body only when test is false.
(define-syntax unless
  (syntax-rules ()
    ((unless test body ...)
     (if (not test) (begin body ...)))))

(unless #f (display "runs"))   ; prints: runs
```

Term rewriting is the other main mechanism. A rewrite system holds a set of rules that match a pattern in an expression and replace it with another expression. Computer algebra systems use this to simplify, differentiate, and solve symbolically. Wolfram Language is built almost entirely on pattern-based rewriting of expressions.

```wolfram
(* A rule-based symbolic derivative of a specific form *)
D[x^3 + 2 x, x]        (* => 3 x^2 + 2 *)
simplify = x_ + x_ -> 2 x_;
a + a /. simplify      (* => 2 a *)
```

The logic programming tradition is symbolic in a different way. Prolog represents knowledge as terms and clauses, and unification matches and binds symbolic terms during a search for proofs. A query is answered by rewriting goals against rules until it resolves, with the engine manipulating symbolic structures throughout.

```prolog
parent(tom, bob).
parent(bob, ann).
grandparent(X, Z) :- parent(X, Y), parent(Y, Z).
% ?- grandparent(tom, Who).   Who = ann.
```

In classic artificial intelligence, symbolic methods drove expert systems, planners, and theorem provers. Knowledge was encoded as symbols and rules, and reasoning meant searching and rewriting that symbolic space. Norvig's case studies reconstruct many of these systems in Common Lisp.

## Strengths and trade-offs

Symbolic programming is the right tool when the problem is itself about expressions: algebra, compilers, program analysis, rule engines, and planning. Homoiconicity makes metaprogramming direct, so you extend the language from inside it rather than bolting on a preprocessor. Exact symbolic computation avoids the rounding error of floating-point numeric methods.

The trade-offs are concrete. Symbolic representations are memory-heavy and slower than packed numeric arrays, so they lose to numeric code on raw computation. Unrestrained macros can produce code that is hard to read and debug, because the source no longer matches what runs. Term-rewriting systems can fail to terminate or blow up in size, and reasoning about a program that rewrites itself is cognitively demanding.

## Languages and tools

The Lisp family is the home of symbolic programming: [Common Lisp](/languages/common-lisp.md), [Scheme](/languages/scheme.md), [Racket](/languages/racket.md), and [Clojure](/languages/clojure.md). [Prolog](/languages/prolog.md) carries the logic and unification branch of the tradition. [Wolfram Language](/languages/wolfram.md) is a large term-rewriting and computer-algebra system.

Beyond general languages, symbolic techniques appear in computer algebra systems such as Maxima, SymPy, Maple, and Mathematica, and in rule engines and theorem provers. Many modern languages borrow the ideas through Lisp-style macros, abstract syntax tree manipulation, and quasi-quotation.

## Secure-coding considerations

The signature risk is evaluation of code built from untrusted input. Passing attacker-controlled data to `eval`, or to a macro that embeds it, allows arbitrary code execution, which maps to CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code). Never feed external input into `eval` or `read` without strict parsing and validation; prefer a restricted reader and an explicit allowlist of forms.

Macros create a second failure mode: variable capture. A macro that introduces a binding can shadow a name from the call site, changing behavior in ways the caller cannot see. Use hygienic macros, as `syntax-rules` provides in Scheme, or generate fresh symbols with `gensym` so expansion cannot clash with caller names. Term-rewriting systems can also run without end on crafted input, a denial-of-service path under CWE-674 (Uncontrolled Recursion); bound rule application and reject inputs that do not converge.

Treat deserialization of symbolic data as code execution, because a reader that constructs arbitrary objects is an execution surface. See /SECURE_CODING_REFERENCE.md for input-validation and safe-deserialization guidance that applies to every symbolic evaluator.

## Resources

- Peter Norvig, *Paradigms of Artificial Intelligence Programming: Case Studies in Common Lisp*, 1992, Morgan Kaufmann
- Harold Abelson and Gerald Jay Sussman, *Structure and Interpretation of Computer Programs*, 1996, MIT Press
- Paul Graham, *On Lisp*, 1993, Prentice Hall
- John McCarthy, *Recursive Functions of Symbolic Expressions and Their Computation by Machine, Part I*, 1960, CACM

## Related pages

- /paradigms/README.md
- /SECURE_CODING_REFERENCE.md
- /paradigms/functional.md
- /paradigms/logic.md
- /paradigms/metaprogramming.md
- /paradigms/declarative.md
- /paradigms/data-oriented.md
