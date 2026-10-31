# Metaprogramming

Metaprogramming is writing programs that treat other programs, or themselves, as data to generate, inspect, or transform. It is cross-cutting rather than a standalone paradigm: it layers onto imperative, functional, and object-oriented code. Used well it removes boilerplate and builds domain-specific abstractions; used carelessly it hides control flow and defeats tooling.

## Core idea

The defining move is collapsing the distance between code and data. In most languages code is opaque once written. A metaprogram instead manipulates a representation of code: a syntax tree, a token stream, a template, or runtime type information. It can read that representation, rewrite it, or emit new code from it.

The crucial axis is when this happens. Compile-time metaprogramming runs during translation and produces source or intermediate code before the program executes. Run-time metaprogramming inspects and alters program structure while the program is running. The two have different costs: compile-time work is free at run time but limited to what the compiler can see, while run-time work is flexible but adds overhead and resists static checking.

## How it works

Macros are the compile-time workhorse. A macro receives unevaluated code and returns code to be compiled in its place. Lisp macros are the clearest case because of homoiconicity: Lisp code is written as lists, the same data structure the language manipulates, so a macro is just a function from a list to a list.

```lisp
;; Common Lisp: 'unless' built from 'if', evaluating 'body' only when test is false
(defmacro unless (test &body body)
  `(if ,test nil (progn ,@body)))

(unless (null lst)
  (print (first lst)))   ; expands to (if (null lst) nil (progn (print (first lst))))
```

Naive macros capture variables by accident: a name the macro introduces can shadow one from the call site, or vice versa. Hygienic macros solve this by renaming introduced identifiers so expansion cannot capture or be captured. Scheme and Racket provide hygiene by default through `syntax-rules` and `syntax-case`. Common Lisp is unhygienic, so programmers use generated symbols (`gensym`) to avoid clashes by hand.

Other languages offer their own compile-time facilities. Rust has declarative `macro_rules!` macros and procedural macros that operate on token streams, both hygienic and run by the compiler. Elixir macros work on its quoted abstract syntax tree and underpin much of the standard library. C++ templates are a separate compile-time mechanism: the compiler instantiates generic definitions per type, and template metaprogramming exploits this to compute types and values during compilation.

```rust
// Rust: a tiny declarative macro that builds a Vec and pushes each argument
macro_rules! vec_of {
    ($($x:expr),* $(,)?) => {{
        let mut v = Vec::new();
        $( v.push($x); )*
        v
    }};
}

let xs = vec_of![1, 2, 3];
```

Run-time metaprogramming centers on reflection and dynamic dispatch of structure. Reflection lets a program enumerate types, fields, and methods and invoke them by name, as in Java, C#, and Python. Dynamic languages go further: Ruby's `method_missing` and `define_method` synthesize behavior on demand, and Python classes can be shaped by metaclasses. The metaobject protocol, developed for the Common Lisp Object Model, exposes the object system itself as objects you can specialize, so class creation and method lookup become programmable.

Code generation sits at the edge of the paradigm. Instead of transforming an in-memory tree, a generator emits source text that a later build step compiles. Protocol buffer compilers, ORM scaffolding, and parser generators all work this way. It is the least integrated form, but it crosses language boundaries that macros and reflection cannot.

## Strengths and trade-offs

Metaprogramming removes repetition that no ordinary function can, because it abstracts over syntax and types, not just values. It lets a library offer a clean domain-specific interface, enforce invariants at compile time, and derive code (serializers, accessors) that would be tedious and error-prone to hand-write. Compile-time variants pay no run-time cost and can catch mistakes early.

The price is understanding and tooling. Generated or rewritten code is code you did not read, so stack traces, debuggers, and go-to-definition degrade. Macros that are unhygienic, or reflection that bypasses types, move errors from compile time to run time and can break assumptions the rest of the program relies on. The guidance across communities is consistent: reach for a function first, and use metaprogramming only when the abstraction genuinely needs to operate on code.

## Languages and tools

Lisp-family languages set the standard for macros and homoiconicity: [Common Lisp](/languages/common-lisp.md), [Clojure](/languages/clojure.md), and [Racket](/languages/racket.md). [C++](/languages/cpp.md) uses templates for compile-time metaprogramming, while [Rust](/languages/rust.md) provides hygienic declarative and procedural macros. [Ruby](/languages/ruby.md) is known for run-time metaprogramming, and [Elixir](/languages/elixir.md) builds much of its surface from AST macros.

## Secure-coding considerations

The sharpest risk is run-time evaluation of strings as code. Functions such as `eval`, dynamic `require`, and templating that compiles user input invite code injection; see [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) and CWE-94, Improper Control of Generation of Code. Never build executable code from untrusted input, and prefer compile-time macros or data-driven dispatch over run-time `eval`.

Reflection weakens boundaries. It can read private fields, invoke hidden methods, and deserialize arbitrary types, which turns reflective deserialization into remote code execution (CWE-502, Deserialization of Untrusted Data). Restrict which types may be instantiated reflectively, avoid deserializing data from untrusted sources into live objects, and keep generated code in reviewed, version-controlled form rather than producing it from runtime data. Audit macros too: a macro that silently drops a check or captures a variable can introduce a flaw that no call site reveals.

## Resources

- Gregor Kiczales, Jim des Rivieres, and Daniel G. Bobrow, *The Art of the Metaobject Protocol*, 1991, MIT Press
- Paul Graham, *On Lisp*, 1993, Prentice Hall
- David Abrahams and Aleksey Gurtovoy, *C++ Template Metaprogramming*, 2004, Addison-Wesley
- Krzysztof Czarnecki and Ulrich Eisenecker, *Generative Programming: Methods, Tools, and Applications*, 2000, Addison-Wesley

## Related pages

- [Programming paradigms](/paradigms/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Symbolic programming](/paradigms/symbolic.md)
- [Generic programming](/paradigms/generic.md)
- [Functional programming](/paradigms/functional.md)
- [Aspect-oriented programming](/paradigms/aspect-oriented.md)
