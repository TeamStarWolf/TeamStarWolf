# Common Lisp

Common Lisp is a dynamically typed, multi-paradigm dialect of Lisp standardized by ANSI in 1994. It is known for interactive development, a macro system that treats code as data, the Common Lisp Object System, and a condition system for recoverable error handling. It is used in symbolic computation, scheduling and optimization, research, and long-lived production systems.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: functional, imperative, object-oriented, metaprogramming |
| Typing | Dynamic, strong, with optional type declarations |
| First appeared | 1984 (ANSI standard in 1994) |
| Memory model | Automatic: garbage collection |
| Reference implementation | No single reference; [SBCL](https://www.sbcl.org/) is a common high-performance one |
| Typical uses | Symbolic computation, optimization, research, production services |
| Governance | ANSI INCITS 226-1994 standard; no active revision body |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Scheme](/languages/scheme.md), [languages index](/languages/README.md).

## Overview and history

Common Lisp was created in the 1980s to consolidate a family of divergent Lisp dialects, chiefly descendants of Maclisp, into one portable language. The effort produced the 1984 book Common Lisp the Language and, a decade later, the 1994 ANSI standard that still defines the language. Because the standard is stable and detailed, conforming implementations remain compatible across decades.

There is no single reference implementation. [SBCL (Steel Bank Common Lisp)](https://www.sbcl.org/) is a widely used compiler that produces fast native code; other implementations include [Clozure CL](https://ccl.clozure.com/), [ECL](https://ecl.common-lisp.dev/) (embeddable, compiles through C), and the commercial Allegro CL and LispWorks. Development is typically interactive: a running image is modified function by function from the read-eval-print loop.

## Paradigm and type system

Common Lisp is dynamically typed with strong typing: values carry their type, and operations check it at run time. Types can be declared to help the compiler generate faster code and catch mistakes, but declarations are optional. The language is multi-paradigm, combining functional programming, imperative loops and assignment, the Common Lisp Object System (CLOS) with multiple dispatch and multiple inheritance, and metaprogramming through macros.

```lisp
(defgeneric area (shape))

(defclass circle () ((radius :initarg :radius :reader radius)))
(defclass rect   () ((width :initarg :width :reader width)
                     (height :initarg :height :reader height)))

(defmethod area ((s circle)) (* pi (radius s) (radius s)))
(defmethod area ((s rect))   (* (width s) (height s)))
```

Macros operate on code represented as ordinary list data before evaluation, which lets programs generate and transform code. The condition system generalizes exceptions: handlers can inspect a condition and restart the computation at a chosen recovery point rather than only unwinding the stack.

## Toolchain and ecosystem

- Implementation and REPL: SBCL and others provide an interactive top level; editor integration is usually through [SLIME](https://github.com/slime/slime) or [SLY](https://github.com/joaotavora/sly) in Emacs.
- Package manager: [Quicklisp](https://www.quicklisp.org/) installs libraries from a curated distribution.
- System definition: [ASDF](https://asdf.common-lisp.dev/) describes systems, their components, and dependencies.
- Project scaffolding and scripts: tools such as [Roswell](https://github.com/roswell/roswell) manage implementations and run Lisp scripts.

```bash
# With Roswell installed
ros install sbcl
ros run
# In the REPL:
# (ql:quickload "alexandria")
```

## Syntax tour

```lisp
;; Everything is an s-expression: (operator operand ...)
(defun insert (x tree)
  (if (null tree)
      (list nil x nil)
      (destructuring-bind (left value right) tree
        (cond ((< x value) (list (insert x left) value right))
              ((> x value) (list left value (insert x right)))
              (t tree)))))

(defun to-list (tree)
  (when tree
    (destructuring-bind (left value right) tree
      (append (to-list left) (list value) (to-list right)))))

;; Higher-order functions and the loop macro
(defun sum-of-squares (xs)
  (reduce #'+ (mapcar (lambda (n) (* n n)) xs)))

(let ((tree (reduce (lambda (acc x) (insert x acc))
                    '(5 3 8 1 4) :initial-value nil)))
  (format t "~a~%" (to-list tree)))  ; (1 3 4 5 8)
```

## Idioms and different approaches

- Build abstractions with macros when a pattern recurs in code structure, not just in values; otherwise use functions, which are simpler to reason about.
- Use CLOS generic functions and multiple dispatch to organize behavior by the types of several arguments, rather than type tests inside one function.
- Handle errors with the condition system and restarts so that a caller higher up can choose a recovery strategy without the lower code unwinding first.
- Develop interactively: redefine functions in the running image and test them at the REPL, then save the result to source.

## Design principles

Common Lisp was designed for programmability and longevity: the language can be extended through macros and CLOS so that libraries add constructs that feel built in, and the standard is deliberately stable so that code keeps working. Homoiconicity, where code and data share the list representation, is the basis of its metaprogramming. The condition system reflects a design goal of recoverable, interactive error handling rather than only termination.

## Standard library and notable packages

The standard specifies a large built-in library: sequences, hash tables, the `format` directive language for output, the `loop` iteration macro, CLOS, and the condition system. Because the standard predates modern needs, libraries fill the gaps: [Alexandria](https://alexandria.common-lisp.dev/) for general utilities, [Bordeaux-Threads](https://github.com/sionescu/bordeaux-threads) for portable threading, [cl-ppcre](https://edicl.github.io/cl-ppcre/) for regular expressions, [Hunchentoot](https://edicl.github.io/hunchentoot/) for web serving, and [Jsown](https://github.com/madnificent/jsown) or similar for JSON.

## Testing and packaging

[FiveAM](https://github.com/lispci/fiveam) is a common test framework; implementations and ASDF run the suites.

```lisp
(fiveam:test addition
  (fiveam:is (= 5 (+ 2 3))))
```

A library is defined as an ASDF system in an `.asd` file that lists components and dependencies; it is distributed through Quicklisp or installed directly from source with ASDF.

## Performance and concurrency

SBCL compiles to native code and, with type declarations and optimization settings, produces fast numeric and general code; the compiler uses declarations to avoid run-time type dispatch. The ANSI standard does not define threads, so concurrency is implementation-specific and usually accessed through the portable Bordeaux-Threads library over the implementation's native threads. Shared mutable state across threads needs explicit locks or atomic operations, since the language provides no automatic isolation. For parallel numeric work, declared types and specialized arrays reduce boxing and let the compiler emit tight loops.

## Common pitfalls

- The reader evaluates `#.` read-time expressions when `*read-eval*` is true, so reading untrusted text can execute code (see Secure coding below).
- Dynamic (special) variables declared with `defvar` or `defparameter` have dynamic extent; rebinding them with `let` affects called code, which surprises those expecting lexical scope.
- `nil` is both the empty list and false, so a function that can legitimately return an empty list needs care to distinguish "no result" from "empty result".
- Macro hygiene is manual: capture of variable names is possible, so generate fresh symbols with `gensym` for macro-introduced bindings.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Read-time code execution: the Lisp reader evaluates `#.` expressions when `*read-eval*` is non-nil, so calling `read` on attacker-controlled input can execute arbitrary code. Bind `*read-eval*` to `nil` before reading untrusted data, and prefer a dedicated parser for the data format instead of the Lisp reader. This maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html) and, for reconstructing arbitrary objects, [CWE-502](https://cwe.mitre.org/data/definitions/502.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Dynamic evaluation: `eval` and `compile` on runtime-constructed forms built from untrusted input are a code-injection vector; avoid building code from external data.
- Input validation at the boundary: dynamic typing means external data is unchecked until you check it; validate structure and ranges explicitly, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Resource exhaustion: recursion or allocation sized by untrusted input can exhaust the heap or control stack; bound input sizes to address [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- Dependency supply chain: pin to a specific Quicklisp distribution date and review libraries, since many are community-maintained; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: SBCL's compiler performs extensive static type inference and emits style and type warnings that catch many errors at compile time; [sblint](https://github.com/cxxxr/sblint) wraps those diagnostics for editor and batch use. Treat compiler warnings as signals to fix rather than noise.

## Learning resources

- [Common Lisp HyperSpec](https://www.lispworks.com/documentation/HyperSpec/Front/), the hyperlinked ANSI standard.
- [Practical Common Lisp](https://gigamonkeys.com/book/), a free applied introduction by Peter Seibel.
- [Common Lisp Cookbook](https://lispcookbook.github.io/cl-cookbook/), task-oriented recipes.

## Related pages

- [Scheme](/languages/scheme.md)
- [Racket](/languages/racket.md)
- [Haskell](/languages/haskell.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
