# Functional Programming

Functional programming builds programs by composing functions and treating computation as the evaluation of expressions. It is a declarative style: you describe what a result is, not a sequence of state mutations to produce it. The discipline matters in real systems because referential transparency makes code easier to test, parallelize, and reason about under concurrency.

## Core idea

The defining idea is that functions are values. A function can be passed as an argument, returned as a result, and stored in a data structure, exactly like an integer or a string. Computation proceeds by applying functions to arguments and composing their results.

The second pillar is purity. A pure function depends only on its arguments and produces only its return value, with no observable side effect. Given the same inputs it always returns the same output. This property, called referential transparency, lets you replace any call with its result without changing meaning.

What distinguishes functional programming from procedural and object-oriented styles is the treatment of state. Procedural code advances by mutating variables over time. Functional code avoids mutation: data is immutable, and "change" means producing a new value from an old one. Control flow is expressed through recursion and higher-order functions rather than loops and assignment.

## How it works

Higher-order functions are functions that take or return other functions. They abstract over patterns of computation. `map`, `filter`, and `fold` (also called `reduce`) replace most explicit loops. Instead of writing the iteration mechanics each time, you pass the per-element behavior as a function.

```haskell
-- Sum the squares of the even numbers in a list.
sumEvenSquares :: [Int] -> Int
sumEvenSquares = sum . map (^2) . filter even

-- sumEvenSquares [1,2,3,4] == 4 + 16 == 20
```

The `.` operator composes functions right to left. The definition names no loop variable and mutates nothing. Each stage is a self-contained transformation, and the pipeline reads as a description of the result.

Closures capture the environment in which a function is defined. A returned function keeps access to the variables that were in scope at its creation. This is how functional code carries context without mutable global state.

```ocaml
(* adder returns a closure over n *)
let adder n = fun x -> x + n
let add5 = adder 5
let result = add5 10   (* 15 *)
```

Algebraic data types model data as a choice between shapes, and pattern matching takes them apart. A sum type lists alternatives; a product type groups fields. Pattern matching is checked for exhaustiveness by the compiler in languages like Haskell and OCaml, so a missing case is a compile error rather than a runtime surprise.

```haskell
data Tree a = Leaf | Node (Tree a) a (Tree a)

depth :: Tree a -> Int
depth Leaf             = 0
depth (Node l _ r)     = 1 + max (depth l) (depth r)
```

Recursion replaces iteration. Because there is no mutable loop counter, repetition is expressed by a function calling itself on a smaller input. Many functional languages guarantee tail-call optimization, so a tail-recursive function runs in constant stack space, like a loop.

Laziness defers evaluation until a value is needed. Haskell is lazy by default, which allows infinite data structures and lets a producer and consumer run in lockstep without an explicit buffer. Laziness decouples how a value is defined from how much of it is used.

Immutability means persistent data structures share structure between versions. Updating a balanced tree produces a new tree that reuses most of the old nodes, so an "update" costs logarithmic time and space, not a full copy. Okasaki's work shows how to make these structures efficient.

Monads provide a disciplined way to sequence computations that carry extra structure, such as possible failure, state, or input and output. A monad defines how to wrap a value and how to chain a function that itself returns a wrapped value. In Haskell, side effects live in the `IO` type, so a function's signature states honestly whether it touches the outside world.

```haskell
lookupUser :: Int -> Maybe User
greet :: Int -> Maybe String
greet uid = do
  user <- lookupUser uid        -- short-circuits on Nothing
  pure ("Hello, " ++ name user)
```

## Strengths and trade-offs

Pure functions are the easiest code to test, because a test is just an input and an expected output with no setup or teardown. Referential transparency also enables aggressive compiler optimization and safe parallelism: expressions with no shared mutable state can run on different cores without locks.

The trade-offs are real. Immutability can cost allocation and cache pressure when a problem is naturally in-place, such as a tight numeric kernel. Laziness makes space usage harder to predict, and a space leak from an unevaluated thunk can be subtle. Heavy use of monad transformers and type-level machinery raises the barrier for new readers, and some algorithms are simply clearer with a mutable array.

## Languages and tools

Statically typed functional languages include [Haskell](/languages/haskell.md), [OCaml](/languages/ocaml.md), [F#](/languages/fsharp.md), [Standard ML](/languages/standard-ml.md), [PureScript](/languages/purescript.md), and [Elm](/languages/elm.md). [Scala](/languages/scala.md) blends functional and object-oriented styles on the JVM.

The Lisp family brings a dynamically typed tradition: [Scheme](/languages/scheme.md), [Racket](/languages/racket.md), and [Clojure](/languages/clojure.md). The BEAM languages [Erlang](/languages/erlang.md) and [Elixir](/languages/elixir.md) use functional cores with immutable data for fault-tolerant concurrency. Mainstream languages such as Java, Python, JavaScript, and Rust have absorbed first-class functions, closures, and immutable collection libraries.

## Secure-coding considerations

Immutability removes a whole class of bugs: shared mutable state cannot be corrupted by another thread or an aliased reference. This directly reduces race conditions, which map to CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization). Pure functions also make input-validation logic easier to audit, because the function cannot smuggle in behavior through hidden state.

Functional code has its own failure modes. Laziness can defer an exception or a resource acquisition to a surprising point, so error handling tied to evaluation order needs care. Partial functions, those that are not defined for every input, raise at runtime when given an unhandled case; prefer total functions and exhaustive pattern matching, and treat a non-exhaustive match warning as an error. Unbounded recursion on attacker-controlled input can exhaust the stack, a denial-of-service risk under CWE-674 (Uncontrolled Recursion).

Explicit effect typing is a security advantage. When `IO` or an equivalent appears in a signature, a reviewer can see exactly which code paths read files, open sockets, or run commands, which narrows the surface to audit for injection. See /SECURE_CODING_REFERENCE.md for input-validation and resource-exhaustion guidance that applies here.

## Resources

- Harold Abelson and Gerald Jay Sussman, *Structure and Interpretation of Computer Programs*, 1996, MIT Press
- John Hughes, *Why Functional Programming Matters*, 1990, The Computer Journal
- Chris Okasaki, *Purely Functional Data Structures*, 1998, Cambridge University Press
- Richard Bird, *Introduction to Functional Programming using Haskell*, 1998, Prentice Hall
- Philip Wadler, *Monads for Functional Programming*, 1992
- Simon Peyton Jones, *The Implementation of Functional Programming Languages*, 1987, Prentice Hall

## Related pages

- /paradigms/README.md
- /SECURE_CODING_REFERENCE.md
- /paradigms/declarative.md
- /paradigms/reactive.md
- /paradigms/logic.md
- /paradigms/object-oriented.md
- /paradigms/concurrent.md
