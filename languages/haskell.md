# Haskell

Haskell is a statically typed, purely functional, lazily evaluated language first standardized in 1990 and named after the logician Haskell Curry. It separates pure computation from side effects through its type system, infers most types without annotations, and evaluates expressions only when their results are demanded. It is used for compilers, static analysis, financial systems, and research into type systems and language design.

| Attribute | Value |
|---|---|
| Paradigm | Purely functional, declarative, non-strict |
| Typing | Static, strong, inferred (Hindley-Milner with type-class and extension-based elaboration) |
| First appeared | 1990 (Haskell 2010 is the current report) |
| Memory model | Automatic: generational, copying garbage collection |
| Reference implementation | [GHC, the Glasgow Haskell Compiler](https://www.haskell.org/ghc/) |
| Typical uses | Compilers, static analysis, financial systems, backend services, research |
| Governance | [Haskell Language Report](https://www.haskell.org/onlinereport/haskell2010/); GHC steering committee |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [OCaml](/languages/ocaml.md), [languages index](/languages/README.md).

## Overview and history

Haskell began as a committee effort in the late 1980s to unify several competing non-strict functional languages into a single standard. The first report appeared in 1990; later revisions led to Haskell 98 and then [Haskell 2010](https://www.haskell.org/onlinereport/haskell2010/), the current language report. In practice the language that people write is GHC Haskell, which adds many extensions beyond the report through `LANGUAGE` pragmas.

The dominant implementation is the Glasgow Haskell Compiler (GHC), which compiles to native code through an intermediate Core language and a runtime system that supports lightweight threads and parallel garbage collection. Day-to-day development usually goes through the [GHCup](https://www.haskell.org/ghcup/) installer, which manages GHC, the build tools, and the language server.

## Paradigm and type system

Haskell is purely functional: a function of the same arguments returns the same result, and effects such as input, output, or mutation are represented as values of type `IO a` rather than performed as a side effect of evaluation. Evaluation is non-strict (lazy) by default, so an expression is reduced only when its value is needed, which makes infinite data structures and some control constructs expressible as ordinary values.

The type system is based on Hindley-Milner inference extended with type classes, which provide bounded polymorphism (ad hoc overloading constrained by an interface). Most code needs no type annotations, though top-level signatures are conventional for documentation and to pin down inferred types.

```haskell
-- A type class and an instance
class Describable a where
  describe :: a -> String

data Shape = Circle Double | Rect Double Double

instance Describable Shape where
  describe (Circle r)   = "circle of radius " ++ show r
  describe (Rect w h)   = "rectangle " ++ show w ++ " by " ++ show h
```

Algebraic data types, pattern matching, and parametric polymorphism are built in. Effects are sequenced with `do` notation over monads, which keeps the pure core separate from `IO`.

## Toolchain and ecosystem

- Compiler: `ghc` compiles modules; `ghci` is the interactive read-eval-print loop.
- Build tools: [Cabal](https://www.haskell.org/cabal/) builds packages from a `.cabal` file, and [Stack](https://docs.haskellstack.org/) layers reproducible, snapshot-based builds on top of it.
- Packages publish to [Hackage](https://hackage.haskell.org/); [Stackage](https://www.stackage.org/) curates version sets that build together.
- Editor support comes from the [Haskell Language Server](https://github.com/haskell/haskell-language-server).
- Formatting and linting: [fourmolu](https://github.com/fourmolu/fourmolu) or `ormolu` format code; [HLint](https://github.com/ndmitchell/hlint) suggests simplifications.

```bash
ghcup install ghc recommended
cabal init
cabal build
cabal run
```

## Syntax tour

```haskell
module Main where

import Data.List (sort)

-- Algebraic data type with a type parameter
data Tree a = Leaf | Node (Tree a) a (Tree a)

-- Insert into a binary search tree
insert :: Ord a => a -> Tree a -> Tree a
insert x Leaf = Node Leaf x Leaf
insert x t@(Node l v r)
  | x < v     = Node (insert x l) v r
  | x > v     = Node l v (insert x r)
  | otherwise = t

-- In-order traversal
toList :: Tree a -> [a]
toList Leaf         = []
toList (Node l v r) = toList l ++ [v] ++ toList r

-- Lazy, infinite list; only as much is computed as is consumed
naturals :: [Integer]
naturals = [0 ..]

main :: IO ()
main = do
  let t = foldr insert Leaf [5, 3, 8, 1, 4 :: Int]
  print (toList t)         -- [1,3,4,5,8]
  print (take 5 naturals)  -- [0,1,2,3,4]
```

## Idioms and different approaches

- Prefer total functions and explicit types such as `Maybe a` and `Either e a` over partial functions that can fail at run time; reserve `head` and `fromJust` for cases you have already proven safe.
- Build pipelines with higher-order functions (`map`, `filter`, `foldr`) and function composition (`.`) rather than explicit recursion where a combinator reads more clearly.
- Model effects with the appropriate abstraction: `Maybe` and `Either` for failure, `State` for threaded state, and `IO` at the program edges. Larger programs often use monad transformers or an effect system.
- Keep laziness deliberate: use strict folds (`foldl'`) and strictness annotations (`!`) in accumulators to avoid building large unevaluated thunks.

## Design principles

Haskell's design favors purity, strong static types, and lazy evaluation as defaults rather than opt-ins. Purity makes equational reasoning possible: you can substitute equals for equals without changing behavior. The type system is meant to make a wide class of errors unrepresentable, so that a program that type-checks has ruled out many failure modes before it runs. These choices are documented in the language report and in the research literature that the language grew out of.

## Standard library and notable packages

The `base` package ships the `Prelude` and core modules for lists, `Data.Map`, `Data.Text`, and `Control.Monad`. Widely used packages on Hackage include [text](https://hackage.haskell.org/package/text) and [bytestring](https://hackage.haskell.org/package/bytestring) for efficient string and binary data, [containers](https://hackage.haskell.org/package/containers) and [unordered-containers](https://hackage.haskell.org/package/unordered-containers) for data structures, [aeson](https://hackage.haskell.org/package/aeson) for JSON, and [servant](https://hackage.haskell.org/package/servant) for typed web APIs.

## Testing and packaging

[HSpec](https://hspec.github.io/) and [tasty](https://hackage.haskell.org/package/tasty) organize test suites; [QuickCheck](https://hackage.haskell.org/package/QuickCheck) generates random inputs to check properties rather than fixed examples.

```haskell
import Test.QuickCheck

prop_reverseTwice :: [Int] -> Bool
prop_reverseTwice xs = reverse (reverse xs) == xs

main :: IO ()
main = quickCheck prop_reverseTwice
```

A package declares its modules and dependencies in a `.cabal` file and builds with `cabal build`; publishing uploads a source distribution to Hackage with `cabal upload`.

## Performance and concurrency

GHC compiles to native code and the runtime schedules large numbers of lightweight green threads over a smaller pool of operating-system threads. Concurrency primitives include `forkIO`, `MVar` for shared mutable cells, and software transactional memory (`STM`) for composable atomic transactions. Pure parallelism is available through the `par` and `pseq` combinators and the `Control.Parallel.Strategies` library, which let independent computations run in parallel without changing results.

Laziness has a performance cost when unevaluated thunks accumulate (a space leak); strict data fields, `foldl'`, and the `BangPatterns` extension keep memory predictable. For hot numeric code, unboxed types and the `vector` package avoid boxing overhead.

## Common pitfalls

- Space leaks from lazy accumulation: a left fold with a lazy accumulator can retain the whole input; use `foldl'` and force intermediate results.
- Partial functions: `head`, `tail`, and `fromJust` throw on empty or `Nothing` inputs; prefer pattern matching or safe variants.
- `String` is a linked list of characters and is slow for large text; use `Data.Text` instead.
- Confusing `IO` with evaluation: binding an `IO` action in `do` runs it, but building the action value does not; order of effects follows the binds, not textual position.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Input validation at the boundary: the type system does not validate the content of external data such as request bodies or file contents, only its shape after parsing. Parse untrusted input into precise types and reject malformed values early, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Unsafe deserialization: a `Read` instance or a generic binary decoder applied to attacker-controlled bytes can construct unexpected values or fail abruptly; validate and bound decoded data, and prefer schema-checked formats. This relates to [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- Resource exhaustion from laziness: an unbounded lazy structure or a growing thunk chain built from untrusted input can exhaust memory; apply strictness and size limits, which addresses [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- Escaping the type system: `unsafePerformIO`, `unsafeCoerce`, and foreign imports bypass the guarantees the compiler otherwise provides; confine them to reviewed, well-documented modules.
- Dependency supply chain: pin package versions and use curated Stackage snapshots or a frozen Cabal plan; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [HLint](https://github.com/ndmitchell/hlint) flags suspect patterns and simplifications, and [Stan](https://github.com/kowainik/stan) is a static analyzer that reports anti-patterns and partiality. Treat compiler warnings as errors with `-Wall` to catch non-exhaustive patterns.

## Learning resources

- [Haskell 2010 Language Report](https://www.haskell.org/onlinereport/haskell2010/), the language definition.
- Learn You a Haskell for Great Good, an introductory tutorial.
- [GHC User's Guide](https://downloads.haskell.org/ghc/latest/docs/users_guide/), reference for the compiler and its extensions.

## Related pages

- [OCaml](/languages/ocaml.md)
- [Standard ML](/languages/standard-ml.md)
- [Elixir](/languages/elixir.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
