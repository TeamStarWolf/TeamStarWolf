# Generic Programming

Generic programming writes algorithms and data structures over types that are supplied later. It is a declarative style layered on top of imperative or functional code: you state requirements on a type, not a concrete type. It matters because one correct implementation can serve many types with no run-time dispatch cost and full type checking.

## Core idea

A generic component is parameterized by one or more types. The code names type parameters such as `T` and operates on values of those types through a stated set of operations. The compiler instantiates the component for each concrete type that a caller supplies.

This is parametric polymorphism: the same definition works uniformly across types. It differs from subtype polymorphism, where behavior is selected by a value's run-time class. Generic code fixes the shape of the computation once and varies only the types it ranges over.

The design discipline is to find the weakest requirements an algorithm needs. Stepanov framed this as lifting a concrete algorithm to its most general correct form. The requirements become a named concept, and any type that meets them can be used.

## How it works

A type parameter is introduced in a declaration and used in the body. In C++ a template is a compile-time pattern. The compiler generates one specialized function or class per set of type arguments, a process called monomorphization.

```cpp
template <typename T>
const T& max_of(const T& a, const T& b) {
    return a < b ? b : a;
}
// usable as max_of(3, 7) or max_of(std::string("a"), std::string("b"))
```

The requirement here is that `T` supports `operator<`. C++20 concepts let you state such requirements by name, so a violation reports a clear message instead of a deep template error. A concept is a compile-time predicate over types.

Rust generics use trait bounds for the same purpose. A bound says a type parameter must implement a named trait, which supplies the needed operations.

```rust
use std::ops::Add;

fn sum<T: Add<Output = T> + Copy>(xs: &[T], zero: T) -> T {
    let mut acc = zero;
    for &x in xs { acc = acc + x; }
    acc
}
```

Java and C# generics take a different implementation path: type erasure on the JVM, and reified generics on the CLR. Java erases type parameters to their bounds at compile time, so `List<String>` and `List<Integer>` share one class at run time. C# keeps type arguments available at run time and specializes value-type instantiations. Erasure avoids code duplication but loses type arguments to reflection; monomorphization and reification keep them at the cost of generated code size.

The canonical realization of the paradigm is the C++ Standard Template Library. Its three pillars are containers, iterators, and algorithms. Algorithms are written against iterator concepts, not against specific containers, so `std::sort` works on any random-access range. Iterators are the interface that decouples the two, which keeps the number of algorithm-plus-container combinations additive rather than multiplicative.

Bounded polymorphism is the general name for constrained type parameters. Haskell expresses bounds with type classes: a function with a `(Ord a) =>` context ranges over any type with an ordering. Ada expresses genericity with generic packages and subprograms instantiated explicitly. All of these share one aim: state the interface a type must satisfy, then range over every type that satisfies it.

## Strengths and trade-offs

The gain is reuse without loss of type safety or speed. A single generic sort is checked once and specialized per type, so there is no cast and no boxing in the fast paths. Correctness proofs and tests apply to every instantiation that meets the requirements.

The cost shows up in three places. Monomorphization can grow the binary when many instantiations exist, and long compile times follow. Error messages from unconstrained templates are notoriously hard to read, which named concepts and traits fix. Erasure-based systems trade those costs for run-time limits, such as being unable to recover a type argument or create an array of a parameter type.

A subtler trade-off is design effort. Finding the weakest correct requirement for an algorithm is real work. Over-constraining excludes valid types; under-constraining lets invalid types through to confusing failures.

## Languages and tools

C++ templates and the STL are the reference model for the paradigm. See [cpp](/languages/cpp.md).

Rust generics with trait bounds give monomorphized, statically checked polymorphism. See [rust](/languages/rust.md).

Java and C# bring generics to managed runtimes with different erasure and reification choices. See [java](/languages/java.md) and [csharp](/languages/csharp.md).

Ada offers explicit generic units with strong instantiation checking. See [ada](/languages/ada.md).

Haskell models bounded polymorphism through type classes rather than templates. See [haskell](/languages/haskell.md).

## Secure-coding considerations

Generic code hides where values cross trust boundaries, so validation can be skipped by accident. A generic container or parser does not know whether a `T` came from a trusted caller or from attacker input. Validate at each instantiation site that handles untrusted data rather than assuming the generic layer did it.

Unconstrained type parameters can admit types that break an invariant the algorithm assumed, for example an ordering that is not a strict weak order. A comparator that violates its contract can drive a generic sort out of bounds. State the requirement precisely with a concept, trait bound, or type class, and reject types that do not meet it.

Numeric generic code is a frequent source of CWE-190 (Integer Overflow or Wraparound) because the same arithmetic runs on types of different width. Check that accumulation and indexing stay in range for every instantiated type. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) for validation and arithmetic-safety guidance.

## Resources

- Alexander Stepanov and Paul McJones, *Elements of Programming*, 2009, Addison-Wesley
- David R. Musser and Alexander A. Stepanov, *Generic Programming*, 1988, ISSAC
- Matthew H. Austern, *Generic Programming and the STL*, 1998, Addison-Wesley
- Bjarne Stroustrup, *The C++ Programming Language*, 2013, Addison-Wesley

## Related pages

- [Programming paradigms](/paradigms/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Object-oriented programming](/paradigms/object-oriented.md)
- [Functional programming](/paradigms/functional.md)
- [Metaprogramming](/paradigms/metaprogramming.md)
- [Procedural programming](/paradigms/procedural.md)
