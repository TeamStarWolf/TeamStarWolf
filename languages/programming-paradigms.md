# Programming Paradigms

A programming paradigm is a way of organizing a program: what the units of code are, how they hold state, and how control moves between them. A paradigm is not a language. Most languages support several paradigms, and a paradigm is often defined as much by what it forbids as by what it allows, so pure functional programming is known for disallowing side effects and structured programming for disallowing unrestricted jumps. This page is the concept behind the per-language pages in this section: each language page names the paradigms the language supports, and this page defines them.

This page describes paradigms in general and treats object-oriented programming in depth, since it is the paradigm most enterprise code is written in. For applying any of them safely, see the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md); for the languages themselves, see [All languages](/languages/README.md).

## What a paradigm is, and its limits

The highest-level split is between imperative and declarative code.

- Imperative code states the order of operations and changes state directly. It allows side effects: state changed in one place is read later in another. Procedural and object-oriented programming are imperative.
- Declarative code describes the result rather than the steps, and the execution model chooses the order. Functional, logic, and query languages are declarative. SQL is the archetypal example: a query states what rows are wanted, not how to retrieve them.

The split is a guide, not a rule. Researchers have argued that many languages cannot be placed in one paradigm because they combine features from several, and most working code mixes paradigms without the author thinking in those terms. Classification is usually done after the fact. Treat the paradigm names as a vocabulary for design choices, not as boxes a language sits in.

## Imperative paradigms

### Procedural programming

Code is organized into procedures, also called functions or subroutines, that call one another and operate on shared or passed-in data. It is the oldest widely used organization and still the right one for small tools, systems code, and hot paths. Example languages: C, COBOL, Fortran, ALGOL, BASIC, and PL/I.

```c
int sum_to(int n) {
    int total = 0;
    for (int i = 1; i <= n; i++) {
        total += i;
    }
    return total;
}
```

### Structured programming

Structured programming is a discipline within imperative code rather than a separate model. It builds programs from sequence, selection, and iteration and avoids unrestricted jumps such as `goto`, which produce control flow that is hard to follow and maintain. Nearly every modern imperative language enforces it by default.

## Object-oriented programming

Object-oriented programming (OOP) groups data and the procedures that act on that data into objects, and a program is a set of objects that interact. The set of features that define OOP is contested, so whether a language is object-oriented, and how fully, is a matter of degree. The concepts below are the ones that appear in most definitions. Example languages: Simula and Smalltalk, which began it, and C++, Java, C#, Python, Ruby, Swift, Kotlin, Scala, Eiffel, and JavaScript. Older languages such as Ada, Fortran, Pascal, and COBOL were later extended with object features.

### Core concepts

- Objects and classes. In class-based OOP a class defines the data (fields) and behavior (methods) of a kind of thing, and an object is an instance of a class, built by a constructor.
- Encapsulation and information hiding. Data and the methods that act on it are kept together, and internal detail is hidden behind access controls such as `private` and `public`. Some languages, such as Python, rely on naming conventions rather than enforced access.
- Inheritance. A subclass takes the fields and methods of a superclass, adds its own, and can override inherited methods. Some languages add multiple inheritance, mixins, or traits.
- Polymorphism. One interface works with objects of different classes, so calling code does not need to know the concrete type. Subtype polymorphism is the common form.
- Abstraction. A type exposes what it does and hides how. An abstract class names behavior without providing all of it and cannot itself be instantiated.
- Message passing and dynamic dispatch. A method call is a message to an object; the object's actual class decides which method runs, chosen at run time. Multiple dispatch chooses the method from several argument types.

```python
class Account:
    def __init__(self, balance=0):
        self._balance = balance          # encapsulated state

    def deposit(self, amount):
        self._balance += amount

    def balance(self):
        return self._balance

class SavingsAccount(Account):           # inheritance
    def __init__(self, balance=0, rate=0.01):
        super().__init__(balance)
        self._rate = rate

    def apply_interest(self):            # added behavior
        self.deposit(self.balance() * self._rate)
```

### Class-based and prototype-based OOP

Most object languages are class-based: a class is a blueprint and objects are its instances. Prototype-based languages have no classes. An object is linked to a prototype object that serves as the model for new objects, and behavior is shared by cloning and delegation. In JavaScript each object has one prototype link, ending at a base object whose prototype is null; in Self an object may have several prototypes or none.

### Design principles

The SOLID principles are the common guidance for class design:

- Single responsibility: a class has one reason to change.
- Open-closed: a class is open for extension but closed for modification.
- Liskov substitution: an object of a subclass can stand in wherever its superclass is expected.
- Interface segregation: a client does not depend on an interface it does not use.
- Dependency inversion: depend on abstractions, not on concrete implementations.

A second, widely cited guideline is to prefer composition over inheritance. Composition builds an object out of other objects (an `Employee` has an `Address`), which expresses a has-a relationship and keeps control over what is exposed. Deep inheritance hierarchies are harder to change and do not guarantee that a subclass can safely replace its parent, the problem the Liskov principle addresses. Some languages, such as Go, omit inheritance and rely on composition and interfaces instead.

### Criticisms

OOP is the default in much enterprise software, and it is also heavily criticized, which is worth knowing when choosing it:

- Behavioral subtyping is not guaranteed by inheritance. A subclass can compile and still break callers that rely on the parent's behavior, especially with mutable objects; the circle-ellipse problem is the standard illustration.
- Information hiding can lead to duplicated code, which works against the do-not-repeat-yourself principle.
- Several practitioners argue OOP overemphasizes objects over algorithms and data, encourages thickly layered designs, and makes instruction flow harder to follow in concurrent code. Others note that composition and plain functions cover much of what inheritance was meant to provide.

Treat OOP as one tool. It organizes large systems and large teams well; it is not the only way to model a problem, and mixing it with functional and procedural code is normal.

## Declarative paradigms

### Functional programming

A program is the evaluation of functions that avoid changing state and mutable data. Functions are values that can be passed and returned, and the same input gives the same output, which makes code easier to test and to run in parallel. Example languages: Haskell, and the Lisp and ML families; the style is also idiomatic in Clojure, Elixir, Erlang, F#, and Scala, and supported in most modern languages.

```clojure
(defn sum-to [n]
  (reduce + (range 1 (inc n))))
```

### Logic programming

Computation is automated reasoning over facts and rules; the program states relationships and the engine searches for values that satisfy them. Prolog is the classic example, and Datalog is its database-oriented relative. See [Datalog](/languages/datalog.md).

### Reactive, dataflow, and constraint

- Reactive programming declares results as data streams and propagates changes through them.
- Dataflow programming recalculates values when their inputs change; a spreadsheet is the everyday example.
- Constraint programming states relations between variables as constraints and lets a solver find allowed solutions.

## Concurrency and other paradigms

- Concurrent and actor programming provide language constructs for doing several things at once: threads, message passing, shared memory, futures, or autonomous actors that communicate only by messages (the model behind Erlang and Elixir).
- Event-driven programming structures a program around handlers that run in response to events, common in user interfaces and network servers.
- Generic programming writes algorithms against types supplied later, through templates or generics.
- Metaprogramming writes or transforms programs, at compile time or run time, through templates, macros, or reflection.
- Symbolic programming manipulates formulas and code as data, the tradition of Lisp and Prolog.

## Choosing and mixing paradigms

Most languages in this section are multi-paradigm, and good designs mix styles on purpose: procedural code in a hot loop, functional transformations over collections, objects for the stable nouns of a domain, declarative queries for data. A few languages hold to one paradigm, such as Smalltalk for objects and Haskell for functions, and C++, PHP, and Object Pascal can be written purely procedural, purely object-oriented, or a blend. Pick the paradigm that makes the specific part of the code simplest to read and to change, not the one the whole program is labelled with.

## Paradigms and secure coding

Each paradigm carries its own failure modes, and the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) is where the defenses live.

- Imperative and object-oriented code shares mutable state, so data races and unexpected aliasing are the risks; limit the scope and lifetime of mutable state and guard it under concurrency.
- Object graphs that are rebuilt from untrusted input are the deserialization risk (CWE-502); never deserialize untrusted data into live objects without validation.
- Declarative and query languages move the injection risk to where the query is built: a string-concatenated SQL or logic query is the classic injection flaw (CWE-89); use parameterized queries.
- Functional code reduces shared-state bugs but still has to validate input and handle errors explicitly rather than swallowing them.

## Learning resources

- [Programming paradigm](https://en.wikipedia.org/wiki/Programming_paradigm) gives the full taxonomy and the debate over classification.
- [Object-oriented programming](https://en.wikipedia.org/wiki/Object-oriented_programming) covers the concepts, class-based and prototype-based styles, and the criticisms in depth.
- For applying any paradigm safely, see the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md); for the discipline, see the [Application Security](/disciplines/application-security.md) learning path.

## Related pages

- [All languages](/languages/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [C](/languages/c.md), [C++](/languages/cpp.md), and [C#](/languages/csharp.md) for procedural and object-oriented code
- [Clojure](/languages/clojure.md) and [Common Lisp](/languages/common-lisp.md) for functional and symbolic programming
- [Datalog](/languages/datalog.md) for logic programming
