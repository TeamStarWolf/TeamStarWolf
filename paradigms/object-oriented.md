# Object-Oriented Programming

Object-oriented programming (OOP) organizes a program as a set of objects that hold data and the procedures that act on it, and that interact by calling one another. It is an imperative paradigm: objects carry mutable state and methods change it in order. The set of features that define OOP is debated, so whether a language is object-oriented, and how fully, is a matter of degree rather than a yes or no.

## Core idea

The unit of structure is the object: a bundle of state (fields) and behavior (methods) that presents an interface and hides its internals. A program is modeled as objects that send each other messages, so the design question becomes which objects exist, what each is responsible for, and how they collaborate. This groups related data and code together and lets calling code depend on what an object does rather than how it does it.

The mental model is responsibility. A well-designed object owns a small, coherent piece of the problem, enforces its own invariants, and exposes only what callers need. Most object languages are class-based, where a class is a template and objects are its instances, but the idea does not require classes: prototype-based languages share behavior by linking objects to other objects.

## How it works

Four concepts appear in almost every definition of OOP, with message passing and abstraction close behind.

Encapsulation keeps an object's data and the methods that maintain it together, and hides internal detail behind access control such as `private` and `public`. The object protects its invariants because outside code cannot reach past the interface. Some languages enforce access; Python relies on naming conventions such as a leading underscore.

Inheritance lets a subclass take the fields and methods of a superclass, add its own, and override inherited behavior. It models an is-a relationship and shares code, and some languages extend it with multiple inheritance, mixins, or traits.

Polymorphism lets one interface work with objects of different classes, so calling code does not branch on the concrete type. The common form is subtype polymorphism, resolved by dynamic dispatch: the object's actual class decides which method runs, chosen at run time.

Abstraction exposes what a type does and hides how. An abstract class names behavior without providing all of it and cannot be instantiated; an interface declares a contract that many classes implement.

```python
from abc import ABC, abstractmethod

class Account(ABC):
    def __init__(self, balance=0):
        self._balance = balance          # encapsulated state

    def deposit(self, amount):
        if amount <= 0:
            raise ValueError("amount must be positive")
        self._balance += amount

    @property
    def balance(self):
        return self._balance

    @abstractmethod
    def accrue(self):                    # subclasses must define this
        ...

class SavingsAccount(Account):           # inheritance
    def __init__(self, balance=0, rate=0.01):
        super().__init__(balance)
        self._rate = rate

    def accrue(self):                    # overrides the abstract method
        self.deposit(self._balance * self._rate)

def end_of_month(accounts):              # polymorphism: any Account works
    for account in accounts:
        account.accrue()
```

A method call is often described as a message sent to an object: the method name and arguments form the message, and the object decides how to respond. Dynamic dispatch selects the method at run time, and some languages add multiple dispatch, which selects based on the types of several arguments. Open recursion lets a method call another method on the same object through `self` or `this`, including one a subclass redefines, which is late binding.

Class-based and prototype-based styles differ in where behavior lives. In class-based OOP a class is the blueprint and objects are its instances. In prototype-based OOP there are no classes: an object links to a prototype that serves as the model, and new objects reuse behavior by delegation. JavaScript gives each object one prototype link ending at a base object whose prototype is `null`; in Self an object may have several prototypes or none.

## Strengths and trade-offs

OOP organizes large systems by giving each concept a home and a boundary, which helps teams divide work and reason about one object at a time. Encapsulation protects invariants, polymorphism lets new types slot into existing code without changing it, and the model maps well to domains with stable nouns such as accounts, orders, and documents.

The costs are real. Deep inheritance hierarchies are hard to change and do not guarantee that a subclass can safely replace its parent. Mutable object graphs are hard to reason about under concurrency. Spreading behavior across many small objects can obscure control flow, and modeling everything as an object can complicate problems that are really about algorithms and data. OOP suits the stable structure of a system; it is not the only tool, and mixing it with functional and procedural code is normal.

## Design principles

The SOLID principles are the common guidance for class design:

- Single responsibility: a class has one reason to change.
- Open-closed: a class is open for extension but closed for modification.
- Liskov substitution: an object of a subclass can stand in wherever its superclass is expected, without breaking callers.
- Interface segregation: a client does not depend on an interface it does not use.
- Dependency inversion: depend on abstractions, not on concrete implementations.

A second rule is to prefer composition over inheritance. Composition builds an object from other objects (an `Employee` has an `Address`), expresses a has-a relationship, and keeps control over what is exposed. Deep inheritance is the source of the fragile-base-class and circle-ellipse problems, which the Liskov principle addresses. Some languages, such as Go, omit inheritance and rely on composition and interfaces. The Gang of Four design patterns catalog recurring object designs such as Strategy, Observer, and Factory.

## Criticisms

OOP is the default in much enterprise software and is also heavily criticized. Inheritance does not guarantee behavioral subtyping, so a subclass can compile and still break callers, especially with mutable objects. Information hiding can push toward duplicated code, working against the do-not-repeat-yourself rule. Several practitioners argue OOP overemphasizes objects over algorithms and data, encourages thickly layered designs, and makes instruction flow harder to follow in concurrent code. Knowing these limits is part of choosing OOP deliberately rather than by default.

## Languages and tools

Simula introduced classes and [Smalltalk](/languages/smalltalk.md) made message passing central. The style is core to [C++](/languages/cpp.md), [Java](/languages/java.md), [C#](/languages/csharp.md), [Python](/languages/python.md), [Ruby](/languages/ruby.md), [Eiffel](/languages/eiffel.md), [Objective-C](/languages/objective-c.md), [Swift](/languages/swift.md), [Kotlin](/languages/kotlin.md), and [Scala](/languages/scala.md). JavaScript is prototype-based. Older languages such as Ada, Fortran, Pascal, and COBOL were later extended with object features. Tooling is mature: refactoring support in IDEs, test frameworks built around objects and mocks, and the design-pattern vocabulary for communicating structure.

## Secure-coding considerations

Rebuilding object graphs from untrusted input is the deserialization risk: untrusted data turned into live objects can run attacker-chosen code or corrupt state (CWE-502). Never deserialize untrusted data without a strict allowlist of types, and prefer data formats that do not carry type information. Encapsulation is a security boundary only if it holds: exposing mutable internal state through a getter that returns the live object (rather than a copy) lets callers bypass an object's invariants. Inheritance can widen access unexpectedly when a subclass overrides a method and relaxes its checks, so validate in the base contract, not only in subclasses. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) for input validation, object lifecycle, and injection defenses.

## Resources

- Erich Gamma, Richard Helm, Ralph Johnson, and John Vlissides, *Design Patterns: Elements of Reusable Object-Oriented Software*, 1994, Addison-Wesley
- Bertrand Meyer, *Object-Oriented Software Construction*, 1997, Prentice Hall
- Grady Booch, *Object-Oriented Analysis and Design with Applications*, 1994, Benjamin/Cummings
- Barbara Liskov and Jeannette Wing, *A Behavioral Notion of Subtyping*, 1994, ACM Transactions on Programming Languages and Systems
- Alan Kay, *The Early History of Smalltalk*, 1993, ACM HOPL-II
- Martin Fowler, *Refactoring: Improving the Design of Existing Code*, 2018, Addison-Wesley
- Robert C. Martin, *Clean Architecture: A Craftsman's Guide to Software Structure and Design*, 2017, Prentice Hall
- Sandi Metz, *Practical Object-Oriented Design in Ruby*, 2012, Addison-Wesley

## Related pages

- [Programming paradigms](/paradigms/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Imperative programming](/paradigms/imperative.md)
- [Generic programming](/paradigms/generic.md)
- [Functional programming](/paradigms/functional.md)
- [Data-oriented design](/paradigms/data-oriented.md)
