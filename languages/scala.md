# Scala

Scala is a statically typed language that combines object-oriented and functional programming, created by Martin Odersky and first released in 2004. It runs primarily on the Java Virtual Machine and interoperates with Java, and a separate backend (Scala.js) targets JavaScript. It is used for data engineering, distributed systems, and server-side back ends, and it is the implementation language of Apache Spark and Apache Kafka tooling.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented and functional, unified |
| Typing | Static, strong, with type inference and a rich type system |
| First appeared | 2004 |
| Memory model | Garbage collected on the JVM |
| Reference implementation | [Scala compiler](https://github.com/scala/scala3) |
| Typical uses | Data engineering, distributed systems, back ends |
| Governance | [Scala Center](https://scala.epfl.ch/) and the SIP process |

Related: [Java](/languages/java.md), [Kotlin](/languages/kotlin.md), [Clojure](/languages/clojure.md).

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who write or maintain Scala code, and the reviewers and security engineers who assess it

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,289 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are writing or reviewing Scala code (typical uses: data engineering, distributed systems, back ends), you need its common pitfalls and secure-coding rules before a review, or you are choosing its toolchain, tests and packages

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Syntax tour](#syntax-tour), [Common pitfalls](#common-pitfalls), [Secure coding](#secure-coding)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Java](/languages/java.md), [Kotlin](/languages/kotlin.md), [Clojure](/languages/clojure.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Martin Odersky designed Scala at EPFL to unify object-oriented and functional programming on the JVM, releasing it publicly in 2004. The 2.x line matured the language over more than a decade. Scala 3, released in 2021 and built on the Dotty research compiler, revised the syntax (optional braces, a new metaprogramming model) and reworked implicits into explicit `given` and `using` clauses. Language changes follow the Scala Improvement Process (SIP), and the [Scala Center](https://scala.epfl.ch/) at EPFL coordinates community work.

Scala compiles to JVM bytecode and interoperates with Java libraries. [Scala.js](https://www.scala-js.org/) compiles to JavaScript, and [Scala Native](https://scala-native.org/) compiles to native code through LLVM.

## Paradigm and type system

Scala treats everything as an object, including functions, and its type system supports generics, higher-kinded types, variance annotations, path-dependent types, and implicit parameters. Type inference reduces annotation noise while keeping static checking. Functional features include immutable collections by default, pattern matching, algebraic data types through sealed hierarchies, and first-class functions.

```scala
def total(prices: List[Double], tax: Double = 0.0): Double =
  prices.sum * (1 + tax)

enum Shape:
  case Circle(radius: Double)
  case Square(side: Double)
```

Case classes are immutable value types with generated equality and a `copy` method. The `given` and `using` mechanism (Scala 3) passes context parameters implicitly, which libraries use for type classes.

## Toolchain and ecosystem

- Compiler: `scalac` compiles source to bytecode; `scala` runs it.
- Build and dependencies: [sbt](https://www.scala-sbt.org/) is the common build tool, with [Mill](https://mill-build.org/) as an alternative; dependencies resolve from [Maven Central](https://central.sonatype.com/).
- Formatting and linting: [scalafmt](https://scalameta.org/scalafmt/) formats code and [scalafix](https://scalacenter.github.io/scalafix/) applies rewrites and lints.

```bash
sbt new scala/scala3.g8
sbt compile
sbt run
```

## Syntax tour

```scala
@main def tour(): Unit =
  // Variables and string interpolation
  val name = "world"
  println(s"hello, $name")

  // Collections and functional transforms
  val squares = (0 until 5).map(n => n * n).toList
  val lookup = Map("a" -> 1, "b" -> 2)

  // Pattern matching
  val label = squares.length match
    case 0 => "empty"
    case n if n < 10 => "short"
    case _ => "long"
  println(label)

// Case class and sealed trait
case class Point(x: Int, y: Int)

sealed trait Animal
case object Cat extends Animal
case object Dog extends Animal
```

## Idioms and different approaches

- Prefer immutable `val` bindings and immutable collections; reach for `var` and mutable collections only in hot local loops.
- Model data with case classes and sealed hierarchies, then branch with exhaustive pattern matching.
- Represent absence with `Option`, failure with `Either` or `Try`, rather than `null` or exceptions.
- Use for-comprehensions to sequence `Option`, `Either`, `Future`, and other monadic types.
- Define behavior with type classes and `given` instances when it should extend to types you do not own.

## Design principles

Scala's premise is that object-oriented and functional programming are complementary, not competing, and that a small set of orthogonal features composes into expressive libraries. The language pushes much capability into libraries rather than keywords, which is why its collection and effect libraries are central to how it is written. Scala 3 made the type system more principled and reduced the surprises of Scala 2 implicits.

## Standard library and notable libraries

The standard library provides immutable and mutable collections, `Option`, `Either`, `Try`, and `Future` for asynchronous results. Notable libraries include [Apache Spark](https://spark.apache.org/) for distributed data processing, [Akka](https://akka.io/) and [Pekko](https://pekko.apache.org/) for actor-based concurrency, [Cats](https://typelevel.org/cats/) and [Cats Effect](https://typelevel.org/cats-effect/) for functional abstractions and effects, and [ZIO](https://zio.dev/) as an alternative effect system.

## Testing and packaging

[ScalaTest](https://www.scalatest.org/) and [MUnit](https://scalameta.org/munit/) are common test frameworks, and [ScalaCheck](https://scalacheck.org/) adds property-based testing.

```scala
import org.scalatest.funsuite.AnyFunSuite

class CalculatorSuite extends AnyFunSuite:
  test("adds two numbers"):
    assert(2 + 3 == 5)
```

Libraries package as JAR files published to Maven Central; `sbt assembly` builds a fat JAR, and `sbt-native-packager` produces distributable archives and container images.

## Performance and concurrency

On the JVM, Scala benefits from the just-in-time compiler and garbage collectors, so performance is close to Java once warm. Immutable data and higher-order functions can add allocation, which the compiler and libraries mitigate with specialization and view-based transforms. Concurrency has several models:

- `Future` with an `ExecutionContext` for simple asynchronous composition.
- The actor model through Akka or Pekko for stateful concurrent components with message passing.
- Effect systems (Cats Effect, ZIO) that represent concurrency as values and provide fibers, which are lightweight and cancelable.

## Common pitfalls

- Implicit resolution (Scala 2) and `given` instances can make it hard to see which instance is used; keep them few and well-named.
- Non-exhaustive pattern matches on non-sealed types compile but can fail at run time; seal hierarchies so the compiler checks coverage.
- Mixing blocking calls into a `Future` or effect runtime starves the thread pool; use a dedicated blocking dispatcher.
- Overusing operator-symbol method names makes code hard to read for newcomers.
- The large feature set invites inconsistent styles across a team; agree on a subset.

## Security relevance

Scala reaches security practitioners mainly as a data-engineering and back-end language that defenders assess rather than as a source of offensive tooling. Because it compiles to JVM bytecode and runs alongside Java, it inherits the JVM's weakness classes and its libraries. The defensive patterns that counter each class are in the Secure coding section that follows; this section is the threat-facing context.

### Where it appears

- Data platforms. [Apache Spark](https://spark.apache.org/) and much of the tooling around [Apache Kafka](https://kafka.apache.org/) are written in Scala, so pipelines that ingest and transform untrusted records are often Scala jobs. These pipelines frequently back security analytics and log processing, which makes their input handling security-relevant.
- Server-side back ends. Web services built on Play, [Akka](https://akka.io/) HTTP, http4s, and similar stacks are assessment targets. See [Web Application Pentesting](/WEB_APPLICATION_PENTESTING.md) and the [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Build and dependency definitions. An `sbt` build runs arbitrary Scala and pulls artifacts from Maven Central, so build files and their resolved dependencies are part of the attack surface. See the [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

### Dominant weakness classes

Scala runs on a garbage-collected virtual machine, so the memory-corruption classes that dominate C and C++ do not apply. The weaknesses that remain come from the JVM libraries and from how untrusted input is handled:

- Insecure deserialization. JVM `ObjectInputStream` and some pickling libraries reconstruct arbitrary objects from a byte stream, reaching code execution through gadget chains. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection. String interpolation that builds query fragments rather than binding parameters lets input change a query's meaning, even behind libraries such as Doobie or Slick. This is [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- XML external entities. JVM XML parsers resolve external entities by default unless disabled, exposing file reads and server-side request forgery. This is [CWE-611](https://cwe.mitre.org/data/definitions/611.html).
- Command injection. Passing a shell string rather than an argument sequence to `ProcessBuilder` lets input reach the shell. This is [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

### Why it matters

Reading Scala lets an analyst review a Spark job or a back-end service for the weakness classes above, and audit an `sbt` build for untrusted plugins and dependencies. There is no Scala-specific scanner equivalent to the Rails analyzers, so review leans on general tools: [Semgrep](https://semgrep.dev/) has Scala rules, [scalafix](https://scalacenter.github.io/scalafix/) can enforce project-specific checks, and [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) flags vulnerable dependencies, as the Secure coding section details.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Deserialization: JVM `ObjectInputStream` and some pickling libraries reconstruct arbitrary objects. Prefer a schema-based format such as JSON or Protocol Buffers for untrusted data, which addresses [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: use parameterized queries through a library such as Doobie or Slick, not string interpolation into SQL, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- XML external entities: configure JVM XML parsers to disable external entity resolution to avoid [CWE-611](https://cwe.mitre.org/data/definitions/611.html).
- Command injection: pass arguments as a sequence to `ProcessBuilder` rather than a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Dependency supply chain: pin and scan sbt dependencies; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [scalafix](https://scalacenter.github.io/scalafix/) can enforce custom rules, and [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) scans dependencies. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Scala documentation](https://docs.scala-lang.org/) and the [tour of Scala](https://docs.scala-lang.org/tour/tour-of-scala.html), the primary sources.
- [Scala 3 Book](https://docs.scala-lang.org/scala3/book/introduction.html) for a current introduction.
- [Typelevel](https://typelevel.org/) documentation for the functional ecosystem.

## Related pages

- [Java](/languages/java.md)
- [Kotlin](/languages/kotlin.md)
- [Clojure](/languages/clojure.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
