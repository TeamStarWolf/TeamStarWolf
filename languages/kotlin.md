# Kotlin

Kotlin is a statically typed, multi-paradigm language created by JetBrains and first released in 1.0 form in 2016. It targets the Java Virtual Machine, JavaScript, and native binaries, and it interoperates closely with Java. Google named it a preferred language for Android development in 2019. It is used for Android applications, server-side back ends, and cross-platform mobile code.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented and functional |
| Typing | Static, strong, with null tracking in the type system |
| First appeared | 2011 (1.0 in 2016) |
| Memory model | Garbage collected on the JVM; reference counting plus tracing on Kotlin/Native |
| Reference implementation | [Kotlin compiler](https://github.com/JetBrains/kotlin) |
| Typical uses | Android, server back ends, cross-platform mobile |
| Governance | [JetBrains](https://kotlinlang.org/) with the Kotlin Foundation |

Related: [Java](/languages/java.md), [Scala](/languages/scala.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

JetBrains began Kotlin in 2010 to address pain points its teams hit with Java while keeping full interoperability, and released version 1.0 in 2016. Google announced first-class Android support in 2017 and made Kotlin its preferred Android language in 2019. The language is governed by the Kotlin Foundation, a joint body of JetBrains and Google, and the specification is published as the [Kotlin language specification](https://kotlinlang.org/spec/introduction.html).

Kotlin compiles to several targets. Kotlin/JVM produces Java bytecode, Kotlin/JS emits JavaScript, and Kotlin/Native compiles to standalone binaries through LLVM. Kotlin Multiplatform shares logic across these targets while allowing platform-specific implementations.

## Paradigm and type system

Kotlin is statically typed with type inference, so most local types need no annotation. Its defining feature is null safety: a type is non-nullable by default, and a nullable type is written with a trailing `?`. The compiler forbids dereferencing a nullable value without a check, which removes a large class of null-pointer errors at compile time.

```kotlin
fun total(prices: List<Double>, tax: Double = 0.0): Double =
    prices.sum() * (1 + tax)

val name: String? = null
val length = name?.length ?: 0   // safe call and Elvis operator
```

Data classes generate `equals`, `hashCode`, `toString`, and `copy`. Sealed classes model closed hierarchies that the `when` expression can match exhaustively. Extension functions add methods to existing types without subclassing.

## Toolchain and ecosystem

- Compiler: `kotlinc` compiles source and can produce a runnable JAR or a native binary.
- Build and dependencies: [Gradle](https://gradle.org/) with the Kotlin DSL is the common build tool; dependencies resolve from [Maven Central](https://central.sonatype.com/). Maven is also supported.
- Formatting and linting: ktlint enforces style, and [detekt](https://detekt.dev/) reports code smells and complexity.

```bash
kotlinc hello.kt -include-runtime -d hello.jar
java -jar hello.jar
```

## Syntax tour

```kotlin
// Top-level function and string templates
fun main() {
    val name = "world"
    println("hello, $name")

    // Collections and functional transforms
    val squares = (0 until 5).map { it * it }
    val lookup = mapOf("a" to 1, "b" to 2)

    // Null safety
    val maybe: String? = readLine()
    val length = maybe?.length ?: 0

    // when expression
    val label = when (length) {
        0 -> "empty"
        in 1..10 -> "short"
        else -> "long"
    }
    println(label)
}

// Data class and sealed hierarchy
data class Point(val x: Int, val y: Int)

sealed interface Shape
data class Circle(val radius: Double) : Shape
data class Square(val side: Double) : Shape
```

## Idioms and different approaches

- Use `val` for read-only bindings by default and `var` only when reassignment is needed.
- Model absence with nullable types and the safe-call and Elvis operators rather than sentinel values.
- Prefer expression bodies and `when` expressions over statement blocks where the function returns a value.
- Use extension functions to keep call sites readable instead of utility classes full of static methods.
- Reach for data classes for value types and sealed classes for state machines and result types.

## Design principles

Kotlin's stated goals are conciseness, safety, and interoperability with Java. The language removes repetitive Java patterns (getters and setters, explicit `equals`, verbose anonymous classes) while keeping the same bytecode target, so a project can mix Kotlin and Java files. Null tracking in the type system is the clearest expression of the safety goal.

## Standard library and notable libraries

The standard library provides collection builders and transforms (`map`, `filter`, `fold`), scope functions (`let`, `apply`, `run`, `also`, `with`), sequences for lazy evaluation, and `kotlinx` extension libraries. Notable libraries include [kotlinx.coroutines](https://github.com/Kotlin/kotlinx.coroutines) for asynchronous code, [Ktor](https://ktor.io/) for clients and servers, [kotlinx.serialization](https://github.com/Kotlin/kotlinx.serialization) for data formats, and [Jetpack Compose](https://developer.android.com/jetpack/compose) for Android user interfaces.

## Testing and packaging

Kotlin uses [JUnit](https://junit.org/junit5/) on the JVM, often with [Kotest](https://kotest.io/) for expressive assertions and property testing, and [MockK](https://mockk.io/) for test doubles.

```kotlin
import kotlin.test.Test
import kotlin.test.assertEquals

class CalculatorTest {
    @Test
    fun addsTwoNumbers() {
        assertEquals(5, 2 + 3)
    }
}
```

JVM libraries package as JAR files published to Maven Central. Kotlin Multiplatform projects publish per-target artifacts, and Android apps package as APK or AAB files.

## Performance and concurrency

Kotlin/JVM runs on the same JVM as Java, so it inherits the just-in-time compiler and garbage collectors and performs comparably. Coroutines are the primary concurrency model: a coroutine is a suspendable computation that is cheap to create, so a program can run many concurrent tasks without one operating-system thread each. Structured concurrency ties coroutine lifetimes to a scope, so cancellation and error propagation are deterministic.

- Use `suspend` functions and `CoroutineScope` for asynchronous work.
- Dispatchers control which thread pool a coroutine runs on (`Dispatchers.IO`, `Dispatchers.Default`).
- Shared mutable state across coroutines still needs synchronization, a `Mutex`, or confinement to a single dispatcher.

## Common pitfalls

- The `!!` not-null assertion throws at run time; it defeats null safety and should be rare.
- Platform types from Java code carry no null information, so values crossing the boundary can be null unexpectedly.
- Launching a coroutine without a structured scope (`GlobalScope`) leaks work that outlives its caller.
- Extension functions are resolved statically by declared type, not dynamically, which can surprise readers expecting virtual dispatch.
- Equality on floating-point data classes inherits floating-point comparison quirks.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Deserialization: the same JVM deserialization risks as Java apply when Kotlin code uses `ObjectInputStream`. Prefer `kotlinx.serialization` with a defined schema over native Java serialization for untrusted data. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: use parameterized queries through JDBC `PreparedStatement` or an ORM binding, not string interpolation into SQL, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Command injection: pass arguments to `ProcessBuilder` as a list rather than a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Android intent and permission handling: validate data received through intents and request the least privilege; improper export of components exposes an app to other processes.
- Dependency supply chain: pin and scan Gradle dependencies; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [detekt](https://detekt.dev/) includes rules for risky patterns, and [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) scans the dependency graph. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Kotlin documentation](https://kotlinlang.org/docs/home.html) and the [language specification](https://kotlinlang.org/spec/introduction.html), the primary sources.
- [Kotlin Koans](https://play.kotlinlang.org/koans/overview) for interactive exercises.
- [Android Kotlin guides](https://developer.android.com/kotlin) for the mobile platform.

## Related pages

- [Java](/languages/java.md)
- [Scala](/languages/scala.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
