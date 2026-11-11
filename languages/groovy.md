# Groovy

Groovy is a dynamic language for the Java Virtual Machine, first released in 2003 and now maintained by the Apache Software Foundation. It keeps a Java-like syntax while adding dynamic typing, closures, and concise collection handling, and it can also be compiled statically. It is used for build scripts, test automation, and domain-specific languages, and it is the original scripting language of the Gradle and Jenkins build tools.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented and scripting, with functional features |
| Typing | Optional: dynamic by default, static when annotated |
| First appeared | 2003 |
| Memory model | Garbage collected on the JVM |
| Reference implementation | [Apache Groovy](https://github.com/apache/groovy) |
| Typical uses | Build scripts, test automation, domain-specific languages |
| Governance | [Apache Software Foundation](https://groovy.apache.org/) |

Related: [Java](/languages/java.md), [Kotlin](/languages/kotlin.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who write or maintain Groovy code, and the reviewers and security engineers who assess it

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,226 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are writing or reviewing Groovy code (typical uses: build scripts, test automation, domain-specific languages), you need its common pitfalls and secure-coding rules before a review, or you are choosing its toolchain, tests and packages

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Syntax tour](#syntax-tour), [Common pitfalls](#common-pitfalls), [Secure coding](#secure-coding)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Java](/languages/java.md), [Kotlin](/languages/kotlin.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Groovy started in 2003 to bring dynamic-language features to the JVM while staying close to Java syntax, so most Java code is also valid Groovy. It reached 1.0 in 2007, moved to the Apache Software Foundation in 2015, and continues under the Apache Groovy project. Groovy source compiles to JVM bytecode and can call any Java library directly.

The language is best known today as the scripting layer for [Gradle](https://gradle.org/) build files and [Jenkins](https://www.jenkins.io/) pipelines, though both tools also support other languages. Its metaprogramming features make it a common choice for embedded domain-specific languages.

## Paradigm and type system

Groovy is dynamically typed by default: a variable declared with `def` holds any type, and method dispatch is resolved at run time, which enables runtime metaprogramming. The language also offers optional static typing: annotating a class or method with `@TypeChecked` turns on compile-time type checking, and `@CompileStatic` additionally compiles to direct bytecode calls rather than dynamic dispatch, approaching Java speed.

```groovy
def total(prices, tax = 0.0) {
    prices.sum() * (1 + tax)
}

@groovy.transform.CompileStatic
int square(int n) { n * n }
```

Groovy adds the Groovy Development Kit, which extends Java types with extra methods, and native syntax for lists, maps, and ranges.

## Toolchain and ecosystem

- Compiler and runner: `groovyc` compiles to bytecode, `groovy` runs a script, and `groovysh` is an interactive shell.
- Build and dependencies: [Gradle](https://gradle.org/) and [Maven](https://maven.apache.org/) build Groovy projects; dependencies resolve from [Maven Central](https://central.sonatype.com/). The `@Grab` annotation can pull dependencies for a script directly.
- Static analysis: [CodeNarc](https://codenarc.org/) is a static analyzer and style checker for Groovy.

```bash
groovy hello.groovy
groovyc Hello.groovy && java -cp .:$GROOVY_HOME/lib/groovy.jar Hello
```

## Syntax tour

```groovy
// Variables and GStrings (interpolated strings)
def name = "world"
println "hello, ${name}"

// Collections with native syntax
def squares = (0..<5).collect { it * it }
def lookup = [a: 1, b: 2]

// Closures
def greet = { who, excited = false ->
    "hi ${who}${excited ? '!' : '.'}"
}

// Safe navigation and Elvis
def length = name?.size() ?: 0

// Class with properties
class Point {
    int x
    int y
}

def p = new Point(x: 1, y: 2)
```

## Idioms and different approaches

- Use closures and the Groovy Development Kit methods (`collect`, `findAll`, `each`, `inject`) for concise collection handling.
- Rely on Groovy truth: empty collections, empty strings, zero, and `null` are falsy, which shortens conditionals.
- Prefer the safe-navigation operator `?.` and the Elvis operator `?:` over explicit null checks.
- Apply `@CompileStatic` to performance-sensitive or library code where dynamic dispatch is not needed.
- Use builders (such as `MarkupBuilder`) and operator overloading to write readable domain-specific languages.

## Design principles

Groovy aims to lower the ceremony of Java while staying source-compatible with it, so a team can adopt it incrementally. It favors optional typing: scripts can stay fully dynamic, and larger code can opt into static checking. Metaprogramming through the meta-object protocol is a first-class capability, which is why Groovy underlies so many build and test DSLs.

## Standard library and notable libraries

Groovy extends the Java standard library through the Groovy Development Kit, and ships modules for JSON (`groovy.json`), XML (`groovy.xml`), SQL (`groovy.sql`), and templating. Notable libraries and tools built on or for Groovy include [Spock](https://spockframework.org/) for testing, [Grails](https://grails.org/) as a web framework, and [Geb](https://www.gebish.org/) for browser automation. Any Java library on Maven Central is usable directly.

## Testing and packaging

[Spock](https://spockframework.org/) is the common test framework, with a behavior-driven given/when/then structure; JUnit also runs Groovy tests.

```groovy
import spock.lang.Specification

class CalculatorSpec extends Specification {
    def "adds two numbers"() {
        expect:
        2 + 3 == 5
    }
}
```

Groovy code packages as JAR files built by Gradle or Maven and published to Maven Central, the same as Java artifacts.

## Performance and concurrency

Dynamic dispatch has runtime cost, which Groovy reduces with call-site caching and, since the 2.x line, the `invokedynamic` bytecode. Code annotated with `@CompileStatic` compiles to direct method calls and performs close to Java. Concurrency uses the JVM thread model and `java.util.concurrent`; the [GPars](http://www.gpars.org/) library adds actors, data-flow, and parallel collection operations. As on any JVM language, shared mutable state needs synchronization or immutable data to avoid races.

## Common pitfalls

- Fully dynamic code moves type errors to run time; apply `@TypeChecked` or `@CompileStatic` to catch them earlier.
- Groovy truth rules differ from Java, so a condition on a collection or string tests emptiness, not null alone.
- Runtime metaprogramming can make behavior hard to trace; document any added or intercepted methods.
- Equality uses `==` for value comparison (unlike Java, where `==` is identity), which surprises Java developers.
- The `@Grab` annotation fetches dependencies at run time, which is convenient for scripts but unsuitable for reproducible builds.

## Security relevance

Groovy reaches security practitioners mainly through build and CI/CD systems, where it is the scripting layer of Gradle and Jenkins, and as an embedded scripting surface in Java applications. This section is the threat-facing context; the defensive patterns that counter each class are in the Secure coding section that follows.

### Where it appears

- Build and CI/CD pipelines. [Gradle](https://gradle.org/) build files and [Jenkins](https://www.jenkins.io/) pipelines are Groovy, so pipeline logic and the credentials it handles are Groovy code, and a compromised script runs with build and deployment privileges. See the [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).
- Embedded scripting and domain-specific languages. Groovy is embedded in [Java](/languages/java.md) applications as a scripting surface, which becomes a remote-code-execution vector when the surface is exposed to untrusted input.
- Test automation. Groovy drives test suites with frameworks such as Spock and runs on the JVM with direct access to any Java library. It has little use as standalone offensive tooling.

### Dominant weakness classes

Groovy is memory-safe (garbage-collected on the JVM), so the memory-corruption classes do not apply. The risks are code evaluation, deserialization, and injection, several of them reached through the JVM:

- Dynamic code evaluation. `Eval`, `GroovyShell`, and `Binding` execute arbitrary Groovy from a string, so evaluating untrusted input runs attacker code, which maps to [CWE-95](https://cwe.mitre.org/data/definitions/95.html).
- Insecure deserialization. JVM `ObjectInputStream` reconstructs arbitrary objects from untrusted data, which is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection. Interpolating a GString into SQL rather than using `groovy.sql.Sql` placeholders maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Command injection. Passing a shell string rather than an argument list to a process maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

### Why it matters

Reading Groovy lets an analyst audit Jenkins and Gradle scripts for exposed credentials and for unsandboxed evaluation of untrusted input, a recurring path to CI/CD compromise, and to check any embedded scripting surface for an open evaluation path. [CodeNarc](https://codenarc.org/) is the Groovy static analyzer and [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) scans dependencies, as the Secure coding section details.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Dynamic code evaluation: `Eval`, `GroovyShell`, and `Binding` execute arbitrary Groovy from strings; never evaluate untrusted input, which maps to [CWE-95](https://cwe.mitre.org/data/definitions/95.html). When a scripting surface is required, restrict it with a `SecureASTCustomizer` and a sandbox.
- Deserialization: JVM `ObjectInputStream` reconstructs arbitrary objects; use a schema-based format for untrusted data, addressing [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: use parameterized queries with `groovy.sql.Sql` placeholders rather than interpolating a GString into SQL, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Command injection: build process arguments as a list for `ProcessBuilder` rather than a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Dependency supply chain: pin and scan dependencies, and avoid `@Grab` in production code; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [CodeNarc](https://codenarc.org/) flags risky and low-quality patterns, and [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) scans dependencies. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- Apache Groovy documentation, the primary source.
- Groovy language specification for syntax and semantics.
- [Spock documentation](https://spockframework.org/spock/docs/) for testing.

## Related pages

- [Java](/languages/java.md)
- [Kotlin](/languages/kotlin.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
