# Java

Java is a statically typed, class-based, object-oriented language created by James Gosling at Sun Microsystems and first released in 1995. Source compiles to bytecode that runs on the Java Virtual Machine (JVM), which gives the language its "write once, run anywhere" portability across operating systems. It is used for server-side back ends, Android applications, large business systems, build tooling, and data platforms.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented, with generics and, since Java 8, functional features |
| Typing | Static, strong, nominal |
| First appeared | 1995 |
| Memory model | Automatic garbage collection on the JVM heap |
| Reference implementation | [OpenJDK](https://openjdk.org/) |
| Typical uses | Server back ends, Android, business systems, data platforms |
| Governance | [Java Community Process](https://www.jcp.org/) and OpenJDK JEPs |

Related: [Kotlin](/languages/kotlin.md), [Scala](/languages/scala.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Java began at Sun Microsystems as the Green Project and was first released in 1995 with the promise of portable bytecode. Oracle acquired Sun in 2010 and now stewards the platform. Since Java 9, feature releases ship every six months, with designated long-term support (LTS) releases such as Java 8, 11, 17, and 21 receiving extended maintenance. The language and virtual machine are specified separately: the [Java Language Specification](https://docs.oracle.com/javase/specs/) defines the source language, and the [Java Virtual Machine Specification](https://docs.oracle.com/javase/specs/jvms/se21/html/) defines the bytecode and runtime.

The reference implementation is [OpenJDK](https://openjdk.org/), an open-source project under the GPL with a linking exception. Builds are distributed by several vendors, including Eclipse Temurin, Amazon Corretto, and Azul Zulu. Language and platform changes move through the JDK Enhancement Proposal (JEP) process.

## Paradigm and type system

Java is statically and nominally typed: every variable has a declared type checked at compile time, and type relationships follow explicit `extends` and `implements` declarations rather than structural shape. Generics, added in Java 5, provide parametric polymorphism but are erased at run time, so generic type arguments are not available through reflection. Primitive types (`int`, `long`, `double`, `boolean`) are distinct from reference types and are boxed into wrapper objects when a reference is required.

```java
record Point(int x, int y) {}

List<Point> points = List.of(new Point(1, 2), new Point(3, 4));
int sumX = points.stream().mapToInt(Point::x).sum();
```

Records (Java 16) declare immutable data carriers, sealed classes (Java 17) restrict which types may extend a hierarchy, and pattern matching for `switch` narrows types without casts.

## Toolchain and ecosystem

- Compiler and runtime: `javac` compiles `.java` to `.class` bytecode; `java` launches the JVM. A single-file source program can run directly with `java Hello.java`.
- Build and dependencies: [Maven](https://maven.apache.org/) and [Gradle](https://gradle.org/) resolve dependencies from [Maven Central](https://central.sonatype.com/) and drive builds.
- Formatting and linting: [google-java-format](https://github.com/google/google-java-format) formats source; [Checkstyle](https://checkstyle.org/) and [SpotBugs](https://spotbugs.github.io/) report style and defect patterns.

```bash
mvn archetype:generate -DgroupId=com.example -DartifactId=app
mvn package
java -jar target/app-1.0.jar
```

## Syntax tour

```java
import java.util.*;
import java.util.stream.*;

public class Tour {
    // Entry point
    public static void main(String[] args) {
        // Variables and local type inference
        var name = "world";
        System.out.println("hello, " + name);

        // Collections and generics
        List<Integer> squares = IntStream.range(0, 5)
            .map(n -> n * n)
            .boxed()
            .collect(Collectors.toList());

        Map<String, Integer> lookup = Map.of("a", 1, "b", 2);

        // Enhanced for loop
        for (int sq : squares) {
            System.out.println(sq);
        }

        // Exceptions with try-with-resources
        try {
            int value = Integer.parseInt("not a number");
        } catch (NumberFormatException err) {
            System.out.println("parse failed");
        }
    }
}

// Interfaces and a lambda implementation
interface Greeter {
    String greet(String who);
}
```

## Idioms and different approaches

- Favor interfaces and dependency injection over concrete types in method signatures, so implementations can be swapped and tested.
- Use the Streams API for declarative transformations of collections; fall back to explicit loops when the logic has side effects or needs early exit.
- Prefer immutable objects and `final` fields where practical; records make small immutable types concise.
- Use `Optional<T>` for return values that may be absent rather than returning `null`, but do not use it for fields or method parameters.
- Build strings in a loop with `StringBuilder`, not repeated `+` concatenation.

## Design principles

Java's design goals, stated in the original white paper, were to be object-oriented, portable through bytecode, and safe through managed memory and a verified type system. The language favors explicitness and backward compatibility: code compiled against an older release generally keeps running on newer JVMs. The JVM's bytecode verifier and class loader enforce type and memory safety before execution.

## Standard library and notable frameworks

The Java Development Kit ships the `java.util` collections framework, `java.io` and `java.nio` for I/O, `java.time` for dates, `java.util.concurrent` for threads and synchronization, and `java.net.http` for HTTP. Widely used third-party frameworks include [Spring](https://spring.io/) and [Spring Boot](https://spring.io/projects/spring-boot) for web and dependency injection, [Hibernate](https://hibernate.org/) for object-relational mapping, [Jackson](https://github.com/FasterXML/jackson) for JSON, and [Netty](https://netty.io/) for asynchronous networking.

## Testing and packaging

[JUnit](https://junit.org/junit5/) is the standard test framework, often paired with [Mockito](https://site.mockito.org/) for test doubles and [AssertJ](https://assertj.github.io/doc/) for fluent assertions.

```java
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CalculatorTest {
    @Test
    void addsTwoNumbers() {
        assertEquals(5, 2 + 3);
    }
}
```

Applications package as JAR files; a runnable JAR declares its main class in the manifest. Larger deployments use the Java Platform Module System (Java 9) or build fat JARs that bundle dependencies.

## Performance and concurrency

The JVM compiles hot bytecode to native code with a just-in-time compiler, so long-running programs approach native speed after warm-up. Garbage collectors are pluggable: G1 is the default, and ZGC and Shenandoah target low pause times. The Java Memory Model defines when writes by one thread become visible to another and underpins the `volatile` and `synchronized` keywords.

- The `java.util.concurrent` package provides thread pools, locks, concurrent collections, and `CompletableFuture`.
- Virtual threads, finalized in Java 21 through [JEP 444](https://openjdk.org/jeps/444), let blocking code scale to many concurrent tasks without a thread pool per connection.
- Shared mutable state needs synchronization or immutable data to avoid data races.

## Common pitfalls

- `==` compares object identity for reference types; use `.equals()` to compare values, and override `equals` and `hashCode` together.
- Autoboxing can produce surprising results: comparing two `Integer` objects with `==` compares references, not numbers.
- Mutable static fields shared across threads cause data races without synchronization.
- Catching `Exception` or `Throwable` broadly can swallow errors; catch the narrowest type that the code can handle.
- Checked exceptions must be declared or handled, which can push developers toward empty `catch` blocks that hide failures.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Insecure deserialization: the built-in `ObjectInputStream` reconstructs arbitrary object graphs and has been the root of many remote-code-execution flaws. Avoid Java serialization for untrusted data; use a data format such as JSON with a schema. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: build queries with `PreparedStatement` and bound parameters, never string concatenation, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- XML external entities: parsers such as `DocumentBuilderFactory` resolve external entities by default; disable `DOCTYPE` processing to avoid [CWE-611](https://cwe.mitre.org/data/definitions/611.html).
- Command injection: pass arguments to `ProcessBuilder` as a list rather than assembling a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Dependency supply chain: pin versions and scan them, because transitive dependencies from Maven Central are a common vector. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [SpotBugs](https://spotbugs.github.io/) with the Find Security Bugs plugin flags insecure patterns statically, and [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) reports vulnerable libraries. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The Java Tutorials](https://docs.oracle.com/javase/tutorial/) and the [Java Language Specification](https://docs.oracle.com/javase/specs/), the primary documentation.
- [OpenJDK](https://openjdk.org/) for the reference implementation and JEP index.
- [Baeldung](https://www.baeldung.com/) for applied tutorials on the ecosystem.

## Related pages

- [Kotlin](/languages/kotlin.md)
- [Scala](/languages/scala.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
