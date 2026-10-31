# Spring Boot

Spring Boot is a Java framework for building production services with minimal configuration. It sits on top of the broader Spring Framework and its dependency injection container. Teams use it because starters and auto-configuration remove most of the boilerplate once needed to wire a Spring application, and an embedded server lets a service run as a single executable.

## Overview and history

Spring began in 2003 as a lighter alternative to the heavy Java EE stack of that era. Its core contribution was an inversion of control container that managed object creation and wiring. Over time the ecosystem grew large, and configuring it by hand became a burden.

Spring Boot arrived in 2014 to answer that burden. It introduced opinionated defaults, dependency starters, and auto-configuration that inspects the classpath and sets up sensible beans. A new service could start from a single main method with almost no XML or manual bean definitions.

Spring Boot 3, released in 2022, moved to Java 17 as a baseline and to the Jakarta EE namespace. It also added first-class support for building native images with GraalVM. The framework remains one of the most common choices for Java backend work.

## Architecture

At the center is the `ApplicationContext`, the IoC container. It creates beans, resolves their dependencies, and manages their lifecycle. Beans are registered through component scanning of annotated classes or through `@Bean` methods in configuration classes.

Dependency injection connects those beans. A component declares what it needs as constructor parameters, and the container supplies matching beans. Constructor injection is the preferred form because it makes dependencies explicit and supports immutable fields.

Auto-configuration runs at startup. It evaluates conditions against the classpath and existing beans, then contributes default beans where the application has not defined its own. A datasource on the classpath, for example, triggers configuration of a connection pool unless the application overrides it. Starters are curated dependency bundles, such as `spring-boot-starter-web`, that pull in a coherent set of libraries.

The web request lifecycle depends on the stack. Spring MVC is the servlet-based, synchronous model built on `DispatcherServlet`. A request enters the servlet, which consults handler mappings to find a controller method, applies interceptors, invokes the method, and renders the result. Spring WebFlux is the reactive alternative built on Project Reactor and a non-blocking runtime, suited to high-concurrency I/O.

An embedded server, usually Tomcat, is packaged inside the deployable artifact. The application runs as a plain Java process rather than deploying a war into an external container. Actuator adds operational endpoints for health, metrics, and environment inspection.

## Routing, data, and key subsystems

Controllers map HTTP requests to methods with annotations such as `@GetMapping` and `@PostMapping`. The `@RestController` stereotype serializes return values to JSON. Request bodies, path variables, and query parameters bind to method parameters by annotation.

Spring Data reduces persistence code. A repository interface that extends `JpaRepository` gains CRUD and query methods without an implementation. Method names such as `findByEmail` are parsed into queries, and custom JPQL or native queries attach with `@Query`.

Configuration comes from `application.properties` or `application.yml`, environment variables, and command-line arguments, layered by precedence. The `@ConfigurationProperties` mechanism binds groups of settings to typed objects. Profiles select different configuration per environment.

Actuator exposes endpoints under a base path. `health` and `info` are common, while `env`, `beans`, `mappings`, and `heapdump` reveal internal detail. These endpoints are useful for operations and dangerous when exposed.

## A minimal example

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class DemoApplication {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
```

## Ecosystem and tooling

Maven and Gradle are the standard build tools, both with Spring Boot plugins that package the executable artifact. The Spring Initializr web service generates a starter project with chosen dependencies.

Spring Security covers authentication and authorization. Spring Data spans JPA, MongoDB, Redis, and more. Spring Cloud adds patterns for distributed systems, such as service discovery and centralized configuration. Micrometer provides the metrics facade that Actuator reports through.

Testing uses `spring-boot-starter-test`, which bundles JUnit 5, Mockito, and test slices. Annotations such as `@WebMvcTest` and `@DataJpaTest` load only part of the context for faster, focused tests.

## Security model and common vulnerabilities

Spring Security installs a filter chain in front of the application. Each filter handles one concern: authentication, session management, CSRF, authorization, and header defaults. Requests pass through the chain before reaching a controller, so security decisions happen in a single, ordered place.

CSRF protection is enabled by default for stateful, session-based applications and must stay on where browsers submit forms with cookies. Teams building stateless token APIs sometimes disable it, which is acceptable only when no cookie-based session exists. Turning it off on a cookie-authenticated app reintroduces cross-site request forgery.

Method security with `@PreAuthorize` and `@PostAuthorize` places authorization next to the code it guards. Missing or misordered rules lead to CWE-306 (missing authentication for a critical function) when an endpoint is reachable without the intended check. Define authorization explicitly rather than relying on a default that may permit access. See `/API_SECURITY_REFERENCE.md` for authorization patterns.

The Java ecosystem has a long history of unsafe deserialization (CWE-502). Accepting serialized Java objects from untrusted input can lead to remote code execution through gadget chains. Prefer data formats such as JSON with typed binding, and never deserialize native Java objects from a client. See `/SECURE_CODING_REFERENCE.md` for deserialization guidance.

Spring Expression Language (SpEL) evaluates expressions at runtime. Passing user input into a SpEL evaluation enables expression injection (CWE-917), which can run arbitrary code. Keep user data out of expression strings. This class of bug underlies several high-impact disclosures.

Recent history offers two cautionary cases. Log4Shell (CVE-2021-44228) exploited expression lookups in the Log4j logging library reachable through logged user input. Spring4Shell (CVE-2022-22965) abused data binding on specific JDK and deployment combinations to reach class loader properties. Both show how input reaching an interpreter or binder becomes code execution, and both argue for prompt dependency patching.

Actuator endpoints expose internal state (CWE-200, exposure of sensitive information). Endpoints such as `env`, `heapdump`, and `beans` can reveal secrets and structure. Expose only `health` publicly, require authentication on the rest, and bind the management port away from public traffic. See `/WEB_APPLICATION_SECURITY_REFERENCE.md` for information-exposure guidance.

## Performance and scaling

Spring MVC scales by thread pool and process. Each request holds a thread for its duration, so blocking calls consume capacity. Sizing the connection pool and the server thread pool together keeps the system balanced. WebFlux trades the thread-per-request model for a reactive one that serves more concurrent connections with fewer threads, at the cost of harder debugging.

Startup time and memory matter for autoscaling and serverless targets. GraalVM native images cut both, producing an ahead-of-time compiled binary that starts in milliseconds. The tradeoff is a more constrained build and reflection configuration.

Caching with the `@Cacheable` abstraction and a backing store such as Redis reduces load on databases and downstream services. Connection pool tuning on the datasource is often the first lever for throughput under load.

## Common pitfalls

Field injection with `@Autowired` hides dependencies and complicates testing. Use constructor injection.

Catching and swallowing exceptions in filters or controllers can bypass security or hide failures. Let the framework's exception handling report them consistently.

Leaving Actuator wide open in production is a recurring exposure. Lock it down before deploy.

Ignoring dependency updates leaves known-vulnerable libraries in place. The Log4Shell and Spring4Shell events hit teams that patched slowly.

## Resources

- Spring Framework reference documentation
- Spring Boot reference documentation
- Spring Security reference documentation
- OWASP Cheat Sheet Series
- OWASP Top 10

## Related pages

- /languages/java.md
- /frameworks/README.md
- /SECURE_CODING_REFERENCE.md
- /WEB_APPLICATION_SECURITY_REFERENCE.md
- /API_SECURITY_REFERENCE.md
- /frameworks/aspnet-core.md
- /frameworks/django.md
- /frameworks/nestjs.md
