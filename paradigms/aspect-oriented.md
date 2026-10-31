# Aspect-Oriented Programming

Aspect-oriented programming separates cross-cutting concerns, such as logging, security checks, and transactions, from the core logic they touch. It is a declarative overlay on top of imperative or object-oriented code: you state where behavior should apply, and a weaver inserts it. It matters because such concerns otherwise scatter across many modules and tangle with unrelated logic.

## Core idea

A cross-cutting concern is one whose code would appear in many places if written by hand. Logging every service call, enforcing an access check before each sensitive method, and wrapping operations in a transaction are classic cases. Writing them inline duplicates code and mixes two purposes in one method.

Aspect-oriented programming moves that code into a separate unit called an aspect. The aspect names the points in the program where its behavior belongs and the behavior to run there. The core code stays free of the concern, and the concern lives in one place.

The paradigm trades explicit calls for a declared rule. Instead of calling `log()` at the top of every method, you declare that logging applies to a set of methods. The payoff is single-point definition; the cost is that control flow is no longer visible at the call site.

## How it works

The model rests on four terms. A join point is a well-defined point in program execution, such as a method call or field access. A pointcut is a predicate that selects a set of join points. Advice is the code to run at matched join points, and weaving is the act of combining advice with the base program.

Advice runs `before`, `after`, or `around` a join point. `around` advice wraps the join point and decides whether and when to proceed, which suits caching and transactions. The following AspectJ aspect adds an access check before any method in a service package.

```java
public aspect AccessControl {
    pointcut sensitiveOps():
        execution(* com.example.service..*(..));

    before(): sensitiveOps() {
        if (!SecurityContext.current().isAuthorized()) {
            throw new SecurityException("not authorized");
        }
    }
}
```

Weaving happens at one of three times. Compile-time weaving injects advice when the aspect and classes are compiled together. Load-time weaving transforms bytecode as classes load, driven by a weaving agent. Run-time weaving uses proxies created while the program runs.

AspectJ is the reference implementation for Java and supports all three weaving times with a full pointcut language. Spring AOP is lighter: it weaves at run time using dynamic proxies and intercepts only Spring-managed bean method calls. Spring covers the common enterprise cases, such as declarative transactions and method security, while AspectJ reaches field access and finer join points.

```java
@Aspect
@Component
public class TimingAspect {
    @Around("execution(* com.example..*Service.*(..))")
    public Object time(ProceedingJoinPoint pjp) throws Throwable {
        long start = System.nanoTime();
        try {
            return pjp.proceed();
        } finally {
            long ms = (System.nanoTime() - start) / 1_000_000;
            Metrics.record(pjp.getSignature().toShortString(), ms);
        }
    }
}
```

The example above is Spring AOP style: an `@Around` advice times every service method and always proceeds in a `finally` block. Note the dependency on a correct pointcut expression. If the expression misses a class, the concern silently does not apply there.

## Strengths and trade-offs

The strength is locality for concerns that would otherwise scatter. A single aspect defines a policy once, and it applies uniformly to every matched join point. Changing the policy means editing one unit, not many methods.

The central trade-off is the tension with explicit control flow. Reading a method no longer tells you everything that runs when it executes, because advice attaches from outside. This makes behavior harder to trace and debuggers harder to follow, and it can surprise maintainers who do not expect hidden interception.

Pointcuts are fragile against refactoring. A pointcut written against a package or naming pattern can quietly stop matching when code moves or is renamed, which is called the fragile pointcut problem. Proxy-based weaving also has limits: Spring AOP does not intercept calls a bean makes to its own methods, since those bypass the proxy.

## Languages and tools

Java is the main home of the paradigm through AspectJ and Spring AOP, named above. See [java](/languages/java.md).

AspectJ extends Java syntax and bytecode and supports compile-time, load-time, and run-time weaving. Spring AOP is a run-time, proxy-based subset aimed at Spring beans and common enterprise concerns such as transactions and security. Comparable interception appears in other ecosystems through decorators, middleware, and dynamic proxies, though those are usually described in their own terms rather than as aspects.

## Secure-coding considerations

Security policy expressed as advice is only as reliable as its pointcut. A pointcut that fails to match a new or renamed sensitive method leaves that method unguarded, which maps to CWE-862 (Missing Authorization). Treat security pointcuts as code that needs tests asserting the advice actually fires on each protected target.

Weaving changes trust assumptions, so untrusted aspects or weaving agents must not be loadable at run time. Load-time weaving reads configuration that names classes and aspects, and an attacker who controls that configuration can inject or suppress behavior. Keep weaving configuration inside the trust boundary and out of attacker-writable locations.

`around` advice that wraps authentication or transaction logic must proceed and clean up correctly on every path, including exceptions. Advice that swallows an exception or forgets to proceed can leave a transaction open or an authorization check bypassed. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) for authorization and error-handling guidance.

## Resources

- Gregor Kiczales, John Lamping, Anurag Mendhekar, Chris Maeda, Cristina Lopes, Jean-Marc Loingtier, and John Irwin, *Aspect-Oriented Programming*, 1997, ECOOP
- Ramnivas Laddad, *AspectJ in Action: Enterprise AOP with Spring Applications*, 2009, Manning
- Robert E. Filman, Tzilla Elrad, Siobhan Clarke, and Mehmet Aksit (eds.), *Aspect-Oriented Software Development*, 2004, Addison-Wesley

## Related pages

- [Programming paradigms](/paradigms/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Object-oriented programming](/paradigms/object-oriented.md)
- [Metaprogramming](/paradigms/metaprogramming.md)
- [Declarative programming](/paradigms/declarative.md)
- [Event-driven programming](/paradigms/event-driven.md)
