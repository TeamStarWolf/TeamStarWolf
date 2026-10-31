# Concurrent Programming

Concurrent programming structures a program as several threads of control that make progress together over overlapping time periods. It is a cross-cutting concern layered onto imperative, object-oriented, or functional code rather than a style of expression on its own. It matters because most systems must handle many clients, devices, or events at once while staying responsive.

## Core idea

Concurrency is about structure: dividing a program into independent activities that can be interleaved. Parallelism is about execution: running activities at the same instant on multiple cores. A single-core machine can run concurrent code by interleaving, with no parallelism at all.

The two ideas are separate. A concurrent design may run sequentially, and a parallel runtime may execute a concurrent design across cores without any code change. You choose concurrency to model independent activities; you get parallelism when hardware and the runtime allow it.

The central difficulty is coordination. When activities share state or must agree on an order of events, the program needs mechanisms to prevent corruption and to make one activity wait for another. Those mechanisms are the substance of the paradigm.

## How it works

Two units of concurrent execution dominate. A process has its own address space and communicates with other processes through pipes, sockets, or shared files. A thread lives inside a process and shares that address space with sibling threads, so thread switches are cheaper but sharing memory is the source of most bugs.

Coordination follows one of two broad models. In shared memory, threads read and write common variables and use synchronization primitives to control access. In message passing, activities own private state and exchange values over channels or mailboxes, which avoids shared mutable state by construction.

Shared-memory synchronization rests on a few primitives. A mutex grants exclusive access to a critical section. A condition variable lets a thread wait until some predicate holds, releasing the lock while it waits. Atomics give indivisible read-modify-write operations such as compare-and-swap without a lock.

```java
class Counter {
    private long value = 0;
    private final Object lock = new Object();

    void increment() {
        synchronized (lock) {
            value++;          // read, add, write: must be one critical section
        }
    }

    long get() {
        synchronized (lock) {
            return value;
        }
    }
}
```

Without the lock, `value++` is three steps, and two threads can interleave them so an update is lost. That is a data race, the canonical concurrency defect. A race occurs when two threads access the same location, at least one writes, and no ordering relation separates them.

Four failure modes recur. A data race corrupts shared state through unsynchronized access. A deadlock stalls threads that each hold a resource the other needs. A livelock keeps threads active but making no progress as they repeatedly react to each other. Starvation leaves a thread perpetually denied a resource it needs.

A memory model defines which writes a thread may observe, because compilers and processors reorder operations. The model establishes a happens-before relation: if one action happens-before another, the first action's effects are visible to the second. Acquiring a lock that a thread released, or reading an atomic another thread wrote, creates such an edge.

Message passing sidesteps shared-state races. Communicating Sequential Processes (CSP) models a program as processes that synchronize by passing values over channels. Go takes this route with goroutines, lightweight activities the runtime multiplexes onto OS threads, and channels for communication.

```go
func main() {
    ch := make(chan int)
    go func() {
        ch <- compute()     // send blocks until a receiver is ready
    }()
    result := <-ch          // receive blocks until a value arrives
    fmt.Println(result)
}
```

Async runtimes offer a third structure. Instead of one OS thread per activity, code yields at `await` points and the runtime resumes it when an operation completes. This suits workloads with many waiting connections, where thread-per-connection would exhaust memory.

## Strengths and trade-offs

Concurrency improves responsiveness: a slow operation on one activity does not freeze the others. It models real-world independence directly, since clients, timers, and devices genuinely act in parallel. On multicore hardware it is the path to using more than one core.

The cost is reasoning difficulty. Interleavings multiply the states a program can reach, and many bugs appear only under rare timing. Such bugs resist reproduction and testing, because adding logging or a debugger changes the timing that triggered them.

Locks trade one problem for others. Too little locking admits races; too much serializes the program and erases the parallelism you wanted. Lock ordering guards against deadlock but adds a discipline every code path must obey. Message passing removes shared-state races but can still deadlock when sends and receives do not match.

## Languages and tools

[Go](/languages/go.md) builds concurrency on goroutines and channels in the CSP tradition. [Erlang](/languages/erlang.md) and [Elixir](/languages/elixir.md) use isolated processes that share nothing and communicate by messages. [Java](/languages/java.md) provides threads, a defined memory model, and the `java.util.concurrent` library of locks, queues, and executors. [Rust](/languages/rust.md) uses its ownership and borrow system to reject data races at compile time through the `Send` and `Sync` traits. [Scala](/languages/scala.md) offers futures and actor libraries on the JVM.

## Secure-coding considerations

See /SECURE_CODING_REFERENCE.md. The defining hazard is the data race, CWE-362 (concurrent execution using shared resource with improper synchronization). A subtle variant is the time-of-check to time-of-use flaw, CWE-367, where state changes between a validation and the action that relies on it, which attackers can exploit to bypass a check.

Unbounded concurrency is itself a weakness. Creating a thread or task per request lets an attacker exhaust memory or thread handles, a denial-of-service path related to CWE-400 (uncontrolled resource consumption). Bound work with fixed thread pools or semaphores. Deadlock under adversarial input is a liveness failure that can hang a service, so order lock acquisition consistently and prefer timeouts on blocking waits.

## Resources

- C. A. R. Hoare, *Communicating Sequential Processes*, 1978, CACM (and the 1985 Prentice Hall book)
- Maurice Herlihy and Nir Shavit, *The Art of Multiprocessor Programming*, 2008, Morgan Kaufmann
- Brian Goetz, Tim Peierls, Joshua Bloch, Joseph Bowbeer, David Holmes, and Doug Lea, *Java Concurrency in Practice*, 2006, Addison-Wesley
- Gregory R. Andrews, *Concurrent Programming: Principles and Practice*, 1991, Benjamin/Cummings
- Leslie Lamport, *Time, Clocks, and the Ordering of Events in a Distributed System*, 1978, CACM

## Related pages

- /paradigms/README.md
- /SECURE_CODING_REFERENCE.md
- /paradigms/actor-model.md
- /paradigms/event-driven.md
- /paradigms/reactive.md
- /paradigms/dataflow.md
