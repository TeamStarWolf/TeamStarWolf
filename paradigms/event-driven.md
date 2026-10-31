# Event-Driven Programming

Event-driven programming organizes control flow around events and the handlers that respond to them, rather than a fixed top-to-bottom sequence. It is a cross-cutting style: the program waits, an event arrives, and a registered handler runs. It matters because interactive user interfaces, network servers, and distributed systems are all naturally described as reactions to things that happen.

## Core idea

In a sequential program, your code decides what happens next. In an event-driven program, the arrival of events decides. You register handlers in advance and hand control to a dispatcher that calls them when matching events occur. This reversal is inversion of control: the framework calls your code, not the other way around.

An event is a record that something happened: a button was clicked, a packet arrived, a timer expired, a file finished writing. A handler, sometimes called a callback or listener, is the function bound to that event. The binding between event and handler is the core unit of the paradigm.

## How it works

Most event-driven runtimes sit on an event loop. The loop waits for events, takes the next one from a queue, and runs its handler to completion before taking the next. This single-threaded cooperative model avoids many data races, but it demands that handlers never block for long, or the whole loop stalls.

```javascript
const emitter = new EventTarget();

emitter.addEventListener("order.placed", (e) => {
  console.log("charging card for", e.detail.total);
});

emitter.dispatchEvent(
  new CustomEvent("order.placed", { detail: { total: 42.0 } })
);
```

Blocking work is expressed as more events. Rather than wait for a disk read, you start it and register a handler for its completion. The historical form is the callback, a function passed in to run when the operation finishes. Nested callbacks grow hard to read, a problem commonly called callback hell.

Promises flatten that nesting by representing a future value you can chain. `async` and `await` are syntax over promises that let you write asynchronous steps in sequential-looking code while the event loop keeps running underneath.

```javascript
async function loadProfile(id) {
  try {
    const res = await fetch(`/users/${id}`);
    const user = await res.json();
    return user.name;
  } catch (err) {
    console.error("load failed", err);
    return null;
  }
}
```

The two `await` points yield control back to the event loop while I/O is pending. The function reads like straight-line code, but each `await` is a resumption point driven by an event. Error handling uses ordinary `try`/`catch`, which is a clear improvement over branching error callbacks.

At larger scale, event-driven systems use publish-subscribe. Publishers emit events to a topic without knowing who listens; subscribers register interest without knowing who publishes. A message broker such as RabbitMQ, Apache Kafka, or a cloud equivalent sits between them, buffering and routing. This decoupling lets services evolve independently and absorb bursts.

```python
import asyncio

async def worker(name, queue):
    while True:
        job = await queue.get()      # suspends until an item is available
        print(name, "handling", job)
        queue.task_done()

async def main():
    queue = asyncio.Queue()
    task = asyncio.create_task(worker("w1", queue))
    for job in ["a", "b", "c"]:
        await queue.put(job)
    await queue.join()
    task.cancel()

asyncio.run(main())
```

Event sourcing takes the idea into persistence. Instead of storing only current state, you store the ordered log of events that produced it. Current state is a fold over that log, so you can rebuild it, audit every change, and derive new read models after the fact. The cost is more storage and the discipline of versioning event schemas as they evolve.

Event-driven design is everywhere in practice. User interfaces dispatch input events to widget handlers. Servers built on an event loop handle many connections with few threads, because idle connections cost almost nothing while they wait.

## Strengths and trade-offs

The style scales to many concurrent waits cheaply and decouples producers from consumers, which aids modularity. It matches the problem domain for interactive and networked software, so the code mirrors how the system actually behaves.

The trade-offs are cognitive. Control flow is implicit and scattered across handlers, so reasoning about overall order is hard. Debugging spans queues and callbacks rather than a single stack. A handler that blocks or throws unexpectedly can stall a loop or drop an event, and at-least-once delivery from brokers forces you to make handlers idempotent.

## Languages and tools

[JavaScript](/languages/javascript.md) is event-driven by design, both in the browser and on Node.js, where the event loop is the core runtime abstraction. [Python](/languages/python.md) supports the style through `asyncio` and its event loop, alongside callback-based GUI and network libraries. [Erlang](/languages/erlang.md) builds reliability on asynchronous message passing between lightweight processes, a closely related model.

For cross-service events, brokers such as Apache Kafka, RabbitMQ, NATS, and cloud messaging services carry the publish-subscribe and event-sourcing patterns in production systems.

## Secure-coding considerations

Unbounded event queues let a flood of events exhaust memory or starve handlers, which maps to CWE-400 (Uncontrolled Resource Consumption). Apply backpressure, bound queues, and rate-limit untrusted sources.

Handlers often act on event payloads that originate outside your trust boundary. Treat every payload as untrusted data and validate it before it drives a side effect, since unchecked input relates to CWE-20 (Improper Input Validation). Deserializing event bodies from a broker invites unsafe deserialization if the format allows arbitrary types. Make handlers idempotent so that duplicate or replayed events cannot cause double charges or repeated state changes. See /SECURE_CODING_REFERENCE.md for validation, deserialization, and resource-limit guidance.

## Resources

- Martin Fowler, *Patterns of Enterprise Application Architecture*, 2002, Addison-Wesley
- Gregor Hohpe and Bobby Woolf, *Enterprise Integration Patterns*, 2003, Addison-Wesley
- Roland Kuhn, Brian Hanafee, and Jamie Allen, *Reactive Design Patterns*, 2017, Manning

## Related pages

- /paradigms/README.md
- /SECURE_CODING_REFERENCE.md
- /paradigms/reactive.md
- /paradigms/dataflow.md
- /paradigms/concurrent.md
- /paradigms/actor-model.md
