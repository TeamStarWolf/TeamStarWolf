# Reactive Programming

Reactive programming is a declarative style built around asynchronous data streams and the automatic propagation of change. You describe how values relate, and the runtime recomputes dependents when a source emits. It matters because it gives a uniform model for events, I/O, and time-varying state that would otherwise be scattered across ad hoc callbacks.

## Core idea

A reactive program treats changing values as first-class streams. A stream is a sequence of events over time: mouse clicks, sensor readings, HTTP responses, or ticks of a clock. Instead of writing code that pulls a value when it needs one, you declare a pipeline that reacts when a value arrives.

The central promise is propagation. When a source changes, every value derived from it updates without explicit re-assignment. This is the same intuition as a spreadsheet cell: edit one input and dependent cells recompute on their own.

Two classic abstractions come from functional reactive programming (FRP). A behavior is a value that varies continuously over time, such as a cursor position. An event is a discrete stream of occurrences, such as key presses. Modern libraries collapse both into a single discrete stream type, but the distinction clarifies what you are modeling.

## How it works

The dominant industrial model is the observable. An observable is a source you subscribe to; it pushes items to an observer through `onNext`, then signals completion with `onComplete` or failure with `onError`. Operators transform one observable into another: `map`, `filter`, `merge`, `debounce`, `flatMap`, and `scan` are typical. Composition of operators is where reactive code earns its keep.

```javascript
import { fromEvent } from "rxjs";
import { map, debounceTime, distinctUntilChanged } from "rxjs/operators";

const input = document.querySelector("#search");
const queries = fromEvent(input, "input").pipe(
  map((e) => e.target.value.trim()),
  debounceTime(250),
  distinctUntilChanged()
);

queries.subscribe((q) => console.log("search for", q));
```

The pipeline above turns raw keystrokes into a clean stream of distinct search terms. `debounceTime` drops intermediate values until typing pauses. `distinctUntilChanged` suppresses repeats. None of this requires manual timer bookkeeping or flag variables.

Propagation needs a scheduling discipline so that dependents update in a consistent order. Naive propagation can cause glitches: a derived value briefly reads inconsistent inputs mid-update. FRP systems and careful reactive runtimes order updates topologically to avoid this. When you build your own propagation, order and consistency are the parts most likely to go wrong.

Backpressure is the second hard problem. A fast producer can overwhelm a slow consumer. The reactive-streams specification addresses this with demand signaling: the consumer requests `n` items, and the producer may emit at most that many. This turns an unbounded push into a bounded pull-push hybrid, which keeps memory stable under load.

```javascript
// A subscriber asks for a bounded number of items at a time.
source.subscribe({
  start(subscription) { subscription.request(10); },
  next(item, subscription) {
    handle(item);
    subscription.request(1); // ask for one more only after handling
  },
  error(err) { log(err); },
  complete() { done(); },
});
```

The distinction from plain event handling is worth stating plainly. A raw event handler is one callback reacting to one event. Reactive programming makes the stream itself a value you can name, pass, transform, and combine. That shift lets you express "search results derived from debounced input joined with the latest filter settings" as one declarative expression rather than a web of mutable handlers.

## Strengths and trade-offs

Reactive code expresses asynchronous coordination clearly. Combining streams, handling timeouts, retrying, and cancelling become operator calls rather than bespoke state machines. Cancellation is explicit through unsubscription, which helps avoid leaks.

The costs are real. Debugging is harder because stack traces rarely show the logical pipeline. Operator semantics around hot versus cold observables, replay, and subscription timing surprise newcomers. Overuse turns simple synchronous logic into opaque chains, so reserve streams for genuinely asynchronous or time-varying problems.

## Languages and tools

Reactive ideas appear across many ecosystems. [Elm](/languages/elm.md) pioneered a disciplined FRP-adjacent architecture with a strict update loop. [JavaScript](/languages/javascript.md) and [TypeScript](/languages/typescript.md) host RxJS, the most widely used reactive library on the web. [Scala](/languages/scala.md) anchors much of the JVM reactive world through Akka Streams and the reactive-streams interfaces.

Beyond specific languages, ReactiveX provides a shared operator vocabulary across RxJava, RxSwift, and others. The reactive-streams specification defines the interoperable backpressure contract that Project Reactor, Akka Streams, and the JDK `Flow` types implement.

## Secure-coding considerations

Streams that never terminate or that buffer without bound are a denial-of-service risk. Ignoring backpressure lets a hostile or merely fast producer exhaust memory, which maps to CWE-400 (Uncontrolled Resource Consumption). Always bound buffers and apply explicit demand.

Error channels deserve care. Swallowing `onError` hides failures and can leave subscriptions and sockets open, leaking resources. Side effects inside operators (logging secrets, writing to shared state) can run concurrently in ways that invite data races. See /SECURE_CODING_REFERENCE.md for input validation and resource-limit guidance, and validate every externally sourced stream element before it drives downstream effects.

## Resources

- Conal Elliott and Paul Hudak, *Functional Reactive Animation*, 1997, ICFP
- Engineer Bainomugisha, Andoni Lombide Carreton, Tom Van Cutsem, Stijn Mostinckx, and Wolfgang De Meuter, *A Survey on Reactive Programming*, 2013, ACM Computing Surveys
- Jonas Boner, Dave Farley, Roland Kuhn, and Martin Thompson, *The Reactive Manifesto*, 2014
- Roland Kuhn, Brian Hanafee, and Jamie Allen, *Reactive Design Patterns*, 2017, Manning

## Related pages

- /paradigms/README.md
- /SECURE_CODING_REFERENCE.md
- /paradigms/dataflow.md
- /paradigms/event-driven.md
- /paradigms/functional.md
- /paradigms/declarative.md
- /paradigms/concurrent.md
