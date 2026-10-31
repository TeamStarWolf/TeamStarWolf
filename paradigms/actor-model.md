# The Actor Model

The actor model treats the actor as the unit of computation: an entity with private state that communicates only by sending asynchronous messages. Actors share no memory, so there are no locks and no data races between them. It is a concurrency paradigm built for distribution and fault tolerance, realized most fully in Erlang/OTP and Akka.

## Core idea

An actor does three things in response to a message: send a finite number of messages to other actors, create a finite number of new actors, and set the behavior it will use for the next message. Nothing else. State lives inside the actor and is reached only through the messages it chooses to handle.

Because actors never touch each other's memory, concurrency control disappears as a separate concern. Each actor processes one message at a time, so its own state is never accessed concurrently. Coordination becomes a question of what messages flow where, not of which lock protects which field.

## How it works

Every actor owns a mailbox, a queue where incoming messages wait. The actor runs a receive loop: take the next message, match it against the behaviors it understands, act, and return to waiting. Sends are asynchronous and the sender does not block, so the mailbox decouples producer speed from consumer speed.

Message delivery is addressed, not shared. A sender needs only a reference to the target, often called a process identifier or an actor reference. This gives location transparency: the reference works the same whether the target runs in the same process or on another machine, so the same code scales from one node to a cluster.

```erlang
-module(counter).
-export([start/0, loop/1]).

start() -> spawn(?MODULE, loop, [0]).

loop(Count) ->
    receive
        {increment, N} ->
            loop(Count + N);          % new behavior = new state
        {get, From} ->
            From ! {count, Count},     % reply by sending a message
            loop(Count)
    end.
```

The actor keeps no mutable variable for its count. It carries state as the argument to the next `loop` call, and it replies by sending rather than returning. A client sends `Pid ! {increment, 1}` and later `Pid ! {get, self()}`, then waits in its own `receive` for the answer.

Fault tolerance is the model's second pillar. Erlang's guidance is "let it crash": do not pepper code with defensive checks for states you did not expect; let the actor fail cleanly and let a supervisor restart it to a known-good state. This works because an actor's failure cannot corrupt another actor's memory.

Supervision organizes this into a tree. Supervisors are actors whose job is to start child actors, watch them, and apply a restart strategy when a child dies. A strategy may restart only the failed child, or restart a group whose members depend on each other. The result is a system that recovers from faults without a global shutdown.

Two realizations dominate. Erlang and its OTP framework bake actors into the runtime, where processes are extremely cheap and isolated, and OTP supplies ready supervision and server behaviors. Akka brings the model to the JVM as a library, with actor references, mailboxes, and supervision built on a thread pool.

## Strengths and trade-offs

The model removes shared-state races by construction, which eliminates a whole category of defect. Isolation plus supervision gives resilience: parts fail and recover independently. Location transparency lets the same program run on one node or many, so the design and the distributed deployment match.

The trade-offs are real. Asynchronous messaging makes control flow harder to follow than a direct call, and request-reply must be built from one-way sends. Mailboxes are unbounded by default, so a fast sender can grow a slow actor's queue until memory runs out. Delivery guarantees are weak: most systems promise at-most-once delivery, and ordering holds only between a single pair of actors, so protocols must tolerate lost or reordered messages.

## Languages and tools

[Erlang](/languages/erlang.md) implements actors as runtime processes with OTP supervision and is the reference realization of the model. [Elixir](/languages/elixir.md) runs on the same BEAM virtual machine and exposes the same process and supervision facilities with a different surface syntax. [Scala](/languages/scala.md) reaches the model through the Akka library, which supplies typed actors, routers, and supervision on the JVM.

## Secure-coding considerations

See /SECURE_CODING_REFERENCE.md. Message isolation removes the classic data race, CWE-362, within a system, since no two actors share memory. The hazard moves to resource exhaustion: an unbounded mailbox fed by an attacker is a denial-of-service path, CWE-400 (uncontrolled resource consumption). Apply backpressure, bound queues, or drop load under pressure.

Messages crossing a trust boundary are untrusted input. A process that deserializes an incoming term must validate it, because decoding attacker-controlled data can trigger CWE-502 (deserialization of untrusted data) or exhaust memory with crafted payloads. Treat every external message as data to be checked, not as a command to obey, and keep internal actor references from leaking to untrusted peers.

## Resources

- Carl Hewitt, Peter Bishop, and Richard Steiger, *A Universal Modular ACTOR Formalism for Artificial Intelligence*, 1973, IJCAI
- Gul Agha, *Actors: A Model of Concurrent Computation in Distributed Systems*, 1986, MIT Press
- Joe Armstrong, *Making Reliable Distributed Systems in the Presence of Software Errors*, 2003, PhD thesis, KTH
- Joe Armstrong, *Programming Erlang: Software for a Concurrent World*, 2013, Pragmatic Bookshelf

## Related pages

- /paradigms/README.md
- /SECURE_CODING_REFERENCE.md
- /paradigms/concurrent.md
- /paradigms/event-driven.md
- /paradigms/functional.md
- /paradigms/reactive.md
