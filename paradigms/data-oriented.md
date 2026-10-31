# Data-Oriented Design

Data-oriented design organizes a program around the data it processes and how that data sits in memory, rather than around objects that bundle state with behavior. It is a cross-cutting design discipline, not a language feature, driven by the gap between processor speed and memory latency. It matters most where throughput decides success: game engines, simulations, compilers, and high-volume data processing.

## Core idea

The starting premise is that the hardware is the real platform. A modern CPU stalls for hundreds of cycles on a cache miss, so the layout that feeds the cache well often beats the layout that models the domain cleanly. Design therefore begins by asking what data exists, how much of it, and in what order the program touches it.

From that question follows the central choice between two layouts. Array-of-structures (AoS) stores each entity's fields together, which is the natural object layout. Structure-of-arrays (SoA) stores each field in its own contiguous array, so all the positions sit together, all the velocities sit together, and so on.

SoA wins when a pass reads only some fields of many entities. Walking one packed array brings only the needed bytes into cache and lets the compiler vectorize the loop. AoS wins when a pass reads most fields of one entity at a time, since those fields share a cache line.

## How it works

The method is to group data by access pattern and process it in homogeneous batches. Instead of calling a virtual `update` on each heterogeneous object, you collect like data and run one tight loop over it. The loop body stays branch-light and predictable, which keeps both the cache and the instruction pipeline busy.

Consider a particle system. The object-shaped version stores an array of particle structs and updates each in turn, so every iteration loads position, velocity, color, and lifetime even though the physics step touches only two of them.

```cpp
struct Particle { float x, y, z;  float vx, vy, vz;  uint32_t color; };
std::vector<Particle> particles;            // array of structures

for (auto& p : particles) {                 // loads color too, wastefully
    p.x += p.vx;  p.y += p.vy;  p.z += p.vz;
}
```

The data-oriented version splits the fields into parallel arrays. The integration pass now streams three position arrays and three velocity arrays, and never loads `color` at all.

```cpp
struct Particles {                          // structure of arrays
    std::vector<float> x, y, z;
    std::vector<float> vx, vy, vz;
    std::vector<uint32_t> color;
};

for (size_t i = 0; i < p.x.size(); ++i) {   // contiguous, vectorizable
    p.x[i] += p.vx[i];  p.y[i] += p.vy[i];  p.z[i] += p.vz[i];
}
```

The second loop reads contiguous memory, so the prefetcher stays ahead and the compiler can emit SIMD instructions that update several particles per step. The win comes from the layout, not from a cleverer algorithm. Measured on large particle counts, the SoA pass commonly runs several times faster for this reason.

The discipline extends beyond layout. Hot and cold fields are separated, so rarely touched data does not pollute cache lines holding hot data. Work is sorted to make branches predictable and to group identical operations. Identifiers and indices often replace pointers, which shrinks records and keeps references valid across reallocation.

## Strengths and trade-offs

The payoff is throughput: fewer cache misses, more successful prefetches, and loops the compiler can vectorize. Batching homogeneous data also simplifies parallelism, because a flat array splits cleanly across threads or SIMD lanes with no shared-object contention. Memory use often drops, since packed arrays avoid per-object padding and headers.

The costs are in expressiveness and maintenance. SoA code is further from the domain model, so a single logical entity is scattered across several arrays and harder to reason about in isolation. Inserting and removing elements needs care to keep parallel arrays aligned, and premature restructuring can obscure code that was never a bottleneck. The honest rule is to measure first and restructure the hot paths, not the whole system.

## Languages and tools

The style is most associated with [C++](/languages/cpp.md) in game and engine development, where control over memory layout is direct and the performance stakes are high. [Rust](/languages/rust.md) supports it well, and its ecosystem includes entity-component-system libraries that store components in SoA form by default. [Zig](/languages/zig.md) provides explicit layout control and a standard multi-array type that stores a struct's fields as parallel arrays.

Entity-component-system architecture is the best-known application of these ideas. It stores components in contiguous arrays and runs systems as batched loops over them, turning data-oriented design into a reusable engine structure.

## Secure-coding considerations

Manual index management across parallel arrays invites out-of-bounds access, since one array can be resized while another is not. This maps to CWE-787 (Out-of-bounds Write) and CWE-125 (Out-of-bounds Read). Keep parallel arrays in a single container that resizes them together, and bound-check indices derived from external data.

Replacing pointers with indices is safer against use-after-free but introduces a new failure: a stale index that still points into a reused slot, a form of CWE-416 behavior at the logical level. Use generational indices or version tags so a reused slot rejects an outdated handle. See /SECURE_CODING_REFERENCE.md for memory-safety and bounds-checking guidance.

## Resources

- Richard Fabian, *Data-Oriented Design: Software Engineering for Limited Resources and Short Schedules*, 2018
- Mike Acton, *Data-Oriented Design and C++*, 2014, CppCon talk
- Noel Llopis, *Data-Oriented Design (Or Why You Might Be Shooting Yourself in the Foot With OOP)*, 2009, Game Developer Magazine

## Related pages

- /paradigms/README.md
- /SECURE_CODING_REFERENCE.md
- /paradigms/object-oriented.md
- /paradigms/array-oriented.md
- /paradigms/procedural.md
- /paradigms/generic.md
