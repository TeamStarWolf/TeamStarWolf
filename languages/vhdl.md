# VHDL

VHDL (VHSIC Hardware Description Language) is a strongly typed language for describing, simulating, and synthesizing digital electronic systems. It was created under a United States Department of Defense program in the early 1980s and standardized by the IEEE in 1987. A VHDL design describes hardware that exists concurrently rather than a sequence of instructions, so the same source can be simulated for verification and synthesized into gates for an FPGA or ASIC. It is used for digital circuit design, modeling, and verification.

| Attribute | Value |
|---|---|
| Paradigm | Concurrent, declarative hardware description; dataflow, behavioral, and structural styles |
| Typing | Static, strong, with user-defined types and subtypes |
| First appeared | 1987 (IEEE 1076-1987) |
| Memory model | Hardware model: signals, variables, and constants, not heap-allocated memory |
| Reference standard / toolchain | [IEEE 1076](https://standards.ieee.org/ieee/1076/10800/); simulators [GHDL](https://github.com/ghdl/ghdl), Questa, Vivado; synthesis via vendor tools |
| Typical uses | FPGA and ASIC design, digital logic modeling, hardware verification |
| Governance | [IEEE Standards Association](https://standards.ieee.org/) (IEEE 1076 working group) |

Related: [Verilog](/languages/verilog.md), [SystemVerilog](/languages/systemverilog.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

VHDL began as a documentation and simulation language for the Very High Speed Integrated Circuit (VHSIC) program, so that hardware behavior could be described in a vendor-neutral, machine-readable form. The IEEE published the first standard as IEEE 1076-1987, with later revisions in 1993, 2002, 2008, and 2019 that added features such as the `std_logic` nine-value logic system (via IEEE 1164), fixed- and floating-point packages, and interface improvements. The language is defined by the IEEE 1076 Language Reference Manual.

VHDL and Verilog are the two established hardware description languages. VHDL is more verbose and more strongly typed; Verilog is terser. Many organizations use both, sometimes in a single project, and simulators and synthesis tools generally accept each.

## Paradigm and type system

A VHDL description is inherently concurrent: statements inside an architecture execute together, modeling signals that change over time, not a step-by-step program. Processes contain sequential statements, but each process runs concurrently with the others and communicates through signals.

The type system is static and strict. Operations between unrelated types are rejected, and conversions must be explicit. Core types include `std_logic` and `std_logic_vector` from the IEEE 1164 package, integers with explicit ranges, enumerations, records, and arrays. A `signal` models a wire whose value is scheduled for a future simulation time; a `variable` inside a process updates immediately.

```vhdl
signal count : unsigned(7 downto 0) := (others => '0');
constant WIDTH : integer := 8;
type state_t is (IDLE, RUNNING, DONE);
```

## Toolchain and ecosystem

- Simulation: [GHDL](https://github.com/ghdl/ghdl) is an open-source simulator; commercial options include Siemens Questa and Aldec Riviera. Simulators run a testbench that drives inputs and checks outputs over time.
- Synthesis: vendor tools such as AMD/Xilinx Vivado and Intel Quartus translate a synthesizable subset into a gate-level netlist for a target device.
- Waveform viewing: [GTKWave](https://gtkwave.sourceforge.net/) displays the value-change dump that a simulation produces.
- Linting and style: VSG (VHDL Style Guide) checks formatting and common issues.

```bash
ghdl -a counter.vhd        # analyze
ghdl -e counter            # elaborate
ghdl -r counter --vcd=out.vcd   # run, writing a waveform
```

## Syntax tour

```vhdl
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

-- Entity: the external interface (ports)
entity counter is
  port (
    clk   : in  std_logic;
    reset : in  std_logic;
    count : out std_logic_vector(7 downto 0)
  );
end entity;

-- Architecture: the implementation
architecture rtl of counter is
  signal value : unsigned(7 downto 0) := (others => '0');
begin
  -- A process sensitive to the clock models a register
  process (clk)
  begin
    if rising_edge(clk) then
      if reset = '1' then
        value <= (others => '0');
      else
        value <= value + 1;
      end if;
    end if;
  end process;

  count <= std_logic_vector(value);  -- concurrent assignment
end architecture;
```

## Idioms and different approaches

- Separate the `entity` (interface) from one or more `architecture` bodies, which lets a model have both a behavioral and a structural implementation.
- Model registers with a clocked process guarded by `rising_edge(clk)`; model combinational logic with concurrent assignments or a process whose sensitivity list names every input it reads.
- Use `numeric_std` with `unsigned` and `signed` for arithmetic rather than the older, nonstandard arithmetic packages.
- Keep a clear boundary between the synthesizable subset (what the hardware tools accept) and simulation-only constructs such as `wait for 10 ns`, file I/O, and assertions.
- Use `generic` parameters to make a component reusable across widths and depths.

## Design principles

VHDL was designed for precise, vendor-neutral description of hardware across its life cycle, from specification through simulation to synthesis. Strong typing and explicit conversions were deliberate: in hardware, a silent width mismatch or a stray sign extension produces wrong circuits, so the language forces the designer to state intent. The separation of interface from implementation and the heavy use of libraries and packages support large designs built from reusable parts.

## Standard library and notable packages

The IEEE standard packages are the core libraries. `std_logic_1164` defines the nine-value logic type used for synthesis and simulation. `numeric_std` defines `signed` and `unsigned` arithmetic. `std.textio` and `std.env` support file input/output and simulation control in testbenches. Design reuse happens through user packages and through vendor and open libraries of components; higher-level verification often uses frameworks such as [OSVVM](https://osvvm.org/) and [UVVM](https://github.com/UVVM/UVVM) for structured, constrained-random testbenches.

## Testing and packaging

Verification is done with a testbench: a VHDL module with no ports that instantiates the design, drives stimulus, and checks results with `assert` statements. There is no package registry in the software sense; reuse is by source files, libraries, and IP (intellectual property) blocks shared within and between organizations. The [VUnit](https://vunit.github.io/) framework adds a test runner and assertion library on top of a simulator.

```vhdl
-- Testbench excerpt
stim : process
begin
  reset <= '1';
  wait for 20 ns;
  reset <= '0';
  wait for 100 ns;
  assert count /= "00000000"
    report "counter did not advance" severity error;
  wait;
end process;
```

## Performance and concurrency

Hardware is concurrent by nature, and VHDL models that directly, so "performance" has two distinct meanings.

- Simulation speed is how fast a simulator evaluates the model on a workstation. Event-driven simulators schedule signal updates; large designs with fine-grained timing run slowly, so testbenches often simulate at the register-transfer level rather than gate level.
- Synthesis results are the speed and area of the real circuit: the maximum clock frequency, the gate count, and the power. These come from the synthesis and place-and-route tools, constrained by timing you specify, not from the language itself.

A key discipline is that simulation and synthesis can disagree. Code that simulates one way may synthesize to different hardware if it falls outside the synthesizable subset or relies on simulation-only timing. Designers keep to the synthesizable subset for anything that becomes hardware and confirm behavior in both.

## Common pitfalls

- Incomplete sensitivity lists in combinational processes cause simulation to differ from the synthesized hardware; list every signal read, or use the VHDL-2008 `process (all)` form.
- Unintended latches arise when a combinational process does not assign a signal on every path; assign defaults at the top of the process.
- Mixing `std_logic_vector` with arithmetic without `numeric_std` conversions produces type errors or, with legacy packages, ambiguous results.
- Initial values on signals are honored in simulation but are not a reset in real hardware for many device families; use an explicit reset.
- Metavalues (`'U'`, `'X'`, `'Z'`) propagate; treating them as `'0'` hides real problems.

## Secure coding

Hardware description carries risks that software tooling does not, so the secure-coding focus is trust, supply chain, and the gap between what is simulated and what is built:

- Simulation-versus-synthesis mismatch: logic that passes simulation can synthesize to different hardware (through latch inference, incomplete sensitivity lists, or non-synthesizable constructs), shipping a circuit that was never actually verified. Keep to the synthesizable subset, lint for latch inference, and run gate-level simulation of the synthesized netlist. This is a correctness-and-trust concern related to [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html)-style processor and hardware behavior gaps; treat unverified synthesis output as untrusted.
- Hardware trojans and supply chain: third-party IP cores, vendor macros, and even synthesis tools can introduce or hide malicious logic that no source review catches. Verify provenance of IP, review and simulate third-party blocks, and track them as dependencies. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).
- Debug and test access left enabled: JTAG, scan chains, and debug ports that remain active in production expose internal state and can bypass controls; gate or disable them for shipped devices.
- Hardcoded secrets in RTL: keys or device credentials written into the source become fixed in silicon and are extractable, matching [CWE-798](https://cwe.mitre.org/data/definitions/798.html). Provision secrets at manufacture or into secure elements instead.

Tooling: use a linter such as VSG and the synthesis tool's own warnings (latch and multi-driver reports) as a first line; apply formal equivalence checking between RTL and netlist for high-assurance parts. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [IEEE 1076 standard](https://standards.ieee.org/ieee/1076/10800/), the formal definition.
- [GHDL documentation](https://ghdl.github.io/ghdl/), for the open-source simulator.
- [VUnit](https://vunit.github.io/) and [OSVVM](https://osvvm.org/), for structured verification.

## Related pages

- [Verilog](/languages/verilog.md)
- [SystemVerilog](/languages/systemverilog.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
