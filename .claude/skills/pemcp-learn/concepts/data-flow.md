# Concept Reference: Data Flow Analysis

Advanced tier reference for Module 3.1. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

Data flow analysis answers the question "where does this value come from, and
where does it go?" Static analysis can read individual instructions, but data
flow connects those instructions into chains of cause and effect. This is what
separates reading code from understanding code.

### Reaching Definitions

A reaching definition answers: "at this program point, which earlier assignments
could have produced the current value of variable X?" A definition of X
*reaches* a point P if there is a path from the definition to P along which X
is not redefined.

**When to use**: When you see a variable used in a function and need to know
where its value was assigned. Critical for understanding encryption key loading,
configuration parsing, and function parameter origins.

```
Tool: get_reaching_definitions(function_address)

Example output:
  Variable: ecx at 0x00401050
  Defined at:
    - 0x00401032: mov ecx, [ebp-0x10]   (from local variable)
    - 0x00401028: mov ecx, [eax+0x4]    (from struct field, conditional path)
```

### Def-Use Chains

Def-use chains connect each definition of a variable directly to every place
that definition is used. This is the inverse perspective of reaching definitions:
instead of asking "where did this value come from?" you ask "where does this
assigned value get consumed?"

**When to use**: After you have identified a variable assignment (a key being
loaded, a buffer being allocated) and need to see everywhere that value is
subsequently read.

```
Tool: get_data_dependencies(function_address)

Example output:
  Definition: eax = call malloc(0x100) at 0x004010A0
  Used at:
    - 0x004010B0: mov [eax], edx        (write to allocated buffer)
    - 0x004010C8: push eax              (passed as argument to encrypt())
    - 0x004010F0: push eax              (passed as argument to free())
```

### Control Dependencies

Control dependency analysis identifies which conditional branches guard which
blocks of code. Block B is control-dependent on block A if A's branch decision
determines whether B executes.

**When to use**: When you need to understand what conditions must be satisfied
for a specific code path to execute. Essential for understanding anti-analysis
checks ("this decryption only runs if IsDebuggerPresent returns 0") and
configuration-driven behaviour.

```
Tool: get_control_dependencies(function_address)

Example output:
  Block 0x00401080 (decrypt_config):
    Depends on: branch at 0x00401060 (taking FALSE path)
    Condition: cmp [ebp-0x4], 0  /  jnz 0x004010A0
    Meaning: block executes only when local variable equals 0
```

### Constant Propagation

Constant propagation traces known constant values through assignments and
arithmetic operations, resolving expressions that the decompiler may leave
as computed values. This is especially valuable against obfuscation that
computes values at runtime from constants to hide them from static string
extraction.

**When to use**: When you see expressions like `x = 0x41 ^ 0x73` or chains of
arithmetic that produce a value the author wanted to hide. Also useful to
simplify obfuscated control flow where opaque predicates use constant math.

```
Tool: propagate_constants(function_address)

Example output:
  0x00401030: mov eax, 0x12345678
  0x00401035: xor eax, 0x12345000
  0x0040103A: add eax, 0x10
  => Propagated value at 0x0040103A: eax = 0x688
     (resolves to a port number: 1672)
```

### Backward Slicing

A backward slice from variable V at point P includes all statements that could
affect V's value at P. You start at the point of interest and trace backwards
through data flow, collecting every instruction in the dependency chain.

**When to use**: This is the primary tool for key tracing. When you find an
encryption function that takes a key parameter, backward slice from that
parameter to discover where the key originates — hardcoded bytes, derived from
a hash, read from a resource, or received over the network.

```
Tool: get_backward_slice(function_address, target_variable)

Example scenario: "The call to AES_encrypt at 0x00401200 takes key in ecx.
Where does the key come from?"

Backward slice of ecx at 0x00401200:
  0x004011F0: mov ecx, [ebp-0x20]         <- loaded from local
  0x004011C0: mov [ebp-0x20], eax         <- stored from eax
  0x004011B8: call derive_key             <- eax = return value
  0x004011B0: push [ebp+0x8]             <- argument: password from caller
  => Key is derived from a password passed by the calling function
```

### Forward Slicing

A forward slice from variable V at point P includes all statements that are
affected by V's value. You start at a definition and trace forward through
the program to see everywhere that value propagates.

**When to use**: Taint tracking. When you identify an input source (network
recv, file read, user input) and want to know what the program does with that
data — does it reach an exec() call? Is it used as an index without bounds
checking? Does the received C2 command propagate to a dispatch table?

```
Tool: get_forward_slice(function_address, source_variable)

Example scenario: "recv() stores data in buffer at [ebp-0x100]. What happens
to that data?"

Forward slice of [ebp-0x100] from 0x00401300:
  0x00401310: movzx eax, byte [ebp-0x100]   <- first byte read as command ID
  0x00401318: cmp eax, 0x10                  <- compared against dispatch table
  0x00401330: call handlers[eax]             <- used as index into handler array
  => Received data is used as a command dispatch index (C2 command handler)
```

### Value Set Analysis

Value set analysis (VSA) tracks the possible set of values a variable (especially
a pointer) could hold at each program point. Unlike constant propagation, which
works only when values are fully determined, VSA handles ranges and sets of
possible values.

**When to use**: When you need to understand what memory a pointer could reference.
Critical for resolving indirect calls (`call [eax]` — what could eax point to?),
understanding buffer access patterns, and analysing pointer arithmetic.

```
Tool: get_value_set_analysis(function_address)

Example output:
  Variable: eax at 0x00401400
  Possible values: {0x00403000..0x00403100}  (points into .data section)
  Variable: ecx at 0x00401420
  Possible values: {0, 1, 2, 3}              (loop counter, bounded)
```

## Choosing the Right Analysis

| Question you are asking | Tool to use |
|---|---|
| "Where does this value come from?" | `get_backward_slice` or `get_reaching_definitions` |
| "What happens to this value after here?" | `get_forward_slice` |
| "What conditions must be true for this code to run?" | `get_control_dependencies` |
| "Can I simplify this obfuscated expression?" | `propagate_constants` |
| "What could this pointer be pointing to?" | `get_value_set_analysis` |
| "Show me all definitions and uses of a variable" | `get_data_dependencies` |

## Socratic Questions

Use these during analysis when data flow concepts are relevant.

- "The encryption function takes a key parameter — where does the caller get
  that value from?" (Leads to: backward slicing from the call site)
- "If we modify this variable here, what other code is affected?"
  (Leads to: forward slicing to trace impact)
- "This block decrypts the config, but under what conditions does it actually
  execute?" (Leads to: control dependency analysis)
- "The decompiler shows `x = (a ^ b) + c` — can we figure out what x actually
  is without running the code?" (Leads to: constant propagation)
- "This function pointer is loaded from a table — what functions could it
  actually call?" (Leads to: value set analysis)

## Common Mistakes

### Confusing data flow with control flow

Data flow tracks values through assignments and uses. Control flow tracks
execution order through branches and jumps. They are complementary: control
flow determines which data flow paths are possible. When a learner asks "why
does execution go here?" that is a control flow question. When they ask "why
does this variable have this value?" that is a data flow question.

### Over-relying on decompiler output instead of using data flow tools

The decompiler shows you the code, but it does not highlight the dependency
chains. Reading decompiled code is like reading a novel — you see the narrative.
Data flow analysis is like a detective's evidence board — you see the connections.
For complex functions (>50 lines of pseudocode), data flow tools are often faster
and more accurate than trying to manually trace values through the decompiler.

### Ignoring inter-procedural flow

Data flow tools in PeMCP operate within a single function by default. When a
value crosses a function boundary (passed as argument, returned as result), you
need to chain analyses: backward slice in the callee to the parameter, then
switch to the caller and backward slice from the argument at the call site.

### Expecting perfect precision

Static data flow analysis is inherently conservative — it may report that a
variable could come from multiple definitions when at runtime only one is
possible. This is a feature, not a bug. The analysis is sound (it never misses
a real dependency) but may be imprecise (it may include spurious dependencies).
When precision matters, combine static analysis with emulation.
