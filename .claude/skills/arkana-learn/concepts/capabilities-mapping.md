# Capabilities Mapping

Reference material for Module 2.5. Builds on Foundation knowledge of suspicious
imports and string extraction. This concept teaches learners to use capa output
for hypothesis generation, not as a source of conclusions.

---

## Core Concepts

### What capa Does

capa is a tool that analyses binaries and identifies their capabilities — what they
CAN do based on the code and data present. It works by matching a library of rules
against the binary's functions, instructions, and data patterns.

Each capa rule describes a specific behavior:
- **Rule name**: A human-readable description like "create process" or "encrypt data
  using AES"
- **Matched addresses**: The specific function(s) or locations where the rule matched
- **ATT&CK mapping**: The MITRE ATT&CK technique ID that the behavior corresponds to
  (e.g., T1059 Command and Scripting Interpreter, T1055 Process Injection)

capa rules match on:
- **API calls**: Imported or dynamically resolved function names
- **Byte patterns**: Specific instruction sequences or data constants
- **String patterns**: Strings that indicate specific behavior
- **Combinations**: Logical combinations of the above (e.g., "calls VirtualAllocEx
  AND calls WriteProcessMemory AND calls CreateRemoteThread")

### Understanding capa Output

Arkana's `get_capa_analysis_info()` returns a structured summary of all matched rules
grouped by ATT&CK tactic and technique. Key elements to read:

**Technique IDs**: ATT&CK IDs like T1055.001 tell you the specific sub-technique.
The tactic (the "why") groups related techniques: Execution, Persistence, Defense
Evasion, etc.

**Rule names**: Descriptive labels like "inject code via process hollowing" or "hash
data using CRC32." These describe the detected capability at a behavioral level.

**Matched addresses**: The function addresses where the rule matched. These are your
starting points for validation — decompile these functions to confirm the behavior.

**Match count**: How many rules matched in each category. A binary with 15 Defense
Evasion matches warrants closer scrutiny than one with 2 basic file operation matches.

### Capability Matches Are Indicators, Not Proof

This is the single most important concept in this module. A capa rule match means
the rule's byte patterns, API calls, or string patterns were found in the binary.
It does NOT mean the binary actually performs that behavior.

**Why matches can be misleading**:

- **Generic API patterns**: `VirtualAlloc` is used for memory allocation in all
  kinds of legitimate code. A rule matching on `VirtualAlloc` does not mean process
  injection.

- **Dead code**: The matched function may exist in the binary but never be called.
  Statically linked libraries pull in many functions that the program does not use.

- **Context-dependent behavior**: A function that encrypts data could be protecting
  legitimate user files or encrypting a C2 channel. The API calls are identical; the
  intent is completely different.

- **Compiler/runtime library code**: CRT startup code, exception handlers, and
  runtime library functions can match capa rules for capabilities the programmer
  never intended.

### Validating Capability Claims

Every significant capa match should be validated before reporting it as a confirmed
capability:

**Step 1: Decompile the matched function**
```
decompile_function_with_angr(matched_address)
```
Read the pseudocode. Does the function actually do what the rule claims?

**Step 2: Check cross-references**
```
get_function_xrefs(matched_address)
```
Who calls this function? Is it called from the main execution path, or is it
dead code? Is it part of a statically linked library?

**Step 3: Check the context**
What arguments are passed to the function? What happens with its return value?
A `CreateFile` call that opens "config.ini" for reading is very different from
one that opens "C:\Users\victim\Documents\secret.docx" for reading.

**Step 4: Corroborate with other evidence**
Does the import analysis support this capability? Do the strings contain related
indicators? If capa says "communicates over HTTP" but there are no URL strings and
no networking imports, the match may be a false positive.

### Building a Behavioral Profile

A behavioral profile combines multiple data sources to paint a complete picture of
what a binary does. No single source is sufficient on its own.

**Capa results**: What capabilities are present (with validation)
**Import analysis**: What OS functions the binary uses
**String analysis**: What operational data is embedded (URLs, paths, commands)
**Function analysis**: What the code actually does when decompiled

The value is in the intersection. When capa matches "encrypt data using AES,"
imports show `CryptEncrypt`, strings contain "ransom_note.txt," and decompilation
confirms a file encryption loop — that is a validated finding. Any one of those
alone would be insufficient.

### Understanding False Positives

False positives fall into several categories: **library code** (statically linked
CRT, STL, or Boost functions matching generic rules), **compiler-generated code**
(stack cookies, exception handlers, CRT init matching defensive rules), **overly
broad rules** (e.g., "access registry" matching any registry API usage), and
**multi-function matches** (a rule requiring API_A AND API_B matching when both exist
in the binary but in unrelated functions).

---

## Key Arkana Tools

| Tool | Purpose |
|------|---------|
| `get_capa_analysis_info()` | Full capa results with ATT&CK mappings and matched addresses |
| `get_capa_rule_match_details(rule_name)` | Deep dive into a specific rule — see exactly what matched and where |
| `get_extended_capabilities()` | Extended capability detection beyond standard capa rules |
| `get_focused_imports()` | Corroborate capability claims with actual import analysis |

---

## Teaching Moments During Guided Analysis

**When capa results first appear**: Explain the structure of the output — tactics,
techniques, rule names, addresses. Emphasise that this is a hypothesis list, not a
verdict. Each match is a question to investigate, not an answer.

**When a capa match looks alarming**: Walk through the validation process. Decompile
the matched function. Check xrefs. Determine whether the behavior is actually
malicious in context, or whether it is a benign use of the same API pattern.

**When capa misses something**: Point out that capa can only detect what it has rules
for. If the binary uses a custom encryption algorithm, capa will not flag it. If the
binary resolves APIs by hash at runtime, capa may miss the API calls entirely. Capa's
absence of a match does not mean absence of a capability.

**When building the final assessment**: Show how to weave together capa results,
imports, strings, and decompilation findings into a coherent behavioral profile. Each
source compensates for the others' blind spots.

---

## Socratic Questions

- "This capa rule matched — but does the function actually do what the rule suggests?"
  *Expected direction*: Decompile the matched function and read the pseudocode.
  Check whether the behavior described by the rule name is actually implemented, or
  whether the match is based on a superficial pattern.

- "How would you verify this capability claim?"
  *Expected direction*: Follow the validation process — decompile, check xrefs for
  reachability, examine arguments and context, corroborate with imports and strings.

- "Capa found 'encrypt data using RC4' — is this malicious?"
  *Expected direction*: Not necessarily. RC4 is used in many legitimate protocols
  and applications. The question is what is being encrypted and why. Decompile the
  function, find what data it processes, and trace where the encrypted output goes.

- "The capa results show no networking capabilities, but the binary has networking
  imports. What might explain this?"
  *Expected direction*: Capa's rules might not cover the specific networking pattern
  used. Or the networking code uses dynamic API resolution that capa did not follow.
  The import analysis is a separate evidence source — trust it independently.

- "This binary has 30 capa matches. Where do you start?"
  *Expected direction*: Prioritise by severity. Defense Evasion and Execution
  techniques are more interesting than basic file operations. Start with specific
  matches over generic ones.

---

## Common Mistakes

**Treating capa output as ground truth**: The most critical mistake. Capa provides
indicators that require validation. Reporting "the binary performs process injection"
because capa matched a rule, without decompiling the matched function, is sloppy
analysis that can lead to incorrect conclusions.

**Not validating matches**: Skipping the decompilation step and taking rule names at
face value. A match for "create service" might be the Windows service control manager
code in a legitimate service binary. Always verify.

**Missing capabilities that capa does not detect**: Capa is not omniscient. It cannot
detect custom cryptographic algorithms, novel evasion techniques, or behaviors
implemented through uncommon API patterns. The absence of a capa match is not evidence
of absence. Use imports, strings, and decompilation to find what capa missed.

**Ignoring match addresses**: capa tells you WHERE the rule matched. Ignoring these
addresses means losing the direct link to the relevant code. Always use the matched
addresses as entry points for deeper investigation.

**Reporting raw capa output without analysis**: Dumping capa results into a report
without interpretation adds noise, not signal. Reports should state which capabilities
were confirmed, which were false positives, and which remain unverified.
