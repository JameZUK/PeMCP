# Concept Reference: Campaign Analysis

Expert tier reference for Module 4.4. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

Campaign analysis moves beyond individual sample analysis to the strategic
level: comparing related samples, tracking how a malware family evolves over
time, mapping the infrastructure behind operations, and attributing activity
to threat groups. A single sample tells you what the malware does. Campaign
analysis tells you who is behind it, how they operate, and where they are
going next.

This requires multi-sample workflows, systematic comparison, and the ability to
synthesize findings across binaries into a coherent narrative.

## Why Compare Samples

### Track Evolution

Malware families are software projects. They have versions, bug fixes, feature
additions, and refactoring — just like legitimate software. Comparing versions
reveals:
- New capabilities added (new C2 protocol, new persistence mechanism)
- Capabilities removed (dropped features suggest operational pivot)
- Bug fixes (patched crashes suggest active development and testing)
- Code reuse from other families (shared libraries, copied techniques)

### Identify Infrastructure

Extracting C2 configs from multiple samples over time builds an infrastructure
map: which servers are active, how long each is used, whether the operator
rotates IPs or domains, and geographic distribution patterns.

### Attribute Activity

Consistent code patterns, compilation artefacts, working hours (from timestamps),
language strings, and tooling choices build a profile of the developer or
operator. This is not forensic attribution (identifying a person) but operational
attribution (connecting activity to a consistent actor).

## Binary Diffing

Binary diffing compares two binaries at the structural level to identify what
changed between them. This is not a text diff — it operates on functions,
basic blocks, and control flow.

```
Tool: diff_binaries()

Compares the currently loaded binary against a second binary. Reports:
- Functions present in both (matched) — with a similarity score
- Functions added (present in B but not A)
- Functions removed (present in A but not B)
- Functions modified (present in both but with changes)

Example output:
  Comparison: sample_v1.exe vs sample_v2.exe
  Matched functions: 142 (85% identical)
  Modified functions: 18
  Added in v2: 7
  Removed in v2: 3

  Notable changes:
    0x00401A00 (decrypt_config): 92% similar — XOR key changed
    0x00402500 (c2_connect): 78% similar — added TLS support
    0x00403000 (new): persist_via_scheduled_task — new persistence method
```

### Interpreting Diff Results

- **High match rate (>90%)**: minor update — config change, bug fix, or small
  feature addition. Same developer, same codebase.
- **Moderate match rate (60-90%)**: significant update — new features, refactored
  modules, possibly new compiler or build settings.
- **Low match rate (<60%)**: major rewrite, different variant, or possibly a
  different family that shares some code.

## Similarity Hashing

Similarity hashes provide a fast, approximate way to cluster samples without
full binary diffing. Each hash captures different structural properties.

```
Tool: compute_similarity_hashes()

Generates multiple hash types for the loaded binary:
  ssdeep: 384:abc123def456...
  TLSH:   T1A2B3C4D5E6F7...
  imphash: a1b2c3d4e5f6...
```

### ssdeep (Fuzzy Hashing)

ssdeep produces a context-triggered piecewise hash. Samples with small
modifications (patched bytes, changed strings) will have similar ssdeep hashes.

**Best for**: detecting minor variants — same binary with different C2 configs,
recompiled with minor changes, or patched with a hex editor.

**Limitation**: sensitive to structural changes. Recompilation, reordering
functions, or adding/removing sections drastically changes the ssdeep hash
even if the logic is identical.

### TLSH (Trend Micro Locality Sensitive Hash)

TLSH is a statistical similarity hash based on byte frequency distributions.
It is more robust to structural changes than ssdeep because it captures
statistical properties rather than byte-level sequences.

**Best for**: detecting samples from the same family even when recompiled or
moderately modified. Good for clustering large sample sets.

**Limitation**: less precise than ssdeep for near-identical samples. May cluster
unrelated samples that happen to have similar byte distributions.

### imphash (Import Hash)

imphash is the MD5 hash of the ordered import table (DLL names + function names,
lowercased). Samples that import the same functions in the same order produce
the same imphash.

**Best for**: clustering samples built from the same source code with the same
compiler and linker settings. Extremely effective for identifying builder-generated
samples where only the config changes.

**Limitation**: any change to imports (adding a function, reordering, different
compiler version) changes the imphash entirely. Packed samples all have similar
imphashes (they import only the unpacking APIs).

```
Tool: compare_file_similarity()

Compares the loaded binary's similarity hashes against another file and
reports a similarity score for each hash type.
```

## Multi-File Workflows in PeMCP

Campaign analysis requires working with multiple samples. PeMCP supports this
through file management and persistent notes.

### Opening and Switching Files

```
Tool: open_file(file_path)    — load a new sample
Tool: close_file()            — close the current sample
Tool: list_samples()          — see all loaded/available samples
```

### Persistent Notes

Notes are associated with the analysis session and persist across file switches.
Use them to track findings across samples:

```
Tool: add_note(title="Sample 1 - v1.0", content="C2: 192.168.1.50:443, ...")
Tool: add_note(title="Sample 2 - v1.1", content="C2: 10.0.0.100:8443, ...")
Tool: get_notes()  — retrieve all notes for cross-reference
```

### Project Export/Import

Save and restore entire analysis sessions, including notes, analysis results,
and tool history:

```
Tool: export_project()  — save current session state
Tool: import_project()  — restore a previous session
```

## Building Campaign Timelines

### Compilation Timestamps

```
Tool: get_pe_metadata()

The PE header contains a TimeDateStamp field set by the linker at compile time.
While this can be forged, many malware authors do not bother, making it a
useful chronological marker.

Example across a campaign:
  sample_a.exe: 2024-03-15 08:30:00 UTC
  sample_b.exe: 2024-04-02 14:15:00 UTC
  sample_c.exe: 2024-04-02 14:22:00 UTC  (7 minutes after sample_b)
  sample_d.exe: 2024-05-10 09:00:00 UTC
```

Patterns to look for:
- **Consistent working hours**: suggest the developer's timezone
- **Burst compilations**: multiple samples minutes apart suggest a builder tool
  generating variants with different configs
- **Regular intervals**: monthly updates suggest a development cycle

### Config Changes Over Time

Extract and compare C2 configs from each sample to map infrastructure evolution:

```
Timeline:
  March 2024:  C2 = 192.168.1.50:443     (initial infrastructure)
  April 2024:  C2 = 10.0.0.100:8443      (rotated IP and port)
  April 2024:  C2 = 10.0.0.100:8443      (same — batch from builder)
  May 2024:    C2 = evil-domain.xyz:443   (switched to domain-based C2)
```

This reveals operational patterns: how often infrastructure rotates, whether
the operator prefers IPs or domains, and when they make significant changes.

## Socratic Questions

- "Two samples have 95% function similarity but different C2 configs. What does
  this tell you about how the samples were produced?"
  (Leads to: a builder tool that compiles once and patches configs per target)
- "Sample A has a compile timestamp of 2024-03-15 and sample B has 2024-03-14.
  But B has a feature that A does not. What might explain this?"
  (Leads to: timestamps can be forged, or development is non-linear with
  feature branches)
- "Three samples share the same imphash but have different ssdeep hashes. What
  does that combination tell you?"
  (Leads to: same imports/structure but different embedded data — likely config
  changes or different payloads in the same framework)
- "You have extracted C2 configs from 10 samples spanning 6 months. What
  analysis would you perform next?"
  (Leads to: build a timeline, map infrastructure, identify rotation patterns,
  check if domains share registrar/hosting, look for operational security lapses)

## Common Mistakes

### Trusting compilation timestamps unconditionally

PE timestamps are trivially forged. Some malware families deliberately set
future dates, epoch zero, or random values. Use timestamps as one data point
among many, not as ground truth. Corroborate with other temporal indicators
(certificate validity periods, domain registration dates, first-seen dates
from VirusTotal).

### Clustering by single hash type

No single hash captures all dimensions of similarity. Two samples with
different imphashes may be from the same family (different compiler settings).
Two samples with similar ssdeep may be from different families (coincidental
byte patterns). Always use multiple hash types and corroborate with structural
comparison.

### Analysing packed samples for comparison

Comparing packed samples tells you about the packer, not the payload. Always
unpack before computing similarity hashes, diffing, or comparing features.
The packer's code dominates the comparison and masks the actual malware's
characteristics.

### Losing track across files

Campaign analysis involves switching between many samples. Without systematic
notes, findings from sample 3 are forgotten by the time you reach sample 7.
Use `add_note` consistently to record key findings (C2, hashes, notable
functions, version indicators) for each sample as you analyse it.
