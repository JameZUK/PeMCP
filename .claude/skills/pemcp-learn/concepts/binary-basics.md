# Concept Reference: Binary Basics

Foundation tier reference for Module 1.1. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

A binary (or executable) is the end product of compiling source code into machine
instructions that a processor can execute directly. Reverse engineering is the
practice of working backwards from the binary to understand what the original
program does, without having the source code.

### The Compilation Pipeline

Explain this as a sequence of transformations, each removing human-readable
information and adding machine-specific structure:

1. **Source code** (.c, .cpp, .rs) — what the programmer wrote
2. **Preprocessor** — expands macros, includes headers, strips comments
3. **Compiler** — translates to assembly (human-readable CPU instructions)
4. **Assembler** — converts assembly to machine code (raw bytes the CPU reads)
5. **Linker** — combines multiple object files, resolves references to libraries,
   produces the final binary with headers, sections, and metadata

Each step discards information. Variable names, comments, and high-level structure
are progressively lost. This is why reverse engineering is hard — and why tools
like PeMCP exist to recover as much meaning as possible.

### The Shipping Container Analogy

Use this analogy consistently throughout Foundation tier teaching:

- **The container itself** = the binary file on disk
- **The manifest/bill of lading** = headers (PE header, ELF header) that describe
  what is inside, where it came from, and where things are located
- **The cargo hold sections** = code and data sections (.text, .data, .rdata)
- **The delivery label** = the entry point — tells the OS where to start executing
- **Customs declaration** = imports and exports — what the binary needs from the OS
  and what it offers to other programs
- **Shipping line branding** = magic bytes — the first few bytes that identify what
  kind of container this is

Extend the analogy: "Reverse engineering a binary is like receiving a sealed
shipping container with no documentation. You can read the manifest, inspect the
cargo, and figure out what it was built to carry — even without the original
shipping documents (source code)."

## File Formats

Teach that the binary format is determined by the **target operating system**, not
the programming language or CPU architecture.

| Format | OS | Magic Bytes | Extension |
|--------|------|-------------|-----------|
| **PE** (Portable Executable) | Windows | `4D 5A` ("MZ") | .exe, .dll, .sys, .scr |
| **ELF** (Executable and Linkable Format) | Linux, Android, BSD | `7F 45 4C 46` (".ELF") | none, .so, .o |
| **Mach-O** (Mach Object) | macOS, iOS | `FE ED FA CE` or `CF FA ED FE` | none, .dylib |

Key teaching points:
- The same C code compiled on different platforms produces different binary formats
- Magic bytes are the first thing any analysis tool checks — they are the binary's
  "file type fingerprint"
- A `.exe` extension does not make something a PE file — always verify with magic
  bytes (malware authors rename files constantly)
- PE is the most commonly encountered format in malware analysis because Windows
  dominates the desktop threat landscape

### Subtypes Within PE

Mention briefly that PE covers more than just `.exe`:
- **EXE** — standalone executable
- **DLL** — dynamic link library (shared code loaded by other programs)
- **SYS** — kernel driver
- **SCR** — screensaver (actually just a renamed EXE)
- **OCX/CPL** — ActiveX controls, Control Panel applets (DLL variants)

## Key PeMCP Tools

When this concept comes up during analysis, use these tools to demonstrate:

- **`open_file(file_path)`** — Load a binary. Show the learner the initial
  detection output: format identification, architecture, hashes, and quick
  indicators. Point out how much PeMCP learns from just loading the file.
- **`detect_binary_format()`** — Explicitly check magic bytes and format. Use this
  to show that format detection is based on file content, not file extension.
- **`classify_binary_purpose()`** — Determine whether the binary is a GUI app,
  CLI tool, DLL, driver, etc. Connects to the concept that binaries have
  different roles in the system.

### Teaching Moment: open_file Output

When a learner loads their first binary, walk through every field in the
`open_file` response:
- File hashes (MD5, SHA1, SHA256) — the binary's unique fingerprint
- Detected format and architecture — what kind of container and what CPU
- File size — context for whether this is a small tool or a large application
- Any initial indicators — what PeMCP noticed immediately

## Socratic Questions

Use these to check understanding and prompt deeper thinking. Do not just ask
them — wait for a natural teaching moment during analysis.

- "What do you think happens differently when you compile for Windows vs Linux?"
  (Expected insight: same logic, different container format and OS interface)
- "If I renamed this .exe file to .txt, would it stop being a PE binary?"
  (Expected insight: format is in the bytes, not the extension)
- "Why do you think the linker step exists? Why not just compile straight to a
  finished binary?"
  (Expected insight: programs use code from multiple files and libraries)
- "What information do you think we lose when source code is compiled?"
  (Expected insight: comments, variable names, high-level structure, types)
- "If you found a file with no extension on a Linux server, how would you figure
  out what it is?"
  (Expected insight: check magic bytes, not the filename)

## Common Misconceptions

### "All .exe files are malware"

Correct gently: .exe is simply the Windows executable format. Every Windows
application — from Notepad to Chrome to Visual Studio — is a .exe file.
Malware uses the same format because it needs to run on the same operating
system. The format tells you nothing about intent; the code inside does.

### "You need the source code to understand a binary"

This is the central misconception that the entire course addresses. Explain that
while source code makes understanding easier, reverse engineering tools can
recover a surprising amount of information: function boundaries, control flow,
string references, API calls, and even approximate source code (decompilation).
PeMCP exists precisely to make this process systematic and accessible.

### "Binaries are just random bytes"

Binaries are highly structured. They have headers, sections, tables, and metadata
that follow strict format specifications. This structure is what makes analysis
possible — every binary must follow the rules of its format, and those rules
give us handholds for understanding.

### "The file extension tells you everything"

Malware frequently uses misleading extensions (.pdf.exe, .txt, .jpg). File
format identification must always be based on magic bytes and header parsing,
never on the filename. Demonstrate this with `detect_binary_format()`.

## When to Teach This

- **Always first**: This is Module 1.1 — it should be the first concept covered
  for any new learner, regardless of whether they are in structured lesson mode
  or guided analysis mode.
- **During guided analysis**: When `open_file()` runs and the learner sees format
  detection for the first time, use it as a natural entry point to explain binary
  formats and magic bytes.
- **When format confusion arises**: If a learner is confused about why a file
  "looks different" from what they expected, revisit the compilation pipeline and
  format differences.
