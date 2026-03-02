# Concept Reference: PE Structure

Foundation tier reference for Module 1.2. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

The Portable Executable (PE) format is the binary container used by Windows for
executables, DLLs, drivers, and other loadable images. Understanding its structure
is essential because every piece of information used during analysis — imports,
sections, entry point, resources — lives at a specific location defined by PE
headers.

### The Building Blueprint Analogy

Use this analogy to make PE structure intuitive:

- **The building** = the PE file itself
- **The architect's nameplate** = the DOS header ("MZ" signature) — a legacy
  marker that says "this is a building, not a pile of rubble"
- **The old lobby** = the DOS stub — a small program that prints "This program
  cannot be run in DOS mode." Still present for backwards compatibility, like
  an old lobby sign nobody reads
- **The building permit** = the PE signature ("PE\0\0") — official confirmation
  this is a valid PE structure
- **The engineering specs** = the COFF header — technical details like target
  CPU architecture, number of sections, and when the building was constructed
  (compilation timestamp)
- **The building directory** = the Optional header — despite its name, this is
  NOT optional for executables. Contains the entry point address, preferred load
  address (ImageBase), and pointers to all data directories
- **The floor plan** = the section table — lists every floor (section), its
  purpose, its size, and who has access (read/write/execute permissions)
- **The floors themselves** = sections (.text, .data, .rdata, .rsrc, .reloc)
- **The lobby/reception** = the entry point — where execution begins when you
  "enter the building"

## PE Header Walkthrough

### DOS Header (64 bytes)

The first structure in every PE file. Only two fields matter for modern analysis:
- `e_magic` — must be `0x5A4D` ("MZ") — the magic bytes
- `e_lfanew` — offset to the PE signature (pointer to the "real" header)

Everything else is a legacy DOS artifact. Malware sometimes hides data in the
unused DOS header fields — mention this as a preview of anti-analysis concepts.

### PE Signature (4 bytes)

At the offset specified by `e_lfanew`. Must be `0x00004550` ("PE\0\0").
If this is absent or corrupted, the file is not a valid PE.

### COFF Header (20 bytes)

Immediately after the PE signature. Key fields:
- **Machine** — target CPU (0x14C = x86, 0x8664 = x64, 0x1C0 = ARM)
- **NumberOfSections** — how many sections follow the headers
- **TimeDateStamp** — Unix timestamp of when the binary was compiled. Frequently
  forged in malware, but valuable when authentic
- **Characteristics** — flags indicating if this is an EXE, DLL, or other type

### Optional Header (variable size)

The most information-dense part of the PE. Despite the name, it is required for
executables (the name is a historical artifact from COFF). Key fields:

- **Magic** — `0x10B` for PE32, `0x20B` for PE32+ (64-bit)
- **AddressOfEntryPoint** — RVA where execution begins
- **ImageBase** — preferred memory load address (0x400000 for EXEs, 0x10000000
  for DLLs, typically)
- **SectionAlignment / FileAlignment** — how sections are aligned in memory vs
  on disk
- **SizeOfImage** — total size when loaded into memory
- **Subsystem** — GUI (2), Console (3), Driver (1)
- **DataDirectory array** — 16 entries pointing to import table, export table,
  resource table, relocation table, TLS, debug info, etc.

## Sections

Each section is a named region with a specific purpose, size, and permissions.

| Section | Purpose | Typical Permissions |
|---------|---------|-------------------|
| `.text` | Executable code | Read + Execute |
| `.data` | Initialised global/static variables | Read + Write |
| `.rdata` | Read-only data (strings, constants, import tables) | Read |
| `.bss` | Uninitialised data | Read + Write |
| `.rsrc` | Resources (icons, dialogs, version info, embedded files) | Read |
| `.reloc` | Relocation fixups for ASLR | Read |
| `.tls` | Thread Local Storage initialisation data | Read + Write |

### Anomalous Section Indicators

Teach the learner to watch for:
- **Writable + Executable** — a section that is both W and X is a red flag. Normal
  compilers do not produce this. It suggests self-modifying code or unpacking.
- **High entropy** (>7.0) — suggests compressed or encrypted data. Normal code
  entropy is 5.5-6.5. Random/encrypted data approaches 8.0.
- **Unusual names** — packers create sections with names like `.UPX0`, `.aspack`,
  `.themida`, `.vmp0`. Non-standard names suggest post-compilation modification.
- **Size mismatch** — large difference between raw size (on disk) and virtual
  size (in memory) can indicate unpacking (virtual >> raw means data expands
  at runtime).

## Virtual vs Raw Addresses

This concept trips up most beginners. Teach it early and reinforce often.

- **Raw offset** = position of data in the file on disk
- **RVA (Relative Virtual Address)** = position of data in memory, relative to
  the ImageBase
- **VA (Virtual Address)** = ImageBase + RVA = absolute memory address

The conversion between raw and virtual addresses depends on section alignment.
Arkana tools handle this conversion internally, but learners need to understand
why addresses in headers differ from addresses in a hex editor.

Analogy: "A book's table of contents lists page numbers (raw offsets). But when
you open the book and spread pages across a table, their physical positions
change (virtual addresses). Both refer to the same content."

## Key Arkana Tools

- **`get_pe_data(key='headers')`** — raw header values. Use to walk through the
  DOS header, COFF header, and Optional header field by field.
- **`get_pe_data(key='sections')`** — section table with names, sizes, entropy,
  and permissions. The primary tool for teaching section analysis.
- **`get_pe_metadata()`** — compilation timestamp, subsystem, linker version,
  characteristics. Useful for determining when and how the binary was built.
- **`get_section_permissions()`** — focused view of read/write/execute flags per
  section. Use to teach permission anomaly detection.
- **`extract_resources()`** — enumerate and optionally extract PE resources.
  Good for showing embedded icons, version info, and hidden payloads.
- **`extract_manifest()`** — application manifest showing requested privileges
  (requireAdministrator, asInvoker) and dependencies.

## Socratic Questions

- "Why do you think this section has both write AND execute permissions?"
  (Expected insight: normal code sections are read+execute only; W+X suggests
  the binary modifies its own code at runtime, possibly for unpacking)
- "What would high entropy in a section suggest to you?"
  (Expected insight: compressed or encrypted data — the section content lacks
  the patterns that normal code or data exhibit)
- "The entry point is at 0x00012340 — is that an address on disk or in memory?"
  (Expected insight: it is an RVA — relative to where the binary loads in memory)
- "This binary was compiled in 1992 according to the timestamp. Does that seem
  right for a file that appeared last week?"
  (Expected insight: timestamps can be forged; malware authors set fake dates)
- "Why would a binary include a .reloc section? What problem does it solve?"
  (Expected insight: ASLR changes the load address; relocations fix pointers)

## Common Misconceptions

### "The entry point is always at the start of .text"

The entry point can be anywhere within the executable sections — it is simply an
address specified in the Optional header. Compilers typically place it at or near
the start of .text, but packers and malware authors frequently set it to a
different section entirely (e.g., a packer's decompression stub in a custom
section). Always check the actual `AddressOfEntryPoint` value.

### "All sections are meaningful / all sections contain useful data"

Some sections may be padding, compiler artifacts, or deliberately empty. Packed
binaries often have empty sections that get filled at runtime. Conversely, some
meaningful data may be stored without a dedicated section (e.g., in the PE overlay
after the last section). Teach learners to look at content and entropy, not just
section names.

### "The Optional header is optional"

The name is a historical artifact from the COFF specification. For PE executables
and DLLs, the Optional header is mandatory and contains critical information
including the entry point and data directory pointers. Object files (.obj) are
the only case where it is truly optional.

### "A valid PE structure means the binary will run correctly"

A PE can have valid headers but corrupted code, missing DLLs, or incompatible
architecture. Headers describe structure; they do not guarantee functionality.
Conversely, some malformed PEs run fine because the Windows loader is more
tolerant than the specification suggests — malware authors exploit this.

## When to Teach This

- **After binary-basics**: This module assumes the learner understands what a
  binary is and can distinguish PE from ELF/Mach-O.
- **When examining headers**: Any time `get_pe_data` or `get_pe_metadata` output
  is on screen, reinforce which header field the data comes from.
- **When section anomalies appear**: W+X permissions, high entropy, or unusual
  names are natural teaching moments for section analysis.
- **Before imports/exports**: Understanding that the import table and export table
  are data directories within the PE structure bridges to Module 1.4.
