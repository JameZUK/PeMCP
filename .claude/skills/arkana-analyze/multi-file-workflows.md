# Multi-File Workflows

Arkana loads one binary at a time. Use `close_file()` then `open_file()` to switch.
Notes and session data for each file are preserved independently — switching back
restores the previous session context automatically.

## Cross-File Reference Discovery

Malicious binaries frequently reference companion files — payloads they drop,
DLLs they sideload, configs they read, or other stage components. When analysing
any binary, actively look for these references:

1. **String search**: Use `get_strings_summary()` and `search_for_specific_strings()`
   to look for filenames, paths, and extensions (.dll, .exe, .dat, .bin, .cfg, .tmp).
   Pay attention to `LoadLibrary`/`GetModuleHandle` string arguments.
2. **Resource names**: Use `extract_resources()` — resource names often match dropped
   filenames or contain embedded companion files.
3. **Decompilation context**: When decompiling functions that call `CreateFile`,
   `WriteFile`, `LoadLibrary`, `ShellExecute`, or `WinExec`, note the filename
   arguments — these reveal what the binary expects to find or intends to create.
4. **Import context**: `get_focused_imports()` — functions like `LoadLibraryA/W`
   paired with specific DLL name strings indicate sideloading targets.

If the user has provided multiple files (e.g., a ZIP with an EXE and a DLL), check
whether the primary binary references the companion files by name before analysing
them separately. This establishes the relationship and priorities — analyse the
orchestrator first, then its dependencies/payloads.

## Dropper + Payload

When a dropper extracts or decrypts a payload during analysis:
1. Complete the dropper analysis through to extraction (Phases 0-5)
2. When extracting the payload, use `output_path` to save it as an artifact:
   e.g., `refinery_xor(file_offset="0x3B80", length=103935, key_hex="42",
   output_path="/output/payload.bin")` — this writes the file AND registers it
3. Note the extraction method and relationship: `add_note("Drops payload via
   resource decryption (RC4, key from .rdata)", category="tool_result")`
4. Search for references to the payload filename in the dropper's strings and
   decompiled code to understand how it is loaded/executed
5. `close_file()` the dropper and `open_file()` the extracted payload artifact
6. Analyse the payload as a fresh binary (Phases 1-7)
7. In the final summary, present both files together with their relationship

## Bundled Dependencies (DLL Sideloading, Config Files)

When the user provides a binary alongside DLLs, data files, or configs:
1. Start with the primary executable — identify it from file type and naming
2. Search its strings and imports for references to the companion filenames:
   `search_for_specific_strings(patterns=["companion.dll", "config.dat", ...])`
3. Note which functions load each companion and how they are used
4. Analyse each companion file in order of relevance — the one most referenced
   or loaded earliest is likely most important
5. For DLL sideloading: check whether the DLL exports match what the EXE imports
   (`get_pe_data(key='exports')` on the DLL vs `get_pe_data(key='imports')` on the EXE)

## Campaign Sample Comparison

When comparing related samples (variants, updates, different builds):
1. Analyse the first sample fully, ensure thorough notes
2. `close_file()` and `open_file()` the second sample
3. Use `diff_binaries()` or `compare_file_similarity()` for structural comparison
4. Use `compute_similarity_hashes()` on each for ssdeep/TLSH clustering
5. Focus the second analysis on what differs — skip what is identical

## Shellcode Extracted from a Loader

When analysis reveals embedded shellcode:
1. Extract the shellcode bytes using `file_offset`/`length`/`output_path`:
   e.g., `refinery_xor(file_offset="0x1000", length=4096, key_hex="FF",
   output_path="/output/shellcode.bin")` — saves and registers as artifact
2. Emulate directly with `emulate_shellcode_with_qiling()` or
   `emulate_shellcode_with_speakeasy()` — no need to switch files
3. Use `qiling_memory_search()` post-emulation to find next-stage URLs or configs
4. If the shellcode drops a PE, extract it and `open_file()` for full analysis

**Session scale**: When analyzing many files (>5 in a session), notes and session
data accumulate. If the session becomes sluggish or context is getting large, use
`export_project()` to save progress, then start a fresh session with
`import_project()`.
