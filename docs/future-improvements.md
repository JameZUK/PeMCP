# Future Improvements

Planned enhancements and feature ideas for Arkana. Items are grouped by domain and roughly prioritised within each section.

---

## .NET Deobfuscation & Decompilation

### Integrate de4dot + NETReactorSlayer

**Priority**: High
**Complexity**: Medium-High
**Docker image impact**: +80-400MB (.NET runtime required)

Add a unified `dotnet_deobfuscate` MCP tool that automatically detects and removes .NET obfuscation, covering the vast majority of protectors seen in real-world malware.

**Tools to integrate:**

| Tool | Purpose | License |
|------|---------|---------|
| [de4dot](https://github.com/de4dot/de4dot) (active fork) | Generic .NET deobfuscator — handles ~20 obfuscators (ConfuserEx, Dotfuscator, SmartAssembly, Agile.NET, Babel, CryptoObfuscator, etc.) | GPLv3 |
| [NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) | Dedicated .NET Reactor deobfuscator — better coverage than de4dot for this specific protector | GPLv3 |

**Why these two:**
- de4dot remains the industry standard despite being archived upstream — active forks (de4dot-cex, de4dotEx) cover modern protectors like ConfuserEx2.
- NETReactorSlayer is complementary, not a replacement — .NET Reactor is common in malware and de4dot handles it poorly.
- No better alternatives exist. Other tools (AsmResolver, dnlib, dnpatch) are libraries for building tools, not standalone deobfuscators.

**Proposed architecture:**
- Both are C# CLI tools requiring .NET runtime — no Python venv needed, but needs `dotnet-runtime` in the Docker image.
- Follow the existing subprocess runner pattern (like Speakeasy/Qiling/Unipacker): thin Python runner script invokes `dotnet de4dot.dll` or `dotnet NETReactorSlayer.CLI.dll`, parses stdout, returns JSON.
- Single MCP tool `dotnet_deobfuscate(method="auto"|"de4dot"|"reactor_slayer")` mirrors the `try_all_unpackers` orchestration pattern — try de4dot first, fall back to NETReactorSlayer.
- Output file registered via `state.register_artifact()`, can be immediately re-analysed with `open_file()` + `dotnet_analyze` + `refinery_dotnet`.
- Availability check in `imports.py` via `_check_de4dot_available()`.

**Implementation steps:**
1. Dockerfile: add `dotnet-runtime-8.0` (or trimmed), download de4dot + NETReactorSlayer release binaries to `/app/de4dot/` and `/app/netreactorslayer/`.
2. Runner script: `scripts/de4dot_runner.py` — accepts JSON command on stdin, invokes CLI, returns JSON result on stdout.
3. MCP tool: `dotnet_deobfuscate` in `tools_dotnet.py` — orchestrates both tools, registers output artifact.
4. Config: add paths and availability flags to `config.py` / `imports.py`.
5. Tests: unit test for runner JSON protocol, integration test with a known obfuscated .NET sample.

**Optional follow-up:** Add `ilspycmd` (ILSpy CLI) as a separate `dotnet_decompile` tool for full C# source recovery beyond CIL disassembly. Pairs well with deobfuscation — deobfuscate first, then decompile to readable C#.

**References:**
- [.NET Deobfuscator list](https://github.com/NotPrab/.NET-Deobfuscator)
- [.NET Deobfuscation techniques (cyber.wtf)](https://cyber.wtf/2025/04/07/dotnet-deobfuscation/)
- [ILSpy/ILSpyCmd](https://github.com/icsharpcode/ILSpy)

---
