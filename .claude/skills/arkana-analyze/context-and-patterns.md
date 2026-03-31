# Context Management & Analysis Patterns

## Context Management

### Phase Transition Protocol

Between analysis phases, follow this protocol to manage context efficiently:

1. **Save findings to notes** — `add_note(category="tool_result", content="...")` for key findings from the phase. Notes survive compaction and are retrievable via `get_analysis_digest()`.
2. **Update hypothesis** — `update_note()` or `add_note(category="hypothesis")` with current assessment.
3. **Compact the session** — use `/compact` to summarize the conversation and free context for the next phase.
4. **Re-orient after compaction** — call `get_session_summary(compact=True)` to restore awareness of session state, then `get_analysis_digest()` for the analytical picture.

**When to compact:**
- After Phase 1 (Identify) -> before mapping/deep-dive
- After Phase 3 (Map) -> before deep-dive (biggest context savings)
- After Phase 4 (Deep Dive) -> before extraction/reporting
- Any time context feels constrained or responses are being truncated

**What survives compaction:** Notes, tool history, triage data, hypothesis chain, session state — all persisted server-side.

### Record Hypotheses Early and Often

Hypotheses survive context compression. Record at three checkpoints:

1. **After initial triage** (end of Phase 1): `add_note(category='hypothesis', content='Preliminary: <assessment>')`.
2. **After capability mapping** (end of Phase 3): `update_note(note_id=N, content='Refined: <assessment>')`.
3. **After deep dive** (end of Phase 4): `update_note(note_id=N, content='Final: <verdict with evidence>')`.

### General Context Tips

`get_analysis_digest()` between phases (not mid-phase). Note categories: `tool_result` (findings), `ioc` (indicators), `hypothesis` (conclusion), `conclusion` (write-up), `manual` (observations). Session persists via `~/.arkana`. `get_tool_history()`, `suggest_next_action()`. After patching: `reanalyze_loaded_pe_file()`.

## Prefer / Avoid

| Instead of... | Prefer... | Why |
|---|---|---|
| `get_full_analysis_results()` | `get_pe_data(key='...')` | Full dump exceeds 8K char soft limit |
| `extract_strings_from_binary()` | `get_strings_summary()` | Raw dumps are noisy; summary categorizes |
| `get_pe_data(key='imports')` | `get_focused_imports()` | Focused imports categorizes by threat behavior |
| `get_function_map(limit=100)` | `get_function_map(limit=15)` | Too many functions overwhelms context |
| Ignoring `has_more` | Check `_pagination` dicts | `has_more: true` means data dropped |
| Repeated `get_analysis_digest()` | Call at phase transitions | Digest has overhead |
| `get_hex_dump()` + `refinery_xor(data_hex=...)` | `refinery_xor(file_offset=..., length=...)` | Single step |
| Writing a Python crypto script | `refinery_pipeline` / `refinery_decrypt` | Logged, reproducible |
| Repeated single-item calls | Batch params (`data_hex_list`, `addresses`) | Single call |
| Paginating to find a pattern | `decompile_function_with_angr(search="pattern")` | Regex grep |
| `get_hex_dump()` + manual byte matching | `search_hex_pattern(pattern)` | Hex search with `??` wildcards |
| Manually checking for overflows | `find_dangerous_data_flows()` | Automated source-to-sink |
| 4 separate tools for function context | `get_analysis_context_for_function(address)` | Single-call aggregator |

## Use `search=` Instead of Paginating

Three tools accept `search` (regex): `decompile_function_with_angr`, `batch_decompile`, `get_annotated_disassembly`.

**Parameters**: `search="pattern"` (regex), `context_lines=2` (default, max 20), `case_sensitive=False`.

**Useful search patterns:**
| Pattern | Finds |
|---------|-------|
| `"VirtualAlloc\|VirtualProtect\|WriteProcessMemory"` | Memory manipulation |
| `"xor\|rol\|ror\|shr\|shl"` (on disassembly) | Crypto/encoding ops |
| `"socket\|connect\|send\|recv\|http"` | Network communication |
| `"RegOpenKey\|RegSetValue\|CreateService"` | Persistence |
| `"CreateRemoteThread\|NtUnmapViewOfSection"` | Process injection |
| `"IsDebuggerPresent\|rdtsc\|cpuid"` | Anti-analysis |
| `"crypt\|aes\|rc4\|encrypt\|decrypt"` | Crypto API usage |
| `"0x[0-9a-f]{6,}"` | Large hex constants |

**Batch search**: `batch_decompile(addresses=[...], search="pattern")` — up to 20 functions, returns only matches.
