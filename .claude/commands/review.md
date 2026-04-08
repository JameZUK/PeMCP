---
name: review
description: Run the rigorous arkana-code-reviewer agent on uncommitted changes (or a specified scope)
---

Use the **arkana-code-reviewer** agent (defined in `.claude/agents/arkana-code-reviewer.md`) to review code changes.

**Default scope:** unstaged + staged changes from `git diff HEAD`. Run that first to discover the in-scope files. If the user specified a scope in the slash command arguments — e.g. `/review arkana/mcp/tools_pe.py` or `/review last 3 commits` — use that instead.

**Hard requirements for the review:**

1. The agent MUST follow the quote-before-claim discipline in its system prompt — every finding must include verbatim quoted code from a file the agent actually read in this session.
2. The agent MUST run the verification checklist on each finding before reporting it. Findings that don't pass verification are dropped silently.
3. The agent MUST check `git log -p` for the in-scope files before reporting "missing" code or "unguarded" patterns — many such findings are already-fixed bugs.
4. **A short verified report is the gold standard.** Do NOT pad with speculation. If the code is clean, the report says "Reviewed N files. No findings."

After the agent returns, present the findings to the user grouped by severity (CRITICAL → HIGH → MEDIUM → LOW → DOCSTRING). For each finding, show:

- File:line reference
- Quoted code (from the agent's report — do NOT re-fetch and risk drift)
- One-paragraph problem statement
- Concrete fix suggestion

If the user wants you to apply the fixes, ask which findings to address (default: all CRITICAL + HIGH). Make the edits, run `pytest tests/` and `ruff check`, then commit with a descriptive message.

**Do not commit without explicit approval** — review findings often require human judgment about whether they're worth fixing.
