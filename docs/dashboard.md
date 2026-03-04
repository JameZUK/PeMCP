# Web Dashboard

Arkana includes a real-time CRT-themed web dashboard that launches automatically on port 8082. It provides a visual companion to the AI-driven analysis, letting you observe and interact with the investigation as it happens.

The dashboard uses token-based authentication (persisted to `~/.arkana/dashboard_token`). The access URL with token is printed at server startup and available via the `get_config()` MCP tool.

---

## Overview

Binary summary with risk score, packing status, security mitigations, key findings, and recent notes.

![Dashboard Overview](Dashboard-Overview.png)

---

## Functions

Sortable function explorer with triage buttons (FLAG / SUS / CLN). Flagged functions are automatically prioritised by the AI in subsequent analysis via `get_session_summary()`, `get_analysis_digest()`, and `suggest_next_action()`.

![Dashboard Functions](Dashboard-Function.png)

---

## Call Graph

Interactive Cytoscape.js call graph with zoom, pan, and node selection. Nodes are coloured by triage status.

![Dashboard Call Graph](Dashboard-Callgraph.png)

---

## Sections

PE/ELF section permissions with anomaly highlighting (W+X detection).

![Dashboard Sections](Dashboard-Sections.png)

---

## Timeline

Chronological log of every tool call and note, with expandable detail panels showing request parameters and result summaries. Expanded state is preserved across live refreshes.

![Dashboard Timeline](Dashboard-Timeline.png)

---

## Notes

Category-filtered view of all analysis notes (function, tool_result, IOC, hypothesis, manual).

![Dashboard Notes](Dashboard-Notes.png)
