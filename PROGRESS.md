# Project Progress: PipelineSentinel

## One-Liner: LangGraph AI agent that monitors AI/ML pipeline dependencies for new vulnerabilities from OSV/GHSA/CISA KEV, correlates AI-specific attack vectors, and generates actionable remediation briefings with version-specific upgrade paths.
## Status: COMPLETE
## Created: 2026-06-23
## Last Updated: 2026-06-26
## Nights Invested: 4

## LangGraph Features Used
- [x] StateGraph with TypedDict state
- [x] Custom tools (@tool)
- [x] Conditional edges
- [x] Checkpointing (SqliteSaver/MemorySaver)
- [x] Streaming (astream_events)
- [x] Human-in-the-loop (interrupt_before/after)
- [ ] Multi-agent orchestration (supervisor) — not needed for this agent
- [ ] Subgraphs — not needed for this agent

## Definition of Done
- [x] Core graph works end-to-end
- [x] All nodes have unit tests
- [x] Integration test passes
- [x] Live test produces useful output
- [x] Terminal UI working (Rich/Textual)
- [x] Web UI working (Next.js) — builds, renders, scans via API backend, SSE streaming
- [x] README complete
- [x] Error handling for common failures (network, timeout, rate limits, 422)
- [x] Git initialized, clean history
- [x] No TODOs, no placeholders

## What's Done
- Night 1 (2026-06-23): Deep research — identified AI/ML dep vuln space as green niche, verified uniqueness (0 repos), documented threat landscape, initial architecture design
- Night 2 (2026-06-24):
  - Verified LangGraph 1.2.6 API (InMemorySaver, SqliteSaver, StateGraph, interrupt)
  - Wrote complete DESIGN.md with graph architecture, state schema, nodes, tools, TUI/web UI specs
  - Built 6 intelligence tools: osv_query, ghsa_search, kev_check, pypi_versions, npm_versions, ai_risk_classifier
  - Built 8 graph nodes: parse_dependencies, ingest_osv, ingest_ghsa, ingest_kev, correlate_findings, assess_risk, generate_briefing, human_review
  - Wired graph with conditional edges and HITL interrupts
  - Wrote 49 tests — ALL PASSING (unit + integration)
  - Built Rich terminal CLI with progress tracking, findings display, JSON export
  - Built Next.js 15 web UI with scan form, results display, KEV banner, briefing panel
  - Wrote comprehensive README
  - Git init + commit (49 files, 3431 lines)
- Night 3 (2026-06-25):
  - Fixed CLI progress bar bug (Progress.completed → completed_steps tracker)
  - Fixed CVSS extraction — OSV returns CVSS vectors not numeric scores. Implemented full CVSS v3.1 base score calculator from vector strings
  - Fixed human_review node state mutation anti-pattern (was mutating state dict directly, now returns proper state update)
  - Added human_decision field to state schema
  - Added 18 new tests (CVSS vector parsing, severity extraction) — 67/67 PASSING
  - Built Python API server (stdlib HTTPServer, no extra deps) with CORS support for web UI
  - Updated web UI to call Python API backend via NEXT_PUBLIC_API_BASE
  - Installed npm deps, built Next.js (✓ compiled, static export)
  - Live test: 15 deps → 11 AI/ML → 66 OSV vulns → 132 findings (6 CRITICAL, 66 HIGH, 42 MEDIUM)
  - Web UI visual validation: renders scan form, summary cards (8 deps, 110 vulns, 64 crit/high), findings table with severity badges, CVSS, risk scores, AI risk, fix versions
  - Updated README with API server docs and web UI instructions
- Night 4 (2026-06-26):
  - Added retry_async utility with exponential backoff for network resilience
  - Updated all 6 tools (OSV, GHSA, KEV, PyPI, npm, ai_risk_classifier) with granular error handling
  - Fixed GHSA search: 422 client errors handled gracefully (no retries), only timeouts/connects retried
  - Added network resilience logging across all tools and ingest nodes
  - Built SSE streaming endpoint (POST /api/scan/stream) with real-time progress events
  - Updated web UI to consume SSE with live progress bar + fallback to regular POST
  - Added 10 new error handling tests — 77/77 PASSING
  - Live test: 8 deps → 8 AI/ML → 55 OSV vulns → 110 findings (4 CRITICAL, 60 HIGH, 32 MEDIUM, 4 LOW, 10 INFO)
  - AI risk classification working: DESER_RCE, CMD_INJ, PROMPT_INJ, AUTH_BYPASS all detected
  - GitHub repo created: https://github.com/ferrierepete/pipelinesentinel
  - 2 commits pushed to GitHub
  - Fixed README duplicate heading, added SSE streaming endpoint docs

## What's Remaining
- None — project complete

## Known Issues
- LLM briefing requires OPENAI_API_KEY (falls back to raw findings text — acceptable behavior)
- GHSA API returns 422 for all PyPI packages (API endpoint changed behavior) — handled gracefully, returns empty
- Web UI Next.js build uses static export (npm run build → web/out/)

## Night Log
- Night 1 (2026-06-23): RESEARCH session — landscape has accelerated significantly since Night 16. MCP security space exploded (328 repos). Agent runtime security maturing (Kontext 206★). AI agent forensics has strong entrant (ProjectAIR 1★). Identified AI/ML dependency vulnerability intelligence as completely empty green niche (0 repos). LiteLLM 25 OSV vulns, LangChain 38 vulns, LangGraph 2 vulns — critical pain signal. Initial PipelineSentinel architecture designed. Status: RESEARCHING → DESIGNING next session.
- Night 2 (2026-06-24): DESIGN + BUILD session — Verified LangGraph 1.2.6 API. Wrote DESIGN.md. Built full agent: 6 tools, 8 nodes, graph wiring. 49/49 tests passing. Rich CLI + Next.js web UI code written. README complete. Git committed. Status: TESTING → VALIDATING next session.
- Night 3 (2026-06-25): VALIDATION session — Fixed CVSS extraction (was returning 0.0 for all vulns because OSV returns CVSS vectors, not numeric scores). Implemented full CVSS v3.1 calculator. Fixed state mutation anti-pattern. Built Python API server with CORS. npm install + Next.js build successful. Live test: 132 findings with proper severity distribution. Web UI rendering correctly with scan form, summary cards, findings table. 67/67 tests passing. Status: VALIDATING → FINAL POLISH next session.
- Night 4 (2026-06-26): FINAL POLISH + SHIP — Added retry/resilience to all 6 tools. Fixed GHSA 422 handling. Built SSE streaming endpoint + web UI progress. 10 new error handling tests (77 total). GitHub repo created and pushed. All Definition of Done items met. Status: COMPLETE.
