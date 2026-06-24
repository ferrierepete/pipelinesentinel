# Project Progress: PipelineSentinel

## One-Liner: LangGraph AI agent that continuously monitors your AI/ML pipeline dependencies for new vulnerabilities from OSV/GHSA/CISA KEV, correlates AI-specific attack vectors, and generates actionable remediation briefings with version-specific upgrade paths.

## Status: RESEARCHING
## Created: 2026-06-23
## Last Updated: 2026-06-23
## Nights Invested: 1

## LangGraph Features Used
- [ ] StateGraph with TypedDict state
- [ ] Custom tools (@tool)
- [ ] Conditional edges
- [ ] Checkpointing (SqliteSaver/MemorySaver)
- [ ] Streaming (astream_events)
- [ ] Human-in-the-loop (interrupt_before/after)
- [ ] Multi-agent orchestration (supervisor)
- [ ] Subgraphs

## Definition of Done
- [ ] Core graph works end-to-end
- [ ] All nodes have unit tests
- [ ] Integration test passes
- [ ] Live test produces useful output
- [ ] Terminal UI working (Rich/Textual)
- [ ] Web UI working (Next.js)
- [ ] README complete
- [ ] Error handling for common failures
- [ ] Git initialized, clean history
- [ ] No TODOs, no placeholders

## Rationale (from Night 17 research)
- **Pain signal**: LiteLLM has 25 OSV vulns (2 in CISA KEV, actively exploited), LangChain has 38 vulns, LangGraph itself has unsafe deserialization
- **Empty niche**: GitHub search for "LangChain vulnerability monitor" returns 0 repos, "ML dependency vulnerability intelligence" returns 0 repos
- **Differentiation from SecStack**: SecStack monitors your tool stack broadly. PipelineSentinel focuses on code dependencies with AI-specific risk assessment (deserialization RCE, model poisoning, proxy command injection)
- **Differentiation from Snyk/Dependabot**: Those tools check ALL dependencies generically. PipelineSentinel understands LLM-specific attack vectors and correlates across multiple intel sources
- **Market**: Every team building AI agents (massive, growing) — $30-100/mo

## Agent Architecture (Preliminary — design in Night 18)

### State Schema
```python
class PipelineSentinelState(TypedDict):
    dependencies: list[dict]           # parsed from requirements.txt / pyproject.toml
    ai_ml_deps: list[dict]            # filtered AI/ML-specific dependencies
    osv_vulns: list[dict]             # OSV API results
    ghsa_vulns: list[dict]            # GitHub Security Advisory results
    kev_entries: list[dict]           # CISA KEV entries
    findings: Annotated[list[dict], add]  # correlated findings with risk scores
    briefing: str                     # generated remediation briefing
    error: str                        # error messages
```

### Nodes (preliminary)
1. **parse_dependencies** — parse requirements.txt/pyproject.toml, identify AI/ML deps using known package registry
2. **ingest_osv** — query OSV API for each dependency
3. **ingest_ghsa** — query GitHub Security Advisories
4. **ingest_kev** — check CISA KEV catalog for matches
5. **correlate_findings** — cross-reference vulns against AI-specific risk categories (deserialization, injection, model access, data exfiltration)
6. **assess_risk** — score each finding based on CVSS + AI-specific severity modifiers + exploitability
7. **generate_briefing** — LLM-generated remediation report with upgrade paths
8. **human_review** — HITL gate for critical findings (KEV entries, CVSS 9.0+)

### Tools
- `osv_query` — OSV.dev vulnerability database API
- `ghsa_query` — GitHub Security Advisory search
- `kev_check` — CISA KEV catalog check
- `pypi_versions` — PyPI version API for upgrade path resolution
- `npm_versions` — npm registry version API
- `ai_risk_classifier` — AI-specific risk categorization (deserialization, injection, model access, proxy abuse)

### Input/Output
- Input: path to requirements.txt, pyproject.toml, or package.json
- Output: structured vulnerability briefing with:
  - Affected packages and versions
  - AI-specific risk assessment per vulnerability
  - CISA KEV status
  - Recommended upgrade versions with verified availability
  - Workaround recommendations when upgrade isn't possible
  - Priority ranking (AI-specific exploitability × severity × exposure)

## Known AI/ML Risk Categories (for classifier)
1. **Deserialization RCE** — unsafe pickle/msgpack/yaml loading (LangGraph GHSA-g48c-2wqr-h844)
2. **Command Injection via Proxy** — LLM proxy misconfiguration (LiteLLM CVE-2026-42271)
3. **Prompt Injection via Supply Chain** — compromised packages injecting prompts
4. **Data Exfiltration** — packages sending model outputs/data to third parties
5. **Model Poisoning** — trojanized model files
6. **Auth Bypass** — missing auth on AI endpoints (Splunk, LiteLLM host header injection)
7. **Memory/Context Poisoning** — adversarial input manipulation
8. **Credential Exposure** — API keys/tokens in package code or configs

## What's Done
- Night 1 (2026-06-23): Deep research — identified AI/ML dep vuln space as green niche, verified uniqueness (0 repos), documented threat landscape, initial architecture design

## What's Remaining
- Night 2: Verify LangGraph current API via Context7, finalize design (DESIGN.md), begin implementation
- Night 3-4: Build core graph (parse_deps → ingest tools → correlate → brief)
- Night 5: Terminal UI (Rich), unit tests, integration test
- Night 6: Web UI (Next.js), README, validation
- Night 7: Final validation, git init, complete

## Known Issues
- None yet

## Night Log
- Night 1 (2026-06-23): RESEARCH session — landscape has accelerated significantly since Night 16. MCP security space exploded (328 repos). Agent runtime security maturing (Kontext 206★). AI agent forensics has strong entrant (ProjectAIR 1★). Identified AI/ML dependency vulnerability intelligence as completely empty green niche (0 repos). LiteLLM 25 OSV vulns, LangChain 38 vulns, LangGraph 2 vulns — critical pain signal. Initial PipelineSentinel architecture designed. Status: RESEARCHING → DESIGNING next session.
