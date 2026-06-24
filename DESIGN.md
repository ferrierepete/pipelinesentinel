# PipelineSentinel — Design Document

## 1. Agent Purpose

PipelineSentinel is a LangGraph AI agent that monitors AI/ML pipeline dependencies for new vulnerabilities from OSV, GHSA, and CISA KEV, correlates AI-specific attack vectors, and generates actionable remediation briefings with version-specific upgrade paths.

**Target audience:** AI/ML engineering teams, DevSecOps teams, security researchers building with LLM frameworks.

## 2. LangGraph Graph Architecture

### State Schema

```python
from typing import Annotated, TypedDict
from operator import add

class PipelineSentinelState(TypedDict):
    # Input
    file_path: str                           # path to requirements.txt / pyproject.toml / package.json
    # Parsed data
    dependencies: list[dict]                 # all dependencies extracted from file
    ai_ml_deps: list[dict]                  # filtered to known AI/ML packages
    # Intelligence sources
    osv_vulns: list[dict]                   # OSV API results per dependency
    ghsa_vulns: list[dict]                  # GitHub Security Advisory results
    kev_entries: list[dict]                  # CISA KEV matches
    # Analysis
    findings: Annotated[list[dict], add]     # correlated, risk-scored findings
    # Output
    briefing: str                            # LLM-generated remediation briefing
    error: str                               # error messages (None if clean)
```

### Nodes

| Node | Type | Description |
|------|------|-------------|
| `parse_dependencies` | sync | Parse dependency file, identify AI/ML packages |
| `ingest_osv` | async | Query OSV.dev API for each AI/ML dependency |
| `ingest_ghsa` | async | Query GitHub Security Advisories |
| `ingest_kev` | sync | Check CISA KEV catalog for CVE matches |
| `correlate_findings` | sync | Cross-reference vulns, classify AI-specific risk |
| `assess_risk` | sync | Score findings: CVSS × AI-modifier × exploitability |
| `generate_briefing` | sync | LLM-generated remediation report |
| `human_review` | sync | HITL gate for critical findings (KEV / CVSS 9.0+) |

### Edges

```
START → parse_dependencies → ingest_osv → ingest_kev → correlate_findings → assess_risk → generate_briefing → human_review → END
```

- `parse_dependencies` → `ingest_osv` (conditional: if no AI/ML deps, skip to END)
- `ingest_osv` and `ingest_kev` run sequentially (OSV first, then KEV cross-check)
- `human_review` uses `interrupt_before` for KEV entries and CVSS 9.0+ findings

### Checkpointing Strategy

- **SqliteSaver** for persistence — sessions can be resumed
- Thread ID: hash of file path + timestamp
- Enables: resume after interruption, time-travel to any step

### Human-in-the-Loop

- `interrupt_before` on `human_review` node
- When findings contain CISA KEV entries or CVSS 9.0+ vulns, graph pauses
- Human can: approve, mark as accepted risk, or request additional context
- `Command(resume=...)` pattern to continue

### LangGraph Features Showcase

| Feature | Usage |
|---------|-------|
| StateGraph with TypedDict | Core state management |
| Custom tools (@tool) | OSV, GHSA, KEV, PyPI, npm queries |
| Conditional edges | Skip if no AI/ML deps; route based on criticality |
| Checkpointing (SqliteSaver) | Session persistence |
| Streaming | Real-time output in TUI/web UI |
| Human-in-the-loop (interrupt) | Critical finding approval gate |
| Parallel nodes | OSV + GHSA ingestion (fan-out) |

## 3. Agent Tools

| Tool | API | Description |
|------|-----|-------------|
| `osv_query` | OSV.dev `/v1/query` | Query vulnerability database by package+version |
| `ghsa_search` | GitHub `/search/advisories` | Search GitHub Security Advisories |
| `kev_check` | CISA KEV JSON feed | Check CVEs against Known Exploited Vulnerabilities |
| `pypi_versions` | PyPI `/pypi/{pkg}/json` | Get available versions for upgrade paths |
| `npm_versions` | npm registry | Get available npm versions |
| `ai_risk_classifier` | Local logic | Classify vuln by AI-specific risk category |

## 4. Input/Output Contract

### Input
- Path to `requirements.txt`, `pyproject.toml`, or `package.json`
- Optional: target framework (LangGraph, LangChain, LiteLLM, etc.)

### Output (Structured)
```json
{
  "scan_metadata": {
    "file_path": "...",
    "timestamp": "...",
    "total_dependencies": 42,
    "ai_ml_dependencies": 8
  },
  "critical_findings": [
    {
      "package": "langgraph",
      "version": "0.2.0",
      "vulnerability": "GHSA-g48c-2wqr-h844",
      "cvss_score": 9.8,
      "ai_risk_category": "Deserialization RCE",
      "in_kev": true,
      "fix_version": "0.2.1",
      "description": "..."
    }
  ],
  "all_findings": [...],
  "remediation_briefing": "...",
  "summary": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2
  }
}
```

## 5. Terminal UI Design (Rich)

```
┌─ PipelineSentinel ──────────────────────────────────────┐
│ Scanning: requirements.txt                                │
│                                                           │
│ [1/8] Parsing dependencies...          ✓ 42 deps found   │
│ [2/8] Identifying AI/ML packages...    ✓ 8 AI/ML deps   │
│ [3/8] Querying OSV database...          ✓ 12 vulns found │
│ [4/8] Querying GitHub Advisories...    ✓ 3 advisories   │
│ [5/8] Checking CISA KEV...             ✓ 1 KEV match     │
│ [6/8] Correlating findings...           ✓ 8 findings     │
│ [7/8] Assessing risk scores...         ✓ scored          │
│ [8/8] Generating briefing...            ✓ briefing ready │
│                                                           │
│ ══════════════════════════════════════════════════════════ │
│ CRITICAL: langgraph 0.2.0 — Deserialization RCE          │
│   CVE: GHSA-g48c-2wqr-h844 | CVSS: 9.8 | IN KEV: YES   │
│   Fix: Upgrade to ≥0.2.1                                 │
│                                                           │
│ HIGH: litellm 1.40.0 — Host Header Injection              │
│   CVE: CVE-2026-42271 | CVSS: 8.1                         │
│   Fix: Upgrade to ≥1.40.1                                 │
│ ══════════════════════════════════════════════════════════ │
│ Summary: 1 Critical | 3 High | 5 Medium | 2 Low         │
│                                                           │
│ [B] View full briefing  [E] Export JSON  [Q] Quit        │
└───────────────────────────────────────────────────────────┘
```

## 6. Web UI Design (Next.js)

### Page Structure
- `/` — Landing page with scan form (upload or paste file path)
- `/scan` — Real-time scan results with streaming output
- `/scan/[thread_id] — Historical scan results (loaded from checkpoints)

### Components
- `DependencyTable` — Lists all dependencies with AI/ML badge
- `FindingCard` — Individual vulnerability finding with severity, risk category, fix version
- `RiskGauge` — Visual gauge for overall risk score
- `StreamingLog` — Real-time agent step output
- `BriefingPanel` — LLM-generated remediation briefing
- `KEVBanner` — Red banner for CISA KEV matches

### Tech Stack
- Next.js 15 App Router
- Tailwind CSS
- Server-Sent Events for streaming
- localStorage for API key config

## 7. Test Strategy

### Unit Tests
- `test_parse_deps.py` — Test parsing requirements.txt, pyproject.toml, package.json
- `test_osv_query.py` — Mock OSV API responses
- `test_ghsa_search.py` — Mock GitHub Advisory responses
- `test_kev_check.py` — Mock CISA KEV data
- `test_correlate.py` — Test correlation logic with known CVE/risk pairs
- `test_risk_assessment.py` — Test risk scoring formula

### Integration Test
- `test_graph.py` — Full graph execution with mocked LLM and mocked APIs
- Verify: state transitions, data flow, edge cases (no vulns, all critical, no AI/ML deps)

### Live Test
- Run against real `requirements.txt` with known vulnerable packages
- Verify real OSV/GHSA/KEV responses
- Verify briefing quality

## 8. AI-Specific Risk Categories

| Category | ID | Description | Severity Modifier |
|----------|-----|-------------|-------------------|
| Deserialization RCE | `DESER_RCE` | Unsafe pickle/msgpack/yaml loading | ×1.5 |
| Command Injection | `CMD_INJ` | LLM proxy misconfiguration | ×1.4 |
| Prompt Injection via Supply Chain | `PROMPT_INJ` | Compromised package injecting prompts | ×1.3 |
| Data Exfiltration | `DATA_EXFIL` | Packages sending data to third parties | ×1.2 |
| Model Poisoning | `MODEL_POISON` | Trojanized model files | ×1.5 |
| Auth Bypass | `AUTH_BYPASS` | Missing auth on AI endpoints | ×1.3 |
| Credential Exposure | `CREDS_EXPOSE` | API keys/tokens in package code | ×1.2 |
| Memory/Context Poisoning | `MEM_POISON` | Adversarial input manipulation | ×1.1 |

## 9. Known AI/ML Package Registry

Pre-curated list of AI/ML packages for dependency filtering:

```python
AI_ML_PACKAGES = {
    # LLM Frameworks
    "langchain", "langgraph", "langchain-core", "langchain-community",
    "langchain-openai", "langchain-anthropic", "langchain-google-genai",
    "litellm", "llamaindex", "llama-index",
    # ML/Deep Learning
    "torch", "tensorflow", "jax", "numpy", "pandas", "scikit-learn",
    "transformers", "datasets", "huggingface-hub", "accelerate",
    "diffusers", "peft", "trl", "safetensors",
    # AI Tools
    "openai", "anthropic", "google-generativeai",
    "sentence-transformers", "faiss-cpu", "chromadb", "pinecone-client",
    "tiktoken", "tokenizers", "vllm", "xformers",
    # Agent Frameworks
    "crewai", "autogen-agentchat", "smolagents",
    "instructor", "guidance", "marvin",
    # Embedding & Vector
    "sentencepiece", "onnxruntime", "tensorboard", "mlflow",
    "wandb", "optuna", "ray",
    # AI Security
    "prompt-guard", "llm-guard",
}
```

## 10. Risk Scoring Formula

```
risk_score = base_cvss × ai_modifier × exploitability_modifier × exposure_modifier

where:
  base_cvss: CVSS score from vulnerability database (0-10)
  ai_modifier: multiplier from AI risk category (1.0-1.5)
  exploitability_modifier:
    - IN KEV: ×1.5
    - Has PoC: ×1.2
    - Theoretical only: ×1.0
  exposure_modifier:
    - Direct network exposure: ×1.3
    - Internal only: ×1.0
    - Requires specific config: ×0.8

Priority ranking: risk_score (descending)
```
