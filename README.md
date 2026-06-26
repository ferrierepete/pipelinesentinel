# PipelineSentinel

**AI/ML Dependency Vulnerability Intelligence Agent**

LangGraph AI agent that continuously monitors your AI/ML pipeline dependencies for new vulnerabilities from OSV, GHSA, and CISA KEV, correlates AI-specific attack vectors, and generates actionable remediation briefings with version-specific upgrade paths.

## Why PipelineSentinel?

Every team building AI agents depends on frameworks like LangChain, LangGraph, LiteLLM, and OpenAI SDKs. These packages have real, actively-exploited vulnerabilities:

- **LangGraph**: Unsafe deserialization RCE (GHSA-g48c-2wqr-h844)
- **LiteLLM**: 25 OSV vulnerabilities, host header injection (CVE-2026-42271)
- **LangChain**: 38 OSV vulnerabilities, multiple injection vectors

Generic tools like Snyk and Dependabot flag these as regular dependency issues. PipelineSentinel understands **AI-specific risk categories** — deserialization RCE on an agent framework enables model manipulation, not just code execution.

## Features

- **Multi-source intelligence**: OSV.dev, GitHub Security Advisories, CISA KEV catalog
- **AI-specific risk classification**: 8 categories (Deserialization RCE, Command Injection, Prompt Injection, Data Exfiltration, Model Poisoning, Auth Bypass, Credential Exposure, Memory Poisoning)
- **Composite risk scoring**: CVSS × AI modifier × exploitability × exposure
- **Upgrade path resolution**: PyPI/npm version lookup with safe upgrade recommendations
- **LLM-powered briefing**: Remediation briefing with AI-context-aware recommendations
- **Human-in-the-loop**: Pause on critical findings (KEV entries, CVSS 9.0+) for review
- **Session persistence**: SQLite checkpointing for resume and time-travel
- **Terminal UI**: Rich-powered interactive terminal interface
- **Web UI**: Next.js dashboard for team use

## LangGraph Features Used

- StateGraph with TypedDict state and Annotated reducers
- Custom tools (@tool pattern) for API integration
- Conditional edges (skip if no AI/ML deps, route by criticality)
- Checkpointing (SqliteSaver) for session persistence
- Streaming (astream_events) for real-time output
- Human-in-the-loop (interrupt_before) for critical finding approval

## Install

```bash
git clone https://github.com/ferrierepete/pipelinesentinel.git
cd pipelinesentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Terminal

```bash
# Scan a requirements.txt
pipelinesentinel requirements.txt

# Scan with JSON export
pipelinesentinel requirements.txt -o scan-results.json

# Scan a pyproject.toml
pipelinesentinel pyproject.toml

# Scan a package.json
pipelinesentinel package.json
```

### Web UI

**Two servers are needed: the Python API backend and the Next.js frontend.**

```bash
# Terminal 1: Start the Python API backend
PYTHONPATH=. python web/api/server.py --port 8742

# Terminal 2: Start the Next.js frontend
cd web
npm install
npm run dev
# Open http://localhost:3000
```

The frontend calls the Python API at `http://127.0.0.1:8742`. Set `NEXT_PUBLIC_API_BASE` to change this.

### Python API

```bash
# Start the standalone API server
PYTHONPATH=. python web/api/server.py --port 8742

# Test health endpoint
curl http://127.0.0.1:8742/api/health

# Run a scan (synchronous JSON response)
curl -X POST http://127.0.0.1:8742/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"file_content": "langchain>=0.3.0\nlanggraph>=0.2.0", "file_name": "requirements.txt"}'

# Run a scan with SSE streaming
curl -X POST http://127.0.0.1:8742/api/scan/stream \
  -H 'Content-Type: application/json' \
  -d '{"file_content": "langchain>=0.3.0\nlanggraph>=0.2.0", "file_name": "requirements.txt"}'
```

### Python Library

```python
from src.graph import build_graph

graph = build_graph()
result = await graph.ainvoke({
    "file_path": "requirements.txt",
    "file_content": open("requirements.txt").read(),
})

# Access results
for finding in result["findings"]:
    print(f"{finding['severity']} {finding['package']}: {finding['summary']}")
    print(f"  Risk Score: {finding['risk_score']} ({finding['priority']})")
    print(f"  AI Risk: {finding['ai_risk_description']}")
    print(f"  Fix: Upgrade to {finding['fix_version']}")

print(result["briefing"])  # LLM-generated remediation report
```

### With Checkpointing

```python
from src.graph import build_graph_with_interrupts
from langgraph.checkpoint.sqlite import SqliteSaver
import sqlite3

conn = sqlite3.connect("checkpoints.sqlite", check_same_thread=False)
checkpointer = SqliteSaver(conn)

graph = build_graph_with_interrupts(checkpointer=checkpointer)

config = {"configurable": {"thread_id": "scan-2026-06-24"}}
result = await graph.ainvoke(initial_state, config)

# Resume after human review
result = await graph.ainvoke(None, config, command={"resume": "approve"})
```

## Supported AI/ML Packages

PipelineSentinel recognizes 80+ AI/ML packages including:

**LLM Frameworks**: LangChain, LangGraph, LiteLLM, LlamaIndex, CrewAI, AutoGen, SmolAgents, Phidata
**ML/Deep Learning**: PyTorch, TensorFlow, JAX, Transformers, Diffusers, PEFT, TRL, Safetensors
**Provider SDKs**: OpenAI, Anthropic, Google Generative AI, Cohere, Mistral
**Vector Databases**: ChromaDB, FAISS, Pinecone, Qdrant, Weaviate, Milvus
**Inference**: vLLM, xFormers, DeepSpeed, Triton, bitsandbytes
**MLOps**: MLflow, Weights & Biases, Optuna, Ray, DVC

## AI Risk Categories

| Category | Modifier | Description |
|----------|----------|-------------|
| DESER_RCE | ×1.5 | Deserialization Remote Code Execution |
| CMD_INJ | ×1.4 | Command/Code Injection via Proxy |
| PROMPT_INJ | ×1.3 | Prompt Injection via Supply Chain |
| MODEL_POISON | ×1.5 | AI Model Poisoning |
| AUTH_BYPASS | ×1.3 | Authentication/Authorization Bypass |
| DATA_EXFIL | ×1.2 | Data Exfiltration to Third Parties |
| CREDS_EXPOSE | ×1.2 | Credential/API Key Exposure |
| MEM_POISON | ×1.1 | Memory/Context Poisoning |

## Risk Scoring

```
risk_score = CVSS × AI_Risk_Modifier × Exploitability × Exposure
```

- **Exploitability**: ×1.5 if in CISA KEV, ×1.2 if PoC exists
- **Exposure**: ×1.3 for network-exposed, ×1.0 for internal, ×0.8 for config-dependent
- Capped at 15.0

## Configuration

```bash
cp .env.example .env
# Set your LLM provider (default: OpenAI gpt-4o-mini)
OPENAI_API_KEY=***
PIPELINESENTINEL_MODEL=gpt-4o-mini
```

## Tests

```bash
source .venv/bin/activate
PYTHONPATH=. pytest tests/ -v
```

## Architecture

```
requirements.txt / pyproject.toml / package.json
    ↓
[parse_dependencies] → identify AI/ML packages
    ↓
[ingest_osv] ←→ [ingest_ghsa]  (parallel queries)
    ↓
[ingest_kev]  (CISA KEV cross-reference)
    ↓
[correlate_findings]  (merge + AI risk classification)
    ↓
[assess_risk]  (composite scoring + upgrade paths)
    ↓
[generate_briefing]  (LLM remediation report)
    ↓
[human_review]  (interrupt on critical findings)
    ↓
END
```

## License

MIT
