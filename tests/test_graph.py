"""Full graph integration test with mocked LLM and APIs."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.graph import build_graph
from src.state import PipelineSentinelState


# Sample requirements.txt content for testing
SAMPLE_REQUIREMENTS = """langchain>=0.1.0
numpy>=1.24.0
requests==2.31.0
openai>=1.0.0
litellm>=1.40.0
"""


@pytest.fixture
def mock_osv_response():
    return [
        {
            "id": "GHSA-g48c-2wqr-h844",
            "summary": "Unsafe deserialization leading to RCE",
            "details": "LangGraph uses pickle for state serialization",
            "aliases": ["CVE-2024-12345"],
            "severity": {},
            "references": [],
            "published": "2024-01-01",
            "modified": "2024-01-02",
            "database_specific": {},
        },
    ]


@pytest.fixture
def mock_ghsa_response():
    return [
        {
            "id": "GHSA-xxxx-yyyy",
            "cve_id": "CVE-2024-12345",
            "summary": "Deserialization vulnerability",
            "description": "Unsafe pickle usage",
            "severity": "HIGH",
            "cvss_score": 8.5,
            "cwes": [],
            "package": "langchain",
            "published_at": "2024-01-01",
            "url": "https://github.com/advisories/GHSA-xxxx-yyyy",
        },
    ]


@pytest.fixture
def mock_pypi_versions():
    return {
        "package": "langchain",
        "latest": "0.2.0",
        "versions": ["0.2.0", "0.1.5", "0.1.0"],
        "summary": "Building LLM apps",
        "requires_python": ">=3.8",
        "home_page": "",
        "yanked": {},
    }


@pytest.fixture
def mock_briefing_response():
    """Mock LLM response for briefing generation."""
    mock_response = MagicMock()
    mock_response.content = "## Executive Summary\nCritical vulnerabilities found.\n\n## Findings\nUpgrade langchain to 0.2.0."
    return mock_response


def _osv_side_effect(package, version, ecosystem):
    """OSV mock that only returns vulns for langgraph."""
    if package == "langgraph":
        return [
            {
                "id": "GHSA-g48c-2wqr-h844",
                "summary": "Unsafe deserialization RCE",
                "details": "Pickle deserialization",
                "aliases": ["CVE-2024-12345"],
                "severity": {"9.8": "CVSS"},
                "references": [],
                "published": "2024-01-01",
                "modified": "2024-01-02",
                "database_specific": {},
                "package_name": "langgraph",
                "current_version": "0.2.0",
                "ecosystem": "PyPI",
            },
        ]
    return []


class TestGraphIntegration:
    @pytest.mark.asyncio
    async def test_full_graph_execution(
        self,
        mock_osv_response,
        mock_ghsa_response,
        mock_pypi_versions,
        mock_briefing_response,
    ):
        """Test complete graph execution with mocked APIs."""
        from langchain_core.messages import AIMessage

        graph = build_graph()

        initial_state = {
            "file_path": "requirements.txt",
            "file_content": SAMPLE_REQUIREMENTS,
        }

        with (
            patch("src.nodes.ingest_osv.osv_tool", new_callable=AsyncMock) as mock_osv,
            patch("src.nodes.ingest_ghsa.ghsa_search", new_callable=AsyncMock) as mock_ghsa,
            patch("src.nodes.assess_risk.pypi_versions", new_callable=AsyncMock) as mock_pypi,
            patch("src.nodes.assess_risk.npm_versions", new_callable=AsyncMock),
            patch("src.nodes.generate_briefing._get_model") as mock_model,
        ):
            # Set up mocks
            mock_osv.return_value = []
            mock_ghsa.return_value = []
            mock_pypi.return_value = mock_pypi_versions

            # Mock the LLM
            mock_llm = AsyncMock()
            mock_llm.ainvoke = AsyncMock(return_value=mock_briefing_response)
            mock_model.return_value = mock_llm

            result = await graph.ainvoke(initial_state)

        # Verify the graph completed
        assert "dependencies" in result
        assert len(result["dependencies"]) == 5
        assert "ai_ml_deps" in result
        assert "findings" in result
        assert "briefing" in result
        assert len(result["briefing"]) > 0

    @pytest.mark.asyncio
    async def test_graph_with_vulns(self):
        """Test graph with mocked vulnerability findings."""
        mock_response = MagicMock()
        mock_response.content = "Vulnerabilities detected. Upgrade immediately."

        graph = build_graph()

        initial_state = {
            "file_path": "requirements.txt",
            "file_content": "langgraph>=0.2.0\nopenai>=1.0.0\n",
        }

        with (
            patch("src.nodes.ingest_osv.osv_tool", new_callable=AsyncMock) as mock_osv,
            patch("src.nodes.ingest_ghsa.ghsa_search", new_callable=AsyncMock) as mock_ghsa,
            patch("src.nodes.assess_risk.pypi_versions", new_callable=AsyncMock) as mock_pypi,
            patch("src.nodes.assess_risk.npm_versions", new_callable=AsyncMock),
            patch("src.nodes.generate_briefing._get_model") as mock_model,
        ):
            mock_osv.side_effect = _osv_side_effect
            mock_ghsa.return_value = []
            mock_pypi.return_value = {
                "package": "langgraph",
                "latest": "0.2.5",
                "versions": ["0.2.5", "0.2.4", "0.2.3", "0.2.2", "0.2.1", "0.2.0"],
                "summary": "",
                "requires_python": "",
                "home_page": "",
                "yanked": {},
            }

            mock_llm = AsyncMock()
            mock_llm.ainvoke = AsyncMock(return_value=mock_response)
            mock_model.return_value = mock_llm

            result = await graph.ainvoke(initial_state)

        assert len(result["findings"]) >= 1
        langgraph_findings = [f for f in result["findings"] if f["package"] == "langgraph"]
        assert len(langgraph_findings) >= 1
        finding = langgraph_findings[0]
        assert finding["package"] == "langgraph"
        assert finding["ai_risk_category"] == "DESER_RCE"
        assert finding["risk_score"] > 0
        assert finding["fix_version"] == "0.2.5"

    @pytest.mark.asyncio
    async def test_graph_no_ai_deps(self):
        """Test graph with no AI/ML dependencies — should produce no findings."""
        mock_response = MagicMock()
        mock_response.content = "No AI/ML dependencies found."

        graph = build_graph()

        initial_state = {
            "file_path": "requirements.txt",
            "file_content": "requests==2.31.0\nflask>=3.0.0\npytest>=8.0.0\n",
        }

        with (
            patch("src.nodes.ingest_osv.osv_tool", new_callable=AsyncMock) as mock_osv,
            patch("src.nodes.ingest_ghsa.ghsa_search", new_callable=AsyncMock) as mock_ghsa,
            patch("src.nodes.assess_risk.pypi_versions", new_callable=AsyncMock) as mock_pypi,
            patch("src.nodes.assess_risk.npm_versions", new_callable=AsyncMock),
            patch("src.nodes.generate_briefing._get_model") as mock_model,
        ):
            mock_osv.return_value = []
            mock_ghsa.return_value = []
            mock_pypi.return_value = {"package": "x", "latest": "", "versions": []}

            mock_llm = AsyncMock()
            mock_llm.ainvoke = AsyncMock(return_value=mock_response)
            mock_model.return_value = mock_llm

            result = await graph.ainvoke(initial_state)

        assert len(result["ai_ml_deps"]) == 0
        assert len(result["osv_vulns"]) == 0
        assert len(result["findings"]) == 0
