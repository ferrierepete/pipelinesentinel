"""State schema for PipelineSentinel LangGraph agent."""

from typing import Annotated, TypedDict

from operator import add


class PipelineSentinelState(TypedDict):
    """State for the PipelineSentinel vulnerability scanning graph."""

    # Input
    file_path: str
    file_content: str

    # Parsed data
    dependencies: list[dict]
    ai_ml_deps: list[dict]

    # Intelligence sources
    osv_vulns: list[dict]
    ghsa_vulns: list[dict]
    kev_entries: list[dict]

    # Analysis
    findings: Annotated[list[dict], add]
    error: str

    # Output
    briefing: str
