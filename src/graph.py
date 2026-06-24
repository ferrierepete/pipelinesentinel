"""PipelineSentinel LangGraph StateGraph definition."""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from src.state import PipelineSentinelState
from src.nodes import (
    assess_risk,
    correlate_findings,
    generate_briefing,
    human_review,
    ingest_kev,
    ingest_osv,
    parse_dependencies,
)
from src.nodes.ingest_ghsa import ingest_ghsa


def build_graph(checkpointer=None):
    """Build and compile the PipelineSentinel LangGraph.

    Args:
        checkpointer: Optional checkpointer for session persistence.
            Pass SqliteSaver or InMemorySaver instance.

    Returns:
        Compiled LangGraph runnable.
    """
    builder = StateGraph(PipelineSentinelState)

    # Add nodes
    builder.add_node("parse_dependencies", parse_dependencies)
    builder.add_node("ingest_osv", ingest_osv)
    builder.add_node("ingest_ghsa", ingest_ghsa)
    builder.add_node("ingest_kev", ingest_kev)
    builder.add_node("correlate_findings", correlate_findings)
    builder.add_node("assess_risk", assess_risk)
    builder.add_node("generate_briefing", generate_briefing)
    builder.add_node("human_review", human_review)

    # Entry point
    builder.add_edge(START, "parse_dependencies")

    # Main flow
    builder.add_edge("parse_dependencies", "ingest_osv")
    builder.add_edge("ingest_osv", "ingest_ghsa")
    builder.add_edge("ingest_ghsa", "ingest_kev")
    builder.add_edge("ingest_kev", "correlate_findings")
    builder.add_edge("correlate_findings", "assess_risk")
    builder.add_edge("assess_risk", "generate_briefing")

    # Conditional: skip human review if no critical findings
    builder.add_conditional_edges(
        "generate_briefing",
        _route_to_review,
        {
            "review": "human_review",
            "end": END,
        },
    )

    builder.add_edge("human_review", END)

    # Compile with optional checkpointer and interrupt configuration
    compile_kwargs = {}
    if checkpointer is not None:
        compile_kwargs["checkpointer"] = checkpointer

    graph = builder.compile(**compile_kwargs)

    return graph


def _route_to_review(state: dict) -> str:
    """Route to human_review if critical findings exist, otherwise end."""
    findings = state.get("findings", [])
    for f in findings:
        if f.get("in_kev") or f.get("cvss", 0) >= 9.0:
            return "review"
    return "end"


def build_graph_with_interrupts(checkpointer=None):
    """Build graph with human-in-the-loop interrupts for critical findings.

    This version uses interrupt_before on human_review so the graph
    pauses and waits for human input before completing.
    """
    builder = StateGraph(PipelineSentinelState)

    builder.add_node("parse_dependencies", parse_dependencies)
    builder.add_node("ingest_osv", ingest_osv)
    builder.add_node("ingest_ghsa", ingest_ghsa)
    builder.add_node("ingest_kev", ingest_kev)
    builder.add_node("correlate_findings", correlate_findings)
    builder.add_node("assess_risk", assess_risk)
    builder.add_node("generate_briefing", generate_briefing)
    builder.add_node("human_review", human_review)

    builder.add_edge(START, "parse_dependencies")
    builder.add_edge("parse_dependencies", "ingest_osv")
    builder.add_edge("ingest_osv", "ingest_ghsa")
    builder.add_edge("ingest_ghsa", "ingest_kev")
    builder.add_edge("ingest_kev", "correlate_findings")
    builder.add_edge("correlate_findings", "assess_risk")
    builder.add_edge("assess_risk", "generate_briefing")

    builder.add_conditional_edges(
        "generate_briefing",
        _route_to_review,
        {"review": "human_review", "end": END},
    )

    builder.add_edge("human_review", END)

    compile_kwargs = {}
    if checkpointer is not None:
        compile_kwargs["checkpointer"] = checkpointer
    compile_kwargs["interrupt_before"] = ["human_review"]

    return builder.compile(**compile_kwargs)
