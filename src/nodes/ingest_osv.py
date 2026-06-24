"""Ingest OSV vulnerability data for AI/ML dependencies."""

from __future__ import annotations

import asyncio

from src.tools.osv_query import osv_query as osv_tool
from src.tools.pypi_versions import pypi_versions


async def ingest_osv(state: dict) -> dict:
    """Query OSV.dev for each AI/ML dependency.

    Returns state update with osv_vulns list.
    """
    ai_ml_deps = state.get("ai_ml_deps", [])

    if not ai_ml_deps:
        return {"osv_vulns": []}

    all_vulns = []

    tasks = []
    for dep in ai_ml_deps:
        ecosystem = "npm" if dep.get("file_type") == "package.json" else "PyPI"
        version = dep.get("version", "")
        if not version:
            continue
        tasks.append(_query_single(dep["name"], version, ecosystem))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            continue
        all_vulns.extend(result)

    return {"osv_vulns": all_vulns}


async def _query_single(name: str, version: str, ecosystem: str) -> list[dict]:
    """Query OSV for a single package and get upgrade info."""
    try:
        vulns = await osv_tool(name, version, ecosystem)
        for vuln in vulns:
            vuln["package_name"] = name
            vuln["current_version"] = version
            vuln["ecosystem"] = ecosystem
        return vulns
    except Exception:
        return []
