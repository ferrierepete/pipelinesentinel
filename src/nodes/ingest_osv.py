"""Ingest OSV vulnerability data for AI/ML dependencies."""

from __future__ import annotations

import asyncio
import logging

from src.tools.osv_query import osv_query as osv_tool
from src.tools.pypi_versions import pypi_versions

logger = logging.getLogger(__name__)


async def ingest_osv(state: dict) -> dict:
    """Query OSV.dev for each AI/ML dependency.

    Returns state update with osv_vulns list.
    """
    ai_ml_deps = state.get("ai_ml_deps", [])

    if not ai_ml_deps:
        return {"osv_vulns": []}

    all_vulns = []
    errors = []

    tasks = []
    for dep in ai_ml_deps:
        ecosystem = "npm" if dep.get("file_type") == "package.json" else "PyPI"
        version = dep.get("version", "")
        if not version:
            continue
        tasks.append((dep["name"], version, ecosystem))

    results = await asyncio.gather(
        *[_query_single(name, ver, eco) for name, ver, eco in tasks],
        return_exceptions=True,
    )

    for i, result in enumerate(results):
        dep_name = tasks[i][0] if i < len(tasks) else "unknown"
        if isinstance(result, Exception):
            errors.append(f"OSV query error for {dep_name}: {result}")
            logger.warning(errors[-1])
        else:
            all_vulns.extend(result)

    if errors:
        logger.info(f"OSV ingest completed with {len(errors)} errors, {len(all_vulns)} vulns found")

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
