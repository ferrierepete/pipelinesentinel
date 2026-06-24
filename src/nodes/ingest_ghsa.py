"""Ingest GitHub Security Advisory data for AI/ML dependencies."""

from __future__ import annotations

import asyncio

from src.tools.ghsa_search import ghsa_search


async def ingest_ghsa(state: dict) -> dict:
    """Query GitHub Security Advisories for each AI/ML dependency.

    Returns state update with ghsa_vulns list.
    """
    ai_ml_deps = state.get("ai_ml_deps", [])

    if not ai_ml_deps:
        return {"ghsa_vulns": []}

    all_advisories = []

    tasks = []
    for dep in ai_ml_deps:
        ecosystem = "npm" if dep.get("file_type") == "package.json" else "pypi"
        tasks.append(_query_single(dep["name"], ecosystem))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            continue
        all_advisories.extend(result)

    return {"ghsa_vulns": all_advisories}


async def _query_single(name: str, ecosystem: str) -> list[dict]:
    """Query GHSA for a single package."""
    try:
        advisories = await ghsa_search(name, ecosystem)
        for adv in advisories:
            adv["package_name"] = name
        return advisories
    except Exception:
        return []
