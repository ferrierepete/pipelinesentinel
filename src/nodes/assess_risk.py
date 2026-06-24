"""Assess risk scores for correlated findings."""

from __future__ import annotations

import asyncio

from src.tools.ai_risk_classifier import calculate_risk_score
from src.tools.pypi_versions import get_safe_upgrade_version, pypi_versions
from src.tools.npm_versions import npm_versions


async def assess_risk(state: dict) -> dict:
    """Calculate composite risk scores and resolve upgrade paths for each finding.

    Updates findings with risk_score, priority, and fix_version.
    """
    findings = state.get("findings", [])
    ai_ml_deps = state.get("ai_ml_deps", [])

    if not findings:
        return {"findings": []}

    # Resolve upgrade versions for all affected packages
    pkg_versions_cache = {}
    tasks = []
    for finding in findings:
        pkg = finding["package"]
        current_ver = finding["current_version"]
        if pkg and current_ver and pkg not in pkg_versions_cache:
            ecosystem = "npm" if finding.get("source", "") == "GHSA" and any(
                d.get("file_type") == "package.json" for d in ai_ml_deps if d["name"] == pkg
            ) else "PyPI"
            tasks.append(_resolve_versions(pkg, ecosystem, pkg_versions_cache))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    # Score each finding
    scored_findings = []
    for finding in findings:
        pkg = finding["package"]
        current_ver = finding["current_version"]
        ai_modifier = finding.get("ai_risk_modifier", 1.0)
        in_kev = finding.get("in_kev", False)

        risk_score = calculate_risk_score(
            cvss=finding["cvss"],
            ai_modifier=ai_modifier,
            in_kev=in_kev,
            exposure="network" if ai_modifier > 1.2 else "internal",
        )

        # Find upgrade version
        fix_version = None
        cache_entry = pkg_versions_cache.get(pkg, {})
        available_versions = cache_entry.get("versions", [])
        if current_ver and available_versions:
            fix_version = get_safe_upgrade_version(current_ver, available_versions)

        finding["risk_score"] = risk_score
        finding["fix_version"] = fix_version or ""
        finding["available_versions"] = available_versions[:10] if available_versions else []
        finding["priority"] = _priority_rank(risk_score, in_kev)

        scored_findings.append(finding)

    # Sort by priority then risk_score
    scored_findings.sort(key=lambda f: (-_priority_sort(f["priority"]), -f["risk_score"]))

    return {"findings": scored_findings}


async def _resolve_versions(
    pkg: str, ecosystem: str, cache: dict
) -> None:
    """Resolve available versions for a package and store in cache."""
    try:
        if ecosystem == "npm":
            result = await npm_versions(pkg)
        else:
            result = await pypi_versions(pkg)
        cache[pkg] = result
    except Exception:
        cache[pkg] = {"latest": "", "versions": []}


def _priority_rank(risk_score: float, in_kev: bool) -> str:
    """Determine priority rank from risk score."""
    if in_kev:
        return "P0"
    if risk_score >= 12.0:
        return "P0"
    if risk_score >= 9.0:
        return "P1"
    if risk_score >= 7.0:
        return "P2"
    if risk_score >= 4.0:
        return "P3"
    return "P4"


def _priority_sort(priority: str) -> int:
    """Convert priority string to sortable int."""
    return {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}.get(priority, 5)
