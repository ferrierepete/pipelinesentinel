"""PyPI version lookup tool — resolves safe upgrade versions."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/pypi/{package}/json"


async def pypi_versions(package: str) -> dict:
    """Get all available versions and metadata for a PyPI package."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(PYPI_URL.format(package=package.lower()))
            resp.raise_for_status()
            data = resp.json()

        info = data.get("info", {})
        releases = data.get("releases", {})
        versions = sorted(
            releases.keys(),
            key=_sort_version,
            reverse=True,
        )

        return {
            "package": package,
            "latest": info.get("version", ""),
            "versions": versions,
            "summary": info.get("summary", ""),
            "requires_python": info.get("requires_python", ""),
            "home_page": info.get("home_page", ""),
            "yanked": {
                v: any(r.get("yanked", False) for r in rels)
                for v, rels in releases.items()
            },
        }
    except httpx.TimeoutException:
        logger.warning(f"PyPI lookup timed out for {package}")
        return {"package": package, "latest": "", "versions": [], "error": "timeout"}
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {"package": package, "latest": "", "versions": [], "error": "not found"}
        logger.warning(f"PyPI lookup failed for {package}: {e}")
        return {"package": package, "latest": "", "versions": [], "error": "lookup failed"}
    except (httpx.ConnectError, Exception):
        logger.warning(f"PyPI error for {package}")
        return {"package": package, "latest": "", "versions": [], "error": "lookup failed"}


def _sort_version(version: str) -> tuple:
    """Simple version sort key using tuple of ints."""
    parts = []
    for part in version.split(".")[:3]:
        p = part.split("-")[0].split("+")[0].split("rc")[0].split("a")[0].split("b")[0]
        parts.append(int(p) if p.isdigit() else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def get_safe_upgrade_version(
    current_version: str, available_versions: list[str], vuln_fixed_in: str | None = None
) -> str | None:
    """Determine the safest upgrade version."""
    if vuln_fixed_in and vuln_fixed_in in available_versions:
        return vuln_fixed_in

    current_parts = _sort_version(current_version)
    for v in available_versions:
        if _sort_version(v) > current_parts:
            return v

    return None
