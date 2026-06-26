"""GitHub Security Advisory search tool."""

from __future__ import annotations

import logging

import httpx

from src.utils.retry import is_rate_limited, retry_async

logger = logging.getLogger(__name__)

GHSA_SEARCH_URL = "https://api.github.com/advisories"


async def _do_ghsa_search(
    package: str, ecosystem: str = "pypi", per_page: int = 10, timeout: float = 30.0
) -> list[dict]:
    """Inner GHSA search function with explicit timeout."""
    params = {
        "affects": package.lower(),
        "ecosystem": ecosystem,
        "per_page": per_page,
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(GHSA_SEARCH_URL, params=params)
        if resp.status_code == 422:
            logger.debug(f"GHSA 422 for {package} (parameter validation, skipping)")
            return []
        if is_rate_limited(resp):
            logger.warning(f"GHSA rate limited for {package}")
        if resp.status_code == 403:
            return []
        resp.raise_for_status()
        data = resp.json()

    results = []
    for adv in data:
        result = {
            "id": adv.get("ghsa_id", ""),
            "cve_id": adv.get("cve_id", ""),
            "summary": adv.get("summary", ""),
            "description": (adv.get("description") or "")[:500],
            "severity": adv.get("severity", ""),
            "cvss_score": _parse_cvss(adv.get("cvss", {})),
            "cwes": [c.get("cwe_id", "") for c in adv.get("cwes", [])],
            "package": package,
            "published_at": adv.get("published_at", ""),
            "url": adv.get("html_url", ""),
        }
        results.append(result)

    return results


async def ghsa_search(
    package: str, ecosystem: str = "pypi", per_page: int = 10
) -> list[dict]:
    """Search GitHub Security Advisories for a package.

    Args:
        package: Package name
        ecosystem: "pypi", "npm", "maven", etc.
        per_page: Max results to return

    Returns:
        List of advisory dicts.
    """
    try:
        return await retry_async(
            _do_ghsa_search, package, ecosystem, per_page,
            max_retries=2, base_delay=1.0,
            retryable_exceptions=(httpx.ConnectError, httpx.TimeoutException),
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"GHSA search failed for {package}: {e}")
        return []
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        logger.error(f"GHSA network error for {package}: {e}")
        return []


def _parse_cvss(cvss_dict: dict) -> float:
    """Parse CVSS score from advisory CVSS dict."""
    if not cvss_dict:
        return 0.0
    score = cvss_dict.get("score", 0.0)
    return float(score) if score else 0.0
