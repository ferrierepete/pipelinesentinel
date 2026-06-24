"""CISA Known Exploited Vulnerabilities (KEV) catalog check tool."""

from __future__ import annotations

import httpx
from functools import lru_cache

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@lru_cache(maxsize=1)
def _load_kev_catalog() -> list[dict]:
    """Load and cache the full CISA KEV catalog."""
    resp = httpx.get(KEV_URL, timeout=30.0)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


def kev_check(cve_ids: list[str]) -> list[dict]:
    """Check if any CVE IDs are in the CISA Known Exploited Vulnerabilities catalog.

    Args:
        cve_ids: List of CVE IDs to check (e.g., ["CVE-2024-12345"])

    Returns:
        List of KEV entries matching the given CVE IDs.
    """
    if not cve_ids:
        return []

    try:
        catalog = _load_kev_catalog()
    except Exception:
        return []

    cve_set = {c.upper() for c in cve_ids}
    matches = []
    for entry in catalog:
        if entry.get("cveID", "").upper() in cve_set:
            matches.append({
                "cve_id": entry.get("cveID", ""),
                "vendor_project": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "vulnerability_name": entry.get("vulnerabilityName", ""),
                "date_added": entry.get("dateAdded", ""),
                "short_description": entry.get("shortDescription", ""),
                "required_action": entry.get("requiredAction", ""),
                "due_date": entry.get("dueDate", ""),
                "notes": entry.get("notes", ""),
            })

    return matches
