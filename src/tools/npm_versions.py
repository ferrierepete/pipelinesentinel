"""npm version lookup tool — resolves safe upgrade versions for JS packages."""

from __future__ import annotations

import httpx

NPM_URL = "https://registry.npmjs.org/{package}"


async def npm_versions(package: str) -> dict:
    """Get all available versions and metadata for an npm package.

    Args:
        package: Package name

    Returns:
        Dict with 'latest', 'versions', 'description'.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(NPM_URL.format(package=package))
            if resp.status_code == 404:
                return {"package": package, "latest": "", "versions": [], "error": "not found"}
            resp.raise_for_status()
            data = resp.json()

        dist_tags = data.get("dist-tags", {})
        versions_data = data.get("versions", {})
        versions = sorted(versions_data.keys(), reverse=True)

        return {
            "package": package,
            "latest": dist_tags.get("latest", ""),
            "next": dist_tags.get("next", ""),
            "versions": versions,
            "description": data.get("description", ""),
            "homepage": data.get("homepage", ""),
        }
    except Exception:
        return {"package": package, "latest": "", "versions": [], "error": "lookup failed"}
