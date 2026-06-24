"""Parse dependencies from requirements.txt, pyproject.toml, or package.json."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .ai_ml_packages import is_ai_ml_package


def parse_dependencies(state: dict) -> dict:
    """Parse dependency file and identify AI/ML packages.

    Updates state with:
        - dependencies: list of all parsed deps
        - ai_ml_deps: filtered AI/ML deps
        - error: error message if parsing fails
    """
    file_path = state.get("file_path", "")
    file_content = state.get("file_content", "")

    if not file_content and file_path:
        try:
            file_content = Path(file_path).read_text(encoding="utf-8")
        except FileNotFoundError:
            return {"error": f"File not found: {file_path}", "dependencies": [], "ai_ml_deps": []}
        except Exception as e:
            return {"error": f"Failed to read file: {e}", "dependencies": [], "ai_ml_deps": []}

    if not file_content:
        return {"error": "No file content provided", "dependencies": [], "ai_ml_deps": []}

    # Detect file type
    if "pyproject.toml" in (file_path or ""):
        deps = _parse_pyproject_toml(file_content)
    elif "package.json" in (file_path or ""):
        deps = _parse_package_json(file_content)
    else:
        deps = _parse_requirements_txt(file_content)

    ai_ml_deps = [d for d in deps if is_ai_ml_package(d["name"])]

    return {
        "dependencies": deps,
        "ai_ml_deps": ai_ml_deps,
    }


def _parse_requirements_txt(content: str) -> list[dict]:
    """Parse requirements.txt format."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Handle comments after package
        line = line.split(" #")[0].strip()

        # Extract name and version
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([><=!~\[]?\s*[^\s;]+)?", line)
        if match:
            name = match.group(1)
            version_spec = match.group(2) or ""
            version = _extract_version(version_spec)
            deps.append({
                "name": name,
                "version_spec": version_spec.strip(),
                "version": version,
                "file_type": "requirements.txt",
            })

    return deps


def _parse_pyproject_toml(content: str) -> list[dict]:
    """Parse pyproject.toml dependencies (simplified, no toml parser dependency)."""
    deps = []

    # Find the [project] section dependencies
    in_project = False
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()

        if stripped.startswith("[project]"):
            in_project = True
            continue
        if stripped.startswith("[") and in_project and not stripped.startswith("[project"):
            in_project = False
            in_deps = False
            continue

        if in_project and stripped.startswith("dependencies"):
            in_deps = True
            if "=" in stripped:
                continue
            continue

        if in_deps:
            if stripped.startswith("]"):
                in_deps = False
                continue
            if stripped.startswith("name") or stripped.startswith("version") or stripped.startswith("description"):
                in_deps = False
                continue

            # Parse dependency line: "package>=1.0,<2.0"
            dep_str = stripped.strip().strip('"').strip("'").strip(",")
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([><=!~\[]?\s*[^\s]+)?", dep_str)
            if match:
                name = match.group(1)
                version_spec = match.group(2) or ""
                version = _extract_version(version_spec)
                deps.append({
                    "name": name,
                    "version_spec": version_spec.strip(),
                    "version": version,
                    "file_type": "pyproject.toml",
                })

    return deps


def _parse_package_json(content: str) -> list[dict]:
    """Parse package.json dependencies."""
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    for dep_type in ("dependencies", "devDependencies"):
        for name, version_spec in data.get(dep_type, {}).items():
            version = _extract_version(version_spec)
            deps.append({
                "name": name,
                "version_spec": version_spec,
                "version": version,
                "file_type": "package.json",
                "is_dev": dep_type == "devDependencies",
            })

    return deps


def _extract_version(spec: str) -> str:
    """Extract a clean version string from a version specifier."""
    if not spec:
        return ""
    # Handle ">=1.0.0", "==1.0.0", "^1.0.0", "~1.0.0"
    spec = spec.strip()
    for prefix in (">=", "==", "<=", "~=", "!=", "^", "~", ">", "<", "="):
        if spec.startswith(prefix):
            spec = spec[len(prefix):]
    # Strip trailing semver ranges
    spec = spec.split(",")[0].strip()
    return spec
