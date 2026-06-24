"""Tests for parse_dependencies node."""

import pytest

from src.nodes.parse_dependencies import (
    _extract_version,
    _parse_package_json,
    _parse_pyproject_toml,
    _parse_requirements_txt,
    parse_dependencies,
)


class TestParseRequirementsTxt:
    def test_simple(self):
        content = "langchain==0.1.0\nnumpy>=1.24.0\n"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 2
        assert deps[0]["name"] == "langchain"
        assert deps[0]["version"] == "0.1.0"
        assert deps[1]["name"] == "numpy"
        assert deps[1]["version"] == "1.24.0"

    def test_comments_and_empty_lines(self):
        content = "# This is a comment\n\nlanggraph>=0.2.0\n# Another comment\nopenai\nnumpy>=1.24.0\n"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 3
        assert deps[0]["name"] == "langgraph"
        assert deps[2]["name"] == "numpy"

    def test_inline_comments(self):
        content = "litellm>=1.40.0  # LLM proxy\n"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "litellm"

    def test_extras_markers(self):
        content = "langchain[docstore]>=0.1.0\n"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "langchain"


class TestParsePyprojectToml:
    def test_basic(self):
        content = """
[project]
name = "myapp"
version = "1.0.0"
dependencies = [
    "langchain>=0.1.0",
    "numpy>=1.24.0",
    "openai",
]
"""
        deps = _parse_pyproject_toml(content)
        assert len(deps) == 3
        assert deps[0]["name"] == "langchain"
        assert deps[1]["name"] == "numpy"

    def test_empty(self):
        deps = _parse_pyproject_toml("No dependencies here")
        assert len(deps) == 0


class TestParsePackageJson:
    def test_basic(self):
        import json
        data = {
            "dependencies": {
                "langchain": "^0.1.0",
                "openai": "^4.0.0",
            },
            "devDependencies": {
                "jest": "^29.0.0",
            },
        }
        deps = _parse_package_json(json.dumps(data))
        assert len(deps) == 3
        assert deps[0]["name"] == "langchain"
        assert deps[0]["file_type"] == "package.json"

    def test_invalid_json(self):
        deps = _parse_package_json("not json")
        assert len(deps) == 0


class TestExtractVersion:
    def test_exact(self):
        assert _extract_version("==1.0.0") == "1.0.0"

    def test_gte(self):
        assert _extract_version(">=1.0.0") == "1.0.0"

    def test_caret(self):
        assert _extract_version("^1.0.0") == "1.0.0"

    def test_tilde(self):
        assert _extract_version("~1.0.0") == "1.0.0"

    def test_empty(self):
        assert _extract_version("") == ""

    def test_complex(self):
        assert _extract_version(">=1.0.0,<2.0.0") == "1.0.0"


class TestParseDependenciesNode:
    def test_full_requirements(self):
        content = "langchain==0.1.0\nnumpy>=1.24.0\nrequests==2.31.0\nopenai>=1.0.0\n"
        state = {"file_path": "requirements.txt", "file_content": content}
        result = parse_dependencies(state)
        assert len(result["dependencies"]) == 4
        assert len(result["ai_ml_deps"]) >= 2  # langchain, openai

    def test_file_not_found(self):
        state = {"file_path": "/nonexistent/requirements.txt", "file_content": ""}
        result = parse_dependencies(state)
        assert "error" in result

    def test_empty_content(self):
        state = {"file_path": "", "file_content": ""}
        result = parse_dependencies(state)
        assert "error" in result
