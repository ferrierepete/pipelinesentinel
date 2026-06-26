"""Tests for network error handling and retry logic."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

import httpx


class TestRetryAsync:
    @pytest.mark.asyncio
    async def test_retry_succeeds_on_second_attempt(self):
        """Verify retry_async retries on transient errors."""
        from src.utils.retry import retry_async

        call_count = 0

        async def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise httpx.ConnectError("Connection refused")
            return "success"

        result = await retry_async(
            flaky_func,
            max_retries=2,
            base_delay=0.01,
            retryable_exceptions=(httpx.ConnectError,),
        )
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_exhausts_and_raises(self):
        """Verify retry_async raises after exhausting retries."""
        from src.utils.retry import retry_async

        async def always_fails():
            raise httpx.TimeoutException("Timeout")

        with pytest.raises(httpx.TimeoutException):
            await retry_async(
                always_fails,
                max_retries=1,
                base_delay=0.01,
                retryable_exceptions=(httpx.TimeoutException,),
            )


class TestIsRateLimited:
    def test_429_is_rate_limited(self):
        from src.utils.retry import is_rate_limited

        resp = MagicMock()
        resp.status_code = 429
        resp.headers = {}
        assert is_rate_limited(resp) is True

    def test_403_without_retry_after_is_not_rate_limited(self):
        from src.utils.retry import is_rate_limited

        resp = MagicMock()
        resp.status_code = 403
        resp.headers = {"X-RateLimit-Remaining": "10"}
        assert is_rate_limited(resp) is False

    def test_200_is_not_rate_limited(self):
        from src.utils.retry import is_rate_limited

        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        assert is_rate_limited(resp) is False


class TestOSVErrorHandling:
    @pytest.mark.asyncio
    async def test_osv_returns_empty_on_timeout(self):
        """OSV query returns empty list on timeout, doesn't raise."""
        from src.tools.osv_query import osv_query

        with patch("src.tools.osv_query.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            # First call triggers retry, all retries fail
            mock_instance.post = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            result = await osv_query("some-pkg", "1.0.0")
            assert result == []


class TestGHSAErrorHandling:
    @pytest.mark.asyncio
    async def test_ghsa_returns_empty_on_403(self):
        """GHSA returns empty list on 403 rate limit."""
        from src.tools.ghsa_search import ghsa_search

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.headers = {}
        mock_resp.json.return_value = []

        with patch("src.tools.ghsa_search.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await ghsa_search("some-pkg")
            assert result == []


class TestKEVErrorHandling:
    def test_kev_returns_empty_on_network_error(self):
        """KEV check returns empty list when catalog fetch fails."""
        from src.tools.kev_check import kev_check

        with patch("src.tools.kev_check.httpx.get") as mock_get:
            mock_get.side_effect = httpx.ConnectError("Network down")
            result = kev_check(["CVE-2024-12345"])
            assert result == []

    def test_kev_returns_empty_on_timeout(self):
        """KEV check returns empty list on timeout."""
        from src.tools.kev_check import kev_check

        with patch("src.tools.kev_check.httpx.get") as mock_get:
            mock_get.side_effect = httpx.TimeoutException("Timeout")
            result = kev_check(["CVE-2024-12345"])
            assert result == []


class TestGraphResilience:
    @pytest.mark.asyncio
    async def test_graph_completes_with_partial_api_failures(self):
        """Graph should complete even if some API calls fail."""
        from src.graph import build_graph

        mock_response = MagicMock()
        mock_response.content = "Scan completed with some failures."

        graph = build_graph()

        initial_state = {
            "file_path": "requirements.txt",
            "file_content": "langchain>=0.1.0\nopenai>=1.0.0\n",
        }

        with (
            patch("src.nodes.ingest_osv.osv_tool", new_callable=AsyncMock) as mock_osv,
            patch("src.nodes.ingest_ghsa.ghsa_search", new_callable=AsyncMock) as mock_ghsa,
            patch("src.nodes.assess_risk.pypi_versions", new_callable=AsyncMock) as mock_pypi,
            patch("src.nodes.assess_risk.npm_versions", new_callable=AsyncMock),
            patch("src.nodes.generate_briefing._get_model") as mock_model,
        ):
            # OSV fails for one package, succeeds for another
            mock_osv.side_effect = lambda pkg, ver, eco: []  # No vulns (could be network error too)
            mock_ghsa.side_effect = Exception("GHSA API unreachable")
            mock_pypi.return_value = {"package": "x", "latest": "", "versions": []}

            mock_llm = AsyncMock()
            mock_llm.ainvoke = AsyncMock(return_value=mock_response)
            mock_model.return_value = mock_llm

            result = await graph.ainvoke(initial_state)

        # Graph should still complete
        assert "dependencies" in result
        assert "findings" in result
        assert "briefing" in result
