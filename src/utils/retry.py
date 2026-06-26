"""Retry and resilience utilities for network calls."""

from __future__ import annotations

import asyncio
import logging
from functools import wraps

logger = logging.getLogger(__name__)


async def retry_async(
    func,
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    backoff_factor: float = 2.0,
    retryable_exceptions: tuple = (Exception,),
    **kwargs,
):
    """Call an async function with exponential backoff retry.

    Args:
        func: Async callable to retry.
        max_retries: Maximum number of retry attempts.
        base_delay: Initial delay between retries in seconds.
        backoff_factor: Multiplier for delay after each retry.
        retryable_exceptions: Tuple of exception types to retry on.
        *args, **kwargs: Arguments passed to func.

    Returns:
        The return value of func.
    """
    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except retryable_exceptions as e:
            last_exc = e
            if attempt < max_retries:
                delay = base_delay * (backoff_factor ** attempt)
                logger.warning(f"Retry {attempt + 1}/{max_retries} for {func.__name__}: {e}")
                await asyncio.sleep(delay)
    raise last_exc


def is_rate_limited(resp) -> bool:
    """Check if an HTTP response indicates rate limiting."""
    if resp.status_code == 429:
        return True
    if resp.status_code == 403:
        retry_after = resp.headers.get("Retry-After", "")
        x_ratelimit_remaining = resp.headers.get("X-RateLimit-Remaining", "1")
        if retry_after or int(x_ratelimit_remaining) == 0:
            return True
    return False
