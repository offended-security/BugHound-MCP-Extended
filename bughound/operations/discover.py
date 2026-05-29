"""Stage 2 operations: full attack-surface discovery."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from bughound.core.job_manager import JobManager
from bughound.stages import discover as stage_discover


HostFilterCallback = Callable[[list[dict[str, Any]]], Awaitable[list[dict[str, Any]] | None]]


async def discover(
    workspace_id: str,
    job_manager: JobManager | None = None,
    target_subset: list[str] | None = None,
    host_filter_cb: HostFilterCallback | None = None,
) -> dict[str, Any]:
    """Probe hosts, crawl URLs, analyze JS, fingerprint tech, etc.

    Args:
        workspace_id: target workspace.
        job_manager: when provided, runs as a background job and returns a
            job_id immediately. When None, runs synchronously (useful for the
            CLI's interactive host selection, where stdin is needed).
        target_subset: optional list of specific subdomains to focus on. If
            None, discovers all subdomains from Stage 1.
        host_filter_cb: optional async callback for interactive host selection.
            Called after httpx probing with the live host list; returns the
            filtered subset to continue scanning, or None to scan all. CLI
            uses this; MCP/webui pass None.

    Returns the discover result dict or a job-started envelope.
    """
    return await stage_discover.discover(
        workspace_id,
        job_manager=job_manager,
        target_override=target_subset,
        host_filter_cb=host_filter_cb,
    )
