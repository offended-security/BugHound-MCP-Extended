"""Stage 1 operations: subdomain enumeration (light + deep)."""

from __future__ import annotations

from typing import Any

from bughound.core.job_manager import JobManager
from bughound.stages import enumerate as stage_enumerate


async def enumerate_light(workspace_id: str) -> dict[str, Any]:
    """Passive subdomain discovery + DNS resolution. Synchronous, ~30-60s.

    Auto-skips for non-broad-domain targets.
    """
    return await stage_enumerate.enumerate_light(workspace_id)


async def enumerate_deep(
    workspace_id: str, job_manager: JobManager
) -> dict[str, Any]:
    """Deep enumeration (passive + active brute-force) as a background job.

    Returns immediately with a job_id; poll via `get_job_status`.
    """
    return await stage_enumerate.enumerate_deep(workspace_id, job_manager)
