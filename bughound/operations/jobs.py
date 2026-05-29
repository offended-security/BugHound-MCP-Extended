"""Job operations: query status, list, cancel.

JobManager is always a parameter. Operations never hold a singleton.
"""

from __future__ import annotations

from typing import Any

from bughound.core.job_manager import JobManager
from bughound.schemas.models import JobStatus


async def get_job_status(
    job_manager: JobManager, job_id: str
) -> dict[str, Any] | None:
    """Return current status of a job. None if not found."""
    return await job_manager.get_status(job_id)


async def get_job_results(
    job_manager: JobManager, job_id: str
) -> dict[str, Any] | None:
    """Return job results (status snapshot once completed).

    Same shape as `get_job_status` — the distinction is semantic for adapters
    that want to differentiate "is it done yet?" from "give me the result."
    Returns None if not found.
    """
    return await job_manager.get_status(job_id)


async def list_jobs(
    job_manager: JobManager,
    workspace_id: str | None = None,
    status_filter: JobStatus | str | None = None,
) -> list[dict[str, Any]]:
    """List jobs, optionally filtered."""
    parsed: JobStatus | None = None
    if isinstance(status_filter, str) and status_filter:
        parsed = JobStatus(status_filter.upper())
    elif isinstance(status_filter, JobStatus):
        parsed = status_filter
    return await job_manager.list_jobs(workspace_id=workspace_id, status_filter=parsed)


async def cancel_job(job_manager: JobManager, job_id: str) -> bool:
    """Cancel a running job. Raises KeyError if job_id is unknown."""
    return await job_manager.cancel_job(job_id)
