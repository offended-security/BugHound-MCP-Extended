"""Stage 5 operations: finding validation."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from bughound.core.job_manager import JobManager
from bughound.schemas.models import JobStatus
from bughound.stages import validate as stage_validate


ProgressCallback = Callable[[int, str], Awaitable[None]]


async def validate_finding(
    workspace_id: str,
    finding_id: str,
    tool: str | None = None,
) -> dict[str, Any]:
    """Surgically validate one finding from Stage 4."""
    return await stage_validate.validate_finding(
        workspace_id, finding_id, tool=tool
    )


async def validate_all(
    workspace_id: str,
    job_manager: JobManager | None = None,
    progress_cb: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Batch-validate every unvalidated finding.

    Behavior depends on `job_manager`:
        - `job_manager is None`: runs synchronously, returns the validation
          summary. `progress_cb` (if provided) is called with (pct, msg).
        - `job_manager is not None`: spawns a background job, returns a
          job-started envelope `{"status": "job_started", "job_id": ...}`.
          The job's progress is reported via `job_manager.update_progress`.
    """
    if job_manager is None:
        return await stage_validate.validate_all(workspace_id, progress_cb=progress_cb)

    try:
        job_id = await job_manager.create_job(
            workspace_id, "validate_all", "batch validation"
        )
    except RuntimeError as exc:
        return {"status": "error", "message": str(exc)}

    async def _job_progress(pct: int, msg: str) -> None:
        await job_manager.update_progress(job_id, pct, msg, "validate")

    async def _run_job(jid: str) -> None:
        result = await stage_validate.validate_all(
            workspace_id, progress_cb=_job_progress
        )
        summary = {
            "total_validated": result.get("total_validated", 0),
            "confirmed": result.get("confirmed", 0),
            "false_positives": result.get("false_positives", 0),
            "manual_review": result.get("manual_review", 0),
        }
        await job_manager.complete_job(jid, summary)

    await job_manager.start_job(job_id, _run_job(job_id))
    return {
        "status": "job_started",
        "job_id": job_id,
        "message": "Batch validation started for all unvalidated findings.",
        "estimated_time": "3-10 minutes",
        "workspace_id": workspace_id,
    }


async def validate_immediate_wins(workspace_id: str) -> dict[str, Any]:
    """Verify Stage 3 immediate wins with quick HTTP checks."""
    return await stage_validate.validate_immediate_wins(workspace_id)


# ---------------------------------------------------------------------------
# Helper for `report.generate_report(wait_for_validation=True)`
# ---------------------------------------------------------------------------


async def find_running_validate_job(
    job_manager: JobManager, workspace_id: str
) -> str | None:
    """Return the job_id of a running validate_all job for the workspace, or None."""
    running = await job_manager.list_jobs(
        workspace_id=workspace_id, status_filter=JobStatus.RUNNING
    )
    for j in running:
        if j.get("job_type") == "validate_all":
            return j.get("job_id")
    return None
