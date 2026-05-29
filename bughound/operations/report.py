"""Stage 6 operations: report generation.

The `wait_for_validation` logic (previously inline in `server.py`'s
`bughound_generate_report` handler) now lives here so CLI, MCP, and webui
all get the same wait-for-validation semantics for free.
"""

from __future__ import annotations

import asyncio
from typing import Any

from bughound.core.job_manager import JobManager
from bughound.operations.validate import find_running_validate_job
from bughound.stages import report as stage_report


# Max time to wait for a running validate_all job before generating a report.
# 10 minutes = 120 polls × 5s each (matches the prior server.py behavior).
_WAIT_FOR_VALIDATION_MAX_POLLS = 120
_WAIT_FOR_VALIDATION_INTERVAL_S = 5


async def generate_report(
    workspace_id: str,
    report_type: str = "all",
    wait_for_validation: bool = True,
    job_manager: JobManager | None = None,
) -> dict[str, Any]:
    """Generate security assessment report(s).

    Args:
        workspace_id: target workspace.
        report_type: 'full' (HTML), 'bug_bounty' (Markdown), 'executive'
            (Markdown summary), or 'all'.
        wait_for_validation: if True (default) and `job_manager` is provided,
            wait up to ~10 minutes for any running `validate_all` job to
            finish before generating the report. Prevents reporting on
            half-validated findings.
        job_manager: required when `wait_for_validation=True` to look up
            running jobs. When None, generation proceeds immediately.
    """
    if wait_for_validation and job_manager is not None:
        await _wait_for_validation(job_manager, workspace_id)
    return await stage_report.generate_report(workspace_id, report_type)


async def _wait_for_validation(
    job_manager: JobManager, workspace_id: str
) -> None:
    """Poll until any running validate_all job for the workspace finishes."""
    job_id = await find_running_validate_job(job_manager, workspace_id)
    if job_id is None:
        return

    for _ in range(_WAIT_FOR_VALIDATION_MAX_POLLS):
        await asyncio.sleep(_WAIT_FOR_VALIDATION_INTERVAL_S)
        status = await job_manager.get_status(job_id)
        if status is None:
            return
        if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT", "CANCELLED"):
            return
