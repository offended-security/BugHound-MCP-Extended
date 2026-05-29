"""Composite operations: multi-stage workflows.

These bundle Stages 0→6 (or 0→2) into one call. They exist for adapters that
want "run the whole thing" semantics — primarily the web UI and any external
script integration. The CLI's `cmd_scan` has nuanced UX (spinners, mid-stage
prompts) and composes the per-stage operations directly rather than calling
these composites.

`progress_cb`, when provided, is awaited at each stage boundary and during
async job polling, so callers (SSE streams, log tails) can render progress.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlparse

from bughound.config.settings import WORKSPACE_BASE_DIR
from bughound.core import workspace
from bughound.core.job_manager import JobManager
from bughound.operations.analyze import get_attack_surface, submit_scan_plan
from bughound.operations.discover import HostFilterCallback, discover
from bughound.operations.enumerate import enumerate_light
from bughound.operations.report import generate_report
from bughound.operations.test import execute_tests
from bughound.operations.validate import validate_all
from bughound.operations.workspace import create_workspace


# progress_cb signature: (stage_num, stage_name, message)
ProgressCallback = Callable[[int, str, str], Awaitable[None]]


_STAGE_NAMES = {
    0: "Initialize",
    1: "Enumerate",
    2: "Discover",
    3: "Analyze",
    4: "Test",
    5: "Validate",
    6: "Report",
}


async def _fire_progress(
    cb: ProgressCallback | None, stage_num: int, message: str = ""
) -> None:
    """Helper: invoke progress_cb only if provided."""
    if cb is not None:
        await cb(stage_num, _STAGE_NAMES.get(stage_num, f"Stage {stage_num}"), message)


async def _await_job(
    job_manager: JobManager,
    job_id: str,
    progress_cb: ProgressCallback | None,
    stage_num: int,
    poll_interval_s: float = 3.0,
) -> dict[str, Any] | None:
    """Poll a background job until it reaches a terminal state.

    Returns the final status dict, or None if the job vanished.
    """
    while True:
        await asyncio.sleep(poll_interval_s)
        status = await job_manager.get_status(job_id)
        if status is None:
            return None
        msg = status.get("message", "")
        if msg:
            await _fire_progress(progress_cb, stage_num, msg)
        if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT", "CANCELLED"):
            return status


def _resume_stage_from_workspace(workspace_id: str) -> int:
    """Determine which stage to resume from based on what files exist."""
    ws_path = WORKSPACE_BASE_DIR / workspace_id

    if (ws_path / "vulnerabilities" / "scan_results.json").exists():
        return 5
    if (ws_path / "analysis" / "attack_surface.json").exists():
        return 4
    if (ws_path / "urls" / "crawled.json").exists():
        return 3
    if (ws_path / "hosts" / "live_hosts.json").exists():
        return 2
    return 1


# ---------------------------------------------------------------------------
# Full pipeline (Stages 0→6)
# ---------------------------------------------------------------------------


async def run_full_pipeline(
    target: str | None,
    job_manager: JobManager,
    depth: str = "light",
    test_profile: str = "both",
    speed: str = "normal",
    skip_validate: bool = False,
    skip_nuclei: bool = False,
    host_filter_cb: HostFilterCallback | None = None,
    progress_cb: ProgressCallback | None = None,
    resume_workspace_id: str | None = None,
) -> dict[str, Any]:
    """Run the full BugHound pipeline (Stages 0→6).

    Args:
        target: target URL/domain. Required unless `resume_workspace_id` is set.
        job_manager: required for async stages (Discover, Test, Validate).
        depth: 'light' or 'deep'.
        test_profile: 'client', 'server', or 'both'.
        speed: 'normal', 'fast', or 'stealth'.
        skip_validate: skip Stage 5.
        skip_nuclei: skip nuclei in Stage 4 (passed through scan_plan globals).
        host_filter_cb: optional callback for interactive host selection in Stage 2.
        progress_cb: optional callback `(stage_num, stage_name, message)`
            awaited at each stage transition and during job polling.
        resume_workspace_id: if set, continue an existing workspace.

    Returns:
        {"status": "ok", "workspace_id": ..., "findings": [...],
         "findings_count": N, "report": {...}}
        {"status": "error", "message": ...} on early failure.
    """
    if not target and not resume_workspace_id:
        return {
            "status": "error",
            "message": "Either 'target' or 'resume_workspace_id' must be provided.",
        }

    # Stage 0: workspace
    if resume_workspace_id:
        meta = await workspace.get_workspace(resume_workspace_id)
        if meta is None:
            return {
                "status": "error",
                "message": f"Workspace '{resume_workspace_id}' not found.",
            }
        workspace_id = resume_workspace_id
        resume_stage = _resume_stage_from_workspace(workspace_id)
        await _fire_progress(progress_cb, resume_stage, f"resuming from stage {resume_stage}")
    else:
        await _fire_progress(progress_cb, 0, "creating workspace")
        try:
            init_result = await create_workspace(target=target or "", depth=depth)
        except ValueError as exc:
            return {"status": "error", "message": str(exc)}
        workspace_id = init_result["workspace_id"]
        resume_stage = 1

    # Stage 1: enumerate
    if resume_stage <= 1:
        await _fire_progress(progress_cb, 1, "enumerating subdomains")
        await enumerate_light(workspace_id)

    # Stage 2: discover (sync because interactive host filter may need stdin)
    if resume_stage <= 2:
        await _fire_progress(progress_cb, 2, "discovering attack surface")
        # Sync mode (job_manager=None) so host_filter_cb can run inline.
        # The CLI uses this; webui can pass a host_filter_cb=None to skip selection.
        discover_result = await discover(
            workspace_id,
            job_manager=None,
            host_filter_cb=host_filter_cb,
        )
        if discover_result.get("status") == "error":
            return {
                "status": "error",
                "stage": 2,
                "message": discover_result.get("message", "Discovery failed."),
                "workspace_id": workspace_id,
            }

    # Stage 3: analyze
    if resume_stage <= 3:
        await _fire_progress(progress_cb, 3, "analyzing attack surface")
    attack_surface = await get_attack_surface(workspace_id)
    if attack_surface.get("status") == "error":
        return {
            "status": "error",
            "stage": 3,
            "message": attack_surface.get("message", "Analysis failed."),
            "workspace_id": workspace_id,
        }

    # Stage 4: test (build scan plan + submit + execute)
    if resume_stage <= 4:
        await _fire_progress(progress_cb, 4, "running tests")
        await _build_and_submit_scan_plan(
            workspace_id, attack_surface, test_profile, speed, skip_nuclei
        )
        test_result = await execute_tests(
            workspace_id, job_manager=job_manager, test_profile=test_profile
        )
        if test_result.get("status") == "job_started":
            await _await_job(job_manager, test_result["job_id"], progress_cb, 4)

    # Load findings
    findings = await _read_findings(workspace_id)

    # Stage 5: validate
    if resume_stage <= 5 and not skip_validate and findings:
        await _fire_progress(progress_cb, 5, "validating findings")
        val_result = await validate_all(workspace_id, job_manager=job_manager)
        if val_result.get("status") == "job_started":
            await _await_job(job_manager, val_result["job_id"], progress_cb, 5)
        # Reload findings (now annotated with validation status)
        findings = await _read_findings(workspace_id)

    # Stage 6: report
    await _fire_progress(progress_cb, 6, "generating report")
    report_result = await generate_report(
        workspace_id,
        report_type="all",
        wait_for_validation=False,  # We already waited above.
        job_manager=job_manager,
    )

    return {
        "status": "ok",
        "workspace_id": workspace_id,
        "findings": findings,
        "findings_count": len(findings),
        "report": report_result,
    }


# ---------------------------------------------------------------------------
# Recon only (Stages 0→2)
# ---------------------------------------------------------------------------


async def run_recon_only(
    target: str,
    job_manager: JobManager,
    depth: str = "light",
    host_filter_cb: HostFilterCallback | None = None,
    progress_cb: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Run reconnaissance (Stages 0→2) and stop."""
    await _fire_progress(progress_cb, 0, "creating workspace")
    try:
        init_result = await create_workspace(target=target, depth=depth)
    except ValueError as exc:
        return {"status": "error", "message": str(exc)}
    workspace_id = init_result["workspace_id"]

    await _fire_progress(progress_cb, 1, "enumerating subdomains")
    await enumerate_light(workspace_id)

    await _fire_progress(progress_cb, 2, "discovering attack surface")
    discover_result = await discover(
        workspace_id, job_manager=None, host_filter_cb=host_filter_cb
    )

    return {
        "status": "ok",
        "workspace_id": workspace_id,
        "classification": init_result["classification"],
        "discover_result": discover_result,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _build_and_submit_scan_plan(
    workspace_id: str,
    attack_surface: dict[str, Any],
    test_profile: str,
    speed: str,
    skip_nuclei: bool,
) -> None:
    """Build a default scan plan from the attack-surface analysis and submit it.

    Mirrors the CLI's `_run_test` logic so composite callers don't have to
    reproduce it.
    """
    from bughound.stages import techniques as stage_techniques

    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return  # Caller already validated workspace.

    target_host = meta.target
    if "://" in target_host:
        target_host = urlparse(target_host).hostname or target_host

    suggested = attack_surface.get("suggested_test_classes", []) or [
        "sqli", "xss", "ssrf", "lfi", "ssti", "open_redirect",
        "crlf", "idor", "rce", "xxe", "header_injection",
        "graphql", "jwt", "misconfig", "default_creds",
        "cors", "bac", "csti", "cve_specific",
    ]
    filtered = stage_techniques.filter_classes_by_profile(suggested, test_profile)

    scan_plan: dict[str, Any] = {
        "targets": [
            {"host": target_host, "priority": 1, "test_classes": filtered}
        ],
        "global_settings": {
            "nuclei_severity": "critical,high,medium,low,info",
            "nuclei_rate_limit": 100,
            "nuclei_concurrency": 25,
            "test_profile": test_profile,
            "speed": speed,
            "skip_nuclei": skip_nuclei,
        },
    }
    await submit_scan_plan(workspace_id, scan_plan)


async def _read_findings(workspace_id: str) -> list[dict[str, Any]]:
    """Load the current findings list from the workspace."""
    raw = await workspace.read_data(workspace_id, "vulnerabilities/scan_results.json")
    if raw is None:
        return []
    findings = raw.get("data", raw) if isinstance(raw, dict) else raw
    return findings if isinstance(findings, list) else []
