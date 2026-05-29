"""Read-only API route handlers.

Each handler is a thin wrapper over `bughound.operations.*`. The webui
package never imports `bughound.stages.*` or any other adapter — all
pipeline state is accessed through the operations contract.
"""

from __future__ import annotations

from typing import Any

from aiohttp import web
from pydantic import BaseModel

from bughound import operations
from bughound.webui.events import stream_workspace_events


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------


def _to_jsonable(obj: Any) -> Any:
    """Recursively convert Pydantic models to plain JSON-serializable structures."""
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, list):
        return [_to_jsonable(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    return obj


def _json(payload: Any, *, status: int = 200) -> web.Response:
    return web.json_response(_to_jsonable(payload), status=status)


# ---------------------------------------------------------------------------
# Workspace endpoints
# ---------------------------------------------------------------------------


async def list_workspaces(request: web.Request) -> web.Response:
    """List every workspace with summary stats."""
    workspaces = await operations.list_workspaces()
    return _json({"workspaces": workspaces, "count": len(workspaces)})


async def get_workspace(request: web.Request) -> web.Response:
    """Full detail (metadata + config + stage history) for one workspace."""
    ws_id = request.match_info["workspace_id"]
    detail = await operations.get_workspace_detail(ws_id)
    if detail is None:
        return _json({"error": "workspace_not_found", "workspace_id": ws_id}, status=404)
    return _json(detail)


async def get_workspace_dashboard(request: web.Request) -> web.Response:
    """Summary dashboard: per-category counts + stage progress."""
    ws_id = request.match_info["workspace_id"]
    dash = await operations.get_workspace_dashboard(ws_id)
    if dash is None:
        return _json({"error": "workspace_not_found", "workspace_id": ws_id}, status=404)
    return _json(dash)


async def get_workspace_category(request: web.Request) -> web.Response:
    """Drill into one data category (findings, urls, hosts, etc.)."""
    ws_id = request.match_info["workspace_id"]
    category = request.match_info["category"]
    result = await operations.get_workspace_category(ws_id, category)
    status = result.get("status")
    if status == "not_found":
        return _json({"error": "workspace_not_found", "workspace_id": ws_id}, status=404)
    if status == "unknown_category":
        return _json(
            {"error": "unknown_category", "category": category, "valid": result["valid"]},
            status=400,
        )
    # "ok" or "no_data" both return as-is — adapters decide how to render.
    return _json(result)


async def get_findings(request: web.Request) -> web.Response:
    """Convenience alias for `category=findings`."""
    ws_id = request.match_info["workspace_id"]
    result = await operations.get_workspace_category(ws_id, "findings")
    if result.get("status") == "not_found":
        return _json({"error": "workspace_not_found", "workspace_id": ws_id}, status=404)
    return _json(result)


async def get_attack_surface(request: web.Request) -> web.Response:
    """Stage 3 attack-surface analysis output."""
    ws_id = request.match_info["workspace_id"]
    result = await operations.get_attack_surface(ws_id)
    if result.get("status") == "error":
        # Distinguish "workspace doesn't exist" from "stage 3 hasn't run yet".
        msg = result.get("message", "")
        if "not found" in msg.lower():
            return _json({"error": "workspace_not_found", "workspace_id": ws_id}, status=404)
        return _json({"error": "stage_error", "message": msg}, status=409)
    return _json(result)


async def get_immediate_wins(request: web.Request) -> web.Response:
    """Stage 3 immediate-win findings (report-ready, no testing needed)."""
    ws_id = request.match_info["workspace_id"]
    result = await operations.get_immediate_wins(ws_id)
    if result.get("status") == "error":
        return _json({"error": "stage_error", "message": result.get("message", "")}, status=409)
    return _json(result)


# ---------------------------------------------------------------------------
# Job endpoints (read-only — no cancel from the web UI in Phase 1)
# ---------------------------------------------------------------------------


async def list_jobs(request: web.Request) -> web.Response:
    """List jobs for the webui-owned JobManager. Optional ?workspace=<id> filter."""
    jm = request.app["job_manager"]
    workspace_id = request.query.get("workspace")
    jobs = await operations.list_jobs(jm, workspace_id=workspace_id)
    return _json({"jobs": jobs, "count": len(jobs)})


async def get_job(request: web.Request) -> web.Response:
    """Snapshot of one job's status."""
    jm = request.app["job_manager"]
    job_id = request.match_info["job_id"]
    status = await operations.get_job_status(jm, job_id)
    if status is None:
        return _json({"error": "job_not_found", "job_id": job_id}, status=404)
    return _json(status)


# ---------------------------------------------------------------------------
# System endpoints
# ---------------------------------------------------------------------------


async def tool_coverage(request: web.Request) -> web.Response:
    """Which security tools are installed (ToolCoverageReport)."""
    return _json(operations.check_tool_coverage())


async def list_techniques(request: web.Request) -> web.Response:
    """All testing techniques + availability + optional profile filter."""
    profile = request.query.get("profile")
    return _json({"techniques": operations.list_techniques(profile)})


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------


def register_routes(app: web.Application) -> None:
    """Attach all read-only API routes to the application."""
    app.router.add_get("/api/workspaces", list_workspaces)
    app.router.add_get("/api/workspaces/{workspace_id}", get_workspace)
    app.router.add_get("/api/workspaces/{workspace_id}/dashboard", get_workspace_dashboard)
    app.router.add_get("/api/workspaces/{workspace_id}/findings", get_findings)
    app.router.add_get("/api/workspaces/{workspace_id}/attack-surface", get_attack_surface)
    app.router.add_get("/api/workspaces/{workspace_id}/immediate-wins", get_immediate_wins)
    app.router.add_get(
        "/api/workspaces/{workspace_id}/category/{category}",
        get_workspace_category,
    )
    app.router.add_get("/api/jobs", list_jobs)
    app.router.add_get("/api/jobs/{job_id}", get_job)
    app.router.add_get("/api/tools/coverage", tool_coverage)
    app.router.add_get("/api/techniques", list_techniques)
    # SSE live event stream — last, since it's a streaming response.
    app.router.add_get(
        "/api/workspaces/{workspace_id}/events", stream_workspace_events,
    )
