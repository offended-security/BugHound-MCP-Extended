"""Workspace operations: CRUD, dashboard, category drill-down, scope checks.

Wraps `bughound.core.workspace` and `bughound.core.target_classifier`. Owns
the canonical category→file mapping (previously duplicated as `_CATEGORY_MAP`
in server.py).
"""

from __future__ import annotations

from typing import Any

from bughound.core import target_classifier, workspace
from bughound.schemas.models import (
    TargetClassification,
    WorkspaceConfig,
    WorkspaceMetadata,
    WorkspaceState,
    WorkspaceSummary,
)


# ---------------------------------------------------------------------------
# Canonical workspace data category map
# ---------------------------------------------------------------------------

# category_name -> (relative_path, truncate_limit). truncate_limit=0 means no limit.
# Previously lived as `_CATEGORY_MAP` in server.py:324. Single source of truth here.
WORKSPACE_CATEGORIES: dict[str, tuple[str, int]] = {
    "subdomains": ("subdomains/all.txt", 100),
    "dns": ("dns/records.json", 0),
    "dns_records": ("dns/records.json", 0),
    "hosts": ("hosts/live_hosts.json", 0),
    "live_hosts": ("hosts/live_hosts.json", 0),
    "flags": ("hosts/flags.json", 0),
    "technologies": ("hosts/technologies.json", 0),
    "urls": ("urls/crawled.json", 100),
    "parameters": ("urls/parameters.json", 0),
    "secrets": ("secrets/js_secrets.json", 0),
    "js_secrets": ("secrets/js_secrets.json", 0),
    "js_secrets_confirmed": ("secrets/js_secrets_confirmed.json", 0),
    "hidden_endpoints": ("endpoints/hidden_endpoints.json", 0),
    "api_endpoints": ("endpoints/api_endpoints.json", 0),
    "sensitive_paths": ("hosts/sensitive_paths.json", 0),
    "cors": ("hosts/cors_results.json", 0),
    "cors_results": ("hosts/cors_results.json", 0),
    "takeover": ("cloud/takeover_candidates.json", 0),
    "takeover_candidates": ("cloud/takeover_candidates.json", 0),
    "takeover_confirmed": ("cloud/takeover_confirmed.json", 0),
    "vulnerabilities": ("vulnerabilities/scan_results.json", 0),
    "waf": ("hosts/waf.json", 0),
    "attack_surface": ("analysis/attack_surface.json", 0),
    "scan_plan": ("scan_plan.json", 0),
    "findings": ("vulnerabilities/scan_results.json", 0),
    "param_classification": ("urls/parameter_classification.json", 0),
    "dynamic_urls": ("urls/dynamic_urls.json", 50),
    "api_urls": ("urls/api_urls.json", 50),
    "admin_urls": ("urls/admin_urls.json", 50),
    "forms": ("urls/forms.json", 0),
}


# ---------------------------------------------------------------------------
# Workspace CRUD
# ---------------------------------------------------------------------------


async def create_workspace(
    target: str,
    depth: str = "light",
) -> dict[str, Any]:
    """Stage 0: classify target + create workspace + record stage history.

    Combines what was three separate calls in adapters: classify, create,
    add_stage_history. Returns the metadata + classification.

    Raises ValueError if target classification fails.
    """
    classification: TargetClassification = target_classifier.classify(target, depth)
    meta: WorkspaceMetadata = await workspace.create_workspace(target, depth)

    await workspace.update_metadata(
        meta.workspace_id,
        target_type=classification.target_type,
        classification=classification.model_dump(mode="json"),
    )
    await workspace.add_stage_history(meta.workspace_id, 0, "completed")

    return {
        "workspace_id": meta.workspace_id,
        "target": meta.target,
        "depth": depth,
        "workspace_dir": str(workspace.workspace_dir(meta.workspace_id)),
        "classification": classification.model_dump(mode="json"),
    }


async def list_workspaces(
    state_filter: WorkspaceState | str | None = None,
) -> list[WorkspaceSummary]:
    """Return all workspaces, optionally filtered by state."""
    parsed: WorkspaceState | None = None
    if isinstance(state_filter, str) and state_filter:
        parsed = WorkspaceState(state_filter.upper())
    elif isinstance(state_filter, WorkspaceState):
        parsed = state_filter
    return await workspace.list_workspaces(parsed)


async def get_workspace_detail(workspace_id: str) -> dict[str, Any] | None:
    """Return workspace metadata + config + stage history. None if not found."""
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return None
    cfg = await workspace.get_config(workspace_id)
    return {
        "metadata": meta.model_dump(mode="json"),
        "config": cfg.model_dump(mode="json") if cfg else None,
    }


async def delete_workspace(workspace_id: str) -> bool:
    """Delete a workspace and all its data. Returns True if deleted."""
    if not workspace.workspace_exists(workspace_id):
        return False
    return await workspace.delete_workspace(workspace_id)


# ---------------------------------------------------------------------------
# Dashboard + category drill-down
# ---------------------------------------------------------------------------


async def get_workspace_dashboard(workspace_id: str) -> dict[str, Any] | None:
    """Build an overview of every data category, with counts and stage progress.

    Returns None if the workspace doesn't exist.
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return None

    # Iterate canonical categories in stable display order
    display_order = [
        ("subdomains", "subdomains/all.txt"),
        ("dns_records", "dns/records.json"),
        ("live_hosts", "hosts/live_hosts.json"),
        ("technologies", "hosts/technologies.json"),
        ("waf", "hosts/waf.json"),
        ("flags", "hosts/flags.json"),
        ("urls", "urls/crawled.json"),
        ("parameters", "urls/parameters.json"),
        ("js_secrets", "secrets/js_secrets.json"),
        ("js_secrets_confirmed", "secrets/js_secrets_confirmed.json"),
        ("hidden_endpoints", "endpoints/hidden_endpoints.json"),
        ("api_endpoints", "endpoints/api_endpoints.json"),
        ("sensitive_paths", "hosts/sensitive_paths.json"),
        ("cors_results", "hosts/cors_results.json"),
        ("takeover_candidates", "cloud/takeover_candidates.json"),
        ("takeover_confirmed", "cloud/takeover_confirmed.json"),
        ("vulnerabilities", "vulnerabilities/scan_results.json"),
        ("attack_surface", "analysis/attack_surface.json"),
    ]

    categories: list[dict[str, Any]] = []
    for label, file_path in display_order:
        data = await workspace.read_data(workspace_id, file_path)
        if data is None:
            categories.append({"name": label, "path": file_path, "count": None})
        elif isinstance(data, list):
            categories.append({"name": label, "path": file_path, "count": len(data)})
        elif isinstance(data, dict):
            count = data.get("count", len(data.get("data", [])))
            categories.append({"name": label, "path": file_path, "count": count})

    completed = [e.stage for e in meta.stage_history if e.status == "completed"]
    all_stages = (
        meta.classification.get("stages_to_run", []) if meta.classification else list(range(7))
    )
    pending = [s for s in all_stages if s not in completed]

    return {
        "workspace_id": workspace_id,
        "target": meta.target,
        "state": meta.state.value,
        "current_stage": meta.current_stage,
        "categories": categories,
        "stages_completed": completed,
        "stages_pending": pending,
        "available_categories": sorted(WORKSPACE_CATEGORIES.keys()),
    }


async def get_workspace_category(
    workspace_id: str,
    category: str,
) -> dict[str, Any]:
    """Return the data for one named category.

    Returns a structured dict:
        {"status": "ok", "category": ..., "items": [...], "total": N, "path": "..."}
    Or:
        {"status": "no_data", ...} when file doesn't exist yet.
        {"status": "unknown_category", "valid": [...]} on invalid category name.
        {"status": "not_found", "message": ...} when workspace doesn't exist.

    Adapters format this; operation returns shape.
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return {"status": "not_found", "message": f"Workspace '{workspace_id}' not found."}

    cat = category.strip().lower()
    if cat not in WORKSPACE_CATEGORIES:
        return {
            "status": "unknown_category",
            "category": cat,
            "valid": sorted(WORKSPACE_CATEGORIES.keys()),
        }

    file_path, truncate_limit = WORKSPACE_CATEGORIES[cat]
    data = await workspace.read_data(workspace_id, file_path)

    if data is None:
        return {
            "status": "no_data",
            "category": cat,
            "path": file_path,
            "message": (
                f"File `{file_path}` does not exist yet. "
                "Collected by a later pipeline stage."
            ),
        }

    # attack_surface stores a single dict, not a list
    if cat == "attack_surface":
        if isinstance(data, dict) and "data" in data:
            return {
                "status": "ok",
                "category": cat,
                "path": file_path,
                "items": data["data"],
                "total": 1,
            }
        return {
            "status": "ok",
            "category": cat,
            "path": file_path,
            "items": data,
            "total": 1,
        }

    if isinstance(data, dict):
        items = data.get("data", [])
        total = data.get("count", len(items))
    elif isinstance(data, list):
        items = data
        total = len(items)
    else:
        items, total = [], 0

    return {
        "status": "ok",
        "category": cat,
        "path": file_path,
        "items": items,
        "total": total,
        "truncate_limit": truncate_limit,
    }


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


async def check_scope(workspace_id: str, target: str) -> dict[str, Any]:
    """Check whether a target is in scope for the workspace.

    Returns:
        {"status": "ok", "in_scope": bool, "scope": {"include": [...], "exclude": [...]}}
        {"status": "not_found", ...} if workspace doesn't exist.
    """
    if not workspace.workspace_exists(workspace_id):
        return {"status": "not_found", "message": f"Workspace '{workspace_id}' not found."}

    in_scope = await workspace.is_in_scope(workspace_id, target)
    cfg: WorkspaceConfig | None = await workspace.get_config(workspace_id)

    scope_view: dict[str, list[str]] = {"include": [], "exclude": []}
    if cfg:
        scope_view = {
            "include": list(cfg.scope.include),
            "exclude": list(cfg.scope.exclude),
        }

    return {
        "status": "ok",
        "target": target,
        "in_scope": in_scope,
        "scope": scope_view,
    }
