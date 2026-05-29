"""Stage 3 operations: attack-surface analysis + derived views + scan-plan submission.

The derived views (`get_attack_surface_for_host`, `get_immediate_wins`) were
previously inline in `server.py` (handlers `bughound_analyze_host` and
`bughound_get_immediate_wins`). They live here so adapters share one
implementation instead of each recomputing the filter.
"""

from __future__ import annotations

from typing import Any

from bughound.stages import analyze as stage_analyze


# ---------------------------------------------------------------------------
# Attack surface
# ---------------------------------------------------------------------------


async def get_attack_surface(workspace_id: str) -> dict[str, Any]:
    """Build the full attack-surface analysis for the workspace.

    Includes scored hosts, attack chains, immediate wins, technology playbooks,
    correlations, and suggested test classes.
    """
    return await stage_analyze.get_attack_surface(workspace_id)


async def get_attack_surface_for_host(
    workspace_id: str, host: str
) -> dict[str, Any]:
    """Filter `get_attack_surface()` down to one host.

    Returns:
        {"status": "ok", "host": ..., "target": {...}, "host_probes": [...],
         "host_candidates": {...}, "host_chains": [...],
         "suggested_test_classes": [...]}
        {"status": "error", "message": ...} from the underlying call.
        {"status": "not_found", "host": ..., "available_hosts": [...]} when
            the host doesn't appear in the scored targets.
    """
    result = await stage_analyze.get_attack_surface(workspace_id)
    if result.get("status") == "error":
        return result

    host_lower = host.strip().lower()
    all_targets = result.get("high_interest_targets", [])
    target = next(
        (t for t in all_targets if t.get("host", "").lower() == host_lower), None
    )
    if target is None:
        return {
            "status": "not_found",
            "host": host,
            "available_hosts": [t.get("host", "?") for t in all_targets[:10]],
        }

    pc = result.get("parameter_classification", {})
    probe_confirmed = pc.get("probe_confirmed", [])
    host_probes = [
        p for p in probe_confirmed if host_lower in p.get("url", "").lower()
    ]

    top_by_type = pc.get("top_candidates_by_type", {})
    host_candidates: dict[str, list[Any]] = {}
    for vtype, cands in top_by_type.items():
        hc = [c for c in cands if host_lower in c.get("url", "").lower()]
        if hc:
            host_candidates[vtype] = hc

    chains = result.get("attack_chains", [])
    host_chains = [
        c
        for c in chains
        if host_lower in str(c.get("affected_hosts", [])).lower()
    ]

    return {
        "status": "ok",
        "host": host,
        "target": target,
        "host_probes": host_probes,
        "host_candidates": host_candidates,
        "host_chains": host_chains,
        "suggested_test_classes": result.get("suggested_test_classes", []),
    }


async def get_immediate_wins(workspace_id: str) -> dict[str, Any]:
    """Pull just the report-ready findings out of the attack surface.

    Returns:
        {"status": "ok", "wins": [...], "count": N}
        {"status": "error", "message": ...} from the underlying call.
        {"status": "empty", "message": ...} when no wins are present.
    """
    result = await stage_analyze.get_attack_surface(workspace_id)
    if result.get("status") == "error":
        return result

    wins = result.get("immediate_wins", [])
    if not wins:
        return {
            "status": "empty",
            "message": "No immediate wins found. All findings require testing to confirm.",
            "wins": [],
            "count": 0,
        }
    return {"status": "ok", "wins": wins, "count": len(wins)}


async def enrich_target(workspace_id: str, host: str) -> dict[str, Any]:
    """Build a full intelligence dossier on one host."""
    return await stage_analyze.enrich_target(workspace_id, host)


# ---------------------------------------------------------------------------
# Scan plan
# ---------------------------------------------------------------------------


async def submit_scan_plan(
    workspace_id: str, scan_plan: dict[str, Any]
) -> dict[str, Any]:
    """Validate and persist a scan plan.

    The operation accepts only a typed dict. Adapters that receive permissive
    input (JSON strings, single-quoted JSON, Python literals — as MCP does
    today) must parse it before calling this.
    """
    if not isinstance(scan_plan, dict):
        return {
            "status": "error",
            "message": f"scan_plan must be a dict, got {type(scan_plan).__name__}",
        }
    return await stage_analyze.submit_scan_plan(workspace_id, scan_plan)
