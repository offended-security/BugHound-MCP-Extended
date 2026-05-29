"""Canonical operations layer for BugHound.

This is the contract that all adapters (CLI, MCP server, web UI) call into.
Adapters MUST NOT call into `bughound.stages.*` or `bughound.core.workspace`
directly for any operation exposed here — use `bughound.operations.<x>`.

Rules for this package:
    1. No I/O concerns (no print, no MCP serialization, no argparse).
    2. Params: typed (primitives or Pydantic models).
    3. Returns: dict[str, Any] pass-through from stages for now; will be
       typed as Pydantic models in a follow-up.
    4. JobManager is always a parameter, never a module-level singleton.
    5. No imports from `bughound.cli`, `bughound.server`, or `bughound.webui`.

Adapter responsibilities (NOT operations):
    - Pretty-printing / terminal colors / banners (CLI)
    - JSON-RPC framing (MCP server)
    - HTTP/SSE/CORS (web UI)
    - Permissive input parsing (e.g. accepting JSON strings for typed dicts)
    - Interactive prompts (CLI host selection)
"""

from __future__ import annotations

from bughound.operations.analyze import (
    enrich_target,
    get_attack_surface,
    get_attack_surface_for_host,
    get_immediate_wins,
    submit_scan_plan,
)
from bughound.operations.composites import run_full_pipeline, run_recon_only
from bughound.operations.discover import discover
from bughound.operations.enumerate import enumerate_deep, enumerate_light
from bughound.operations.jobs import cancel_job, get_job_results, get_job_status, list_jobs
from bughound.operations.report import generate_report
from bughound.operations.system import (
    TOOL_REGISTRY,
    ToolCoverageReport,
    ToolSpec,
    check_tool_coverage,
    filter_test_classes,
    list_pipelines,
    list_techniques,
)
from bughound.operations.test import (
    execute_tests,
    nuclei_scan,
    run_pipeline,
    test_single,
)
from bughound.operations.validate import (
    validate_all,
    validate_finding,
    validate_immediate_wins,
)
from bughound.operations.workspace import (
    WORKSPACE_CATEGORIES,
    check_scope,
    create_workspace,
    delete_workspace,
    get_workspace_category,
    get_workspace_dashboard,
    get_workspace_detail,
    list_workspaces,
)

__all__ = [
    # Workspace
    "create_workspace",
    "list_workspaces",
    "get_workspace_detail",
    "delete_workspace",
    "get_workspace_dashboard",
    "get_workspace_category",
    "check_scope",
    "WORKSPACE_CATEGORIES",
    # System
    "check_tool_coverage",
    "list_techniques",
    "list_pipelines",
    "filter_test_classes",
    "TOOL_REGISTRY",
    "ToolSpec",
    "ToolCoverageReport",
    # Stage 1
    "enumerate_light",
    "enumerate_deep",
    # Stage 2
    "discover",
    # Stage 3
    "get_attack_surface",
    "get_attack_surface_for_host",
    "get_immediate_wins",
    "enrich_target",
    "submit_scan_plan",
    # Stage 4
    "execute_tests",
    "test_single",
    "nuclei_scan",
    "run_pipeline",
    # Stage 5
    "validate_finding",
    "validate_all",
    "validate_immediate_wins",
    # Stage 6
    "generate_report",
    # Jobs
    "get_job_status",
    "get_job_results",
    "list_jobs",
    "cancel_job",
    # Composites
    "run_full_pipeline",
    "run_recon_only",
]
