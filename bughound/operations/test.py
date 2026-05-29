"""Stage 4 operations: vulnerability testing.

Includes the direct `nuclei_scan` operation. The nuclei target-source URL
resolver (previously in `server.py:_resolve_nuclei_targets`) lives here so
all adapters share it.
"""

from __future__ import annotations

from typing import Any

from bughound.core import workspace
from bughound.core.job_manager import JobManager
from bughound.stages import test as stage_test


# ---------------------------------------------------------------------------
# execute_tests / test_single
# ---------------------------------------------------------------------------


async def execute_tests(
    workspace_id: str,
    job_manager: JobManager | None = None,
    test_profile: str | None = None,
) -> dict[str, Any]:
    """Run the persisted scan plan against the workspace.

    test_profile: 'client', 'server', or 'both'. Overrides scan_plan's
        global_settings.test_profile when set.
    """
    return await stage_test.execute_tests(
        workspace_id, job_manager=job_manager, test_profile=test_profile
    )


async def test_single(
    workspace_id: str,
    target_url: str,
    tool: str = "nuclei",
    tags: str | None = None,
    severity: str | None = None,
    template: str | None = None,
    technique: str | None = None,
) -> dict[str, Any]:
    """Surgical test of one endpoint. Scope-checked. Synchronous."""
    return await stage_test.test_single(
        workspace_id,
        target_url,
        tool,
        tags=tags,
        severity=severity,
        template=template,
        technique=technique,
    )


# ---------------------------------------------------------------------------
# nuclei_scan
# ---------------------------------------------------------------------------


# Mapping of target_source name -> (workspace file path, item extractor).
# Used by `resolve_nuclei_targets` below.
_NUCLEI_SOURCE_FILES: dict[str, str] = {
    "all_urls": "urls/crawled.json",
    "dynamic_urls": "urls/dynamic_urls.json",
    "js_files": "urls/js_files.json",
    "live_hosts": "hosts/live_hosts.json",
    "admin_paths": "urls/admin_urls.json",
}


async def resolve_nuclei_targets(
    workspace_id: str, source: str
) -> list[str]:
    """Resolve a target_source name to a deduplicated list of URLs.

    Sources: all_urls, dynamic_urls, js_files, live_hosts, api_endpoints,
             admin_paths, forms.
    Unknown source returns []. Order preserved, duplicates removed.
    """
    urls: list[str] = []

    if source in _NUCLEI_SOURCE_FILES:
        path = _NUCLEI_SOURCE_FILES[source]
        data = await workspace.read_data(workspace_id, path)
        items = data.get("data", []) if isinstance(data, dict) else (data or [])

        if source == "live_hosts":
            urls = [
                h.get("url", "")
                for h in items
                if isinstance(h, dict) and h.get("url")
            ]
        else:
            urls = [
                u.get("url", u) if isinstance(u, dict) else str(u)
                for u in items
            ]

    elif source == "api_endpoints":
        # Combines api_endpoints + openapi_specs (nested .endpoints).
        api_data = await workspace.read_data(
            workspace_id, "endpoints/api_endpoints.json"
        )
        api_items = (
            api_data.get("data", []) if isinstance(api_data, dict) else (api_data or [])
        )
        for ep in api_items:
            if isinstance(ep, dict) and ep.get("url"):
                urls.append(ep["url"])

        oas_data = await workspace.read_data(
            workspace_id, "endpoints/openapi_specs.json"
        )
        oas_items = (
            oas_data.get("data", []) if isinstance(oas_data, dict) else (oas_data or [])
        )
        for spec in oas_items:
            if isinstance(spec, dict):
                for endpoint in spec.get("endpoints", []):
                    if isinstance(endpoint, dict) and endpoint.get("url"):
                        urls.append(endpoint["url"])

    elif source == "forms":
        # GET forms — use testable_url or action.
        data = await workspace.read_data(workspace_id, "urls/forms.json")
        items = data.get("data", []) if isinstance(data, dict) else (data or [])
        for form in items:
            if isinstance(form, dict) and form.get("method", "").upper() == "GET":
                test_url = form.get("testable_url", form.get("action", ""))
                if test_url:
                    urls.append(test_url)

    # Deduplicate, preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


VALID_NUCLEI_SOURCES: tuple[str, ...] = (
    "all_urls",
    "dynamic_urls",
    "js_files",
    "live_hosts",
    "api_endpoints",
    "admin_paths",
    "forms",
)


async def nuclei_scan(
    workspace_id: str,
    target: str = "",
    target_source: str = "",
    tags: str = "",
    severity: str = "critical,high,medium",
    template_path: str = "",
    extra_args: str = "",
) -> dict[str, Any]:
    """Run nuclei against either a single target URL or a workspace URL source.

    Either `target` (single URL) or `target_source` (workspace list) must be set.

    Returns:
        {"status": "ok", "findings": [...], "scan_urls_count": N,
         "severity_breakdown": {...}, "source": "...", "tags": "..."}
        {"status": "error", "message": ..., "valid_sources": [...] | omitted}
    """
    # TODO(operations): stage_test exposes these helpers as `_*` — promote to
    # public API in a follow-up so this module doesn't reach into privates.
    from bughound.stages.test import (
        _append_findings,
        _deduplicate_nuclei_findings,
        _process_nuclei_findings,
    )
    from bughound.tools.scanning import nuclei

    if not nuclei.is_available():
        return {"status": "error", "message": "nuclei is not installed."}

    if not target and not target_source:
        return {
            "status": "error",
            "message": "Provide either 'target' (URL) or 'target_source' (workspace list).",
            "valid_sources": list(VALID_NUCLEI_SOURCES),
        }

    if target_source and target_source not in VALID_NUCLEI_SOURCES:
        return {
            "status": "error",
            "message": f"Unknown target_source '{target_source}'.",
            "valid_sources": list(VALID_NUCLEI_SOURCES),
        }

    # Resolve targets
    scan_urls: list[str] = (
        [target] if target else await resolve_nuclei_targets(workspace_id, target_source)
    )
    if not scan_urls:
        return {
            "status": "error",
            "message": f"No URLs found for target_source='{target_source}'.",
        }

    # Build nuclei kwargs
    nuclei_kwargs: dict[str, Any] = {}
    if tags:
        nuclei_kwargs["tags"] = [t.strip() for t in tags.split(",")]
    if severity:
        nuclei_kwargs["severity"] = severity
    if template_path:
        nuclei_kwargs["template_path"] = template_path

    nuclei_target = scan_urls[0] if len(scan_urls) == 1 else scan_urls
    result = await nuclei.execute(nuclei_target, **nuclei_kwargs)

    if not result.success:
        err = result.error.message if result.error else "nuclei execution failed"
        return {"status": "error", "message": err}

    raw = result.results if isinstance(result.results, list) else []
    findings = _process_nuclei_findings(raw, workspace_id)
    findings = _deduplicate_nuclei_findings(findings)

    if findings:
        await _append_findings(workspace_id, findings)

    sev_counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    return {
        "status": "ok",
        "findings": findings,
        "scan_urls_count": len(scan_urls),
        "severity_breakdown": sev_counts,
        "source": target if target else f"target_source={target_source}",
        "tags": tags,
    }


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------


async def run_pipeline(workspace_id: str, pipeline_id: str) -> dict[str, Any]:
    """Run a one-liner pipeline (gf/qsreplace/kxss/etc.) for fast pre-filtering."""
    from bughound.tools.oneliners.pipeline import run_pipeline as _run_pipeline

    return await _run_pipeline(pipeline_id, workspace_id)
