"""Single BugHound MCP server. All tools registered here."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

import structlog
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Logging — ALL output must go to stderr. stdout is the JSON-RPC stdio pipe.
# Writing anything to stdout (including structlog's default ConsoleRenderer)
# corrupts the MCP transport and freezes the AI client (gemini-cli, etc.).
# ---------------------------------------------------------------------------
logging.basicConfig(format="%(message)s", level=logging.WARNING, stream=sys.stderr)
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
)

from bughound import operations
from bughound.core import workspace  # primitive reads (read_data, workspace_dir, etc.)
from bughound.core.job_manager import JobManager, JobStatus
from bughound.schemas.models import WorkspaceState

# Shared job manager instance (lives for server lifetime)
_job_manager = JobManager()

mcp = FastMCP("bughound")


# ---------------------------------------------------------------------------
# Stage 0: Initialize + Workspace management
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_init",
    description=(
        "Initialize a new BugHound workspace for a target. Stage 0: classifies "
        "the target (broad domain, single host, endpoint, or URL list), creates "
        "a workspace, and returns which pipeline stages to run. Always call this "
        "first before any other bughound tool. Sync.\n\n"
        "depth parameter:\n"
        "- 'light' (default): fast passive recon only, good for quick assessments\n"
        "- 'deep': thorough recon with active tools, background jobs, brute-force — "
        "use when user says 'full recon', 'deep scan', 'thorough', or 'comprehensive'\n\n"
        "If the user just says 'scan X' or 'check X', use light. "
        "If they say 'full recon on X' or 'deep scan X', use deep."
    ),
)
async def bughound_init(target: str, depth: str = "light") -> str:
    """Classify target and create workspace."""
    try:
        init = await operations.create_workspace(target=target, depth=depth)
    except ValueError as exc:
        return f"Error: {exc}"

    classification = init["classification"]
    workspace_id = init["workspace_id"]
    ws_path = init["workspace_dir"]
    stages_to_run = classification.get("stages_to_run", [])
    skip_reasons = classification.get("skip_reasons", {})
    normalized = classification.get("normalized_targets", [])
    target_type_val = classification.get("target_type", "?")

    stage_names = {
        0: "Initialize", 1: "Enumerate", 2: "Discover",
        3: "Analyze", 4: "Test", 5: "Validate", 6: "Report",
    }

    next_step = _suggest_next(stages_to_run)

    pipeline_parts = []
    for s in sorted(stage_names.keys()):
        if s not in stages_to_run:
            continue
        if s == 0:
            pipeline_parts.append(f"Stage {s} [done]")
        else:
            pipeline_parts.append(f"Stage {s}")
    pipeline_line = " > ".join(pipeline_parts)

    skip_lines = ""
    if skip_reasons:
        skip_lines = "\n  Skipped:\n"
        for stage_num, reason in skip_reasons.items():
            skip_lines += f"    Stage {stage_num}: {reason}\n"

    header = "=" * 45
    return (
        f"{header}\n"
        f"  BugHound -- Workspace Initialized\n"
        f"{header}\n\n"
        f"  Target:     {target}\n"
        f"  Type:       {target_type_val}\n"
        f"  Depth:      {depth}\n"
        f"  Workspace:  {workspace_id}\n"
        f"  Path:       {ws_path}\n"
        f"  Normalized: {', '.join(normalized)}\n"
        f"{skip_lines}\n"
        f"  Pipeline: {pipeline_line}\n\n"
        f"  Next: {next_step}\n"
    )


@mcp.tool(
    name="bughound_workspace_list",
    description=(
        "List all BugHound workspaces. Optionally filter by state "
        "(INITIALIZED, ENUMERATING, DISCOVERING, ANALYZING, TESTING, "
        "VALIDATING, COMPLETED, ARCHIVED). Sync."
    ),
)
async def bughound_workspace_list(state: str = "") -> str:
    """List workspaces with optional state filter."""
    if state:
        try:
            WorkspaceState(state.upper())  # Validate; operations also accepts strings.
        except ValueError:
            valid = ", ".join(s.value for s in WorkspaceState)
            return f"Error: Invalid state '{state}'. Valid states: {valid}"

    workspaces = await operations.list_workspaces(state or None)

    if not workspaces:
        return "No workspaces found. Use `bughound_init` to create one."

    lines = [f"## BugHound Workspaces ({len(workspaces)})\n"]
    for ws in workspaces:
        stats = ws.stats
        lines.append(
            f"- **`{ws.workspace_id}`** | {ws.target} | "
            f"{ws.state.value} | {ws.depth} | "
            f"subs: {stats.subdomains_found}, hosts: {stats.live_hosts}, "
            f"urls: {stats.urls_discovered}"
        )

    return "\n".join(lines) + "\n"


@mcp.tool(
    name="bughound_workspace_get",
    description=(
        "Get full details of a BugHound workspace including metadata, "
        "config, current stage, and stats. Requires workspace_id from "
        "bughound_init or bughound_workspace_list. Sync."
    ),
)
async def bughound_workspace_get(workspace_id: str) -> str:
    """Get workspace metadata and config."""
    detail = await operations.get_workspace_detail(workspace_id)
    if detail is None:
        return f"Error: Workspace '{workspace_id}' not found. Run `bughound_init` first."

    meta = detail["metadata"]
    cfg = detail.get("config")
    s = meta.get("stats", {})

    stage_history = ""
    history = meta.get("stage_history", [])
    if history:
        stage_history = "\n**Stage History:**\n"
        for entry in history:
            stage_history += f"  - Stage {entry['stage']}: {entry['status']}\n"

    scope_str = ""
    if cfg:
        scope = cfg.get("scope", {})
        scope_str = (
            f"\n**Scope:**\n"
            f"  - Include: {', '.join(scope.get('include', [])) or 'all'}\n"
            f"  - Exclude: {', '.join(scope.get('exclude', [])) or 'none'}\n"
        )

    target_type = meta.get("target_type") or "not classified"

    return (
        f"## Workspace: {meta['workspace_id']}\n\n"
        f"**Target:** {meta['target']}\n"
        f"**Target Type:** {target_type}\n"
        f"**State:** {meta['state']}\n"
        f"**Depth:** {meta['depth']}\n"
        f"**Current Stage:** {meta['current_stage']}\n"
        f"**Created:** {meta['created_at']}\n"
        f"**Updated:** {meta['updated_at']}\n\n"
        f"**Stats:**\n"
        f"  - Subdomains found: {s.get('subdomains_found', 0)}\n"
        f"  - Live hosts: {s.get('live_hosts', 0)}\n"
        f"  - URLs discovered: {s.get('urls_discovered', 0)}\n"
        f"  - Findings total: {s.get('findings_total', 0)}\n"
        f"  - Findings confirmed: {s.get('findings_confirmed', 0)}\n"
        f"{stage_history}"
        f"{scope_str}"
    )


@mcp.tool(
    name="bughound_workspace_delete",
    description=(
        "Delete a BugHound workspace and all its data. This is irreversible. "
        "Requires workspace_id. Sync."
    ),
)
async def bughound_workspace_delete(workspace_id: str) -> str:
    """Delete a workspace."""
    deleted = await operations.delete_workspace(workspace_id)
    if deleted:
        return f"Workspace `{workspace_id}` deleted successfully."
    return f"Error: Workspace '{workspace_id}' not found."


@mcp.tool(
    name="bughound_workspace_results",
    description=(
        "View workspace results dashboard or drill into specific data categories. "
        "Without a category, returns an overview of all collected data with counts. "
        "With a category, returns the actual data. Categories: subdomains, dns, "
        "hosts, flags, technologies, urls, parameters, secrets, js_secrets_confirmed, "
        "hidden_endpoints, api_endpoints, sensitive_paths, cors, takeover, "
        "takeover_confirmed, vulnerabilities, waf, attack_surface. "
        "Use anytime to check recon progress or review findings. "
        "The attack_surface category returns the saved Stage 3 analysis "
        "(scored targets, chains, wins) without recomputing."
    ),
)
async def bughound_workspace_results(workspace_id: str, category: str = "") -> str:
    """View workspace data dashboard or drill into a specific category."""
    if not category:
        return await _results_dashboard(workspace_id)
    return await _results_category(workspace_id, category.strip().lower())


async def _results_dashboard(workspace_id: str) -> str:
    """Build a dashboard overview of all workspace data."""
    dash = await operations.get_workspace_dashboard(workspace_id)
    if dash is None:
        return f"Error: Workspace '{workspace_id}' not found."

    lines = [
        f"## Workspace Dashboard: `{workspace_id}`\n",
        f"**Target:** {dash['target']}",
        f"**State:** {dash['state']}",
        f"**Current Stage:** {dash['current_stage']}\n",
        "**Data Collected:**",
    ]

    for cat in dash["categories"]:
        label = cat["name"]
        path = cat["path"]
        count = cat["count"]
        if count is None:
            lines.append(f"  - {label}: —")
        else:
            lines.append(f"  - **{label}**: {count} entries  (`{path}`)")

    stage_names = {
        0: "Initialize", 1: "Enumerate", 2: "Discover",
        3: "Analyze", 4: "Test", 5: "Validate", 6: "Report",
    }
    completed = dash["stages_completed"]
    pending = dash["stages_pending"]
    completed_str = ", ".join(f"{s} ({stage_names.get(s, '?')})" for s in completed)
    pending_str = ", ".join(f"{s} ({stage_names.get(s, '?')})" for s in pending)

    lines.append(f"\n**Stages completed:** {completed_str or 'none'}")
    lines.append(f"**Stages pending:** {pending_str or 'none'}")

    # Available drill-down categories (canonical from operations)
    lines.append(
        "\n**Drill down:** call with category = subdomains | dns | hosts | flags | "
        "technologies | urls | parameters | secrets | js_secrets_confirmed | "
        "hidden_endpoints | api_endpoints | sensitive_paths | cors | takeover | "
        "takeover_confirmed | vulnerabilities | waf | attack_surface"
    )

    return "\n".join(lines) + "\n"


async def _results_category(workspace_id: str, category: str) -> str:
    """Return actual data for a specific category, human-formatted."""
    result = await operations.get_workspace_category(workspace_id, category)
    status = result.get("status")

    if status == "not_found":
        return f"Error: Workspace '{workspace_id}' not found."
    if status == "unknown_category":
        valid = ", ".join(result.get("valid", []))
        return f"Error: Unknown category '{category}'. Valid categories: {valid}"
    if status == "no_data":
        return (
            f"## {category} — No Data\n\n"
            f"File `{result['path']}` does not exist yet. "
            f"This data is collected during a later pipeline stage."
        )

    # attack_surface returns a single dict, not a list — format with the
    # attack-surface formatter directly.
    if category == "attack_surface":
        return _format_attack_surface(result["items"])

    items = result["items"]
    total = result["total"]
    truncate_limit = result.get("truncate_limit", 0)

    lines = [f"## {category} — `{workspace_id}`\n", f"**Total:** {total}\n"]

    formatter = _CATEGORY_FORMATTERS.get(category)
    if formatter:
        show = items[:truncate_limit] if truncate_limit else items
        lines.extend(formatter(show))
        if truncate_limit and total > truncate_limit:
            lines.append(f"\n... and {total - truncate_limit} more (showing first {truncate_limit})")
    else:
        lines.append(f"```json\n{json.dumps(items[:20], indent=2)}\n```")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Per-category formatters — return list of markdown lines
# ---------------------------------------------------------------------------


def _fmt_subdomains(items: list) -> list[str]:
    lines: list[str] = []
    for item in items:
        lines.append(f"  - {item}")
    return lines


def _fmt_hosts(items: list) -> list[str]:
    lines: list[str] = []
    for h in items:
        status = h.get("status_code", "?")
        title = h.get("title", "—")[:60]
        server = h.get("web_server", "—")
        techs = ", ".join(h.get("technologies", [])[:5])
        cdn = h.get("cdn") or ""
        flags = h.get("flags", [])

        lines.append(f"### {h.get('host', h.get('url', '?'))}")
        lines.append(f"  - **URL:** {h.get('url', '?')}  |  **Status:** {status}")
        lines.append(f"  - **Title:** {title}")
        lines.append(f"  - **Server:** {server}  |  **Tech:** {techs or '—'}")
        if cdn:
            lines.append(f"  - **CDN:** {cdn}")
        if flags:
            lines.append(f"  - **Flags:** {', '.join(flags)}")
        lines.append("")
    return lines


def _fmt_flags(items: list) -> list[str]:
    lines: list[str] = []
    for h in items:
        host = h.get("host", h.get("url", "?"))
        flags = h.get("flags", [])
        if flags:
            lines.append(f"**{host}** ({len(flags)} flags)")
            for f in flags:
                lines.append(f"  - {f}")
            lines.append("")
    return lines


def _fmt_waf(items: list) -> list[str]:
    lines: list[str] = []
    for w in items:
        url = w.get("url", "?")
        detected = w.get("detected", False)
        waf_name = w.get("waf", "None")
        if detected:
            lines.append(f"  - **{url}**: {waf_name} ({w.get('manufacturer', '?')})")
        else:
            lines.append(f"  - {url}: No WAF detected")
    return lines


def _fmt_technologies(items: list) -> list[str]:
    lines: list[str] = []
    for t in items:
        tech = t.get("technology", "?")
        count = t.get("host_count", 0)
        lines.append(f"  - **{tech}**: {count} host{'s' if count != 1 else ''}")
    return lines


def _fmt_urls(items: list) -> list[str]:
    lines: list[str] = []
    # Group by source
    by_source: dict[str, int] = {}
    for u in items:
        src = u.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1

    if by_source:
        lines.append("**By source:**")
        for src, cnt in sorted(by_source.items(), key=lambda x: -x[1]):
            lines.append(f"  - {src}: {cnt}")
        lines.append("")

    lines.append("**URLs:**")
    for u in items:
        lines.append(f"  - {u.get('url', '?')}  ({u.get('source', '?')})")
    return lines


def _fmt_parameters(items: list) -> list[str]:
    lines: list[str] = []
    for p in items:
        path = p.get("path", "?")
        params = p.get("params", [])
        param_names = [pr.get("name", "?") for pr in params]
        high_freq = [pr.get("name", "?") for pr in params if pr.get("high_frequency")]
        lines.append(f"  - **{path}**: {', '.join(param_names)}")
        if high_freq:
            lines.append(f"    High frequency: {', '.join(high_freq)}")
    return lines


def _fmt_secrets(items: list) -> list[str]:
    lines: list[str] = []
    for s in items:
        conf = s.get("confidence", "?")
        stype = s.get("type", "?")
        value = s.get("value", "?")
        src = s.get("source_file", "?").split("/")[-1]
        lines.append(f"  - **[{conf}]** {stype}: `{value}`")
        lines.append(f"    Source: {src}")
    return lines


def _fmt_hidden_endpoints(items: list) -> list[str]:
    lines: list[str] = []
    for ep in items:
        method = ep.get("method", "GET")
        path = ep.get("path", "?")
        etype = ep.get("endpoint_type", "?")
        src = ep.get("source_file", "?").split("/")[-1]
        lines.append(f"  - **{method}** `{path}`  [{etype}]  (from {src})")
    return lines


def _fmt_sensitive_paths(items: list) -> list[str]:
    lines: list[str] = []
    # Group by host
    by_host: dict[str, list] = {}
    for sp in items:
        host = sp.get("host_url", "?")
        by_host.setdefault(host, []).append(sp)

    for host, paths in by_host.items():
        lines.append(f"**{host}** ({len(paths)} paths)")
        for sp in paths:
            cat = sp.get("category", "?")
            path = sp.get("path", "?")
            status = sp.get("status_code", "?")
            lines.append(f"  - [{cat}] `{path}` (status {status})")
        lines.append("")
    return lines


def _fmt_cors(items: list) -> list[str]:
    lines: list[str] = []
    for c in items:
        url = c.get("url", "?")
        severity = c.get("severity", "?")
        origin = c.get("origin_tested", "?")
        acao = c.get("acao", "?")
        creds = c.get("credentials_allowed", False)
        lines.append(
            f"  - **[{severity}]** {url}\n"
            f"    Origin: {origin} | ACAO: {acao} | Credentials: {'Yes' if creds else 'No'}"
        )
    return lines


def _fmt_takeover(items: list) -> list[str]:
    lines: list[str] = []
    for t in items:
        sub = t.get("subdomain", t.get("host", "?"))
        cname = t.get("cname", "?")
        service = t.get("service", t.get("provider", "?"))
        lines.append(f"  - **{sub}** → `{cname}` ({service})")
    return lines


def _fmt_vulnerabilities(items: list) -> list[str]:
    lines: list[str] = []
    for v in items:
        severity = v.get("severity", "?").upper()
        name = v.get("template_id", v.get("vulnerability_class", "?"))
        host = v.get("host", "?")
        endpoint = v.get("endpoint", "")
        tool = v.get("tool", "?")
        lines.append(f"  - **[{severity}]** {name}")
        lines.append(f"    Host: {host}{endpoint}  |  Tool: {tool}")
    return lines


def _fmt_api_endpoints(items: list) -> list[str]:
    lines: list[str] = []
    for ep in items:
        method = ep.get("method", "GET")
        path = ep.get("path", ep.get("endpoint", "?"))
        source = ep.get("source", ep.get("from", ""))
        host = ep.get("host", "")
        prefix = f"{host}" if host else ""
        lines.append(f"  - **{method}** `{path}`  {f'({source})' if source else ''} {prefix}")
    return lines


def _fmt_dns(items: list) -> list[str]:
    lines: list[str] = []
    for rec in items:
        domain = rec.get("domain", "?")
        a_records = rec.get("A", [])
        cname = rec.get("CNAME", [])
        resolved = rec.get("resolved", False)
        status = "resolved" if resolved else "unresolved"
        ips = ", ".join(a_records[:3]) if a_records else ""
        cnames = ", ".join(cname[:2]) if cname else ""
        detail = ips or cnames or status
        lines.append(f"  - **{domain}** → {detail}")
    return lines


_CATEGORY_FORMATTERS: dict[str, Any] = {
    "subdomains": _fmt_subdomains,
    "hosts": _fmt_hosts,
    "live_hosts": _fmt_hosts,
    "flags": _fmt_flags,
    "waf": _fmt_waf,
    "technologies": _fmt_technologies,
    "urls": _fmt_urls,
    "parameters": _fmt_parameters,
    "secrets": _fmt_secrets,
    "js_secrets": _fmt_secrets,
    "js_secrets_confirmed": _fmt_secrets,
    "hidden_endpoints": _fmt_hidden_endpoints,
    "api_endpoints": _fmt_api_endpoints,
    "sensitive_paths": _fmt_sensitive_paths,
    "cors": _fmt_cors,
    "cors_results": _fmt_cors,
    "takeover": _fmt_takeover,
    "takeover_candidates": _fmt_takeover,
    "takeover_confirmed": _fmt_takeover,
    "vulnerabilities": _fmt_vulnerabilities,
    "dns": _fmt_dns,
    "dns_records": _fmt_dns,
}


# ---------------------------------------------------------------------------
# Stage 1: Enumerate
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_enumerate",
    description=(
        "Discover subdomains for a broad domain target. Stage 1: runs passive "
        "subdomain sources (subfinder, assetfinder, findomain, crt.sh) in parallel, "
        "resolves DNS, detects wildcards, and analyzes naming patterns. Requires "
        "bughound_init first. Auto-skips for non-domain targets. Sync, ~30-60s. "
        "IMPORTANT: After results, present them to the user and WAIT. "
        "Do NOT automatically call bughound_discover. "
        "Each stage requires explicit user approval before proceeding."
    ),
)
async def bughound_enumerate(workspace_id: str) -> str:
    """Run light subdomain enumeration."""
    result = await operations.enumerate_light(workspace_id)
    return _format_enumerate(result)


@mcp.tool(
    name="bughound_enumerate_deep",
    description=(
        "Deep subdomain enumeration as a background job. Stage 1 deep mode: "
        "runs all passive sources plus active bruteforce and permutation fuzzing "
        "if tools are available. Requires bughound_init first. Returns job_id — "
        "poll with bughound_job_status. Async, 5-15 minutes."
    ),
)
async def bughound_enumerate_deep(workspace_id: str) -> str:
    """Start deep enumeration as a background job."""
    result = await operations.enumerate_deep(workspace_id, _job_manager)
    return _format_job_started(result)


# ---------------------------------------------------------------------------
# Stage 2: Discover
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_discover",
    description=(
        "Full attack surface discovery: probe live hosts, fingerprint technologies, "
        "detect WAF/CDN, crawl URLs, analyze JavaScript for secrets and hidden "
        "endpoints, check 70+ sensitive paths, detect subdomain takeovers, test "
        "CORS misconfigurations, harvest parameters. Returns intelligence flags per "
        "host for AI reasoning. Always async — returns job_id immediately. "
        "Optional 'targets' param: comma-separated subdomains to focus on "
        "(e.g. 'api.example.com,staging.example.com'). If empty, discovers all. "
        "For broad domains with many subdomains, ask the user which ones to focus on. "
        "IMPORTANT: After receiving the job_id, do NOT automatically call "
        "bughound_job_status. Do NOT poll or loop. Just tell the user the job "
        "is running and wait for them to ask you to check."
    ),
)
async def bughound_discover(workspace_id: str, targets: str = "") -> str:
    """Run Stage 2 discovery.

    targets: optional comma-separated list of specific subdomains to focus on.
             If empty, discovers ALL subdomains from Stage 1.
             Example: "api.example.com,staging.example.com"
    """
    target_list = None
    if targets and targets.strip():
        target_list = [t.strip() for t in targets.split(",") if t.strip()]

    result = await operations.discover(
        workspace_id, job_manager=_job_manager, target_subset=target_list,
    )
    return _format_discover(result)


# ---------------------------------------------------------------------------
# Stage 3: Analyze
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_get_attack_surface",
    description=(
        "Get comprehensive attack surface analysis with exploitability-scored targets, "
        "attack chain detection, immediate reportable wins, technology-specific playbooks, "
        "and cross-stage correlations. This is the intelligence brain of BugHound. "
        "Stage 3, read-only, sync. "
        "IMPORTANT: After receiving results, present the analysis to the user and WAIT. "
        "Do NOT automatically call bughound_submit_scan_plan or any other tool. "
        "Each stage requires explicit user approval before proceeding."
    ),
)
async def bughound_get_attack_surface(workspace_id: str) -> str:
    """Analyze full attack surface from Stage 2 data."""
    result = await operations.get_attack_surface(workspace_id)
    return _format_attack_surface(result)


@mcp.tool(
    name="bughound_analyze_host",
    description=(
        "Deep-dive analysis of a specific host. Returns detailed probe results, "
        "confirmed vulnerabilities, flags, technologies, parameters, and attack "
        "chains for ONE host. Use this after bughound_get_attack_surface to "
        "drill into high-interest targets. Stage 3, read-only, sync."
    ),
)
async def bughound_analyze_host(workspace_id: str, host: str) -> str:
    """Get detailed analysis for a single host."""
    result = await operations.get_attack_surface_for_host(workspace_id, host)

    if result.get("status") == "error":
        return f"Error: {result['message']}"
    if result.get("status") == "not_found":
        available = result.get("available_hosts", [])
        return f"Host '{host}' not found. Available hosts:\n" + "\n".join(
            f"  - {h}" for h in available
        )

    target = result["target"]
    host_probes = result["host_probes"]
    host_candidates = result["host_candidates"]
    host_chains = result["host_chains"]
    suggested = result.get("suggested_test_classes", [])

    hdr = "=" * 45
    lines = [
        f"{hdr}",
        f"  Host Analysis: {host}",
        f"{hdr}",
        "",
        f"  Score: {target.get('score', 0)} [{target.get('risk_level', '?')}]",
        f"  URL: {target.get('url', '?')}",
    ]

    if target.get("technologies"):
        lines.append(f"  Tech: {', '.join(target['technologies'][:10])}")
    if target.get("flags"):
        lines.append(f"\n  Flags:")
        for f in target["flags"]:
            lines.append(f"    - {f}")

    if host_probes:
        lines.append(f"\n  Probe-Confirmed Vulnerabilities ({len(host_probes)}):")
        for p in host_probes[:10]:
            lines.append(f"    [{p['vuln_type'].upper()}] {p['url'][:55]} param={p['param']}")

    if host_candidates:
        lines.append(f"\n  Vulnerable Parameters:")
        for vtype, cands in host_candidates.items():
            for c in cands[:3]:
                lines.append(f"    [{vtype.upper()}] {c.get('url', '?')[:50]} param={c.get('param', '?')}")

    if host_chains:
        lines.append(f"\n  Attack Chains ({len(host_chains)}):")
        for c in host_chains[:5]:
            lines.append(f"    [{c.get('severity', '?')}] {c.get('name', '?')[:50]}")
            steps = c.get("exploitation_steps", [])
            for s in steps[:3]:
                lines.append(f"      {s}")

    if target.get("reasons"):
        lines.append(f"\n  Why this host is interesting:")
        for r in target["reasons"]:
            lines.append(f"    - {r}")

    lines.append(f"\n  Suggested test classes: {', '.join(suggested)}")

    return "\n".join(lines) + "\n"


@mcp.tool(
    name="bughound_get_immediate_wins",
    description=(
        "Get all immediate wins — findings that are ready to report NOW without "
        "any testing. Includes exposed .git, .env, credentials, actuator endpoints, "
        "source maps, phpinfo, backups. These should be reported first while "
        "testing continues. Stage 3, read-only, sync."
    ),
)
async def bughound_get_immediate_wins(workspace_id: str) -> str:
    """Get report-ready findings from discovery data."""
    result = await operations.get_immediate_wins(workspace_id)

    if result.get("status") == "error":
        return f"Error: {result['message']}"
    if result.get("status") == "empty":
        return result.get("message", "No immediate wins found.")

    wins = result["wins"]

    hdr = "=" * 45
    lines = [
        f"{hdr}",
        f"  Immediate Wins: {len(wins)} report-ready findings",
        f"{hdr}",
        "",
    ]

    for i, w in enumerate(wins, 1):
        lines.append(f"  {i}. [{w.get('severity', '?')}] {w.get('type', '?')}")
        lines.append(f"     Host: {w.get('host', '?')}")
        lines.append(f"     Path: {w.get('path', '?')}")
        if w.get("evidence"):
            lines.append(f"     Evidence: {str(w['evidence'])[:80]}")
        if w.get("reproduction"):
            lines.append(f"     Reproduce: {w['reproduction'][:80]}")
        if w.get("bounty_estimate"):
            lines.append(f"     Est. Bounty: {w['bounty_estimate']}")
        lines.append("")

    lines.append(f"  These can be reported immediately without running Stage 4 testing.")
    return "\n".join(lines) + "\n"


@mcp.tool(
    name="bughound_submit_scan_plan",
    description=(
        "Submit testing strategy after reviewing attack surface. Validates targets "
        "against scope and checks tool availability. Required before "
        "bughound_execute_tests. Pass scan_plan as a JSON object (not a string) with "
        "'targets' array and optional 'global_settings'. Stage 3, sync. "
        "IMPORTANT: After scan plan is approved, present confirmation to the user "
        "and WAIT. Do NOT automatically call bughound_execute_tests. "
        "Each stage requires explicit user approval before proceeding."
    ),
)
async def bughound_submit_scan_plan(workspace_id: str, scan_plan: dict | str) -> str:
    """Validate and store scan plan."""
    # Accept dict (native MCP/FastMCP), JSON string, or Python dict string
    if isinstance(scan_plan, dict):
        parsed = scan_plan
    elif isinstance(scan_plan, str):
        # Try strict JSON first
        try:
            parsed = json.loads(scan_plan)
        except (json.JSONDecodeError, TypeError):
            # Try fixing single quotes → double quotes (common AI client issue)
            try:
                parsed = json.loads(scan_plan.replace("'", '"'))
            except (json.JSONDecodeError, TypeError):
                # Last resort: Python literal eval
                try:
                    import ast
                    parsed = ast.literal_eval(scan_plan)
                except (ValueError, SyntaxError):
                    return json.dumps({
                        "status": "error",
                        "message": "Could not parse scan_plan. Send as JSON object with double quotes.",
                        "example": '{"targets": [{"host": "example.com", "techniques": ["nuclei_scan"]}]}',
                    })
    else:
        return json.dumps({
            "status": "error",
            "message": f"scan_plan must be a JSON object or string, got {type(scan_plan).__name__}",
        })
    if not isinstance(parsed, dict):
        return json.dumps({
            "status": "error",
            "message": f"scan_plan must be a JSON object/dict, got {type(parsed).__name__}",
        })
    result = await operations.submit_scan_plan(workspace_id, parsed)
    return _format_scan_plan_result(result)


@mcp.tool(
    name="bughound_enrich_target",
    description=(
        "Get complete intelligence dossier on a single host. All fingerprint data, "
        "flags, URLs, parameters, secrets, sensitive paths, CORS results, attack "
        "chains. Use when drilling into a high-interest target from the attack "
        "surface analysis. Stage 3, sync."
    ),
)
async def bughound_enrich_target(workspace_id: str, host: str) -> str:
    """Get all workspace intelligence for one host."""
    result = await operations.enrich_target(workspace_id, host)
    return _format_enrich_target(result)


@mcp.tool(
    name="bughound_scope_check",
    description=(
        "Verify if a target is within workspace scope before testing. Returns "
        "in_scope boolean. Use to confirm targets before manual testing. Sync."
    ),
)
async def bughound_scope_check(workspace_id: str, target: str) -> str:
    """Check scope for a target."""
    result = await operations.check_scope(workspace_id, target)
    if result.get("status") == "not_found":
        return f"Error: Workspace '{workspace_id}' not found."

    in_scope = result.get("in_scope", False)
    scope = result.get("scope", {})
    include = scope.get("include", [])
    exclude = scope.get("exclude", [])

    scope_rules = (
        f"\n**Scope rules:**\n"
        f"  - Include: {', '.join(include) or 'all'}\n"
        f"  - Exclude: {', '.join(exclude) or 'none'}"
    )
    status = "IN SCOPE" if in_scope else "OUT OF SCOPE"
    return f"## Scope Check\n\n**Target:** {target}\n**Result:** {status}{scope_rules}\n"


@mcp.tool(
    name="bughound_check_tool_coverage",
    description=(
        "Check which security tools are installed on this system. Returns available "
        "and missing tools with install commands. Use to understand testing "
        "capabilities before submitting a scan plan. Sync."
    ),
)
async def bughound_check_tool_coverage() -> str:
    """Check installed security tools."""
    coverage = operations.check_tool_coverage()

    # All non-oneliner tools share the "main" view; oneliners get their own section.
    main_installed = [t for t in coverage.installed if t.category != "oneliner"]
    main_missing = [
        t for t in (coverage.missing_critical + coverage.missing_optional)
        if t.category != "oneliner"
    ]
    main_total = main_installed.__len__() + main_missing.__len__()

    lines = [
        "## Tool Coverage\n",
        f"**Available:** {len(main_installed)}/{main_total}\n",
    ]

    if main_installed:
        lines.append("**Installed:**")
        for t in sorted(main_installed, key=lambda x: x.name):
            lines.append(f"  - {t.name}")
        lines.append("")

    if main_missing:
        lines.append("**Missing (with install commands):**")
        for t in sorted(main_missing, key=lambda x: x.name):
            lines.append(f"  - **{t.name}**: `{t.install_cmd}`")
        lines.append("")

    # Coverage by category (uses operations' canonical category breakdown)
    lines.append("**Coverage by category:**")
    for cat in ("recon", "discovery", "scanning", "validation", "secrets",
                "cms", "takeover", "oob"):
        c = coverage.by_category.get(cat)
        if c and c["total"]:
            lines.append(f"  - {cat.title()}: {c['installed']}/{c['total']}")

    # One-liners (all have Python fallbacks, displayed separately)
    oneliner_installed = [t for t in coverage.installed if t.category == "oneliner"]
    oneliner_missing = [
        t for t in (coverage.missing_critical + coverage.missing_optional)
        if t.category == "oneliner"
    ]
    oneliner_total = len(oneliner_installed) + len(oneliner_missing)
    lines.append(
        f"  - One-liners: {len(oneliner_installed)}/{oneliner_total} "
        f"(all have Python fallbacks)"
    )
    if oneliner_missing:
        lines.append("\n**One-liner tools (optional, faster with native binary):**")
        for t in sorted(oneliner_missing, key=lambda x: x.name):
            lines.append(f"  - **{t.name}**: `{t.install_cmd}`")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Stage 4: Test
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_execute_tests",
    description=(
        "Execute comprehensive vulnerability testing based on scan plan. Runs 5 phases: "
        "nuclei templates, directory fuzzing, parameter discovery, injection testing "
        "(SQLi, XSS, SSRF, LFI, IDOR, CRLF, SSTI, header injection, open redirect), "
        "and technology-specific tests (GraphQL, JWT, WordPress, Spring Boot). "
        "Requires bughound_submit_scan_plan first. Always async — returns job_id. "
        "Optional test_profile filters which side of the test surface runs: "
        "'client' (XSS/redirect/CORS/proto-pollution/CSP), "
        "'server' (SQLi/SSRF/RCE/LFI/XXE/IDOR/deserialization/auth), "
        "'both' (default — full coverage). Use 'client' for quick wins, "
        "'server' for deep auth/injection work. "
        "IMPORTANT: After receiving the job_id, do NOT automatically call "
        "bughound_job_status. Do NOT poll or loop. Just tell the user the job "
        "is running and wait for them to ask you to check. Stage 4."
    ),
)
async def bughound_execute_tests(
    workspace_id: str,
    test_profile: str = "both",
) -> str:
    """Run the scan plan."""
    result = await operations.execute_tests(
        workspace_id,
        job_manager=_job_manager,
        test_profile=test_profile if test_profile in ("client", "server", "both") else "both",
    )
    if result.get("status") == "job_started":
        return _format_job_started(result)
    return _format_test_results(result)


@mcp.tool(
    name="bughound_test_single",
    description=(
        "Surgical vulnerability test on a specific endpoint. Specify tool "
        "(nuclei, sqlmap, dalfox, ffuf) or technique (ssrf_test, graphql_test, "
        "jwt_test, lfi_test, ssti_test, open_redirect_test, crlf_test, idor_test, "
        "header_injection_test, wordpress_test, spring_actuator_test). "
        "Always synchronous. Scope-checked. Stage 4."
    ),
)
async def bughound_test_single(
    workspace_id: str,
    target_url: str,
    tool: str = "nuclei",
    tags: str = "",
    severity: str = "",
    template: str = "",
    technique: str = "",
) -> str:
    """Test one specific endpoint."""
    result = await operations.test_single(
        workspace_id, target_url, tool,
        tags=tags or None,
        severity=severity or None,
        template=template or None,
        technique=technique or None,
    )
    return _format_test_results(result)


@mcp.tool(
    name="bughound_list_techniques",
    description=(
        "List all available testing techniques with their requirements and "
        "descriptions. Shows tool availability status. Use to plan which "
        "techniques to include in scan plans. Stage 4."
    ),
)
async def bughound_list_techniques(test_profile: str = "both") -> str:
    """List available testing techniques. Optional test_profile filter."""
    techs = operations.list_techniques(test_profile)
    # operations normalizes invalid profiles to 'both'
    if test_profile not in ("client", "server", "both"):
        test_profile = "both"

    lines = [f"# Available Testing Techniques (profile={test_profile})\n"]
    by_phase: dict[str, list] = {}
    for t in techs:
        by_phase.setdefault(t["phase"], []).append(t)

    for phase in sorted(by_phase):
        lines.append(f"\n## Phase {phase}\n")
        for t in by_phase[phase]:
            status = "✓" if t["available"] else f"✗ (needs: {', '.join(t['missing_tools'])})"
            prof = t.get("profile", "both")
            lines.append(f"- **{t['id']}** [{status}] [{prof}]: {t['description']}")
            lines.append(f"  Vuln classes: {', '.join(t['vuln_classes'])}")

    lines.append(f"\n**Total:** {len(techs)} techniques, "
                 f"{sum(1 for t in techs if t['available'])} available")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Direct nuclei scan
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_nuclei_scan",
    description=(
        "Run nuclei vulnerability scanner with full flexibility. Specify a single "
        "target URL, or use target_source to scan workspace URL lists. "
        "target_source options: 'all_urls' (all crawled), 'dynamic_urls' (URLs with "
        "query params), 'js_files', 'live_hosts' (root URLs), 'api_endpoints' "
        "(API + OpenAPI), 'admin_paths' (admin/internal), 'forms' (GET form URLs). "
        "Control templates via tags, severity, or custom template_path. "
        "Examples: scan dynamic URLs for injection (target_source='dynamic_urls', "
        "tags='sqli,xss'), scan JS files for secrets (target_source='js_files', "
        "tags='exposure'), scan specific endpoint (target='https://example.com/api', "
        "tags='api'). Findings are appended to workspace scan_results.json. Sync."
    ),
)
async def bughound_nuclei_scan(
    workspace_id: str,
    target: str = "",
    target_source: str = "",
    tags: str = "",
    severity: str = "critical,high,medium",
    template_path: str = "",
    extra_args: str = "",
) -> str:
    """Direct nuclei scan with flexible targeting."""
    result = await operations.nuclei_scan(
        workspace_id,
        target=target,
        target_source=target_source,
        tags=tags,
        severity=severity,
        template_path=template_path,
        extra_args=extra_args,
    )

    if result.get("status") == "error":
        payload: dict[str, Any] = {"status": "error", "message": result["message"]}
        if "valid_sources" in result:
            payload["target_source_options"] = result["valid_sources"]
        return json.dumps(payload)

    findings = result["findings"]
    sev_counts = result["severity_breakdown"]
    scan_urls_count = result["scan_urls_count"]

    lines = [f"## Nuclei Scan Results\n"]
    source_label = f"target={target}" if target else f"target_source={target_source}"
    lines.append(f"**Scan:** {source_label}")
    lines.append(f"**URLs scanned:** {scan_urls_count}")
    if tags:
        lines.append(f"**Tags:** {tags}")
    lines.append(f"**Findings:** {len(findings)}\n")

    if sev_counts:
        lines.append("**By severity:**")
        for s in ("critical", "high", "medium", "low", "info"):
            if s in sev_counts:
                lines.append(f"  - {s}: {sev_counts[s]}")
        lines.append("")

    if findings:
        lines.append("**Top findings:**")
        for f in findings[:15]:
            lines.append(
                f"  - [{f.get('severity', '?').upper()}] {f.get('template_name', '?')} "
                f"@ {f.get('matched_at', f.get('host', '?'))[:80]}"
            )
        if len(findings) > 15:
            lines.append(f"  ... and {len(findings) - 15} more")
        lines.append("")

    lines.append("Findings written to `vulnerabilities/scan_results.json`.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# One-liner Pipelines
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_run_pipeline",
    description=(
        "Run a one-liner pipeline for fast pre-filtering of URLs. Chains tools "
        "like gf, qsreplace, kxss, gxss, urldedupe, bhedak for quick candidate "
        "identification. 17 pipelines: 9 basic (xss_reflection_check, sqli_candidates, "
        "ssrf/redirect/lfi/crlf quick tests, js_secret_extract, param_bruteforce) + "
        "8 smart (xss_deep_reflection_check, smart_xss_pipeline, smart_sqli_pipeline, "
        "mass_ssrf/redirect/lfi/crlf tests, ssti_quick_test). Smart pipelines verify "
        "hits via HTTP response matching. All have Python fallbacks. Stage 4."
    ),
)
async def bughound_run_pipeline(workspace_id: str, pipeline_id: str) -> str:
    """Run a one-liner pipeline."""
    result = await operations.run_pipeline(workspace_id, pipeline_id)
    return _format_pipeline_result(result)


@mcp.tool(
    name="bughound_list_pipelines",
    description=(
        "List all 17 one-liner pipelines (9 basic + 8 smart) with descriptions "
        "and tool chains. Shows which tools are native vs Python fallback. Stage 4."
    ),
)
async def bughound_list_pipelines() -> str:
    """List available one-liner pipelines."""
    info = operations.list_pipelines()
    pipelines = info["pipelines"]
    tools = info["tools_used"]

    lines = ["# One-liner Pipelines\n"]
    for p in pipelines:
        lines.append(f"- **{p['id']}**: {p['description']}")
        lines.append(f"  Steps: `{p['steps']}`")
        lines.append(f"  Vuln class: {p['vuln_class']}")
        lines.append("")

    lines.append("## Tool Status\n")
    for tool_name, status in tools.items():
        indicator = "native" if status == "native" else "Python fallback"
        lines.append(f"- **{tool_name}**: {indicator}")

    lines.append(f"\n**Total:** {len(pipelines)} pipelines")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Stage 5: Validate
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_validate_finding",
    description=(
        "Surgically validate a single finding from Stage 4. Runs the appropriate "
        "validation tool (sqlmap for SQLi, dalfox for XSS, curl-based for others) "
        "against the specific endpoint/parameter. Returns CONFIRMED, LIKELY_FALSE_POSITIVE, "
        "or NEEDS_MANUAL_REVIEW with full PoC evidence including curl commands and "
        "reproduction steps. CVSS 3.1 scoring for confirmed findings. Stage 5, sync."
    ),
)
async def bughound_validate_finding(
    workspace_id: str,
    finding_id: str,
    tool: str = "",
) -> str:
    """Validate a single finding."""
    result = await operations.validate_finding(
        workspace_id, finding_id, tool=tool or None,
    )
    return _format_validation_result(result)


@mcp.tool(
    name="bughound_validate_all",
    description=(
        "Batch-validate all unvalidated findings from Stage 4. Processes findings "
        "in severity order (critical first). For each finding, auto-selects the "
        "best validation tool. Returns summary with confirmed/false positive/manual "
        "review counts. Writes validated.json, false_positives.json, manual_review.json, "
        "and individual confirmed finding files. Stage 5."
    ),
)
async def bughound_validate_all(workspace_id: str) -> str:
    """Batch-validate all findings."""
    # operations.validate_all handles the create_job → start_job → run_job
    # → complete_job sequence when given a job_manager.
    result = await operations.validate_all(workspace_id, job_manager=_job_manager)
    if result.get("status") == "error":
        return f"Error: {result.get('message', 'unknown error')}"
    return _format_job_started(result)


@mcp.tool(
    name="bughound_validate_immediate_wins",
    description=(
        "Verify Stage 3 immediate wins — exposed .git, .env, credentials, CORS "
        "misconfigs, subdomain takeovers, actuator endpoints, phpinfo, backups. "
        "Quick HTTP verification with content-aware checks. Confirmed wins get "
        "individual finding files with PoC evidence. Stage 5, sync."
    ),
)
async def bughound_validate_immediate_wins(workspace_id: str) -> str:
    """Verify immediate wins from Stage 3."""
    result = await operations.validate_immediate_wins(workspace_id)
    return _format_immediate_wins_result(result)


# ---------------------------------------------------------------------------
# Stage 6: Report
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_generate_report",
    description=(
        "Generate a security assessment report from all findings. "
        "Creates professional HTML report, bug bounty markdown, and executive summary. "
        "report_type: 'full' (default, HTML), 'bug_bounty' (markdown per-finding), "
        "'executive' (one-page summary), or 'all' (generate all three). Stage 6, sync."
    ),
)
async def bughound_generate_report(workspace_id: str, report_type: str = "all") -> str:
    """Generate security assessment report(s)."""
    # operations.generate_report handles the wait-for-validation poll when
    # given a job_manager and wait_for_validation=True (the default).
    result = await operations.generate_report(
        workspace_id,
        report_type,
        wait_for_validation=True,
        job_manager=_job_manager,
    )
    return _format_report_result(result)


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_job_status",
    description=(
        "Check the status of an async background job. Returns progress percentage, "
        "current module, status, and result summary if completed. Sync."
    ),
)
async def bughound_job_status(job_id: str) -> str:
    """Poll job status."""
    status = await operations.get_job_status(_job_manager, job_id)
    if status is None:
        return f"Error: Job '{job_id}' not found."

    st = status['status']
    pct = status['progress_pct']

    # Progress bar
    filled = int(pct / 5)
    bar = "#" * filled + "-" * (20 - filled)

    status_label = {
        "PENDING": "PENDING",
        "RUNNING": "RUNNING",
        "COMPLETED": "COMPLETED",
        "FAILED": "FAILED",
        "TIMED_OUT": "TIMED OUT",
    }.get(st, st)

    # Pick header based on status
    if st == "COMPLETED":
        header = "  Job Completed"
    elif st == "FAILED":
        header = "  Job Failed"
    else:
        header = "  Job Status"

    lines = [
        "=" * 45,
        header,
        "=" * 45,
        "",
        f"  Job:      {job_id}",
        f"  Status:   {status_label}",
        f"  Progress: [{bar}] {pct}%",
    ]
    msg = status.get('message', '')
    if msg:
        lines.append(f"  Current:  {msg}")
    if status.get("current_module"):
        lines.append(f"  Module:   {status['current_module']}")
    lines.append("")

    if status.get("result_summary"):
        rs = status["result_summary"]

        table_rows: list[tuple[str, Any]] = []
        detail_lines: list[str] = []
        for k, v in rs.items():
            if isinstance(v, dict):
                flat = ", ".join(f"{sk}: {sv}" for sk, sv in v.items() if sv)
                if flat:
                    detail_lines.append(f"  {k.replace('_', ' ').title()}: {flat}")
            elif isinstance(v, list):
                if v:
                    detail_lines.append(f"  {k.replace('_', ' ').title()}: {len(v)} items")
            elif v or v == 0:
                table_rows.append((k, v))

        if table_rows:
            lines.append("  | Metric | Value |")
            lines.append("  |--------|-------|")
            for k, v in table_rows:
                lines.append(f"  | {k.replace('_', ' ').title()} | {v} |")
            lines.append("")

        for dl in detail_lines:
            lines.append(dl)

    if status.get("error"):
        lines.append(f"  Error: {status['error']}")

    if st in ("RUNNING", "PENDING"):
        lines.append(f"  Wait at least 30 seconds before checking again.")

    if st == "COMPLETED":
        lines.append(f"  Use bughound_job_results for full details.")

    return "\n".join(lines) + "\n"


@mcp.tool(
    name="bughound_job_results",
    description=(
        "Get results of a completed async job. Returns the workspace data "
        "written by the job. Requires a completed job_id. Sync."
    ),
)
async def bughound_job_results(job_id: str) -> str:
    """Get completed job results."""
    status = await operations.get_job_results(_job_manager, job_id)
    if status is None:
        return f"Error: Job '{job_id}' not found."

    if status["status"] not in ("COMPLETED", "FAILED", "TIMED_OUT"):
        return (
            f"Job {job_id} is still {status['status']} "
            f"({status['progress_pct']}%). Tell the user the current progress and wait for them to check again."
        )

    st = status["status"]
    ws = status.get("workspace_id", "unknown")

    lines = [
        "=" * 45,
        "  Job Results",
        "=" * 45,
        "",
        f"  Job:       {job_id}",
        f"  Status:    {st}",
        f"  Workspace: {ws}",
        "",
    ]

    if status.get("result_summary"):
        rs = status["result_summary"]

        table_rows: list[tuple[str, Any]] = []
        detail_lines: list[str] = []
        for k, v in rs.items():
            if isinstance(v, dict):
                flat = ", ".join(f"{sk}: {sv}" for sk, sv in v.items() if sv)
                if flat:
                    detail_lines.append(f"  {k.replace('_', ' ').title()}: {flat}")
            elif isinstance(v, list):
                if v:
                    detail_lines.append(f"  {k.replace('_', ' ').title()}: {len(v)} items")
            elif v or v == 0:
                table_rows.append((k, v))

        if table_rows:
            lines.append("  | Metric | Value |")
            lines.append("  |--------|-------|")
            for k, v in table_rows:
                lines.append(f"  | {k.replace('_', ' ').title()} | {v} |")
            lines.append("")

        for dl in detail_lines:
            lines.append(dl)

    if status.get("error"):
        lines.append(f"  Error: {status['error']}")

    return "\n".join(lines) + "\n"


@mcp.tool(
    name="bughound_job_cancel",
    description="Cancel a running async job. Returns confirmation. Sync.",
)
async def bughound_job_cancel(job_id: str) -> str:
    """Cancel a background job."""
    try:
        cancelled = await operations.cancel_job(_job_manager, job_id)
    except KeyError:
        return f"Error: Job '{job_id}' not found."

    if cancelled:
        return f"Job `{job_id}` cancelled successfully."
    return f"Job `{job_id}` is not running (cannot cancel)."


# ---------------------------------------------------------------------------
# Formatters — convert stage result dicts to human-friendly text
# ---------------------------------------------------------------------------


def _format_enumerate(result: dict[str, Any]) -> str:
    """Format enumerate result as readable text."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    data = result.get("data", {})

    if data.get("skipped"):
        return result["message"]

    lines = [
        "=" * 45,
        "  BugHound -- Enumeration Results",
        "=" * 45,
        "",
        f"  {result.get('message', '')}",
        "",
    ]

    # Summary table
    total_subs = data.get("total_subdomains", data.get("subdomains_found", 0))
    resolved = data.get("resolved_count", data.get("resolved", 0))
    wildcards = data.get("wildcard_domains", 0)
    lines.append("  | Metric             | Count |")
    lines.append("  |--------------------|-------|")
    lines.append(f"  | Subdomains Found   | {total_subs:<5} |")
    if resolved:
        lines.append(f"  | Resolved           | {resolved:<5} |")
    if wildcards:
        lines.append(f"  | Wildcard Domains   | {wildcards:<5} |")
    lines.append("")

    # Tools used
    tools = data.get("tools_used", {})
    if tools:
        tool_parts = [f"{t} ({time})" for t, time in tools.items()]
        lines.append(f"  Tools: {', '.join(tool_parts)}")
        lines.append("")

    # Patterns
    patterns = data.get("patterns", {})
    interesting = patterns.get("interesting_targets", [])
    if interesting:
        lines.append(f"  Interesting Targets ({len(interesting)}):")
        for t in interesting[:15]:
            lines.append(f"    * {t}")
        if len(interesting) > 15:
            lines.append(f"    ... and {len(interesting) - 15} more")
        lines.append("")

    prefixes = patterns.get("common_prefixes", [])
    if prefixes:
        lines.append("  Naming Patterns:")
        for p in prefixes[:10]:
            lines.append(f"    * {p.get('prefix', '?')}* ({p.get('count', 0)} subdomains)")
        lines.append("")

    subnets = patterns.get("top_subnets", [])
    if subnets:
        lines.append("  IP Subnet Clusters:")
        for s in subnets[:5]:
            lines.append(f"    * {s.get('subnet', '?')}: {s.get('host_count', 0)} hosts")
        lines.append("")

    if wildcards:
        lines.append(f"  [!] {wildcards} wildcard DNS domain(s) detected")
        lines.append("")

    # Warnings
    warnings = result.get("warnings", [])
    if warnings:
        for w in warnings:
            lines.append(f"  [!] {w}")
        lines.append("")

    lines.append(f"  Next: {result.get('next_step', 'Continue to next stage.')}")
    return "\n".join(lines) + "\n"


def _format_discover(result: dict[str, Any]) -> str:
    """Format discover result as readable text."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    # Job started (async)
    if result.get("status") == "job_started":
        return _format_job_started(result)

    data = result.get("data", {})
    lines = [
        "=" * 45,
        "  BugHound -- Discovery Results",
        "=" * 45,
        "",
    ]

    # Summary table
    lines.append("  | Metric             | Count |")
    lines.append("  |--------------------|-------|")
    lines.append(f"  | Live Hosts         | {data.get('live_hosts', 0):<5} |")
    lines.append(f"  | URLs Discovered    | {data.get('urls_discovered', 0):<5} |")
    lines.append(f"  | JS Files           | {data.get('js_files_found', 0):<5} |")
    params = data.get("parameters_harvested", 0)
    if params:
        lines.append(f"  | Parameters         | {params:<5} |")
    sp = data.get("sensitive_paths_found", 0)
    if sp:
        lines.append(f"  | Sensitive Paths    | {sp:<5} |")
    secrets_count = data.get("secrets_found", 0)
    if secrets_count:
        lines.append(f"  | Secrets Found      | {secrets_count:<5} |")
    hidden = data.get("hidden_endpoints", 0)
    if hidden:
        lines.append(f"  | Hidden Endpoints   | {hidden:<5} |")
    takeover = data.get("takeover_candidates", 0)
    if takeover:
        lines.append(f"  | Takeover Candidates| {takeover:<5} |")
    cors = data.get("cors_vulnerable", 0)
    if cors:
        lines.append(f"  | CORS Misconfig     | {cors:<5} |")
    lines.append("")

    # Technologies
    techs = data.get("top_technologies", [])
    if techs:
        tech_names = [f"{t}" for t, _c in techs[:8]]
        lines.append(f"  Technologies: {', '.join(tech_names)}")

    # Intelligence flags
    flags = data.get("flag_distribution", {})
    if flags:
        flag_parts = [f"{flag} ({count})" for flag, count in flags.items()]
        lines.append(f"  Flags: {', '.join(flag_parts)}")

    if techs or flags:
        lines.append("")

    # Probe results (if available from analyze data embedded in discover)
    probe_data = data.get("probe_results", {})
    if probe_data:
        probe_parts = []
        for vtype, count in probe_data.items():
            if count:
                probe_parts.append(f"{count} {vtype.upper()}")
        if probe_parts:
            lines.append(f"  Probe Results: {', '.join(probe_parts)} confirmed")
            lines.append("")

    # URL sources
    url_sources = data.get("url_sources", {})
    if url_sources:
        lines.append("  URL Sources:")
        for tool_name, count in url_sources.items():
            if count == -1:
                lines.append(f"    * {tool_name}: not installed (skipped)")
            else:
                lines.append(f"    * {tool_name}: {count}")
        lines.append("")

    # Secrets breakdown
    if secrets_count:
        conf = data.get("secrets_by_confidence", {})
        high = conf.get("HIGH", 0)
        med = conf.get("MEDIUM", 0)
        low = conf.get("LOW", 0)
        lines.append(f"  Secrets: {secrets_count} total (HIGH: {high}, MEDIUM: {med}, LOW: {low})")
        stypes = data.get("secret_types", {})
        if stypes:
            for stype, count in stypes.items():
                lines.append(f"    * {stype}: {count}")
        lines.append("")

    # Sensitive path categories
    if sp:
        sp_cats = data.get("sensitive_path_categories", {})
        if sp_cats:
            lines.append(f"  Sensitive Paths ({sp}):")
            for cat, count in sp_cats.items():
                lines.append(f"    * {cat}: {count}")
            lines.append("")

    # Takeover
    takeover_conf = data.get("takeover_confirmed", 0)
    if takeover:
        lines.append(f"  Subdomain Takeover: {takeover} candidates" +
                      (f", {takeover_conf} confirmed" if takeover_conf else ""))
        lines.append("")

    # CORS
    if cors:
        cors_sev = data.get("cors_severities", {})
        if cors_sev:
            sev_parts = [f"{s}: {c}" for s, c in cors_sev.items()]
            lines.append(f"  CORS Misconfig: {cors} hosts ({', '.join(sev_parts)})")
        else:
            lines.append(f"  CORS Misconfig: {cors} hosts")
        lines.append("")

    # CDN
    cdn = data.get("majority_cdn")
    if cdn:
        lines.append(f"  CDN: {cdn}")

    # Warnings
    warnings = result.get("warnings", [])
    if warnings:
        for w in warnings:
            lines.append(f"  [!] {w}")
        lines.append("")

    lines.append(f"  Next: {result.get('next_step', 'Continue to next stage.')}")
    return "\n".join(lines) + "\n"


def _format_job_started(result: dict[str, Any]) -> str:
    """Format async job-started response."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    job_id = result.get('job_id', '?')
    est = result.get('estimated_time', 'a few minutes')
    msg = result.get('message', '')
    hdr = "=" * 45
    return (
        f"{hdr}\n"
        f"  Background Job Started\n"
        f"{hdr}\n\n"
        f"  Job ID:         {job_id}\n"
        f"  Estimated Time: {est}\n"
        f"  Details:        {msg}\n\n"
        f"  The job is running in the background.\n"
        f"  Ask to check status when ready.\n"
    )


def _format_attack_surface(result: dict[str, Any]) -> str:
    """Format attack surface analysis as readable markdown."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    stats = result.get("stats", {})
    target_name = result.get('target', '?')
    target_type = result.get('target_type', '?')

    # Calculate overall score from high-interest targets
    targets = result.get("high_interest_targets", [])
    top_score = targets[0].get("score", 0) if targets else 0
    top_risk = targets[0].get("risk_level", "LOW") if targets else "LOW"

    lines = [
        "=" * 45,
        "  BugHound -- Attack Surface Analysis",
        "=" * 45,
        "",
        f"  Target: {target_name} ({target_type})",
        f"  Score:  {top_score} [{top_risk}]",
        "",
    ]

    # Probe-confirmed vulnerabilities (from high-interest target data)
    probe_sections: list[str] = []
    for t in targets:
        pc = t.get("probe_confirmed", {})
        if pc:
            for vtype, items in pc.items():
                param_count = len(items)
                endpoints = set()
                param_names = []
                for item in items[:5]:
                    if isinstance(item, dict):
                        url = item.get("url", "")
                        # Extract page name from URL
                        page = url.split("/")[-1].split("?")[0] if url else "?"
                        endpoints.add(page)
                        pname = item.get("parameter", item.get("param", ""))
                        if pname:
                            param_names.append(pname)
                    elif isinstance(item, str):
                        endpoints.add(item)
                sev_map = {"sqli": "CRITICAL", "xss": "HIGH", "lfi": "HIGH",
                           "ssti": "HIGH", "rce": "CRITICAL", "ssrf": "HIGH"}
                sev = sev_map.get(vtype.lower(), "MEDIUM")
                ep_str = ", ".join(sorted(endpoints)[:3])
                param_str = f" ({', '.join(param_names[:4])})" if param_names else ""
                probe_sections.append(
                    f"    [{sev}] {vtype.upper()} -- {ep_str}{param_str} [{param_count} params]"
                )

    if probe_sections:
        lines.append("  Probe-Confirmed Vulnerabilities:")
        lines.extend(probe_sections)
        lines.append("")

    # Attack chains
    chains = result.get("attack_chains", [])
    if chains:
        lines.append(f"  Attack Chains ({len(chains)}):")
        lines.append("  " + "-" * 43)
        for c in chains:
            sev = c.get("severity", "?")
            name = c.get("name", "?")
            bounty = c.get("bounty_estimate", "?")
            lines.append(f"    [{sev}] {name} ({bounty})")
        lines.append("")

    # Immediate wins
    wins = result.get("immediate_wins", [])
    if wins:
        lines.append(f"  Immediate Wins ({len(wins)}) -- Report NOW:")
        lines.append("  " + "-" * 43)
        for w in wins:
            sev = w.get("severity", "?")
            wtype = w.get("type", "?")
            host = w.get("host", "?")
            lines.append(f"    [{sev}] {wtype} on {host}")
            path = w.get("path", "")
            if path:
                lines.append(f"      Path: {path}")
            bounty = w.get("bounty_estimate", "")
            if bounty:
                lines.append(f"      Bounty: {bounty}")
        lines.append("")

    # AI Reasoning Prompts (from correlations)
    corrs = result.get("correlations", [])
    if corrs:
        lines.append("  AI Reasoning Prompts:")
        for c in corrs[:5]:
            lines.append(f"    * {c.get('description', '?')}")
        lines.append("")

    # High-interest targets
    if targets:
        lines.append(f"  High-Interest Targets ({len(targets)}):")
        lines.append("  " + "-" * 43)
        for t in targets:
            risk = t.get("risk_level", "?")
            host = t.get("host", "?")
            score = t.get("score", 0)
            lines.append(f"    {host} -- Score: {score} [{risk}]")
            if t.get("technologies"):
                lines.append(f"      Tech: {', '.join(t['technologies'][:5])}")
            if t.get("flags"):
                lines.append(f"      Flags: {', '.join(t['flags'][:5])}")
            if t.get("secrets_on_host"):
                for s in t["secrets_on_host"][:2]:
                    lines.append(f"      Secret: [{s.get('confidence', '?')}] {s.get('type', '?')} in {s.get('file', '?')}")
            if t.get("cors_issue"):
                ci = t["cors_issue"]
                lines.append(f"      CORS: [{ci.get('severity', '?')}] {ci.get('detail', '?')}")
            if t.get("sensitive_paths_found"):
                lines.append(f"      Sensitive: {', '.join(t['sensitive_paths_found'][:5])}")
            params_c = t.get("parameters_count", 0)
            urls_c = t.get("urls_count", 0)
            hidden_c = t.get("hidden_endpoints_count", 0)
            api_c = t.get("api_endpoints_count", 0)
            lines.append(f"      Params: {params_c} | URLs: {urls_c} | Hidden: {hidden_c} | API: {api_c}")
        lines.append("")

    # Technology playbooks
    pbs = result.get("technology_playbooks", [])
    if pbs:
        lines.append("  Technology Playbooks:")
        for pb in pbs:
            lines.append(f"    {pb.get('technology', '?')}:")
            for check in pb.get("checks", [])[:3]:
                if "path" in check:
                    lines.append(f"      * {check['path']} -- {check.get('purpose', '')}")
                elif "test" in check:
                    lines.append(f"      * {check['test']} -- {check.get('purpose', '')}")
                elif "tool" in check:
                    lines.append(f"      * {check['tool']} {check.get('args', '')} -- {check.get('purpose', '')}")
        lines.append("")

    # Suggested test classes
    tc = result.get("suggested_test_classes", [])
    if tc:
        lines.append(f"  Test Classes: {', '.join(tc)}")
        lines.append("")

    # Flags summary
    flags_sum = result.get("flags_summary", {})
    if flags_sum:
        flag_parts = [f"{flag} ({count})" for flag, count in flags_sum.items()]
        lines.append(f"  Flags: {', '.join(flag_parts)}")
        lines.append("")

    lines.append(f"  Next: {result.get('next_step', 'Continue to next stage.')}")
    return "\n".join(lines) + "\n"


def _format_scan_plan_result(result: dict[str, Any]) -> str:
    """Format scan plan submission result."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    if result.get("status") == "rejected":
        lines = [
            "=" * 45,
            "  Scan Plan REJECTED",
            "=" * 45,
            "",
            f"  {result.get('message', '')}",
            "",
            "  Reasons:",
        ]
        for r in result.get("rejected_reasons", []):
            lines.append(f"    * {r}")
        lines.append("")
        lines.append("  Fix the issues and resubmit.")
        return "\n".join(lines) + "\n"

    # Approved
    targets_count = result.get("targets_count", 0)
    test_classes_total = result.get("test_classes_total", 0)
    tools_avail = result.get("tools_available", [])
    tools_missing = result.get("tools_missing", [])

    lines = [
        "=" * 45,
        "  Scan Plan Approved",
        "=" * 45,
        "",
        f"  Targets: {targets_count}  |  Test Classes: {test_classes_total}",
        "",
    ]

    # Show test classes grouped
    test_classes = result.get("test_classes_list", [])
    if test_classes:
        injection = [c for c in test_classes if c in ("sqli", "xss", "ssrf", "lfi", "ssti", "csti", "crlf", "rce", "open_redirect")]
        auth_access = [c for c in test_classes if c in ("idor", "bac", "jwt", "rate_limiting", "cors", "mass_assignment")]
        infra = [c for c in test_classes if c in ("misconfig", "default_creds", "header_injection", "graphql", "wordpress", "spring")]
        other = [c for c in test_classes if c not in injection + auth_access + infra]

        if injection:
            lines.append(f"  Injection:    {', '.join(injection)}")
        if auth_access:
            lines.append(f"  Auth/Access:  {', '.join(auth_access)}")
        if infra:
            lines.append(f"  Infra:        {', '.join(infra)}")
        if other:
            lines.append(f"  Other:        {', '.join(other)}")
        lines.append("")

    # Tools status
    if tools_avail or tools_missing:
        avail_str = ", ".join(f"{t} [ok]" for t in tools_avail)
        missing_str = ", ".join(f"{t} [missing]" for t in tools_missing)
        parts = [p for p in [avail_str, missing_str] if p]
        lines.append(f"  Tools: {', '.join(parts)}")
        lines.append("")

    lines.append(f"  Next: {result.get('next_step', 'Submit scan plan and execute tests.')}")
    return "\n".join(lines) + "\n"


def _format_enrich_target(result: dict[str, Any]) -> str:
    """Format target enrichment dossier."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    fp = result.get("fingerprint", {})
    host = result.get("host", "?")
    score = result.get("score", 0)
    risk = result.get("risk_level", "?")

    lines = [
        "=" * 45,
        f"  Target Dossier: {host}",
        "=" * 45,
        "",
        f"  Score: {score} [{risk}]",
        "",
        "  Fingerprint:",
        f"    URL:    {fp.get('url', '?')}",
        f"    Status: {fp.get('status_code', '?')}",
        f"    Title:  {fp.get('title', '?')}",
        f"    Server: {fp.get('web_server', '?')}",
        f"    IP:     {fp.get('ip', '?')}",
        f"    CDN:    {fp.get('cdn') or 'None'}",
        "",
    ]

    if result.get("flags"):
        lines.append(f"  Flags: {', '.join(result['flags'])}")
        lines.append("")

    if result.get("technologies"):
        lines.append(f"  Technologies: {', '.join(result['technologies'])}")
        lines.append("")

    waf = result.get("waf")
    if waf:
        waf_status = "detected" if waf.get("detected") else "not detected"
        lines.append(f"  WAF: {waf.get('waf', 'None')} ({waf_status})")
        lines.append("")

    if result.get("reasons"):
        lines.append("  Risk Factors:")
        for r in result["reasons"]:
            lines.append(f"    * {r}")
        lines.append("")

    if result.get("secrets"):
        lines.append(f"  Secrets ({len(result['secrets'])}):")
        for s in result["secrets"][:10]:
            lines.append(f"    * [{s.get('confidence', '?')}] {s.get('type', '?')}: {s.get('value', '?')}")
        lines.append("")

    if result.get("sensitive_paths"):
        lines.append(f"  Sensitive Paths ({len(result['sensitive_paths'])}):")
        for sp_item in result["sensitive_paths"][:10]:
            lines.append(f"    * [{sp_item.get('category', '?')}] {sp_item.get('path', '?')} (status {sp_item.get('status_code', '?')})")
        lines.append("")

    if result.get("cors_results"):
        lines.append(f"  CORS Issues ({len(result['cors_results'])}):")
        for c in result["cors_results"]:
            lines.append(f"    * [{c.get('severity', '?')}] origin {c.get('origin_tested', '?')} reflected")
        lines.append("")

    if result.get("hidden_endpoints"):
        lines.append(f"  Hidden Endpoints ({len(result['hidden_endpoints'])}):")
        for ep in result["hidden_endpoints"][:15]:
            lines.append(f"    * {ep.get('method', 'GET')} {ep.get('path', '?')}")
        if len(result["hidden_endpoints"]) > 15:
            lines.append(f"    ... and {len(result['hidden_endpoints']) - 15} more")
        lines.append("")

    if result.get("api_endpoints"):
        lines.append(f"  API Endpoints ({len(result['api_endpoints'])}):")
        for ep in result["api_endpoints"][:15]:
            lines.append(f"    * {ep.get('method', 'GET')} {ep.get('path', '?')}")
        if len(result["api_endpoints"]) > 15:
            lines.append(f"    ... and {len(result['api_endpoints']) - 15} more")
        lines.append("")

    if result.get("parameters"):
        lines.append(f"  Parameters ({len(result['parameters'])} paths):")
        for p in result["parameters"][:10]:
            param_names = [pr.get("name", "?") for pr in p.get("params", [])]
            lines.append(f"    * {p.get('path', '?')}: {', '.join(param_names)}")
        lines.append("")

    urls_total = result.get("urls_total", 0)
    if urls_total:
        shown = result.get("urls", [])[:20]
        lines.append(f"  URLs: {urls_total} total (showing {len(shown)}):")
        for u in shown:
            lines.append(f"    * {u}")
        lines.append("")

    if result.get("attack_chains"):
        lines.append("  Attack Chains:")
        for c in result["attack_chains"]:
            lines.append(f"    * [{c.get('severity', '?')}] {c.get('name', '?')} (est. {c.get('bounty_estimate', '?')})")
        lines.append("")

    if result.get("dns_records"):
        lines.append("  DNS Records:")
        for rec in result["dns_records"][:5]:
            lines.append(f"    * {json.dumps(rec)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def _format_test_results(result: dict[str, Any]) -> str:
    """Format test execution results as readable text."""
    if result.get("status") == "error":
        return f"Error [{result.get('error_type', '?')}]: {result['message']}"

    targets_tested = result.get("targets_tested", 0)
    findings_total = result.get("findings_total", 0)
    definitive = result.get("findings_definitive", 0)
    needs_val = result.get("findings_needing_validation", 0)

    lines = [
        "=" * 45,
        "  BugHound -- Test Results",
        "=" * 45,
        "",
        f"  Targets: {targets_tested}  |  Findings: {findings_total} unique",
    ]
    if definitive is not None and needs_val is not None:
        lines.append(f"  Definitive: {definitive}  |  Needs Validation: {needs_val}")
    lines.append("")

    # Severity breakdown
    sev = result.get("findings_by_severity", {})
    if any(sev.values()):
        lines.append("  Severity Breakdown:")
        for level in ("critical", "high", "medium", "low", "info"):
            count = sev.get(level, 0)
            if count:
                lines.append(f"    {level.upper():<10} {count}")
        lines.append("")

    # By vuln class with tool info
    by_class = result.get("findings_by_class", {})
    if by_class:
        lines.append("  | Class      | Count |")
        lines.append("  |------------|-------|")
        for cls, count in sorted(by_class.items(), key=lambda x: -x[1]):
            lines.append(f"  | {cls:<10} | {count:<5} |")
        lines.append("")

    # Findings list - grouped by severity
    findings = result.get("findings", [])
    if findings:
        lines.append("  Findings:")
        lines.append("  " + "-" * 43)
        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "info"), 5))

        for i, f in enumerate(sorted_findings[:15], 1):
            s = f.get("severity", "info").upper()
            desc = f.get("description", f.get("template_name", f.get("template_id", "?")))
            val_status = "[CONFIRMED]" if not f.get("needs_validation") else "[PENDING]"
            endpoint = f.get("endpoint", f.get("host", "?"))
            tool = f.get("tool", "?")

            # Instance count
            instances = f.get("instances_count", f.get("instances", 1))
            inst_str = f" ({instances} instances)" if isinstance(instances, int) and instances > 1 else ""

            lines.append(f"  {i:>2}. [{s}] {desc} {val_status}")
            lines.append(f"      {endpoint}{inst_str}  |  {tool}")
            lines.append("")

        if len(findings) > 15:
            lines.append(f"  ... and {len(findings) - 15} more findings.")
            lines.append("")

    # Warnings
    warnings = result.get("warnings", [])
    if warnings:
        lines.append("  Warnings:")
        for w in warnings[:10]:
            lines.append(f"    [!] {w}")
        lines.append("")

    lines.append(f"  Next: {result.get('next_step', 'Run validation or generate report.')}")
    return "\n".join(lines) + "\n"


def _format_pipeline_result(result: dict[str, Any]) -> str:
    """Format pipeline execution result."""
    if result.get("status") == "error":
        return f"Error [{result.get('error_type', '?')}]: {result['message']}"

    pipeline_name = result.get("pipeline_name", "?")
    input_urls = result.get("input_urls", 0)
    candidates_found = result.get("candidates_found", 0)
    exec_time = result.get("execution_time_seconds", 0)

    lines = [
        "=" * 45,
        f"  Pipeline: {pipeline_name}",
        "=" * 45,
        "",
        f"  {result.get('description', '')}",
        f"  Steps: {result.get('steps', '?')}",
        "",
        f"  Input URLs: {input_urls}  |  Candidates: {candidates_found}  |  Time: {exec_time}s",
        "",
    ]

    tools = result.get("tools_used", {})
    if tools:
        tool_parts = [f"{t} ({status})" for t, status in tools.items()]
        lines.append(f"  Tools: {', '.join(tool_parts)}")
        lines.append("")

    candidates = result.get("candidates", [])
    if candidates:
        lines.append("  Candidates:")
        lines.append("  " + "-" * 43)
        for c in candidates[:20]:
            if isinstance(c, dict):
                url = c.get("url", c.get("path", c.get("param", "?")))
                ctype = c.get("type", "candidate")
                lines.append(f"    * {url} [{ctype}]")
            else:
                lines.append(f"    * {c}")

        if len(candidates) > 20:
            lines.append(f"    ... and {len(candidates) - 20} more")
        lines.append("")

    lines.append(f"  Next: {result.get('next_step', 'Continue.')}")
    return "\n".join(lines) + "\n"


def _format_validation_result(result: dict[str, Any]) -> str:
    """Format single finding validation result."""
    if result.get("status") == "error":
        return f"Error [{result.get('error_type', '?')}]: {result['message']}"

    if result.get("status") == "already_validated":
        return (
            f"Finding {result['finding_id']} already {result['validation_status']}. "
            "No re-validation needed."
        )

    val_status = result.get("validation_status", "?")
    finding_id = result.get("finding_id", "?")
    val_tool = result.get("validation_tool", "?")
    val_time = result.get("validation_time_seconds", 0)

    lines = [
        "=" * 45,
        "  BugHound -- Validation Result",
        "=" * 45,
        "",
        f"  Finding: {finding_id}",
        f"  Status:  [{val_status}]",
        f"  Tool:    {val_tool}",
        f"  Time:    {val_time}s",
    ]

    cvss = result.get("cvss_score")
    if cvss:
        lines.append(f"  CVSS:    {cvss}")
    lines.append("")

    evidence = result.get("evidence_summary", "")
    if evidence:
        lines.append("  Evidence:")
        lines.append("  " + "-" * 43)
        for eline in evidence[:500].split("\n")[:10]:
            lines.append(f"    {eline}")
        lines.append("")

    curl = result.get("curl_command", "")
    if curl:
        lines.append(f"  Curl: {curl[:200]}")
        lines.append("")

    finding = result.get("finding", {})
    steps = finding.get("reproduction_steps", [])
    if steps:
        lines.append("  Reproduction Steps:")
        for step in steps:
            lines.append(f"    {step}")
        lines.append("")

    impact = finding.get("impact", "")
    if impact:
        lines.append(f"  Impact: {impact}")

    assessment = finding.get("severity_assessment", "")
    if assessment:
        lines.append(f"  Assessment: {assessment}")

    lines.append(f"\n  Next: {result.get('next_step', 'Continue.')}")
    return "\n".join(lines) + "\n"


def _format_validate_all_result(result: dict[str, Any]) -> str:
    """Format batch validation results."""
    if result.get("status") == "error":
        return f"Error [{result.get('error_type', '?')}]: {result['message']}"

    if result.get("status") == "nothing_to_validate":
        return (
            f"Nothing to validate. {result.get('total_findings', 0)} total findings, "
            f"{result.get('already_validated', 0)} already validated."
        )

    total_validated = result.get("total_validated", 0)
    val_time = result.get("validation_time_seconds", 0)
    confirmed = result.get("confirmed", 0)
    fp = result.get("false_positives", 0)
    manual = result.get("needs_manual_review", 0)
    errors = result.get("errors", 0)

    lines = [
        "=" * 45,
        "  BugHound -- Validation Results",
        "=" * 45,
        "",
        f"  Validated: {total_validated} findings in {val_time}s",
        "",
        "  | Status           | Count |",
        "  |------------------|-------|",
        f"  | [CONFIRMED]      | {confirmed:<5} |",
        f"  | [FALSE POSITIVE] | {fp:<5} |",
        f"  | [MANUAL REVIEW]  | {manual:<5} |",
    ]
    if errors:
        lines.append(f"  | [ERRORS]         | {errors:<5} |")
    lines.append("")

    # Show individual results
    results_list = result.get("results", [])
    if results_list:
        # Show confirmed first
        confirmed_items = [r for r in results_list if r.get("validation_status") == "CONFIRMED"]
        if confirmed_items:
            lines.append("  Confirmed:")
            lines.append("  " + "-" * 43)
            for i, r in enumerate(confirmed_items[:15], 1):
                sev = r.get("severity", "?").upper()
                fid = r.get("finding_id", "?")
                vclass = r.get("vulnerability_class", "?")
                validator = r.get("validator", "?")
                lines.append(f"  {i:>2}. [{sev}] {vclass} in {fid} -- {validator} confirmed")
            if len(confirmed_items) > 15:
                lines.append(f"      ... and {len(confirmed_items) - 15} more")
            lines.append("")

        # Show manual review
        manual_items = [r for r in results_list if r.get("validation_status") == "NEEDS_MANUAL_REVIEW"]
        if manual_items:
            lines.append(f"  Manual Review ({len(manual_items)}):")
            for r in manual_items[:10]:
                lines.append(
                    f"    * {r.get('finding_id', '?')} ({r.get('vulnerability_class', '?')})"
                )
            if len(manual_items) > 10:
                lines.append(f"      ... and {len(manual_items) - 10} more")
            lines.append("")

    lines.append(f"  Next: {result.get('next_step', 'Generate report with bughound_generate_report.')}")
    return "\n".join(lines) + "\n"


def _format_immediate_wins_result(result: dict[str, Any]) -> str:
    """Format immediate wins validation results."""
    if result.get("status") == "error":
        return f"Error [{result.get('error_type', '?')}]: {result['message']}"

    if result.get("status") == "no_immediate_wins":
        return result.get("message", "No immediate wins found.")

    total_checked = result.get("total_checked", 0)
    confirmed_count = result.get("confirmed", 0)
    val_time = result.get("validation_time_seconds", 0)

    lines = [
        "=" * 45,
        "  BugHound -- Immediate Wins Verification",
        "=" * 45,
        "",
        f"  Checked: {total_checked}  |  Confirmed: {confirmed_count}  |  Time: {val_time}s",
        "",
    ]

    results_list = result.get("results", [])
    confirmed_items = [r for r in results_list if r.get("status") == "CONFIRMED"]
    other_items = [r for r in results_list if r.get("status") != "CONFIRMED"]

    if confirmed_items:
        lines.append("  Confirmed Wins:")
        lines.append("  " + "-" * 43)
        for i, r in enumerate(confirmed_items, 1):
            win_type = r.get("type", "?")
            host = r.get("host", "?")
            url = r.get("url", "")
            cvss = r.get("cvss_score", "")
            impact = r.get("impact", "")
            lines.append(f"  {i:>2}. {win_type} on {host}")
            if url:
                lines.append(f"      URL: {url}")
            if cvss:
                lines.append(f"      CVSS: {cvss}")
            if impact:
                lines.append(f"      Impact: {impact}")
            curl = r.get("curl_command", "")
            if curl:
                lines.append(f"      Curl: {curl[:120]}")
            lines.append("")

    if other_items:
        lines.append(f"  Not Confirmed ({len(other_items)}):")
        for r in other_items[:5]:
            status = r.get("status", "?")
            reason = r.get("reason", "")
            lines.append(f"    * {r.get('type', '?')} ({r.get('host', '?')}): {status}")
            if reason:
                lines.append(f"      Reason: {reason}")
        if len(other_items) > 5:
            lines.append(f"      ... and {len(other_items) - 5} more")
        lines.append("")

    lines.append(f"  Next: {result.get('next_step', 'Continue.')}")
    return "\n".join(lines) + "\n"


def _format_report_result(result: dict[str, Any]) -> str:
    """Format report generation result."""
    if result.get("status") == "error":
        return f"Error [{result.get('error_type', '?')}]: {result['message']}"

    hdr = "=" * 45
    lines = [hdr, "  BugHound -- Report Generated", hdr, ""]

    for report_type, path in result.get("reports", {}).items():
        lines.append(f"  {report_type}: {path}")

    lines.append("")
    lines.append(f"  Findings: {result.get('total_findings', 0)}")
    lines.append(f"  Confirmed: {result.get('confirmed', 0)}")
    lines.append(f"  Target: {result.get('target', '?')}")

    by_sev = result.get("by_severity", {})
    if by_sev:
        sev_parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = by_sev.get(sev, 0)
            if count:
                sev_parts.append(f"{sev.title()}: {count}")
        if sev_parts:
            lines.append(f"  Severity: {', '.join(sev_parts)}")

    lines.append("")
    lines.append(f"  Next: {result.get('next_step', 'Done.')}")

    return "\n".join(lines) + "\n"


def _suggest_next(stages: list[int]) -> str:
    """Suggest the next tool to call based on stages_to_run."""
    if 1 in stages:
        return "Call `bughound_enumerate` to discover subdomains."
    if 2 in stages:
        return "Call `bughound_discover` to probe and discover the attack surface."
    if 3 in stages:
        return "Call `bughound_get_attack_surface` to analyze the attack surface."
    if 4 in stages:
        return "Call `bughound_execute_tests` to run the scan plan."
    return "Call the next stage tool in the pipeline."


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the BugHound MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
