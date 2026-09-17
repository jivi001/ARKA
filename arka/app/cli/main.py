import sys
from typing import Any

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console()
app = typer.Typer(name="arka", help="ARKA — Autonomous Risk Knowledge & Assessment")

# Default API base URL
DEFAULT_API_URL = "http://localhost:8000"


def get_api_url() -> str:
    import os

    return os.environ.get("ARKA_API_URL", DEFAULT_API_URL)


def api_get(path: str, silent: bool = False) -> dict:
    """Make a GET request to the ARKA API."""
    url = f"{get_api_url()}{path}"
    try:
        response = httpx.get(url, timeout=30.0)
        response.raise_for_status()
        return response.json()
    except httpx.ConnectError:
        if not silent:
            console.print("[red]Error: Cannot connect to ARKA API.[/red]")
            console.print(f"Make sure the server is running at {get_api_url()}")
        raise typer.Exit(1) from None
    except httpx.HTTPStatusError as e:
        data = (
            e.response.json()
            if e.response.headers.get("content-type", "").startswith("application/json")
            else {}
        )
        console.print(
            f"[red]API Error ({e.response.status_code}): {data.get('error', str(e))}[/red]"
        )
        if data.get("detail"):
            console.print(f"  {data['detail']}")
        raise typer.Exit(1) from e


def api_post(path: str, data: dict | None = None) -> dict:
    """Make a POST request to the ARKA API."""
    url = f"{get_api_url()}{path}"
    try:
        response = httpx.post(url, json=data or {}, timeout=30.0)
        response.raise_for_status()
        return response.json()
    except httpx.ConnectError:
        console.print("[red]Error: Cannot connect to ARKA API.[/red]")
        console.print(f"Make sure the server is running at {get_api_url()}")
        raise typer.Exit(1) from None
    except httpx.HTTPStatusError as e:
        data_resp = (
            e.response.json()
            if e.response.headers.get("content-type", "").startswith("application/json")
            else {}
        )
        console.print(
            f"[red]API Error ({e.response.status_code}): {data_resp.get('error', str(e))}[/red]"
        )
        if data_resp.get("detail"):
            console.print(f"  {data_resp['detail']}")
        raise typer.Exit(1) from e


@app.command()
def init() -> None:
    """Initialize ARKA configuration."""
    console.print(
        Panel.fit(
            "[bold blue]ARKA[/bold blue] — Autonomous Risk Knowledge & Assessment",
            subtitle="Phase 1 Foundation",
        )
    )
    console.print("\nTo start the ARKA server:")
    console.print("  [cyan]uvicorn arka.app.api:app --reload[/cyan]")
    console.print("\nConfigure your .env file from .env.example")


@app.command()
def health() -> None:
    """Check ARKA API health."""
    result = api_get("/health")
    status = result.get("status", "unknown")
    if status == "healthy":
        console.print("[green][OK] ARKA is healthy[/green]")
    else:
        console.print(f"[red][X] ARKA status: {status}[/red]")


# Provider commands
provider_app = typer.Typer(name="provider", help="Manage LLM providers")
app.add_typer(provider_app)


@provider_app.command("list")
def provider_list() -> None:
    """List configured LLM providers."""
    providers = api_get("/providers")
    table = Table(title="LLM Providers")
    table.add_column("Name", style="cyan")
    table.add_column("Model", style="green")
    table.add_column("Role", style="yellow")
    table.add_column("Configured", style="bold")
    for p in providers:
        configured = "[OK]" if p["configured"] else "[X]"
        style = "green" if p["configured"] else "red"
        table.add_row(p["name"], p["model"], p["role"], f"[{style}]{configured}[/{style}]")
    console.print(table)


@provider_app.command("test")
def provider_test(prompt: str = "Say 'ARKA is operational'") -> None:
    """Test LLM provider connectivity."""
    with console.status("Testing LLM provider..."):
        result = api_post("/llm/test", {"prompt": prompt})
    if result.get("status") == "success":
        console.print("[green][OK] LLM test successful[/green]")
        console.print(f"  Provider: {result['provider']}")
        console.print(f"  Model: {result['model']}")
        console.print(f"  Response: {result['response']}")
        console.print(f"  Latency: {result['latency_ms']}ms")
        console.print(f"  Tokens: {result['tokens_used']}")
    else:
        console.print(f"[red][X] LLM test failed: {result.get('error', 'Unknown error')}[/red]")


# Engagement commands
engagement_app = typer.Typer(name="engagement", help="Manage engagements")
app.add_typer(engagement_app)


@engagement_app.command("create")
def engagement_create(
    name: str = typer.Argument(..., help="Engagement name"),
    objective: str = typer.Option("", help="Engagement objective"),
    description: str = typer.Option("", help="Description"),
) -> None:
    """Create a new engagement."""
    result = api_post(
        "/engagements",
        {
            "name": name,
            "objective": objective,
            "description": description,
        },
    )
    console.print("[green][OK] Engagement created[/green]")
    console.print(f"  ID: {result['engagement_id']}")
    console.print(f"  Name: {result['name']}")
    console.print(f"  Status: {result['status']}")


@engagement_app.command("start")
def engagement_start(engagement_id: str = typer.Argument(..., help="Engagement ID")) -> None:
    """Start an engagement."""
    result = api_post(f"/engagements/{engagement_id}/start")
    console.print("[green][OK] Engagement started[/green]")
    console.print(f"  Status: {result['status']}")


def _render_scope_table(scope_data: dict) -> Table:
    table = Table(title=f"Scope Definition (v{scope_data.get('version', 1)})")
    table.add_column("Boundary", style="cyan", width=12)
    table.add_column("Type", style="yellow", width=16)
    table.add_column("Configured Targets", style="white")

    inc = scope_data.get("includes", {})
    exc = scope_data.get("excludes", {})

    has_entries = False
    if inc.get("domains"):
        sub = (
            " (subdomains allowed)"
            if inc.get("subdomains_allowed", True)
            else " (exact domain only)"
        )
        table.add_row("Included", "Domains", ", ".join(inc["domains"]) + sub)
        has_entries = True
    if inc.get("ip_addresses"):
        table.add_row("Included", "IP Addresses", ", ".join(inc["ip_addresses"]))
        has_entries = True
    if inc.get("cidrs"):
        table.add_row("Included", "CIDRs", ", ".join(inc["cidrs"]))
        has_entries = True
    if inc.get("urls"):
        table.add_row("Included", "URLs", ", ".join(inc["urls"]))
        has_entries = True
    if inc.get("ports"):
        table.add_row("Included", "Ports", ", ".join(str(p) for p in inc["ports"]))
        has_entries = True
    if inc.get("port_ranges"):
        table.add_row("Included", "Port Ranges", ", ".join(inc["port_ranges"]))
        has_entries = True

    if exc.get("domains"):
        table.add_row("[red]Excluded[/red]", "Domains", ", ".join(exc["domains"]))
        has_entries = True
    if exc.get("ip_addresses"):
        table.add_row("[red]Excluded[/red]", "IP Addresses", ", ".join(exc["ip_addresses"]))
        has_entries = True
    if exc.get("cidrs"):
        table.add_row("[red]Excluded[/red]", "CIDRs", ", ".join(exc["cidrs"]))
        has_entries = True
    if exc.get("urls"):
        table.add_row("[red]Excluded[/red]", "URLs", ", ".join(exc["urls"]))
        has_entries = True
    if exc.get("ports"):
        table.add_row("[red]Excluded[/red]", "Ports", ", ".join(str(p) for p in exc["ports"]))
        has_entries = True

    if scope_data.get("notes"):
        table.add_row("Info", "Notes", scope_data["notes"])

    if not has_entries:
        table.add_row("Included", "[dim]Targets[/dim]", "[dim]No targets configured[/dim]")

    return table


@engagement_app.command("status")
def engagement_status(engagement_id: str = typer.Argument(..., help="Engagement ID")) -> None:
    """Get engagement status and active scope configuration."""
    result = api_get(f"/engagements/{engagement_id}")
    table = Table(title=f"Engagement: {result['name']}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("ID", result["engagement_id"])
    table.add_row("Status", result["status"])
    table.add_row("Objective", result.get("objective", ""))
    table.add_row("Created", result["created_at"])
    table.add_row("Started", result.get("started_at", "N/A"))

    scope = result.get("scope")
    if scope:
        table.add_row("Scope", f"[green]Configured (v{scope.get('version', 1)})[/green]")
    else:
        table.add_row(
            "Scope", "[red]Not configured (Run 'arka engagement scope <ID>' to set)[/red]"
        )

    console.print(table)
    if scope:
        console.print(_render_scope_table(scope))


@engagement_app.command("scope")
def engagement_scope(
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    target: list[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="Target specification (e.g. 127.0.0.1:3000, http://127.0.0.1:3000, example.com)",
    ),
    ip: list[str] = typer.Option(None, "--ip", help="Authorized IP address"),
    domain: list[str] = typer.Option(None, "--domain", help="Authorized domain"),
    cidr: list[str] = typer.Option(None, "--cidr", help="Authorized CIDR network range"),
    url: list[str] = typer.Option(None, "--url", help="Authorized URL target"),
    port: list[int] = typer.Option(None, "--port", "-p", help="Authorized port number (1-65535)"),
    port_range: list[str] = typer.Option(
        None, "--port-range", help="Authorized port range (e.g. 80-443)"
    ),
    no_subdomains: bool = typer.Option(
        False, "--no-subdomains", help="Disallow subdomains for authorized domains"
    ),
    exclude_ip: list[str] = typer.Option(None, "--exclude-ip", help="Excluded IP address"),
    exclude_domain: list[str] = typer.Option(None, "--exclude-domain", help="Excluded domain"),
    exclude_cidr: list[str] = typer.Option(None, "--exclude-cidr", help="Excluded CIDR range"),
    exclude_url: list[str] = typer.Option(None, "--exclude-url", help="Excluded URL target"),
    notes: str = typer.Option("", "--notes", help="Scope definition notes"),
    expected_version: int | None = typer.Option(
        None, "--expected-version", help="Expected version for optimistic concurrency control"
    ),
    show: bool = typer.Option(False, "--show", "-s", help="Display current scope definition"),
) -> None:
    """Define or inspect the authoritative scope for an engagement.

    SEMANTICS: create-or-replace (not merge).
    """
    has_mutation_flags = any(
        [
            target,
            ip,
            domain,
            cidr,
            url,
            port,
            port_range,
            exclude_ip,
            exclude_domain,
            exclude_cidr,
            exclude_url,
        ]
    )

    if show or not has_mutation_flags:
        scope_data = api_get(f"/engagements/{engagement_id}/scope")
        console.print(_render_scope_table(scope_data))
        return

    # Parse and sort user inputs
    target_ips = list(ip or [])
    target_domains = list(domain or [])
    target_cidrs = list(cidr or [])
    target_urls = list(url or [])
    target_ports = list(port or [])
    target_port_ranges = list(port_range or [])

    if target:
        for t in target:
            t_clean = t.strip()
            if t_clean.startswith(("http://", "https://")):
                target_urls.append(t_clean)
            elif "/" in t_clean:
                target_cidrs.append(t_clean)
            elif ":" in t_clean and not t_clean.startswith("["):
                parts = t_clean.split(":")
                if len(parts) == 2 and parts[1].isdigit():
                    host_part = parts[0]
                    target_ports.append(int(parts[1]))
                    try:
                        import ipaddress

                        ipaddress.ip_address(host_part)
                        target_ips.append(host_part)
                    except ValueError:
                        target_domains.append(host_part)
                else:
                    target_domains.append(t_clean)
            else:
                try:
                    import ipaddress

                    ipaddress.ip_address(t_clean)
                    target_ips.append(t_clean)
                except ValueError:
                    target_domains.append(t_clean)

    payload: dict[str, Any] = {
        "includes": {
            "domains": target_domains,
            "subdomains_allowed": not no_subdomains,
            "ip_addresses": target_ips,
            "cidrs": target_cidrs,
            "urls": target_urls,
            "ports": target_ports,
            "port_ranges": target_port_ranges,
        },
        "excludes": {
            "domains": list(exclude_domain or []),
            "subdomains_allowed": True,
            "ip_addresses": list(exclude_ip or []),
            "cidrs": list(exclude_cidr or []),
            "urls": list(exclude_url or []),
            "ports": [],
            "port_ranges": [],
        },
        "notes": notes,
    }
    if expected_version is not None:
        payload["expected_version"] = expected_version

    result = api_post(f"/engagements/{engagement_id}/scope", payload)
    console.print(f"[green][OK] Scope established (version {result.get('version', 1)})[/green]")
    console.print(_render_scope_table(result))


@engagement_app.command("pause")
def engagement_pause(engagement_id: str = typer.Argument(..., help="Engagement ID")) -> None:
    """Pause an engagement."""
    result = api_post(f"/engagements/{engagement_id}/pause")
    console.print("[yellow][PAUSED] Engagement paused[/yellow]")
    console.print(f"  Status: {result['status']}")


@engagement_app.command("stop")
def engagement_stop(engagement_id: str = typer.Argument(..., help="Engagement ID")) -> None:
    """Stop an engagement."""
    result = api_post(f"/engagements/{engagement_id}/stop")
    console.print("[red][STOPPED] Engagement stopped[/red]")
    console.print(f"  Status: {result['status']}")


# Tasks command
@app.command("tasks")
def tasks(engagement_id: str = typer.Argument(..., help="Engagement ID")) -> None:
    """List tasks for an engagement."""
    result = api_get(f"/engagements/{engagement_id}/tasks")
    if not result.get("tasks"):
        console.print("[dim]No tasks found for this engagement.[/dim]")
        return
    table = Table(title="Tasks")
    table.add_column("Task ID", style="cyan")
    table.add_column("Type")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Created", style="dim")
    for task in result["tasks"]:
        status_val = task.get("status", "")
        status_color = (
            "green"
            if status_val == "completed"
            else "yellow"
            if status_val == "running"
            else "red"
            if status_val == "failed"
            else "white"
        )
        table.add_row(
            task.get("task_id", ""),
            task.get("task_type", ""),
            task.get("name", ""),
            f"[{status_color}]{status_val}[/{status_color}]",
            task.get("created_at", "")[:19] if task.get("created_at") else "",
        )
    console.print(table)


# Audit command
@app.command("audit")
def audit(
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    limit: int = typer.Option(20, help="Max events"),
) -> None:
    """View audit trail for an engagement."""
    result = api_get(f"/engagements/{engagement_id}/audit?limit={limit}")
    events = result.get("events", [])
    if not events:
        console.print("[dim]No audit events found.[/dim]")
        return
    table = Table(title=f"Audit Trail ({len(events)} events)")
    table.add_column("Time", style="dim")
    table.add_column("Type", style="cyan")
    table.add_column("Actor")
    table.add_column("Action")
    table.add_column("Status")
    for event in events:
        table.add_row(
            event.get("timestamp", "")[:19],
            event.get("event_type", ""),
            event.get("actor", ""),
            event.get("action", ""),
            event.get("result_status", ""),
        )
    console.print(table)


# Recon commands
recon_app = typer.Typer(name="recon", help="Autonomous reconnaissance operations")
app.add_typer(recon_app)


@recon_app.command("run")
def recon_run(
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    objective: str = typer.Option("Autonomous reconnaissance", help="Recon objective"),
    max_iterations: int = typer.Option(10, help="Max iterations"),
) -> None:
    """Run autonomous reconnaissance on an authorized engagement."""
    with console.status("Starting reconnaissance..."):
        result = api_post(
            f"/engagements/{engagement_id}/recon",
            {"objective": objective, "max_iterations": max_iterations},
        )
    console.print("[green][OK] Reconnaissance initiated[/green]")
    if result.get("task_id"):
        console.print(f"  Task ID: {result.get('task_id')}")
    console.print(f"  Engagement: {result.get('engagement_id')}")
    console.print(f"  Status: {result.get('status')}")
    console.print(f"  Objective: {result.get('objective')}")


# LLM commands
llm_app = typer.Typer(name="llm", help="Universal LLM provider subsystem management")
app.add_typer(llm_app)


@llm_app.command("providers")
def llm_providers() -> None:
    """List supported LLM providers and their configuration status."""
    providers: list[dict[str, Any]] = []
    try:
        data = api_get("/llm/providers", silent=True)
        if isinstance(data, list):
            providers = [p for p in data if isinstance(p, dict)]
    except (typer.Exit, Exception):
        # Fall back to local registry and settings
        from arka.app.core.config import get_settings
        from arka.app.llm.providers.registry import ProviderRegistry

        settings = get_settings()
        supported = ProviderRegistry.list_supported()
        active_provider = ProviderRegistry.normalize_provider_name(settings.arka_llm_provider.value)
        providers = []
        for name in supported:
            key = settings.get_effective_llm_api_key(name)
            is_configured = bool(key and key.get_secret_value())
            role = "primary" if name == active_provider else "available"
            status = (
                "ACTIVE"
                if (name == active_provider and is_configured)
                else ("CONFIGURED" if is_configured else "SUPPORTED")
            )
            providers.append(
                {
                    "name": name,
                    "role": role,
                    "status": status,
                    "configured": is_configured,
                    "model": settings.arka_llm_model if name == active_provider else "",
                }
            )

    table = Table(title="Supported LLM Providers")
    table.add_column("Provider", style="cyan bold")
    table.add_column("Status")
    table.add_column("Role")
    table.add_column("Configured Model")
    for p in providers:
        status_val = str(p.get("status", "SUPPORTED"))
        if status_val in ("ACTIVE", "AVAILABLE"):
            styled_status = f"[green bold]{status_val}[/green bold]"
        elif status_val == "CONFIGURED":
            styled_status = f"[yellow]{status_val}[/yellow]"
        else:
            styled_status = f"[dim]{status_val}[/dim]"

        table.add_row(
            str(p.get("name", "")).capitalize(),
            styled_status,
            str(p.get("role", "available")),
            str(p.get("model", "-") or "-"),
        )
    console.print(table)


@llm_app.command("config")
def llm_config() -> None:
    """Display active LLM provider configuration without credentials."""
    from arka.app.core.config import get_settings

    settings = get_settings()
    profile = settings.get_primary_llm_profile()

    table = Table(title="Active LLM Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="bold")
    table.add_row("Primary Provider", profile.provider.capitalize())
    table.add_row("Primary Model", profile.model)
    table.add_row("Endpoint (Base URL)", profile.base_url or "(default)")
    table.add_row("Timeout (s)", str(profile.timeout))
    table.add_row("Max Retries", str(profile.max_retries))
    has_key = bool(profile.api_key.get_secret_value() if profile.api_key else False)
    table.add_row(
        "API Key Configured",
        "[green]Yes[/green]" if has_key else "[red]No[/red]",
    )
    if profile.fallbacks:
        fb_summary = ", ".join(f"{fb.provider}:{fb.model}" for fb in profile.fallbacks)
        table.add_row("Fallbacks", fb_summary)
    else:
        table.add_row("Fallbacks", "(none)")
    console.print(table)


@llm_app.command("test")
def llm_test(
    provider: str | None = typer.Option(None, help="Override provider"),
    model: str | None = typer.Option(None, help="Override model"),
    prompt: str = typer.Option(
        "Say 'ARKA is operational' and nothing else.", help="Prompt to test"
    ),
) -> None:
    """Test LLM provider connectivity safely."""
    with console.status("Testing LLM connectivity..."):
        try:
            result = api_post(
                "/llm/test",
                {"prompt": prompt, "provider": provider, "model": model},
            )
            if result.get("status") == "success":
                console.print("[green][OK] LLM Provider is operational[/green]")
                console.print(f"  Provider: {result.get('provider')}")
                console.print(f"  Model: {result.get('model')}")
                console.print(f"  Latency: {result.get('latency_ms')} ms")
                console.print(f"  Response: {result.get('response')}")
            else:
                console.print(f"[red][X] LLM test failed: {result.get('error')}[/red]")
        except Exception as e:
            console.print(f"[red]Error contacting API: {e}[/red]")


# Web Security Subcommands
web_app = typer.Typer(name="web", help="Web & API security analysis commands")
app.add_typer(web_app, name="web")


@web_app.command("crawl")
def web_crawl(
    target: str = typer.Argument(..., help="Seed URL to crawl"),
    max_pages: int = typer.Option(30, help="Maximum pages to crawl"),
    max_depth: int = typer.Option(3, help="Maximum traversal depth"),
) -> None:
    """Run an authorized, scope-bounded web crawl against a target."""
    console.print(f"[bold blue]Starting Web Crawler on {target}[/bold blue]")
    try:
        result = api_post(
            "/web/crawl",
            {"target": target, "max_pages": max_pages, "max_depth": max_depth},
        )
        table = Table(title="Crawl Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold")
        table.add_row("Pages Crawled", str(result.get("pages_crawled", 0)))
        table.add_row("Endpoints Discovered", str(result.get("endpoints_count", 0)))
        table.add_row("Forms Discovered", str(result.get("forms_count", 0)))
        console.print(table)
    except Exception as e:
        console.print(f"[red]Crawl failed or API unavailable: {e}[/red]")


@web_app.command("openapi")
def web_openapi(
    target: str = typer.Argument(..., help="Target base URL or OpenAPI specification URL"),
) -> None:
    """Discover and analyze OpenAPI/Swagger specifications."""
    console.print(f"[bold blue]Probing OpenAPI specifications on {target}[/bold blue]")
    try:
        result = api_post("/web/openapi", {"target": target})
        console.print(f"[green]Schemas found: {result.get('schemas_found', 0)}[/green]")
        console.print(f"Endpoints extracted: {result.get('endpoints_discovered', 0)}")
    except Exception as e:
        console.print(f"[red]OpenAPI discovery failed: {e}[/red]")


@web_app.command("graphql")
def web_graphql(
    target: str = typer.Argument(..., help="Target base URL or GraphQL endpoint URL"),
) -> None:
    """Discover and introspect GraphQL endpoints."""
    console.print(f"[bold blue]Probing GraphQL endpoint on {target}[/bold blue]")
    try:
        result = api_post("/web/graphql", {"target": target})
        if result.get("graphql_detected"):
            console.print("[green]GraphQL detected[/green]")
            console.print(f"Introspection: {result.get('introspection_enabled')}")
            console.print(f"Queries: {result.get('queries_count', 0)}")
            console.print(f"Mutations: {result.get('mutations_count', 0)}")
        else:
            console.print("[yellow]No active GraphQL endpoint detected[/yellow]")
    except Exception as e:
        console.print(f"[red]GraphQL analysis failed: {e}[/red]")


@web_app.command("endpoints")
def web_endpoints(
    engagement_id: str = typer.Argument(..., help="Engagement ID to query"),
) -> None:
    """List discovered web endpoints for an engagement."""
    try:
        result = api_get(f"/engagements/{engagement_id}/endpoints")
        endpoints = result.get("endpoints", [])
        table = Table(title=f"Discovered Endpoints ({len(endpoints)})")
        table.add_column("Scheme", style="cyan")
        table.add_column("Host", style="bold")
        table.add_column("Path", style="green")
        table.add_column("Source")
        table.add_column("Authorized Scope")
        for ep in endpoints:
            in_scope = ep.get("metadata", {}).get("in_authorized_scope", False)
            table.add_row(
                ep.get("scheme", "http"),
                ep.get("host", ""),
                ep.get("path", "/"),
                ep.get("source", ""),
                "[green]Yes[/green]" if in_scope else "[yellow]No (Discovered)[/yellow]",
            )
        console.print(table)
    except Exception as e:
        console.print(f"[red]Failed to retrieve endpoints: {e}[/red]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
