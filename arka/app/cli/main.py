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


def api_get(path: str) -> dict:
    """Make a GET request to the ARKA API."""
    url = f"{get_api_url()}{path}"
    try:
        response = httpx.get(url, timeout=30.0)
        response.raise_for_status()
        return response.json()
    except httpx.ConnectError:
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
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Status")
    for task in result["tasks"]:
        table.add_row(task.get("task_id", ""), task.get("name", ""), task.get("status", ""))
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
    console.print(f"  Engagement: {result.get('engagement_id')}")
    console.print(f"  Status: {result.get('status')}")
    console.print(f"  Objective: {result.get('objective')}")


def main() -> None:

    app()


if __name__ == "__main__":
    main()
