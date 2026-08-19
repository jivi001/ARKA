import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
        console.print("[green]✓ ARKA is healthy[/green]")
    else:
        console.print(f"[red]✗ ARKA status: {status}[/red]")


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
        configured = "✓" if p["configured"] else "✗"
        style = "green" if p["configured"] else "red"
        table.add_row(p["name"], p["model"], p["role"], f"[{style}]{configured}[/{style}]")
    console.print(table)


@provider_app.command("test")
def provider_test(prompt: str = "Say 'ARKA is operational'") -> None:
    """Test LLM provider connectivity."""
    with console.status("Testing LLM provider..."):
        result = api_post("/llm/test", {"prompt": prompt})
    if result.get("status") == "success":
        console.print("[green]✓ LLM test successful[/green]")
        console.print(f"  Provider: {result['provider']}")
        console.print(f"  Model: {result['model']}")
        console.print(f"  Response: {result['response']}")
        console.print(f"  Latency: {result['latency_ms']}ms")
        console.print(f"  Tokens: {result['tokens_used']}")
    else:
        console.print(f"[red]✗ LLM test failed: {result.get('error', 'Unknown error')}[/red]")


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
    console.print("[green]✓ Engagement created[/green]")
    console.print(f"  ID: {result['engagement_id']}")
    console.print(f"  Name: {result['name']}")
    console.print(f"  Status: {result['status']}")


@engagement_app.command("start")
def engagement_start(engagement_id: str = typer.Argument(..., help="Engagement ID")) -> None:
    """Start an engagement."""
    result = api_post(f"/engagements/{engagement_id}/start")
    console.print("[green]✓ Engagement started[/green]")
    console.print(f"  Status: {result['status']}")


@engagement_app.command("status")
def engagement_status(engagement_id: str = typer.Argument(..., help="Engagement ID")) -> None:
    """Get engagement status."""
    result = api_get(f"/engagements/{engagement_id}")
    table = Table(title=f"Engagement: {result['name']}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("ID", result["engagement_id"])
    table.add_row("Status", result["status"])
    table.add_row("Objective", result.get("objective", ""))
    table.add_row("Created", result["created_at"])
    table.add_row("Started", result.get("started_at", "N/A"))
    console.print(table)


@engagement_app.command("pause")
def engagement_pause(engagement_id: str = typer.Argument(..., help="Engagement ID")) -> None:
    """Pause an engagement."""
    result = api_post(f"/engagements/{engagement_id}/pause")
    console.print("[yellow]⏸ Engagement paused[/yellow]")
    console.print(f"  Status: {result['status']}")


@engagement_app.command("stop")
def engagement_stop(engagement_id: str = typer.Argument(..., help="Engagement ID")) -> None:
    """Stop an engagement."""
    result = api_post(f"/engagements/{engagement_id}/stop")
    console.print("[red]⏹ Engagement stopped[/red]")
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
