import typer
import asyncio
from src.core.scoring import analyze_ioc
from rich.console import Console
from rich.table import Table
from rich import box

app = typer.Typer()

@app.command()
def scan(iocs: list[str]):

    table = Table(title="Threat Triage Report", show_lines=True, box=box.DOUBLE_EDGE)
    
    table.add_column("Indicator (IOC)", style="bold", header_style="cyan")
    table.add_column("Verdict", style="bold", header_style="cyan")
    table.add_column("VT Score", justify="center", header_style="cyan")
    table.add_column("AbuseIPDB Score", justify="center", header_style="cyan")
    with console.status(f"[bold cyan] Scanning ...[/bold cyan]", spinner="bouncingBar"):
        
        for ioc in iocs:
            result = asyncio.run(analyze_ioc(ioc))
            table.add_row(ioc,
            result["verdict"],
            str(result["vt_score"]),
            str(result["abuse_score"])
            )
        
    console.print(table)

console = Console()


if __name__ == "__main__":
    app()
