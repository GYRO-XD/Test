"""
Live dashboard for GYRO Honeypot using Rich.
Shows real-time attacker activity with colored table.
"""

import asyncio
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich import box
from datetime import datetime


class Dashboard:
    def __init__(self, state: dict, refresh_seconds: int = 2, max_rows: int = 20,
                 show_credentials: bool = True, colors: dict = None):
        self.state = state
        self.refresh_seconds = refresh_seconds
        self.max_rows = max_rows
        self.show_credentials = show_credentials
        self.colors = colors or {
            "ssh": "red",
            "telnet": "yellow",
            "ftp": "blue",
            "tiktok": "magenta",
            "instagram": "cyan",
            "facebook": "blue",
            "snapchat": "yellow"
        }
        self.console = Console()
        self.running = True

    async def run(self):
        """Run the dashboard with live updates."""
        with Live(self._build_dashboard(), refresh_per_second=1/self.refresh_seconds) as live:
            while self.running:
                live.update(self._build_dashboard())
                await asyncio.sleep(self.refresh_seconds)

    def _build_dashboard(self):
        """Build the dashboard layout."""
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="stats", size=3),
            Layout(name="table")
        )
        
        # Header
        header = Panel(
            "[bold red]GYRO Honeypot[/bold red] - Live Intrusion Monitor\n"
            f"[dim]Last update: {datetime.now().strftime('%H:%M:%S')}[/dim]",
            box=box.ROUNDED
        )
        layout["header"].update(header)

        # Stats
        total_attacks = sum(entry.get("hits", 0) for entry in self.state.values())
        unique_ips = len({entry["ip"] for entry in self.state.values()})
        
        stats = Panel(
            f"[bold]Total Attacks:[/bold] {total_attacks}    "
            f"[bold]Unique IPs:[/bold] {unique_ips}    "
            f"[bold]Active Services:[/bold] {len(self.state)}",
            box=box.ROUNDED
        )
        layout["stats"].update(stats)

        # Main table
        table = Table(
            title="[bold]Recent Activity[/bold]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan"
        )
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Service", no_wrap=True)
        table.add_column("Port", justify="right")
        table.add_column("Country", no_wrap=True)
        table.add_column("City", no_wrap=True)
        table.add_column("Last Seen", no_wrap=True)
        table.add_column("Hits", justify="right")
        
        if self.show_credentials:
            table.add_column("Credentials", style="yellow")

        # Sort by last seen (most recent first)
        sorted_entries = sorted(
            self.state.values(),
            key=lambda x: x.get("last_seen", ""),
            reverse=True
        )[:self.max_rows]

        for entry in sorted_entries:
            service = entry.get("service", "Unknown")
            color = self.colors.get(service.lower(), "white")
            
            creds = entry.get("last_creds") or entry.get("credentials")
            creds_str = ""
            if creds and isinstance(creds, dict):
                # Show first credential pair
                for k, v in creds.items():
                    if k in ["password", "pass", "pwd"]:
                        creds_str = f"🔑 {k}: {v[:10]}..."
                        break
                else:
                    first_key = next(iter(creds))
                    creds_str = f"{first_key}: {creds[first_key][:15]}..."
            
            row = [
                entry.get("ip", "unknown"),
                f"[{color}]{service}[/{color}]",
                str(entry.get("port", "?")),
                entry.get("country", "?"),
                entry.get("city", "?"),
                entry.get("last_seen", "?"),
                str(entry.get("hits", 0))
            ]
            
            if self.show_credentials:
                row.append(creds_str or "—")
            
            table.add_row(*row)

        layout["table"].update(table)
        return layout

    def stop(self):
        """Stop the dashboard."""
        self.running = False