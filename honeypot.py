#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GYRO Honeypot - Premium Version
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from rich import print as rprint
from rich.panel import Panel

from core.logger import EventLogger
from core.geoip import GeoIPResolver
from core.notifier import TelegramNotifier
from core.listener import HoneypotService
from core.dashboard import Dashboard

BANNER = r"""
[bold red]  ______ __     ______  ____ 
 / ____// /_   / ____/ / __ \
/ / __ / __ \ / /     / / / /
/ /_/ // /_/ // /___  / /_/ /
\____//_.___/ \____/  \____/[/bold red]
[bold white]        Honeypot & Intrusion Logger[/bold white]
[dim]        Premium Version - by GYRO-XD[/dim]
"""


def load_config(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        rprint(f"[bold red]Config file not found:[/bold red] {path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        rprint(f"[bold red]Invalid JSON in config:[/bold red] {e}")
        sys.exit(1)


async def main_async(config: dict, show_dashboard: bool):
    rprint(Panel(BANNER, border_style="red"))

    # Initialize components
    log_cfg = config["logging"]
    event_logger = EventLogger(
        log_cfg["log_dir"], 
        log_cfg["log_file"],
        max_size_mb=log_cfg.get("max_file_size_mb", 100),
        backup_count=log_cfg.get("backup_count", 5)
    )

    geo_cfg = config["geoip"]
    geoip_resolver = GeoIPResolver(
        provider_url=geo_cfg["provider_url"],
        enabled=geo_cfg["enabled"]
    )

    tg_cfg = config["telegram"]
    notifier = TelegramNotifier(
        tg_cfg["bot_token"], 
        tg_cfg["admin_chat_id"],
        enabled=True, 
        rate_limit_seconds=tg_cfg.get("rate_limit_seconds", 30)
    )

    dashboard_state: dict = {}
    servers = []
    
    security_cfg = config.get("security", {})
    web_cfg = config.get("web", {"template_dir": "templates"})
    perf_cfg = config.get("performance", {})
    
    template_dir = Path(web_cfg.get("template_dir", "templates"))
    template_dir.mkdir(exist_ok=True)

    # Start services
    for svc in config["services"]:
        service_type = svc.get("type", "tcp")
        
        try:
            if service_type == "http":
                service = HoneypotService(
                    name=svc["name"], 
                    port=svc["port"], 
                    banner=svc.get("banner"),
                    event_logger=event_logger, 
                    geoip_resolver=geoip_resolver,
                    notifier=notifier, 
                    dashboard_state=dashboard_state,
                    template_dir=template_dir,
                    service_config=svc,
                    security_config=security_cfg,
                    performance_config=perf_cfg
                )
            else:
                service = HoneypotService(
                    name=svc["name"], 
                    port=svc["port"], 
                    banner=svc.get("banner"),
                    event_logger=event_logger, 
                    geoip_resolver=geoip_resolver,
                    notifier=notifier, 
                    dashboard_state=dashboard_state,
                    security_config=security_cfg,
                    performance_config=perf_cfg
                )
            
            server = await service.start()
            servers.append(server)
            
            if service_type == "http":
                rprint(f"[green]✓[/green] Fake [bold]{svc['name']}[/bold] HTTP service on port [bold]{svc['port']}[/bold]")
            else:
                rprint(f"[green]✓[/green] Fake [bold]{svc['name']}[/bold] service on port [bold]{svc['port']}[/bold]")
                
        except OSError as e:
            rprint(f"[bold red]✗[/bold red] Could not bind port {svc['port']} for {svc['name']}: {e}")
        except Exception as e:
            rprint(f"[bold red]✗[/bold red] Error starting {svc['name']}: {e}")

    if not servers:
        rprint("[bold red]No services could be started. Exiting.[/bold red]")
        return

    rprint("\n[dim]Logging to: " + f"{log_cfg['log_dir']}/{log_cfg['log_file']}" + "[/dim]")
    rprint("[green]✓[/green] Telegram alerts [bold green]enabled[/bold green]")
    rprint("[dim]Press Ctrl+C to stop.[/dim]\n")

    tasks = [asyncio.create_task(s.serve_forever()) for s in servers]

    if show_dashboard:
        dash_cfg = config["dashboard"]
        dashboard = Dashboard(
            dashboard_state, 
            dash_cfg.get("refresh_seconds", 2), 
            dash_cfg.get("max_rows", 20)
        )
        tasks.append(asyncio.create_task(dashboard.run()))

    await asyncio.gather(*tasks)


def main():
    parser = argparse.ArgumentParser(description="GYRO Honeypot Premium")
    parser.add_argument("--config", default="config.json", help="Path to config JSON file")
    parser.add_argument("--no-dashboard", action="store_true", help="Run headless")
    args = parser.parse_args()

    config = load_config(args.config)
    
    if not config.get("services"):
        rprint("[bold red]Error: No services defined in config.json[/bold red]")
        sys.exit(1)

    try:
        asyncio.run(main_async(config, show_dashboard=not args.no_dashboard))
    except KeyboardInterrupt:
        rprint("\n[bold yellow]Shutting down GYRO Honeypot...[/bold yellow]")
    except Exception as e:
        rprint(f"[bold red]Unexpected error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
