from datetime import datetime
from typing import List, Set
import time

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.align import Align
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .fingerprint import get_open_ports_summary


class Display:
    def __init__(self):
        if RICH_AVAILABLE:
            self.console = Console()

    def banner(self):
        if RICH_AVAILABLE:
            self.console.print(Panel.fit(
                "[bold cyan]  LAN Device Scanner[/bold cyan]\n"
                "[dim]Discover and monitor devices on your network[/dim]",
                border_style="cyan"
            ))
            self.console.print()
        else:
            print("=" * 50)
            print("  LAN Device Scanner")
            print("=" * 50)

    def print_info(self, msg: str):
        if RICH_AVAILABLE:
            self.console.print(f"[dim]{msg}[/dim]")
        else:
            print(msg)

    def _build_table(self, devices, new_macs: Set[str], title: str = "", show_ports: bool = False) -> "Table":
        table = Table(
            title=title,
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="cyan",
            show_lines=True,
            expand=True,
        )
        table.add_column("#", style="dim", width=3, justify="right")
        table.add_column("Type", width=18)
        table.add_column("IP Address", style="cyan", min_width=15)
        table.add_column("Name", min_width=20)
        table.add_column("Vendor", min_width=16)
        table.add_column("MAC", style="dim", min_width=18)
        table.add_column("OS", min_width=14)
        if show_ports:
            table.add_column("Services", min_width=20)
        table.add_column("Seen", justify="right", width=5)
        table.add_column("", width=5)

        for i, device in enumerate(devices, 1):
            is_new = device.mac in new_macs
            badge = "[bold green]NEW[/bold green]" if is_new else ""
            row_style = "on dark_green" if is_new else ""

            # Name: label > hostname > ?
            if device.label:
                name = f"[bold yellow]{device.label}[/bold yellow]"
            elif device.hostname != "Unknown":
                name = device.hostname
            else:
                name = "[dim]Unknown[/dim]"

            # Device type with icon
            dtype = f"{device.device_icon}  {device.device_type}"

            # Vendor coloring
            vendor = device.vendor if device.vendor != "Unknown" else "[dim]Unknown[/dim]"

            row = [
                str(i),
                dtype,
                device.ip,
                name,
                vendor,
                device.mac,
                device.os_guess(),
            ]
            if show_ports:
                row.append(get_open_ports_summary(device.open_services))
            row += [str(getattr(device, "seen_count", 1)), badge]

            table.add_row(*row, style=row_style)

        return table

    def show_devices(self, devices, new_devices=None, show_ports=False):
        new_macs = {d.mac for d in (new_devices or [])}
        ts = datetime.now().strftime("%H:%M:%S")
        title = f"[bold]Found {len(devices)} device(s)[/bold]  [dim]{ts}[/dim]"
        if RICH_AVAILABLE:
            table = self._build_table(devices, new_macs, title, show_ports=show_ports)
            self.console.print(table)
        else:
            print(f"\nFound {len(devices)} device(s) at {ts}\n")
            for d in devices:
                flag = " *NEW*" if d.mac in new_macs else ""
                print(f"{d.ip:<18} {d.device_icon} {d.device_type:<18} {d.hostname:<22} {d.vendor:<18} {d.mac}{flag}")

    def live_watch(self, scanner, history, interval: int, on_new_device=None):
        if not RICH_AVAILABLE:
            raise RuntimeError("Rich is required for live dashboard")

        devices = []
        new_macs: Set[str] = set()
        status = "[dim]Starting first scan...[/dim]"
        next_scan_at = time.time()
        first_scan = True

        def make_renderable():
            ts = datetime.now().strftime("%H:%M:%S")
            secs_left = max(0, int(next_scan_at - time.time()))
            title = (
                f"[bold cyan] LAN Device Scanner[/bold cyan]  "
                f"[dim]{ts}  —  next scan in {secs_left}s[/dim]"
            )
            if not devices:
                return Panel(Align.center("[dim]Scanning...[/dim]"), title=title, border_style="cyan")

            show_ports = any(d.open_services for d in devices)
            table = self._build_table(
                devices, new_macs,
                f"[bold]{len(devices)} device(s) on network[/bold]",
                show_ports=show_ports,
            )
            return Panel(table, title=title, border_style="cyan", subtitle=status)

        with Live(make_renderable(), console=self.console, refresh_per_second=2) as live:
            while True:
                now = time.time()
                if now >= next_scan_at:
                    status = "[dim]Scanning...[/dim]"
                    live.update(make_renderable())

                    scanned = scanner.scan()
                    new_this_round = history.update(scanned)

                    if first_scan:
                        new_macs = set()
                        first_scan = False
                    else:
                        new_macs = {d.mac for d in new_this_round}
                        for d in new_this_round:
                            if on_new_device:
                                on_new_device(d)

                    devices = scanned
                    next_scan_at = time.time() + interval
                    if new_macs:
                        names = ", ".join(d.device_type for d in new_this_round)
                        status = f"[bold yellow]⚠ New device(s): {names}[/bold yellow]"
                    else:
                        status = "[dim]All clear.[/dim]"

                live.update(make_renderable())
                time.sleep(0.5)

    def alert_new_device(self, device):
        if RICH_AVAILABLE:
            name = device.label or device.hostname or device.ip
            self.console.print(Panel(
                f"[bold yellow]⚠  NEW DEVICE DETECTED[/bold yellow]\n"
                f"{device.device_icon}  [bold]{device.device_type}[/bold]\n"
                f"IP: [cyan]{device.ip}[/cyan]   MAC: [dim]{device.mac}[/dim]\n"
                f"Name: {name}   Vendor: {device.vendor}",
                border_style="yellow"
            ))
        else:
            print(f"\n*** NEW DEVICE: {device.ip} ({device.mac}) - {device.device_type} ***\n")

    def show_history(self, records):
        if not records:
            self.print_info("No history yet. Run a scan first.")
            return
        if RICH_AVAILABLE:
            table = Table(
                title=f"[bold]Device History — {len(records)} devices seen[/bold]",
                box=box.ROUNDED, header_style="bold cyan", border_style="cyan",
                show_lines=True, expand=True,
            )
            table.add_column("Label", min_width=14)
            table.add_column("Type", min_width=16)
            table.add_column("IP", style="cyan", min_width=15)
            table.add_column("MAC", style="dim", min_width=18)
            table.add_column("Vendor", min_width=16)
            table.add_column("Hostname", min_width=18)
            table.add_column("First Seen", min_width=16)
            table.add_column("Last Seen", min_width=16)
            table.add_column("Times", justify="right")

            for r in records:
                label = f"[bold yellow]{r['label']}[/bold yellow]" if r["label"] else "[dim]—[/dim]"
                dtype = f"{r.get('device_icon','❓')}  {r.get('device_type','Unknown')}"
                table.add_row(
                    label, dtype, r["ip"], r["mac"],
                    r["vendor"] or "Unknown", r["hostname"],
                    r["first_seen"][:16], r["last_seen"][:16], str(r["seen_count"])
                )
            self.console.print(table)
        else:
            for r in records:
                print(f"{r['ip']:<18} {r['mac']:<20} {r['vendor']:<20} seen {r['seen_count']}x")
