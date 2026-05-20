#!/usr/bin/env python3
"""LAN Device Scanner v3"""

import argparse
import json
from lan_scanner.scanner import Scanner
from lan_scanner.display import Display
from lan_scanner.history import DeviceHistory


def main():
    parser = argparse.ArgumentParser(
        description="LAN Device Scanner - Discover and monitor devices on your network"
    )
    parser.add_argument("--range", "-r", default=None,
        help="IP range to scan (e.g. 192.168.1.0/24)")
    parser.add_argument("--watch", "-w", action="store_true",
        help="Live dashboard mode")
    parser.add_argument("--interval", "-i", type=int, default=30,
        help="Scan interval in seconds (default: 30)")
    parser.add_argument("--deep", "-d", action="store_true",
        help="Deep scan: port scan each device to identify type (slower)")
    parser.add_argument("--history", action="store_true",
        help="Show all devices ever seen")
    parser.add_argument("--label", nargs=2, metavar=("MAC", "NAME"),
        help='Label a device: --label aa:bb:cc:dd:ee:ff "Dad\'s Phone"')
    parser.add_argument("--export", metavar="FILE",
        help="Export results to JSON")
    args = parser.parse_args()

    display = Display()
    history = DeviceHistory()
    scanner = Scanner(ip_range=args.range, deep=args.deep)

    if args.label:
        mac, name = args.label
        history.set_label(mac.lower(), name)
        display.print_info(f'Labeled {mac} as "{name}"')
        return

    if args.history:
        display.show_history(history.get_all())
        return

    display.banner()

    if args.deep:
        display.print_info("[yellow]Deep scan mode — port scanning each device. This takes ~10-20 seconds.[/yellow]\n")

    if args.watch:
        display.print_info(f"Live dashboard — scanning every {args.interval}s. Press Ctrl+C to stop.\n")
        try:
            display.live_watch(scanner=scanner, history=history, interval=args.interval)
        except KeyboardInterrupt:
            display.print_info("\nStopped.")
        return

    display.print_info("Scanning network...\n")
    devices = scanner.scan()
    new_devices = history.update(devices)
    display.show_devices(devices, new_devices, show_ports=args.deep)

    if args.export:
        with open(args.export, "w") as f:
            json.dump([d.to_dict() for d in devices], f, indent=2, default=str)
        display.print_info(f"\nExported to {args.export}")


if __name__ == "__main__":
    main()
