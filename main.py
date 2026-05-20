import socket
import time
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Callable, Set

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .vendor import VendorLookup
from .fingerprint import scan_ports, guess_device_type, get_open_ports_summary


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    label: str = ""
    device_type: str = "Unknown Device"
    device_icon: str = "❓"
    open_services: list = field(default_factory=list)
    last_seen: datetime = field(default_factory=datetime.now)
    first_seen: datetime = field(default_factory=datetime.now)
    ttl: Optional[int] = None
    seen_count: int = 1

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "label": self.label,
            "device_type": self.device_type,
            "open_services": self.open_services,
            "last_seen": self.last_seen.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "ttl": self.ttl,
            "seen_count": self.seen_count,
        }

    def os_guess(self) -> str:
        if self.ttl is None:
            return "?"
        if self.ttl <= 64:
            return "Linux / Android"
        elif self.ttl <= 128:
            return "Windows"
        elif self.ttl <= 255:
            return "macOS / iOS"
        return "?"

    def display_name(self) -> str:
        if self.label:
            return self.label
        if self.hostname != "Unknown":
            return self.hostname
        return self.vendor if self.vendor != "Unknown" else "?"


class Scanner:
    def __init__(self, ip_range: Optional[str] = None, deep: bool = False):
        self.ip_range = ip_range or self._detect_ip_range()
        self.vendor_lookup = VendorLookup()
        self.deep = deep  # If True, run port scan on each device

    def _detect_ip_range(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.rsplit(".", 1)
            return f"{parts[0]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def scan(self) -> List[Device]:
        if SCAPY_AVAILABLE:
            return self._scan_scapy()
        return self._scan_fallback()

    def _scan_scapy(self) -> List[Device]:
        conf.verb = 0
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip_range),
            timeout=3, retry=1
        )

        devices = []
        for _, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            hostname = self._resolve_hostname(ip)
            netbios_name = self._netbios_lookup(ip)
            if netbios_name and hostname == "Unknown":
                hostname = netbios_name
            vendor = self.vendor_lookup.lookup(mac)
            ttl = self._get_ttl(ip)

            open_services = []
            if self.deep:
                open_services = scan_ports(ip)

            os_g = self._ttl_to_os(ttl)
            device_type, icon = guess_device_type(open_services, vendor, os_g, hostname)

            devices.append(Device(
                ip=ip, mac=mac, hostname=hostname, vendor=vendor,
                device_type=device_type, device_icon=icon,
                open_services=open_services, ttl=ttl,
            ))

        return sorted(devices, key=lambda d: list(map(int, d.ip.split("."))))

    def _scan_fallback(self) -> List[Device]:
        import subprocess, platform
        devices = []
        network = ipaddress.IPv4Network(self.ip_range, strict=False)
        for host in network.hosts():
            ip = str(host)
            param = "-n" if platform.system().lower() == "windows" else "-c"
            try:
                result = subprocess.run(
                    ["ping", param, "1", "-w", "500", ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1
                )
                if result.returncode == 0:
                    hostname = self._resolve_hostname(ip)
                    device_type, icon = guess_device_type([], "Unknown", "?", hostname)
                    devices.append(Device(ip=ip, mac="N/A", hostname=hostname,
                                          device_type=device_type, device_icon=icon))
            except Exception:
                continue
        return devices

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

    def _netbios_lookup(self, ip: str) -> Optional[str]:
        """Try NetBIOS name query for Windows machines."""
        try:
            import subprocess
            result = subprocess.run(
                ["nbtstat", "-A", ip],
                capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                if "<00>" in line and "UNIQUE" in line:
                    name = line.strip().split()[0]
                    if name and name != ip:
                        return name
        except Exception:
            pass
        return None

    def _ttl_to_os(self, ttl: Optional[int]) -> str:
        if ttl is None:
            return "?"
        if ttl <= 64:
            return "Linux / Android"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "macOS / iOS"
        return "?"

    def _get_ttl(self, ip: str) -> Optional[int]:
        import subprocess, platform, re
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            result = subprocess.run(["ping", param, "1", ip],
                capture_output=True, text=True, timeout=2)
            match = re.search(r"[Tt][Tt][Ll]=(\d+)", result.stdout)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None

    def watch(self, interval: int = 30, on_scan=None, on_new_device=None):
        first = True
        known_macs: Set[str] = set()
        while True:
            devices = self.scan()
            new_devices = []
            for device in devices:
                if device.mac == "N/A":
                    continue
                if device.mac not in known_macs:
                    if not first:
                        new_devices.append(device)
                        if on_new_device:
                            on_new_device(device)
                    known_macs.add(device.mac)
            first = False
            if on_scan:
                on_scan(devices, new_devices)
            time.sleep(interval)
