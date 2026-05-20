import socket
import time
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Callable, Set

try:
    from scapyall import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from vendor import VendorLookup
from fingerprint import scan_ports, guess_device_type, get_open_ports_summary


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
    last_seen: datetime = field(default_factory=datetimenow)
    first_seen: datetime = field(default_factory=datetimenow)
    ttl: Optional[int] = None
    seen_count: int = 1

    def to_dict(self):
        return {
            "ip": selfip,
            "mac": selfmac,
            "hostname": selfhostname,
            "vendor": selfvendor,
            "label": selflabel,
            "device_type": selfdevice_type,
            "open_services": selfopen_services,
            "last_seen": selflast_seenisoformat(),
            "first_seen": selffirst_seenisoformat(),
            "ttl": selfttl,
            "seen_count": selfseen_count,
        }

    def os_guess(self) -> str:
        if selfttl is None:
            return "?"
        if selfttl <= 64:
            return "Linux / Android"
        elif selfttl <= 128:
            return "Windows"
        elif selfttl <= 255:
            return "macOS / iOS"
        return "?"

    def display_name(self) -> str:
        if selflabel:
            return selflabel
        if selfhostname != "Unknown":
            return selfhostname
        return selfvendor if selfvendor != "Unknown" else "?"


class Scanner:
    def __init__(self, ip_range: Optional[str] = None, deep: bool = False):
        selfip_range = ip_range or self_detect_ip_range()
        selfvendor_lookup = VendorLookup()
        selfdeep = deep  # If True, run port scan on each device

    def _detect_ip_range(self) -> str:
        try:
            s = socketsocket(socketAF_INET, socketSOCK_DGRAM)
            sconnect(("8888", 80))
            local_ip = sgetsockname()[0]
            sclose()
            parts = local_iprsplit("", 1)
            return f"{parts[0]}0/24"
        except Exception:
            return "19216810/24"

    def scan(self) -> List[Device]:
        if SCAPY_AVAILABLE:
            return self_scan_scapy()
        return self_scan_fallback()

    def _scan_scapy(self) -> List[Device]:
        confverb = 0
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=selfip_range),
            timeout=3, retry=1
        )

        devices = []
        for _, received in answered:
            ip = receivedpsrc
            mac = receivedhwsrc
            hostname = self_resolve_hostname(ip)
            netbios_name = self_netbios_lookup(ip)
            if netbios_name and hostname == "Unknown":
                hostname = netbios_name
            vendor = selfvendor_lookuplookup(mac)
            ttl = self_get_ttl(ip)

            open_services = []
            if selfdeep:
                open_services = scan_ports(ip)

            os_g = self_ttl_to_os(ttl)
            device_type, icon = guess_device_type(open_services, vendor, os_g, hostname)

            devicesappend(Device(
                ip=ip, mac=mac, hostname=hostname, vendor=vendor,
                device_type=device_type, device_icon=icon,
                open_services=open_services, ttl=ttl,
            ))

        return sorted(devices, key=lambda d: list(map(int, dipsplit(""))))

    def _scan_fallback(self) -> List[Device]:
        import subprocess, platform
        devices = []
        network = ipaddressIPv4Network(selfip_range, strict=False)
        for host in networkhosts():
            ip = str(host)
            param = "-n" if platformsystem()lower() == "windows" else "-c"
            try:
                result = subprocessrun(
                    ["ping", param, "1", "-w", "500", ip],
                    stdout=subprocessDEVNULL, stderr=subprocessDEVNULL, timeout=1
                )
                if resultreturncode == 0:
                    hostname = self_resolve_hostname(ip)
                    device_type, icon = guess_device_type([], "Unknown", "?", hostname)
                    devicesappend(Device(ip=ip, mac="N/A", hostname=hostname,
                                          device_type=device_type, device_icon=icon))
            except Exception:
                continue
        return devices

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socketgethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

    def _netbios_lookup(self, ip: str) -> Optional[str]:
        """Try NetBIOS name query for Windows machines"""
        try:
            import subprocess
            result = subprocessrun(
                ["nbtstat", "-A", ip],
                capture_output=True, text=True, timeout=3
            )
            for line in resultstdoutsplitlines():
                if "<00>" in line and "UNIQUE" in line:
                    name = linestrip()split()[0]
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
        param = "-n" if platformsystem()lower() == "windows" else "-c"
        try:
            result = subprocessrun(["ping", param, "1", ip],
                capture_output=True, text=True, timeout=2)
            match = research(r"[Tt][Tt][Ll]=(\d+)", resultstdout)
            if match:
                return int(matchgroup(1))
        except Exception:
            pass
        return None

    def watch(self, interval: int = 30, on_scan=None, on_new_device=None):
        first = True
        known_macs: Set[str] = set()
        while True:
            devices = selfscan()
            new_devices = []
            for device in devices:
                if devicemac == "N/A":
                    continue
                if devicemac not in known_macs:
                    if not first:
                        new_devicesappend(device)
                        if on_new_device:
                            on_new_device(device)
                    known_macsadd(devicemac)
            first = False
            if on_scan:
                on_scan(devices, new_devices)
            timesleep(interval)
