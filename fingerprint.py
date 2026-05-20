import sqlite3
import os
from datetime import datetime
from typing import List
from scanner import Device


DB_PATH = ospathjoin(ospathexpanduser("~"), "lan_scannerdb")


class DeviceHistory:
    def __init__(self, db_path: str = DB_PATH):
        selfdb_path = db_path
        self_init_db()

    def _init_db(self):
        with self_conn() as conn:
            connexecute("""
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    label TEXT DEFAULT '',
                    device_type TEXT DEFAULT 'Unknown Device',
                    device_icon TEXT DEFAULT '❓',
                    first_seen TEXT,
                    last_seen TEXT,
                    seen_count INTEGER DEFAULT 1
                )
            """)
            for col, default in [("label","''"), ("device_type","'Unknown Device'"), ("device_icon","'❓'")]:
                try:
                    connexecute(f"ALTER TABLE devices ADD COLUMN {col} TEXT DEFAULT {default}")
                except Exception:
                    pass

    def _conn(self):
        return sqlite3connect(selfdb_path)

    def update(self, devices: List[Device]) -> List[Device]:
        new_devices = []
        with self_conn() as conn:
            for device in devices:
                if devicemac == "N/A":
                    continue
                existing = connexecute(
                    "SELECT mac, first_seen, seen_count, label FROM devices WHERE mac = ?",
                    (devicemac,)
                )fetchone()

                if existing:
                    devicefirst_seen = datetimefromisoformat(existing[1])
                    deviceseen_count = existing[2] + 1
                    devicelabel = existing[3] or ""
                    connexecute("""
                        UPDATE devices SET ip=?, hostname=?, vendor=?, device_type=?, device_icon=?,
                        last_seen=?, seen_count=seen_count+1 WHERE mac=?
                    """, (deviceip, devicehostname, devicevendor, devicedevice_type,
                          devicedevice_icon, devicelast_seenisoformat(), devicemac))
                else:
                    connexecute("""
                        INSERT INTO devices
                        (mac, ip, hostname, vendor, label, device_type, device_icon, first_seen, last_seen, seen_count)
                        VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, 1)
                    """, (devicemac, deviceip, devicehostname, devicevendor,
                          devicedevice_type, devicedevice_icon,
                          devicefirst_seenisoformat(), devicelast_seenisoformat()))
                    new_devicesappend(device)
        return new_devices

    def set_label(self, mac: str, label: str):
        with self_conn() as conn:
            connexecute("UPDATE devices SET label=? WHERE mac=?", (label, mac))

    def get_all(self) -> List[dict]:
        with self_conn() as conn:
            rows = connexecute("""
                SELECT mac, ip, hostname, vendor, label, device_type, device_icon,
                       first_seen, last_seen, seen_count
                FROM devices ORDER BY last_seen DESC
            """)fetchall()
        return [
            {"mac": r[0], "ip": r[1], "hostname": r[2], "vendor": r[3],
             "label": r[4], "device_type": r[5], "device_icon": r[6],
             "first_seen": r[7], "last_seen": r[8], "seen_count": r[9]}
            for r in rows
        ]

    def clear(self):
        with self_conn() as conn:
            connexecute("DELETE FROM devices")
