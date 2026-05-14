"""
scanner.py
----------
Quet cac Access Point xung quanh trong thoi gian ngan
de build danh sach truoc khi bat dau sniff.
"""

import time
import threading
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.dot11 import Dot11ProbeResp


def _parse_beacon(pkt) -> dict | None:
    """
    Phan tich mot Beacon hoac ProbeResponse frame.
    Tra ve dict thong tin AP hoac None neu khong phan tich duoc.
    """
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return None

    bssid = pkt[Dot11].addr3
    if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
        return None

    # Doc SSID tu Dot11Elt
    ssid = ""
    channel = 0
    encryption = "Open"

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:  # SSID element
            try:
                ssid = elt.info.decode("utf-8", errors="replace").strip()
            except Exception:
                ssid = ""
        elif elt.ID == 3:  # DS Parameter Set (channel)
            try:
                channel = int.from_bytes(elt.info, "big")
            except Exception:
                channel = 0
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    # Detect encryption
    if pkt.haslayer(Dot11Beacon):
        cap = pkt[Dot11Beacon].cap
        if cap.privacy:
            encryption = "WEP/WPA"
        # Kiem tra RSN (WPA2/WPA3)
        elt2 = pkt.getlayer(Dot11Elt)
        while elt2:
            if elt2.ID == 48:  # RSN element -> WPA2
                encryption = "WPA2"
                break
            elif elt2.ID == 221 and elt2.info[:4] == b"\x00\x50\xf2\x01":  # WPA1
                encryption = "WPA"
                break
            elt2 = elt2.payload.getlayer(Dot11Elt) if elt2.payload else None

    # Doc RSSI tu RadioTap
    rssi = -100
    if pkt.haslayer(RadioTap):
        try:
            rssi = -(256 - pkt[RadioTap].dBm_AntSignal)
        except Exception:
            rssi = -100

    return {
        "ssid": ssid if ssid else "<Hidden>",
        "bssid": bssid.upper(),
        "channel": channel,
        "encryption": encryption,
        "rssi": rssi,
    }


class APScanner:
    """
    Quet AP trong khoang thoi gian ngan va tra ve danh sach.

    Su dung:
        scanner = APScanner(interface="wlan1mon")
        aps = scanner.scan(seconds=10)
    """

    def __init__(self, interface: str):
        self.interface = interface
        self._ap_map: dict[str, dict] = {}  # bssid -> ap_info
        self._lock = threading.Lock()

    def _packet_handler(self, pkt):
        ap = _parse_beacon(pkt)
        if ap is None:
            return
        bssid = ap["bssid"]
        with self._lock:
            if bssid not in self._ap_map:
                self._ap_map[bssid] = ap
            else:
                # Cap nhat RSSI moi nhat
                self._ap_map[bssid]["rssi"] = ap["rssi"]

    def scan(self, seconds: int = 10, max_results: int = 20) -> list[dict]:
        """
        Quet Beacon frame trong `seconds` giay.
        Tra ve list ap dict sap xep theo RSSI (manh nhat truoc).
        """
        print(f"[*] Scanning on {self.interface} for {seconds} seconds...")
        self._ap_map.clear()

        sniff(
            iface=self.interface,
            prn=self._packet_handler,
            timeout=seconds,
            store=False,
            monitor=True,
        )

        results = sorted(
            self._ap_map.values(),
            key=lambda x: x["rssi"],
            reverse=True,
        )
        return results[:max_results]

    def print_ap_table(self, aps: list[dict]) -> None:
        """In bang AP dep len terminal."""
        if not aps:
            print("[!] Khong phat hien duoc AP nao. Kiem tra lai monitor mode.")
            return

        print(f"\n{'NO':>3}  {'BSSID':<20} {'SSID':<28} {'CH':>3}  {'ENC':<6}  {'RSSI':>6}")
        print("-" * 75)
        for i, ap in enumerate(aps, start=1):
            print(
                f"{i:>3}  {ap['bssid']:<20} {ap['ssid']:<28} "
                f"{ap['channel']:>3}  {ap['encryption']:<6}  {ap['rssi']:>4} dBm"
            )
        print()

    def interactive_select(self, aps: list[dict]) -> list[dict] | None:
        """
        Hien thi menu, cho user chon AP muc tieu.
        Tra ve list AP da chon, hoac None neu chon tat ca.
        """
        self.print_ap_table(aps)
        choice = input(
            "Nhap so thu tu AP muon giam sat (Enter = giam sat tat ca): "
        ).strip()

        if not choice:
            print("[*] Giam sat tat ca AP...")
            return None

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(aps):
                selected = [aps[idx]]
                print(f"[*] Da chon: {selected[0]['ssid']} ({selected[0]['bssid']})")
                return selected
        except ValueError:
            pass

        print("[!] Lua chon khong hop le. Giam sat tat ca AP.")
        return None
