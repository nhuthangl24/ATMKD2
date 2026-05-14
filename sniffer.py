"""
sniffer.py
----------
Bat va phan tich Beacon / Deauth frame realtime.
Ket noi RogueDetector va DeauthDetector.
Ghi log JSON, day len OpenSearch va gui Telegram.
"""

import json
import time
import threading
import requests
from pathlib import Path
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Deauth, RadioTap
from scapy.layers.dot11 import Dot11ProbeResp, Dot11Elt

from detector.rogue_detector import RogueDetector
from detector.deauth_detector import DeauthDetector


# -----------------------------------------------
# Helper: doc RSSI tu RadioTap
# -----------------------------------------------
def _get_rssi(pkt) -> int:
    try:
        if pkt.haslayer(RadioTap):
            return -(256 - pkt[RadioTap].dBm_AntSignal)
    except Exception:
        pass
    return -100


# -----------------------------------------------
# Helper: doc SSID tu Beacon
# -----------------------------------------------
def _get_ssid(pkt) -> str:
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:
            try:
                return elt.info.decode("utf-8", errors="replace").strip() or "<Hidden>"
            except Exception:
                return "<Hidden>"
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return "<Hidden>"


# -----------------------------------------------
# Helper: doc channel tu Beacon
# -----------------------------------------------
def _get_channel(pkt) -> int:
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3:
            try:
                return int.from_bytes(elt.info, "big")
            except Exception:
                return 0
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return 0


class WiFiSniffer:
    """
    Sniff goi tin Wi-Fi realtime.
    Phat hien Rogue AP va Deauth Attack.
    Ghi log va gui notification.
    """

    def __init__(self, config: dict):
        self.config = config
        self.interface = config["interface"]
        self.log_path = Path(config["log_path"])
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Target filter (None = tat ca)
        self.target_bssids: set[str] | None = None

        # Detectors
        self.rogue_detector = RogueDetector(
            whitelist_path=config["whitelist_path"],
            ssid_threshold=config.get("ssid_similarity_threshold", 0.85),
            cooldown_seconds=config.get("alert_cooldown_seconds", 30),
        )
        self.deauth_detector = DeauthDetector(
            window_seconds=config.get("deauth_window_seconds", 10),
            threshold=config.get("deauth_threshold", 20),
            cooldown_seconds=config.get("alert_cooldown_seconds", 30),
        )

        # Trang thai
        self._running = False
        self._sniff_thread: threading.Thread | None = None
        self._alert_callbacks: list = []  # callback(alert_dict)

        # Thong ke
        self.stats = {
            "total_beacons": 0,
            "total_deauths": 0,
            "total_alerts": 0,
            "alerts": [],
        }

    # -----------------------------------------------
    # Public API
    # -----------------------------------------------

    def set_target(self, bssids: list[str] | None):
        """Loc chi sniff mot so BSSID. None = tat ca."""
        self.target_bssids = (
            {b.upper() for b in bssids} if bssids else None
        )

    def add_alert_callback(self, fn):
        """Dang ky ham duoc goi khi co alert moi."""
        self._alert_callbacks.append(fn)

    def start(self):
        """Bat dau sniff trong background thread."""
        if self._running:
            return
        self._running = True
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, daemon=True
        )
        self._sniff_thread.start()
        print(f"[*] Sniffing started on {self.interface}")

    def stop(self):
        """Dung sniff."""
        self._running = False
        print("[*] Sniffing stopped.")

    def is_running(self) -> bool:
        return self._running

    # -----------------------------------------------
    # Sniff loop (chay trong thread)
    # -----------------------------------------------

    def _sniff_loop(self):
        while self._running:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                timeout=2,       # Moi 2 giay check _running mot lan
                store=False,
                monitor=True,
            )

    def _process_packet(self, pkt):
        """Ham xu ly moi goi tin bat duoc."""

        # ---- Beacon / ProbeResponse ----
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self.stats["total_beacons"] += 1
            bssid = pkt[Dot11].addr3
            if not bssid:
                return

            bssid = bssid.upper()

            # Bo qua neu khong phai target
            if self.target_bssids and bssid not in self.target_bssids:
                return

            ssid = _get_ssid(pkt)
            channel = _get_channel(pkt)
            rssi = _get_rssi(pkt)

            ap_info = {
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "rssi": rssi,
            }

            alert = self.rogue_detector.check(ap_info)
            if alert:
                self._handle_alert(alert)

        # ---- Deauthentication ----
        elif pkt.haslayer(Dot11Deauth):
            self.stats["total_deauths"] += 1
            bssid = pkt[Dot11].addr1  # addr1 = destination (AP bi tan cong)
            source = pkt[Dot11].addr2  # addr2 = source (attacker)
            if not bssid:
                return

            bssid = bssid.upper()

            # Tim SSID tuong ung tu whitelist
            ssid = self._lookup_ssid(bssid)

            alert = self.deauth_detector.process(
                bssid=bssid,
                ssid=ssid,
                source_mac=source or "",
            )
            if alert:
                self._handle_alert(alert)

    # -----------------------------------------------
    # Alert handling
    # -----------------------------------------------

    def _handle_alert(self, alert: dict):
        """Xu ly alert: in, log, gui notification."""
        self.stats["total_alerts"] += 1
        self.stats["alerts"].append(alert)

        # In ra terminal
        self._print_alert(alert)

        # Ghi log JSON
        self._write_log(alert)

        # Gui OpenSearch
        if self.config.get("opensearch", {}).get("enabled", False):
            self._push_opensearch(alert)

        # Gui Telegram
        if self.config.get("telegram", {}).get("enabled", False):
            self._send_telegram(alert)

        # Goi callbacks (dung boi webapp)
        for cb in self._alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def _print_alert(self, alert: dict):
        ts = alert.get("timestamp", "")
        ev = alert.get("event_type", "")
        sev = alert.get("severity", "").upper()

        if ev == "rogue_ap_detected":
            print(
                f"\n{'='*60}\n"
                f"[!!!] ROGUE AP DETECTED  [{ts}]  Severity: {sev}\n"
                f"  SSID     : {alert.get('ssid')}\n"
                f"  Legit    : {alert.get('legit_bssid')}\n"
                f"  Detected : {alert.get('detected_bssid')}\n"
                f"  Channel  : {alert.get('channel')}  RSSI: {alert.get('rssi')} dBm\n"
                f"  Sim      : {alert.get('ssid_similarity', 'N/A')}\n"
                f"{'='*60}"
            )
        elif ev == "deauth_attack_detected":
            print(
                f"\n{'='*60}\n"
                f"[!!!] DEAUTH ATTACK DETECTED  [{ts}]  Severity: {sev}\n"
                f"  Target BSSID : {alert.get('target_bssid')}\n"
                f"  SSID         : {alert.get('ssid') or 'Unknown'}\n"
                f"  Source MAC   : {alert.get('source_mac') or 'Unknown'}\n"
                f"  Frame count  : {alert.get('frame_count')} in {alert.get('window_seconds')}s\n"
                f"  Threshold    : {alert.get('threshold')}\n"
                f"{'='*60}"
            )

    def _write_log(self, alert: dict):
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[ERR] Log write failed: {e}")

    def _push_opensearch(self, alert: dict):
        cfg = self.config["opensearch"]
        url = f"{cfg['endpoint']}/{cfg['index']}/_doc"
        try:
            resp = requests.post(
                url,
                json=alert,
                auth=(cfg.get("username", "admin"), cfg.get("password", "admin")),
                verify=cfg.get("verify_tls", False),
                timeout=5,
            )
            if resp.status_code not in (200, 201):
                print(f"[WARN] OpenSearch push failed: {resp.status_code}")
        except Exception as e:
            print(f"[WARN] OpenSearch error: {e}")

    def _send_telegram(self, alert: dict):
        cfg = self.config["telegram"]
        ev = alert.get("event_type", "")

        if ev == "rogue_ap_detected":
            icon = "🚨"
            text = (
                f"{icon} *ROGUE AP DETECTED*\n"
                f"SSID: `{alert.get('ssid')}`\n"
                f"Legit: `{alert.get('legit_bssid')}`\n"
                f"Rogue: `{alert.get('detected_bssid')}`\n"
                f"CH: {alert.get('channel')}  RSSI: {alert.get('rssi')} dBm\n"
                f"Time: {alert.get('timestamp')}"
            )
        elif ev == "deauth_attack_detected":
            icon = "⚡"
            text = (
                f"{icon} *DEAUTH ATTACK*\n"
                f"Target: `{alert.get('target_bssid')}`\n"
                f"SSID: `{alert.get('ssid') or 'Unknown'}`\n"
                f"Frames: {alert.get('frame_count')} in {alert.get('window_seconds')}s\n"
                f"Time: {alert.get('timestamp')}"
            )
        else:
            text = f"⚠️ WiFi Alert: {alert.get('message', '')}"

        try:
            requests.post(
                f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage",
                json={
                    "chat_id": cfg["chat_id"],
                    "text": text,
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )
        except Exception as e:
            print(f"[WARN] Telegram error: {e}")

    def _lookup_ssid(self, bssid: str) -> str:
        """Tim SSID theo BSSID trong whitelist."""
        for ap in self.rogue_detector.get_whitelist():
            if ap.get("bssid", "").upper() == bssid.upper():
                return ap.get("ssid", "")
        return ""
