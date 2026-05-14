"""
rogue_detector.py
-----------------
Phat hien Rogue AP va Evil Twin bang cach:
1. So sanh SSID: neu giong whitelist nhung BSSID khac -> Rogue
2. Dung difflib de bat SSID tuong tu (vi du: "Lab-WiFi" vs "Lab_WiFi")
"""

import json
import time
from difflib import SequenceMatcher
from pathlib import Path


def _ssid_similarity(a: str, b: str) -> float:
    """Tinh do tuong dong giua 2 SSID (0.0 - 1.0)."""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


class RogueDetector:
    """
    Phat hien Rogue AP / Evil Twin dua tren whitelist.

    Su dung:
        detector = RogueDetector("config/whitelist.json", threshold=0.85)
        result = detector.check(ap_info)  # ap_info tu scanner hoac sniffer
    """

    def __init__(self, whitelist_path: str, ssid_threshold: float = 0.85,
                 cooldown_seconds: int = 30):
        self.whitelist_path = whitelist_path
        self.ssid_threshold = ssid_threshold
        self.cooldown_seconds = cooldown_seconds

        # { ssid_detected: last_alert_timestamp }
        self._alert_cooldown: dict[str, float] = {}

        self.whitelist = self._load_whitelist()

    def _load_whitelist(self) -> list[dict]:
        """Doc whitelist tu file JSON."""
        path = Path(self.whitelist_path)
        if not path.exists():
            print(f"[!] Whitelist khong tim thay: {self.whitelist_path}")
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"[*] Da tai whitelist: {len(data)} AP hop le.")
        return data

    def reload_whitelist(self):
        """Tai lai whitelist (dung khi user sua file trong luc chay)."""
        self.whitelist = self._load_whitelist()

    def get_whitelist(self) -> list[dict]:
        return self.whitelist

    def add_to_whitelist(self, entry: dict):
        """Them AP vao whitelist va luu file."""
        self.whitelist.append(entry)
        self._save_whitelist()

    def remove_from_whitelist(self, bssid: str):
        """Xoa AP khoi whitelist theo BSSID."""
        self.whitelist = [
            ap for ap in self.whitelist
            if ap.get("bssid", "").upper() != bssid.upper()
        ]
        self._save_whitelist()

    def _save_whitelist(self):
        with open(self.whitelist_path, "w", encoding="utf-8") as f:
            json.dump(self.whitelist, f, indent=2, ensure_ascii=False)

    def _is_in_cooldown(self, key: str) -> bool:
        last = self._alert_cooldown.get(key)
        if last is None:
            return False
        return (time.time() - last) < self.cooldown_seconds

    def _set_cooldown(self, key: str):
        self._alert_cooldown[key] = time.time()

    def check(self, ap: dict) -> dict | None:
        """
        Kiem tra mot AP co phai Rogue/Evil Twin khong.

        ap: {"ssid": str, "bssid": str, "channel": int, "rssi": int, ...}

        Tra ve dict alert neu phat hien, None neu OK.
        """
        ssid = ap.get("ssid", "").strip()
        bssid = ap.get("bssid", "").upper()

        if not ssid or ssid == "<Hidden>":
            return None

        for legit in self.whitelist:
            legit_ssid = legit.get("ssid", "").strip()
            legit_bssid = legit.get("bssid", "").upper()

            # Tinh do tuong dong
            similarity = _ssid_similarity(ssid, legit_ssid)
            if similarity < self.ssid_threshold:
                continue  # SSID khac xa, bo qua

            # SSID giong -> kiem tra BSSID
            if bssid == legit_bssid:
                # AP hop le, khong canh bao
                return None

            # SSID khop nhung BSSID khac -> ROGUE!
            cooldown_key = f"{ssid}:{bssid}"
            if self._is_in_cooldown(cooldown_key):
                return None  # Da canh bao gan day, bo qua

            self._set_cooldown(cooldown_key)

            alert = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event_type": "rogue_ap_detected",
                "ssid": ssid,
                "legit_bssid": legit_bssid,
                "detected_bssid": bssid,
                "channel": ap.get("channel", 0),
                "rssi": ap.get("rssi", -100),
                "ssid_similarity": round(similarity, 3),
                "severity": "high" if similarity >= 0.99 else "medium",
                "message": (
                    f"SSID '{ssid}' matches legitimate AP but BSSID is unknown. "
                    f"Legit: {legit_bssid}, Detected: {bssid}"
                ),
            }
            return alert

        return None
