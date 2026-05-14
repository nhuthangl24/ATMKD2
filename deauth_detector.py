"""
deauth_detector.py
------------------
Dem va phat hien Deauthentication Attack.

Khi attacker gui nhieu Deauth frame vao mot AP trong thoi gian ngan
-> co the dang co tan cong Wi-Fi.
"""

import time
from collections import deque


class DeauthDetector:
    """
    Phat hien Deauth Attack bang sliding window counter.

    Moi BSSID co mot cua so rieng. Khi so frame trong cua so
    vuot qua nguong (threshold) -> tao alert.

    Su dung:
        detector = DeauthDetector(window_seconds=10, threshold=20)
        alert = detector.process(bssid, ssid)
    """

    def __init__(self, window_seconds: int = 10, threshold: int = 20,
                 cooldown_seconds: int = 30):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds

        # { bssid: deque([timestamp, ...]) }
        self._windows: dict[str, deque] = {}

        # { bssid: last_alert_timestamp }
        self._alert_cooldown: dict[str, float] = {}

    def _clean_window(self, bssid: str):
        """Xoa cac timestamp cu khoi cua so."""
        if bssid not in self._windows:
            return
        cutoff = time.time() - self.window_seconds
        while self._windows[bssid] and self._windows[bssid][0] < cutoff:
            self._windows[bssid].popleft()

    def _is_in_cooldown(self, bssid: str) -> bool:
        last = self._alert_cooldown.get(bssid)
        if last is None:
            return False
        return (time.time() - last) < self.cooldown_seconds

    def process(self, bssid: str, ssid: str = "", source_mac: str = "") -> dict | None:
        """
        Xu ly mot Deauth frame.

        Tra ve dict alert neu phat hien tan cong, None neu binh thuong.
        """
        bssid = bssid.upper()
        now = time.time()

        if bssid not in self._windows:
            self._windows[bssid] = deque()

        self._windows[bssid].append(now)
        self._clean_window(bssid)

        count = len(self._windows[bssid])

        if count < self.threshold:
            return None  # Chua du nguong

        if self._is_in_cooldown(bssid):
            return None  # Da alert gan day

        self._alert_cooldown[bssid] = now

        alert = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": "deauth_attack_detected",
            "target_bssid": bssid,
            "ssid": ssid,
            "source_mac": source_mac,
            "frame_count": count,
            "window_seconds": self.window_seconds,
            "threshold": self.threshold,
            "severity": "high",
            "message": (
                f"Deauth attack detected on {ssid or bssid}: "
                f"{count} frames in {self.window_seconds}s "
                f"(threshold: {self.threshold})"
            ),
        }
        return alert

    def get_stats(self) -> dict:
        """Lay thong ke hien tai cua tat ca BSSID dang theo doi."""
        stats = {}
        for bssid in self._windows:
            self._clean_window(bssid)
            stats[bssid] = len(self._windows[bssid])
        return stats
