"""
main.py
-------
Diem vao CLI cua WiFi Security Monitor.
Chay: sudo .venv/bin/python -m detector.main
"""

import sys
import time
import signal
import yaml
from pathlib import Path

from detector.scanner import APScanner
from detector.sniffer import WiFiSniffer


CONFIG_PATH = "config/config.yaml"


def load_config(path: str = CONFIG_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def flatten_config(cfg: dict) -> dict:
    """Flat hoa config YAML thanh dict phang de dung de hon."""
    flat = {
        "interface": cfg.get("interface", "wlan1mon"),
        "whitelist_path": cfg.get("whitelist_path", "config/whitelist.json"),
        "log_path": cfg.get("log_path", "logs/wifi_alerts.jsonl"),
        "interactive_scan": cfg.get("interactive_scan", True),
        "scan_seconds": cfg.get("scan_seconds", 10),
        "scan_max_results": cfg.get("scan_max_results", 20),
        "ssid_similarity_threshold": cfg.get("ssid_similarity_threshold", 0.85),
        "alert_cooldown_seconds": cfg.get("alert_cooldown_seconds", 30),
        "deauth_window_seconds": cfg.get("deauth_window_seconds", 10),
        "deauth_threshold": cfg.get("deauth_threshold", 20),
        "opensearch": cfg.get("opensearch", {"enabled": False}),
        "telegram": cfg.get("telegram", {"enabled": False}),
    }
    return flat


def print_banner():
    print("""
╔══════════════════════════════════════════════════════╗
║         WiFi Security Monitor v1.0                  ║
║   Rogue AP | Evil Twin | Deauth Attack Detection    ║
╚══════════════════════════════════════════════════════╝
""")


def main():
    print_banner()

    # Load config
    if not Path(CONFIG_PATH).exists():
        print(f"[ERR] Khong tim thay config: {CONFIG_PATH}")
        sys.exit(1)

    cfg = flatten_config(load_config(CONFIG_PATH))
    interface = cfg["interface"]

    # ---- Phase 1: Scan ----
    scanner = APScanner(interface=interface)

    target_bssids = None  # None = giam sat tat ca

    if cfg["interactive_scan"]:
        aps = scanner.scan(
            seconds=cfg["scan_seconds"],
            max_results=cfg["scan_max_results"],
        )

        if not aps:
            print("[!] Khong phat hien AP. Kiem tra lai monitor mode va interface.")
            sys.exit(1)

        selected = scanner.interactive_select(aps)
        if selected:
            target_bssids = [ap["bssid"] for ap in selected]
    else:
        print(f"[*] Bo qua scan, giam sat tat ca AP tren {interface}...")

    # ---- Phase 2: Sniff + Detect ----
    sniffer = WiFiSniffer(config=cfg)
    sniffer.set_target(target_bssids)

    # Xu ly Ctrl+C dep
    def shutdown(sig, frame):
        print("\n\n[*] Dang dung...")
        sniffer.stop()
        stats = sniffer.stats
        print(f"\n[SUMMARY]")
        print(f"  Beacon frames   : {stats['total_beacons']}")
        print(f"  Deauth frames   : {stats['total_deauths']}")
        print(f"  Total alerts    : {stats['total_alerts']}")
        print(f"  Log file        : {cfg['log_path']}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    sniffer.start()
    print("[*] Dang giam sat... (Nhan Ctrl+C de dung)\n")

    # Keep main thread song
    while True:
        time.sleep(5)
        if not sniffer.is_running():
            break


if __name__ == "__main__":
    main()
