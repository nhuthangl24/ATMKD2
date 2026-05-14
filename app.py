"""
webapp/app.py
-------------
FastAPI dashboard cho WiFi Security Monitor.
Chay: sudo .venv/bin/python -m uvicorn webapp.app:app --host 0.0.0.0 --port 8000
"""

import json
import yaml
import time
import threading
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from detector.scanner import APScanner
from detector.sniffer import WiFiSniffer

# -----------------------------------------------
# App setup
# -----------------------------------------------
app = FastAPI(title="WiFi Security Monitor")
templates = Jinja2Templates(directory="webapp/templates")

CONFIG_PATH = "config/config.yaml"
_sniffer: WiFiSniffer | None = None
_recent_alerts: list = []   # Buffer 100 alert gan nhat cho dashboard
_lock = threading.Lock()


# -----------------------------------------------
# Helper
# -----------------------------------------------
def _load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    return {
        "interface": cfg.get("interface", "wlan1mon"),
        "whitelist_path": cfg.get("whitelist_path", "config/whitelist.json"),
        "log_path": cfg.get("log_path", "logs/wifi_alerts.jsonl"),
        "interactive_scan": cfg.get("interactive_scan", False),
        "scan_seconds": cfg.get("scan_seconds", 10),
        "scan_max_results": cfg.get("scan_max_results", 20),
        "ssid_similarity_threshold": cfg.get("ssid_similarity_threshold", 0.85),
        "alert_cooldown_seconds": cfg.get("alert_cooldown_seconds", 30),
        "deauth_window_seconds": cfg.get("deauth_window_seconds", 10),
        "deauth_threshold": cfg.get("deauth_threshold", 20),
        "opensearch": cfg.get("opensearch", {"enabled": False}),
        "telegram": cfg.get("telegram", {"enabled": False}),
    }


def _on_alert(alert: dict):
    """Callback duoc goi khi sniffer tao alert moi."""
    with _lock:
        _recent_alerts.insert(0, alert)
        if len(_recent_alerts) > 100:
            _recent_alerts.pop()


# -----------------------------------------------
# Routes: Pages
# -----------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# -----------------------------------------------
# Routes: API - Status
# -----------------------------------------------
@app.get("/api/status")
async def api_status():
    global _sniffer
    cfg = _load_config()
    return {
        "running": _sniffer.is_running() if _sniffer else False,
        "interface": cfg["interface"],
        "stats": _sniffer.stats if _sniffer else {},
    }


# -----------------------------------------------
# Routes: API - Scan
# -----------------------------------------------
@app.post("/api/scan")
async def api_scan():
    """Quet AP trong 10 giay, tra ve danh sach."""
    cfg = _load_config()
    scanner = APScanner(interface=cfg["interface"])
    aps = scanner.scan(
        seconds=cfg.get("scan_seconds", 10),
        max_results=cfg.get("scan_max_results", 20),
    )
    return {"aps": aps}


# -----------------------------------------------
# Routes: API - Monitor control
# -----------------------------------------------
@app.post("/api/monitor/start")
async def api_start(request: Request, background_tasks: BackgroundTasks):
    global _sniffer, _recent_alerts

    body = await request.json()
    target_bssids = body.get("target_bssids", None)  # None = tat ca

    cfg = _load_config()

    # Dung sniffer cu neu dang chay
    if _sniffer and _sniffer.is_running():
        _sniffer.stop()
        time.sleep(0.5)

    _recent_alerts.clear()
    _sniffer = WiFiSniffer(config=cfg)
    _sniffer.set_target(target_bssids)
    _sniffer.add_alert_callback(_on_alert)
    _sniffer.start()

    return {"status": "started", "interface": cfg["interface"]}


@app.post("/api/monitor/stop")
async def api_stop():
    global _sniffer
    if _sniffer:
        _sniffer.stop()
    return {"status": "stopped"}


# -----------------------------------------------
# Routes: API - Alerts
# -----------------------------------------------
@app.get("/api/alerts")
async def api_alerts(limit: int = 50, event_type: Optional[str] = None):
    """Lay danh sach alert gan nhat."""
    with _lock:
        data = list(_recent_alerts)

    if event_type:
        data = [a for a in data if a.get("event_type") == event_type]

    return {"alerts": data[:limit], "total": len(data)}


@app.get("/api/alerts/log")
async def api_alerts_log(limit: int = 100):
    """Doc log file JSONL va tra ve."""
    cfg = _load_config()
    log_path = Path(cfg["log_path"])
    alerts = []

    if log_path.exists():
        with open(log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for line in reversed(lines[-limit:]):
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    pass

    return {"alerts": alerts, "total": len(alerts)}


@app.delete("/api/alerts/log")
async def api_clear_log():
    """Xoa log file."""
    cfg = _load_config()
    log_path = Path(cfg["log_path"])
    if log_path.exists():
        log_path.write_text("")
    with _lock:
        _recent_alerts.clear()
    return {"status": "cleared"}


# -----------------------------------------------
# Routes: API - Whitelist
# -----------------------------------------------
@app.get("/api/whitelist")
async def api_get_whitelist():
    cfg = _load_config()
    wl_path = Path(cfg["whitelist_path"])
    if not wl_path.exists():
        return {"whitelist": []}
    with open(wl_path, "r", encoding="utf-8") as f:
        return {"whitelist": json.load(f)}


@app.post("/api/whitelist")
async def api_add_whitelist(request: Request):
    """Them AP vao whitelist."""
    body = await request.json()
    required = ["ssid", "bssid"]
    for field in required:
        if not body.get(field):
            raise HTTPException(status_code=400, detail=f"Missing field: {field}")

    cfg = _load_config()
    wl_path = Path(cfg["whitelist_path"])

    whitelist = []
    if wl_path.exists():
        with open(wl_path, "r", encoding="utf-8") as f:
            whitelist = json.load(f)

    # Kiem tra trung BSSID
    new_bssid = body["bssid"].upper()
    for ap in whitelist:
        if ap.get("bssid", "").upper() == new_bssid:
            raise HTTPException(status_code=409, detail="BSSID already in whitelist")

    entry = {
        "ssid": body["ssid"],
        "bssid": new_bssid,
        "channel": body.get("channel", 0),
        "encryption": body.get("encryption", "WPA2"),
        "note": body.get("note", ""),
    }
    whitelist.append(entry)

    with open(wl_path, "w", encoding="utf-8") as f:
        json.dump(whitelist, f, indent=2, ensure_ascii=False)

    # Reload detector neu dang chay
    if _sniffer:
        _sniffer.rogue_detector.reload_whitelist()

    return {"status": "added", "entry": entry}


@app.delete("/api/whitelist/{bssid}")
async def api_delete_whitelist(bssid: str):
    """Xoa AP khoi whitelist theo BSSID."""
    cfg = _load_config()
    wl_path = Path(cfg["whitelist_path"])

    if not wl_path.exists():
        raise HTTPException(status_code=404, detail="Whitelist not found")

    with open(wl_path, "r", encoding="utf-8") as f:
        whitelist = json.load(f)

    new_wl = [ap for ap in whitelist if ap.get("bssid", "").upper() != bssid.upper()]

    if len(new_wl) == len(whitelist):
        raise HTTPException(status_code=404, detail="BSSID not found")

    with open(wl_path, "w", encoding="utf-8") as f:
        json.dump(new_wl, f, indent=2, ensure_ascii=False)

    if _sniffer:
        _sniffer.rogue_detector.reload_whitelist()

    return {"status": "deleted", "bssid": bssid}


# -----------------------------------------------
# Routes: API - Deauth stats
# -----------------------------------------------
@app.get("/api/deauth/stats")
async def api_deauth_stats():
    if not _sniffer:
        return {"stats": {}}
    return {"stats": _sniffer.deauth_detector.get_stats()}
