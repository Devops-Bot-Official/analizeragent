#!/usr/bin/env python3
# crow_analyzer_agent.py
import os, sys, time, json, pathlib, signal, secrets, hashlib, hmac, base64
from datetime import datetime, timezone
from typing import Dict, Any, List
import requests, psutil

CONF_PATH = os.environ.get("CROW_CONF", "/etc/crow/analyzer.env")

def load_env(path: str) -> Dict[str, str]:
    out = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#") or "=" not in ln: continue
                k, v = ln.split("=", 1)
                out[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return out

E = load_env(CONF_PATH)
BACKEND_BASE = E.get("BACKEND_BASE", "").rstrip("/")
ENTRA_ID     = E.get("ENTRA_ID", "")             # e.g. 814060
RUNNER_NAME  = E.get("RUNNER_NAME", "")          # e.g. runner-01
CATEGORY     = E.get("CATEGORY", "linux")
AGENT_TOKEN  = E.get("AGENT_TOKEN", "")          # provided manually for v0
INTERVAL_SEC = int(E.get("INTERVAL_SEC", "5"))
QUEUE_PATH   = E.get("QUEUE_PATH", "/var/lib/crow/analyzer_queue.jsonl")

if not BACKEND_BASE or not ENTRA_ID or not RUNNER_NAME or not AGENT_TOKEN:
    print("Missing BACKEND_BASE / ENTRA_ID / RUNNER_NAME / AGENT_TOKEN in config", file=sys.stderr)
    sys.exit(2)

session = requests.Session()
session.headers.update({"User-Agent": "crow-analyzer/0.1"})
session.timeout = 15

RUN = True
def handle_signal(signum, frame):
    global RUN
    RUN = False
signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

def utc_iso():
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00","Z")

_prev_net = psutil.net_io_counters(pernic=True)

def collect_series() -> List[Dict[str, Any]]:
    ts = utc_iso()
    series = []

    # CPU
    try:
        cpu = psutil.cpu_percent(interval=None)
        series.append(("cpu.usage_percent", {"core":"all"}, float(cpu), "percent"))
    except Exception: pass

    # Memory
    try:
        vm = psutil.virtual_memory()
        series.append(("memory.used_percent", {}, float(vm.percent), "percent"))
    except Exception: pass

    # Disk (partitions)
    try:
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                series.append(("disk.used_percent", {"mount": part.mountpoint}, float(usage.percent), "percent"))
            except Exception:
                pass
    except Exception: pass

    # Network throughput (MB/s, tx+rx)
    global _prev_net
    try:
        now = psutil.net_io_counters(pernic=True)
        for iface, curr in now.items():
            prev = _prev_net.get(iface)
            if prev:
                dt = max(INTERVAL_SEC, 1)
                tx = max(curr.bytes_sent - prev.bytes_sent, 0) / dt / (1024*1024)
                rx = max(curr.bytes_recv - prev.bytes_recv, 0) / dt / (1024*1024)
                series.append(("network.throughput_mb_s", {"iface": iface, "direction":"txrx"}, float(tx+rx), "mb_s"))
        _prev_net = now
    except Exception: pass

    # Temperature (best effort)
    try:
        temps = psutil.sensors_temperatures() or {}
        for chip, entries in temps.items():
            if entries:
                series.append(("sensors.temperature_c", {"chip": chip}, float(entries[0].current), "celsius"))
    except Exception: pass

    # Process count
    try:
        series.append(("system.process_count", {}, float(len(psutil.pids())), "count"))
    except Exception: pass

    # pack to unique metric+labels
    s_map: Dict[str, Dict[str, Any]] = {}
    for metric, labels, value, unit in series:
        key = metric + "|" + json.dumps(labels, sort_keys=True)
        if key not in s_map:
            s_map[key] = {"metric": metric, "unit": unit, "labels": labels, "points": []}
        s_map[key]["points"].append({"t": ts, "v": value})
    return list(s_map.values())

def enqueue(obj: Dict[str, Any]):
    pathlib.Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(QUEUE_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")

def drain() -> List[Dict[str, Any]]:
    p = pathlib.Path(QUEUE_PATH)
    if not p.exists(): return []
    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("", encoding="utf-8")
    out = []
    for ln in lines:
        try: out.append(json.loads(ln))
        except Exception: pass
    return out

def body_sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sign_request(secret: str, method: str, path: str, body: bytes, sent_at: str, nonce: str) -> str:
    canon = (
        f"{method.upper()}\n{path}\n"
        f"content-sha256={body_sha256_hex(body)}\n"
        f"x-sent-at={sent_at}\n"
        f"x-nonce={nonce}\n"
    )
    mac = hmac.new(secret.encode(), canon.encode(), hashlib.sha256).digest()
    return "v1=" + base64.b64encode(mac).decode("ascii")

def ingest(batch: List[Dict[str, Any]]):
    path = "/agent/analizer/ingest"
    url  = f"{BACKEND_BASE}{path}"
    sent_at = utc_iso()
    nonce = secrets.token_hex(16)
    body = json.dumps({"batch": batch}).encode("utf-8")
    sig = sign_request(AGENT_TOKEN, "POST", path, body, sent_at, nonce)
    r = session.post(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {AGENT_TOKEN}",
        "X-Sent-At": sent_at,
        "X-Nonce": nonce,
        "X-Signature": sig,
        "X-Runner-Name": RUNNER_NAME,
        "X-Category": CATEGORY,
        "X-Entra-Id": ENTRA_ID,
    })
    r.raise_for_status()

def main():
    print("[crow-agent] starting; backend:", BACKEND_BASE, "runner:", RUNNER_NAME)
    while RUN:
        try:
            series = collect_series()
            payload = {
                "runner_name": RUNNER_NAME,
                "category": CATEGORY,
                "entra_id": ENTRA_ID,
                "sent_at": utc_iso(),
                "series": series
            }
            enqueue(payload)
            items = drain()
            if items:
                # chunk by ~200 points (roughly)
                chunk, pts = [], 0
                for it in items:
                    pts += sum(len(s["points"]) for s in it["series"])
                    chunk.append(it)
                    if pts >= 200:
                        ingest(chunk); chunk=[]; pts=0
                if chunk:
                    ingest(chunk)
        except Exception as e:
            print("[crow-agent] loop error:", e, file=sys.stderr)
        time.sleep(INTERVAL_SEC)

if __name__ == "__main__":
    main()
