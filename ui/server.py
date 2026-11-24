#!/usr/bin/env python3
"""
Web UI for the Cyber-Adaptive MLFQ simulator.

    python3 ui/server.py            # then open http://localhost:8000
    python3 ui/server.py --port 9000

Uses only the Python standard library. Every button in the page runs the
real C++ binary (./cmlfq) with the chosen options plus `--json`, and the
page draws the JSON it writes. The raw terminal output is also shown, so
it is clear that the numbers come from the C++ program.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UI_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(UI_DIR)
BINARY = os.path.join(ROOT, "cmlfq")
WORKLOAD_DIR = os.path.join(ROOT, "workloads")
ATTACKS = {"none", "ddos", "stuffing", "mixed"}
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def ensure_binary():
    """Build ./cmlfq with make if it is missing or older than the sources."""
    newest_src = 0.0
    for d in ("src", "include"):
        for f in os.listdir(os.path.join(ROOT, d)):
            newest_src = max(newest_src, os.path.getmtime(os.path.join(ROOT, d, f)))
    if not os.path.exists(BINARY) or os.path.getmtime(BINARY) < newest_src:
        print("Building ./cmlfq with make ...")
        subprocess.run(["make", "-j4"], cwd=ROOT, check=True)


def list_workloads():
    return sorted(f for f in os.listdir(WORKLOAD_DIR) if f.endswith(".txt"))


def int_arg(body, key, default, lo, hi):
    try:
        v = int(body.get(key, default))
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be an integer")
    if not lo <= v <= hi:
        raise ValueError(f"{key} must be between {lo} and {hi}")
    return v


def common_overrides(body):
    if body.get("handConfig"):
        # round-number settings used by the hand-verification examples
        return ["--config", os.path.join("workloads", "hand_config.ini")]
    args = [
        "--quantum", str(int_arg(body, "quantum", 2, 1, 100)),
        "--cs-cost", str(int_arg(body, "csCost", 1, 0, 50)),
        "--window", str(int_arg(body, "window", 50, 1, 10000)),
    ]
    if not body.get("starvationAging", True):
        args.append("--no-starvation-aging")
    return args


def generate_args(body):
    attack = body.get("attack", "mixed")
    if attack not in ATTACKS:
        raise ValueError("unknown attack type")
    return [
        "--generate",
        "--legit", str(int_arg(body, "legit", 50, 0, 2000)),
        "--bots", str(int_arg(body, "bots", 200, 0, 5000)),
        "--seed", str(int_arg(body, "seed", 42, 0, 2**31 - 1)),
        "--attack", attack,
    ]


def custom_workload_file(rows, tmpdir):
    """Validate the table typed in the browser and write it as a workload file."""
    if not isinstance(rows, list) or not rows:
        raise ValueError("add at least one process")
    if len(rows) > 500:
        raise ValueError("at most 500 processes in a custom workload")
    lines = ["# custom workload from the web UI", "# pid source arrival burst anomaly label"]
    for i, r in enumerate(rows, 1):
        src = str(r.get("source", "")).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", src):
            raise ValueError(f"row {i}: source must be 1-32 letters/digits/-_.:")
        try:
            arrival, burst = int(r["arrival"]), int(r["burst"])
            anomaly = float(r.get("anomaly", 0))
        except (KeyError, TypeError, ValueError):
            raise ValueError(f"row {i}: arrival/burst must be integers, anomaly a number")
        if arrival < 0 or burst < 1 or not 0 <= anomaly <= 1:
            raise ValueError(f"row {i}: need arrival >= 0, burst >= 1, 0 <= anomaly <= 1")
        label = "M" if r.get("malicious") else "L"
        lines.append(f"{i} {src} {arrival} {burst} {anomaly:.3f} {label}")
    path = os.path.join(tmpdir, "custom.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def run_cmlfq(args, tmpdir):
    out = os.path.join(tmpdir, "out.json")
    cmd = [BINARY] + args + ["--json", out]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)
    shown = "./cmlfq " + " ".join(a if not a.startswith(tmpdir) else os.path.basename(a) for a in args)
    if proc.returncode != 0 or not os.path.exists(out):
        raise RuntimeError((proc.stderr or proc.stdout or "cmlfq failed").strip())
    with open(out) as f:
        data = json.load(f)
    data["stdout"] = ANSI.sub("", proc.stdout)
    data["stderr"] = proc.stderr
    data["command"] = shown
    return data


def handle_api(path, body):
    with tempfile.TemporaryDirectory() as tmp:
        if path == "/api/compare":
            src = body.get("source", "generate")
            if src == "generate":
                wl = generate_args(body)
            elif src == "file":
                name = body.get("file", "")
                if name not in list_workloads():
                    raise ValueError("unknown workload file")
                wl = ["--workload", os.path.join("workloads", name)]
            elif src == "custom":
                wl = ["--workload", custom_workload_file(body.get("rows"), tmp)]
            else:
                raise ValueError("unknown workload source")
            return run_cmlfq(wl + common_overrides(body) + ["--compare"], tmp)
        if path == "/api/scenarios":
            return run_cmlfq(generate_args(body) + common_overrides(body) + ["--scenarios"], tmp)
    raise LookupError(path)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))

    def send(self, code, payload, ctype="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(UI_DIR, "index.html"), "rb") as f:
                self.send(200, f.read(), "text/html; charset=utf-8")
        elif path == "/api/workloads":
            items = []
            for name in list_workloads():
                with open(os.path.join(WORKLOAD_DIR, name)) as f:
                    n = sum(1 for ln in f if ln.strip() and not ln.lstrip().startswith("#"))
                items.append({"name": name, "processes": n})
            self.send(200, items)
        else:
            self.send(404, {"error": "not found"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            self.send(200, handle_api(self.path, body))
        except LookupError:
            self.send(404, {"error": "not found"})
        except (ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
            self.send(400, {"error": str(e)})


def main():
    ap = argparse.ArgumentParser(description="Web UI for the Cyber-Adaptive MLFQ simulator")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    a = ap.parse_args()
    ensure_binary()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    url = f"http://localhost:{a.port}"
    print(f"\n  Cyber-Adaptive MLFQ UI running at {url}   (Ctrl+C to stop)\n")
    if not a.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")


if __name__ == "__main__":
    main()
