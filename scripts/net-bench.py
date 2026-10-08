"""Two `mycel serve --net local` devices on this Mac: message latency of
consecutive sends, and a 1 GiB attachment transfer.

usage: scripts/net-bench.py <mycel binary> <work dir> <label> <big file> [--cold]
"""
import hashlib
import http.client
import json
import os
import shutil
import signal
import subprocess
import sys
import time

binary, work, label, big = sys.argv[1:5]
cold = "--cold" in sys.argv
PORTS = {"alice": 7811, "bob": 7812}
procs = []


def start(name):
    data = os.path.join(work, name)
    shutil.rmtree(data, ignore_errors=True)
    os.makedirs(data)
    log = open(os.path.join(work, f"{name}.log"), "w")
    p = subprocess.Popen(
        [binary, "serve", "--data", data, "--name", name.capitalize(), "--net", "local",
         "--http", f"127.0.0.1:{PORTS[name]}"],
        stdout=log, stderr=subprocess.STDOUT)
    procs.append(p)
    tok = os.path.join(data, "http-token")
    for _ in range(300):
        if os.path.exists(tok) and open(tok).read().strip():
            break
        time.sleep(0.1)
    addr, token = open(tok).read().split()
    return {"addr": addr, "token": token, "data": data, "pid": p.pid}


def call(dev, cmd, args=None):
    host, port = dev["addr"].split(":")
    c = http.client.HTTPConnection(host, int(port), timeout=600)
    body = json.dumps(args or {})
    c.request("POST", f"/api/cmd/{cmd}", body, {"X-Mycel": dev["token"], "Content-Type": "application/json", "Host": dev["addr"]})
    r = c.getresponse()
    out = r.read()
    if r.status != 200:
        raise RuntimeError(f"{cmd}: {r.status} {out[:300]}")
    v = json.loads(out)
    return v.get("ok", v) if isinstance(v, dict) and ("ok" in v) else v


def upload(dev, path):
    host, port = dev["addr"].split(":")
    c = http.client.HTTPConnection(host, int(port), timeout=600)
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        c.request("POST", "/api/upload?name=big.bin", f, {"X-Mycel": dev["token"], "Content-Length": str(size), "Host": dev["addr"]})
        r = c.getresponse()
        out = json.loads(r.read())
    return out["path"]


def rss(pid):
    try:
        return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)]).strip()) // 1024
    except Exception:
        return -1


def wait(what, f, timeout=60, step=0.005):
    end = time.time() + timeout
    while time.time() < end:
        v = f()
        if v:
            return v
        time.sleep(step)
    raise RuntimeError(f"timed out: {what}")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                return h.hexdigest()
            h.update(b)


try:
    a, b = start("alice"), start("bob")
    pa, pb = call(a, "get_profile"), call(b, "get_profile")
    call(a, "add_contact", {"code": pb["contactCode"]})
    call(b, "add_contact", {"code": pa["contactCode"]})
    conv = call(a, "create_conversation", {"members": [pb["id"]]})
    cid = conv["id"]
    wait("bob has the conversation", lambda: any(c["id"] == cid for c in call(b, "list_conversations")), step=0.05)
    try:
        call(b, "accept_request", {"id": cid})
    except Exception:
        pass

    def bob_has(body):
        return any(m.get("body") == body for m in call(b, "list_messages", {"id": cid, "limit": 50}))

    lat = []
    if cold:
        time.sleep(65)  # past the pool's 60 s idle timeout
    else:
        time.sleep(2)
    for i in range(10):
        body = f"{label} message {i} {time.time()}"
        t = time.time()
        call(a, "send_message", {"id": cid, "body": body})
        wait("message arrives", lambda: bob_has(body))
        lat.append((time.time() - t) * 1000)
    print(f"[{label}] message latency ms (send → visible on Bob), consecutive: " + ", ".join(f"{x:.0f}" for x in lat))
    print(f"[{label}]   first {lat[0]:.0f} ms, median of rest {sorted(lat[1:])[len(lat[1:]) // 2]:.0f} ms")

    t = time.time()
    up = upload(a, big)
    t_up = time.time() - t
    t = time.time()
    call(a, "send_message", {"id": cid, "body": f"{label} big file", "attachments": [up]})
    t_send = time.time() - t

    def att():
        for m in call(b, "list_messages", {"id": cid, "limit": 50}):
            for x in m.get("attachments") or []:
                return x["blob"]
        return None

    blob = wait("bob sees the attachment", att, step=0.05)
    peak = [0, 0]
    t = time.time()
    import threading
    done = threading.Event()

    def sample():
        while not done.is_set():
            peak[0] = max(peak[0], rss(a["pid"]))
            peak[1] = max(peak[1], rss(b["pid"]))
            time.sleep(0.5)

    th = threading.Thread(target=sample)
    th.start()
    out = call(b, "fetch_attachment", {"blob": blob})
    t_fetch = time.time() - t
    done.set()
    th.join()
    size = os.path.getsize(big)
    ok = sha(out) == sha(big)
    print(f"[{label}] 1 GiB: upload {t_up:.1f} s, encrypt+store {t_send:.1f} s, fetch+decrypt {t_fetch:.1f} s "
          f"({size / 1e6 / t_fetch:.0f} MB/s), sha256 {'match' if ok else 'MISMATCH'}, peak RSS alice {peak[0]} MB / bob {peak[1]} MB")
finally:
    for p in procs:
        p.send_signal(signal.SIGINT)
    for p in procs:
        try:
            p.wait(10)
        except Exception:
            p.kill()
    shutil.rmtree(os.path.join(work, "alice"), ignore_errors=True)
    shutil.rmtree(os.path.join(work, "bob"), ignore_errors=True)
