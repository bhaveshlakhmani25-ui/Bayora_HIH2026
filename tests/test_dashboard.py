import json, threading, urllib.error, urllib.request
from bayora.dashboard.server import make_server, listen_v6
from test_receipt import setup_run


def get(base, path, data=None):
    return json.loads(urllib.request.urlopen(urllib.request.Request(base + path, data), timeout=5).read())


def test_dashboard_events_state_and_verify(tmp_path):
    *_, out = setup_run(tmp_path)
    httpd = make_server(str(out), 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    assert get(base, "/api/events?since=6")["total"] == 8 and len(get(base, "/api/events?since=6")["events"]) == 2
    st = get(base, "/api/state")
    assert st["statement"]["predicateType"] == "https://bayora.dev/receipt/v1" and [c["size"] for c in st["checkpoints"]] == [5, 8]
    r0 = get(base, "/api/verify", b"")
    assert r0["ok"] is True and r0["pinned"] is False          # no --trust: consistent, but keys not pinned
    t = json.loads(urllib.request.urlopen(urllib.request.Request(base + "/api/verify", json.dumps({"tamper": 2}).encode()), timeout=5).read())
    assert t["ok"] is False and t["tampered"].startswith("event #2") and get(base, "/api/verify", b"")["ok"] is True   # real log untouched
    log = out / "log.jsonl"; log.write_bytes(log.read_bytes().replace(b'{"i":1}', b'{"i":7}'))
    r = get(base, "/api/verify", b"")
    assert r["ok"] is False and "root does not match" in r["message"]
    f = urllib.request.urlopen(base + "/fonts/ibm-plex-sans.woff2", timeout=5)
    assert f.headers["Content-Type"] == "font/woff2" and f.read(4) == b"wOF2"
    for bad in ("/fonts/../server.py", "/fonts/OFL-ibm-plex-sans.txt", "/fonts/%2e%2e%2fserver.py"):
        try: urllib.request.urlopen(base + bad, timeout=5); assert False, bad
        except urllib.error.HTTPError as e: assert e.code == 404
    v6 = listen_v6(httpd)                                    # http://localhost may resolve to ::1 first
    if v6:
        assert get(f"http://[::1]:{httpd.server_address[1]}", "/api/events?since=0")["total"] == 8
        v6.shutdown()
    httpd.shutdown()
