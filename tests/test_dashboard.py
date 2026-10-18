import json, threading, urllib.request
from bayora.dashboard.server import make_server
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
    assert get(base, "/api/verify", b"")["ok"] is True
    log = out / "log.jsonl"; log.write_bytes(log.read_bytes().replace(b'{"i":1}', b'{"i":7}'))
    r = get(base, "/api/verify", b"")
    assert r["ok"] is False and "root does not match" in r["message"]
    httpd.shutdown()
