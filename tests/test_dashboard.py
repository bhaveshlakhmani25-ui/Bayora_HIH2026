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
    assert f.headers["Content-Type"] == "font/woff2" and f.read(4) == b"wOF2" and "immutable" in f.headers["Cache-Control"]
    # the page ships with the run inlined; log text cannot break out of that script block
    with open(out / "log.jsonl", "ab") as lf: lf.write(b'{"kind":"note","x":"</script><img src=x onerror=alert(1)>"}\n')
    html = urllib.request.urlopen(base + "/", timeout=5).read().decode()
    assert "window.__BOOT__ = {" in html and "</script><img" not in html and "\\u003c/script\\u003e" in html
    for bad in ("/fonts/../server.py", "/fonts/OFL-ibm-plex-sans.txt", "/fonts/%2e%2e%2fserver.py"):
        try: urllib.request.urlopen(base + bad, timeout=5); assert False, bad
        except urllib.error.HTTPError as e: assert e.code == 404
    v6 = listen_v6(httpd)                                    # http://localhost may resolve to ::1 first
    if v6:
        assert get(f"http://[::1]:{httpd.server_address[1]}", "/api/events?since=0")["total"] == get(base, "/api/events?since=0")["total"]
        v6.shutdown()
    httpd.shutdown()


def test_half_written_line_and_stray_checkpoint_file_do_not_break_the_page(tmp_path):
    from bayora.dashboard.server import page, events
    from bayora.verify import verify
    *_, out = setup_run(tmp_path)
    full = events(str(out), 0)["total"]
    with open(out / "log.jsonl", "ab") as f: f.write(b'{"kind":"isolation_probe","probe":"red->bl')   # a run still writing
    (out / "checkpoints" / "notes.txt").write_text("not a checkpoint")
    assert b"window.__BOOT__ = {" in page(str(out))
    assert events(str(out), 0)["total"] == full                 # the partial line waits until it is complete
    with open(out / "log.jsonl", "ab") as f: f.write(b'ue","result":"BLOCKED"}\n')
    assert events(str(out), full)["events"][0]["probe"] == "red->blue"
    with open(out / "log.jsonl", "rb") as f: lines = f.read().splitlines()
    (out / "log.jsonl").write_bytes(b"".join(l + b"\n" for l in lines[:-1]))   # back to the receipt's log
    assert verify(str(out / "receipt.json"), str(out / "log.jsonl"), None, str(out / "checkpoints"))[0] is True


def test_page_carries_the_exact_log_so_the_browser_can_recompute_the_root(tmp_path):
    from bayora.dashboard.server import page
    from bayora.ledger import MerkleLog, leaf_hash
    *_, out = setup_run(tmp_path)
    with open(out / "log.jsonl", "ab") as f: f.write(b'{"kind":"half')     # an unfinished line is left out, as in events()
    boot = json.loads(page(str(out)).decode().split("window.__BOOT__ = ", 1)[1].split(";</script>", 1)[0])
    m = MerkleLog(); m.leaves = [leaf_hash(l.encode()) for l in boot["log"].split("\n")[:-1]]
    assert m.root().hex() == boot["state"]["statement"]["predicate"]["log_root"]


def test_static_export_carries_run_keys_and_fonts(tmp_path):
    from bayora.dashboard.server import export
    *_, out = setup_run(tmp_path)
    keys = tmp_path / "keys.json"; keys.write_text(json.dumps({"operator": "ab", "witnesses": {}, "quorum": 2}))
    export(str(out), str(tmp_path / "site"), str(keys))
    html = (tmp_path / "site" / "index.html").read_text()
    boot = json.loads(html.split("window.__BOOT__ = ", 1)[1].split(";</script>", 1)[0])
    assert boot["static"] is True and boot["trust"]["operator"] == "ab" and boot["state"]["statement"]
    assert "/fonts/" not in html.replace('"fonts/', "") and (tmp_path / "site" / "fonts" / "ibm-plex-sans.woff2").exists()
