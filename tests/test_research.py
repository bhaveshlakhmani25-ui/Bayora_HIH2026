import hashlib, json, os, shutil
import pytest
from bayora import research as rs

MANIFEST = {"claims": {"C1": "a claim"}, "sources": [
    {"id": "a", "title": "A", "url": "https://example.org/a", "kind": "docs", "read": "full", "supports": ["C1"]},
    {"id": "b", "title": "B", "url": "https://example.org/b", "kind": "docs", "read": "snippet", "supports": ["C1"]}]}


def fake(pages):
    """Stands in for the TinyFish Fetch API: returns the pages it knows, and an error for the rest."""
    def call(url, key, body=None, timeout=0):
        assert key == "k" and url == rs.FETCH_URL
        return {"results": [{"url": u, "final_url": u, "title": "t", "text": pages[u]} for u in body["urls"] if u in pages],
                "errors": [{"url": u, "error": "blocked"} for u in body["urls"] if u not in pages]}
    return call


def test_the_real_manifest_is_valid_and_honest_about_how_much_was_read():
    m = rs.load_manifest(os.path.join(os.path.dirname(__file__), "..", "research", "sources.yaml"))
    assert len(m["sources"]) >= 20 and all(s["supports"] for s in m["sources"])
    assert {c for s in m["sources"] for c in s["supports"]} == set(m["claims"])      # every claim has a source


@pytest.mark.parametrize("bad", [{"read": "skimmed"}, {"supports": ["C9"]}, {"url": "ftp://x"}])
def test_manifest_rejects_bad_sources(tmp_path, bad):
    import yaml
    src = dict(MANIFEST["sources"][0], **bad)
    (tmp_path / "m.yaml").write_text(yaml.safe_dump({"claims": MANIFEST["claims"], "sources": [src]}))
    with pytest.raises(ValueError): rs.load_manifest(str(tmp_path / "m.yaml"))


def test_collect_seal_verify_and_every_way_to_break_it(tmp_path):
    out = str(tmp_path)
    rows = rs.collect(MANIFEST, out, "k", fake({"https://example.org/a": "page A"}), now=lambda: 0)
    assert [r["status"] for r in rows] == ["ok", "error"] and rows[1]["error"] == "blocked"
    assert rows[0]["sha256"] == hashlib.sha256(b"page A").hexdigest() and rows[0]["fetched_at"] == "1970-01-01T00:00:00Z"
    s = rs.seal(out, str(tmp_path / "key"))
    assert s["size"] == 2 and rs.verify_pack(out)[0] is True
    assert rs.verify_pack(out, trust="00" * 32)[0] is False                      # a different key is refused
    shutil.copytree(out, str(tmp_path / "t1")); (tmp_path / "t1" / "cache" / "a.md").write_text("page A, edited")
    ok, msg = rs.verify_pack(str(tmp_path / "t1")); assert not ok and "no longer match" in msg
    shutil.copytree(out, str(tmp_path / "t2"))
    ev = tmp_path / "t2" / "evidence.jsonl"; ev.write_text(ev.read_text().replace('"status":"ok"', '"status":"ko"', 1))
    ok, msg = rs.verify_pack(str(tmp_path / "t2")); assert not ok and "root does not match" in msg


def test_watch_reports_a_page_that_changed_since_the_last_check(tmp_path):
    state = tmp_path / "m.json"
    state.write_text(json.dumps({"monitors": [{"id": "m1", "name": "Art. 55", "url": "https://example.org/a"}]}))
    text = ["version 1"]
    call = lambda url, key, body=None, timeout=0: {"run": {"results": [{"text": text[0]}]}}
    assert rs.watch(str(state), str(tmp_path), "k", call) == []                # first run is the baseline
    assert rs.watch(str(state), str(tmp_path), "k", call) == []                # unchanged
    text[0] = "version 2"
    d = rs.watch(str(state), str(tmp_path), "k", call)
    assert len(d) == 1 and d[0]["monitor"] == "Art. 55" and d[0]["was"] != d[0]["now"]
    assert json.loads((tmp_path / "drift.jsonl").read_text())["url"] == "https://example.org/a"
