"""export_alerts.py - xuat alert Windows (gate lan 3) va chia dev/test theo scenario (D2 quyet dinh 58, 59).

Chay tren may khao sat, cung tham so voi count_gate.py buoc 4:
 python -I scripts/survey/export_alerts.py --splunk ... --otrf ... --evtx ... --sheet ... --stix ... \
 --review-dir C:\\survey_review\\run3 --sample C:\\survey_review\\run3\\_sample.json \
 --dev-fraction 0.5 --split-seed 42 --expect-alerts 2463 --out-dir <thu muc moi, rong>

Dung lai DUNG pipeline cua count_gate.py (iter_runs, ProcessTable, Pipeline): alert xuat ra phai trung so voi gate.
Sai so luong -> khong ghi gi, exit 2.

Dau ra (--out-dir):
 dev/alerts.jsonl alert_id, source, channel, event_id, fields (da strip, gia tri goc, KHONG co nhan)
 dev/labels.jsonl alert_id, labels (ID da chuan hoa qua STIX; da gop khi trung - label_conflict)
 dev/scenarios.jsonl alert_id, run_code, scenario_c, scenario_b
 test.zip cung 3 file cho phia test (NIEM PHONG: khong giai nen truoc moc freeze)
 manifest.json so dong + sha256 tung file, sha256 test.zip, sha256 script, tham so, so scenario moi phia
Chia: don vi = scenario (c); xep scenario theo sha256(split_seed:scenario_c); round(n*(1-dev_fraction)) scenario
dau la test. Khong in gia tri field, hostname hay duong dan log.
"""
import argparse
import collections
import hashlib
import json
import os
import shutil
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import count_gate as cg  # noqa: E402


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def components(table):
    """table: {run_id: set(keys)} -> {run_id: dai dien thanh phan lien thong} (giong count_gate.scenarios)."""
    uf, keyrun = cg.UF(), {}
    for run, keys in table.items():
        uf.find(run)
        for k in keys:
            if k in keyrun:
                uf.union(keyrun[k], run)
            else:
                keyrun[k] = run
    groups = collections.defaultdict(list)
    for run in table:
        groups[uf.find(run)].append(run)
    out = {}
    for runs in groups.values():
        rep = min(runs)  # dai dien tat dinh, khong phu thuoc thu tu union
        for r in runs:
            out[r] = rep
    return out


def jsonl(rows):
    return "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows).encode("utf-8")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    cg.add_common_args(ap)
    ap.add_argument("--review-dir", required=True)
    ap.add_argument("--sample", required=True)
    ap.add_argument("--dev-fraction", type=float, required=True)
    ap.add_argument("--split-seed", type=int, required=True)
    ap.add_argument("--expect-alerts", type=int, required=True)
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args()
    if not 0 < a.dev_fraction < 1:
        print("--dev-fraction phai trong (0, 1)")
        sys.exit(2)
    if os.path.exists(a.out_dir) and os.listdir(a.out_dir):
        print("--out-dir da ton tai va khong rong - DUNG")
        sys.exit(2)

    cg.check_stix(a.stix)
    pl = cg.Pipeline(cg.Stix(a.stix))
    reviews = cg.load_reviews(a.review_dir)
    with open(a.sample, encoding="utf-8-sig") as fh:
        sampled = set(json.load(fh)["sampled_codes"])
    kept = {}  # digest -> dict(fields, channel, event_id)
    tmp = tempfile.mkdtemp(prefix="export_alerts_")
    try:
        for src, run_id, raw, events in cg.iter_runs(a, pl.st, tmp):
            labels, reason = pl.register_run(src, raw)
            code = cg.run_code(a.seed, run_id)
            table = cg.ProcessTable()
            for f in events:
                table.add_event(f)
            table.finalize()
            if code not in sampled:
                status_all = "not_sampled"
            elif not table.procs:
                status_all = "no_tree"
            elif code not in reviews:
                status_all = "unreviewed"
            else:
                status_all = None
            keep = table.subtree(reviews.get(code, ())) if status_all is None else set()
            for f in events:
                if status_all is not None:
                    tree_ok = status_all
                else:
                    k = table.link(f)
                    tree_ok = "ambiguous" if k is None else (k in keep)
                before = pl.st[src]["pass_4_7"]
                channel, eid = cg.event_key(f)
                pl.process(src, run_id, labels, reason, f, tree_ok)
                if pl.st[src]["pass_4_7"] > before:
                    dg = next(reversed(pl.dedup))
                    kept[dg] = {"fields": dict(f), "channel": channel, "event_id": eid}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    n = len(pl.dedup)
    if n != a.expect_alerts or len(kept) != n:
        print(f"SO ALERT LECH: pipeline {n}, da giu {len(kept)}, ky vong {a.expect_alerts} - KHONG GHI GI")
        sys.exit(2)

    comp_c, comp_b = {}, {}
    for s in cg.SOURCE_ORDER:
        comp_c.update(components(pl.run_pairs[s]))
        comp_b.update(components(pl.run_hosts[s]))

    def sid(rep):
        return hashlib.sha256(f"{a.seed}:{rep}".encode("utf-8")).hexdigest()[:12]

    alerts = []
    for dg, (run_id, labels, src) in pl.dedup.items():
        k = kept[dg]
        alerts.append({
            "alert_id": dg.hex(), "source": src, "channel": k["channel"], "event_id": k["event_id"],
            "fields": k["fields"], "labels": sorted(labels), "run_code": cg.run_code(a.seed, run_id),
            "scenario_c": sid(comp_c[run_id]), "scenario_b": sid(comp_b[run_id]),
        })

    scen = sorted({x["scenario_c"] for x in alerts},
                  key=lambda s: hashlib.sha256(f"{a.split_seed}:{s}".encode("utf-8")).hexdigest())
    n_test = round(len(scen) * (1 - a.dev_fraction))
    test_scen = set(scen[:n_test])

    os.makedirs(os.path.join(a.out_dir, "dev"))
    files, parts = {}, {"dev": [], "test": []}
    for x in alerts:
        parts["test" if x["scenario_c"] in test_scen else "dev"].append(x)
    payload = {}
    for side, rows in parts.items():
        rows.sort(key=lambda x: x["alert_id"])
        payload[side] = {
            "alerts.jsonl": jsonl({k: x[k] for k in ("alert_id", "source", "channel", "event_id", "fields")}
                                  for x in rows),
            "labels.jsonl": jsonl({"alert_id": x["alert_id"], "labels": x["labels"]} for x in rows),
            "scenarios.jsonl": jsonl({k: x[k] for k in ("alert_id", "run_code", "scenario_c", "scenario_b")}
                                     for x in rows),
        }
    for name, data in payload["dev"].items():
        p = os.path.join(a.out_dir, "dev", name)
        with open(p, "wb") as fh:
            fh.write(data)
        files["dev/" + name] = {"sha256": hashlib.sha256(data).hexdigest(), "lines": data.count(b"\n")}
    zpath = os.path.join(a.out_dir, "test.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(payload["test"].items()):
            info = zipfile.ZipInfo("test/" + name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
            files["test/" + name] = {"sha256": hashlib.sha256(data).hexdigest(), "lines": data.count(b"\n")}

    here = os.path.dirname(os.path.abspath(__file__))
    manifest = {
        "export": "windows_run3",
        "params": {"seed": a.seed, "split_seed": a.split_seed, "dev_fraction": a.dev_fraction,
                   "split_unit": "scenario_c", "expect_alerts": a.expect_alerts},
        "alerts_total": n,
        "alerts": {s: len(r) for s, r in parts.items()},
        "scenarios_c": {"dev": len(scen) - n_test, "test": n_test},
        "scenarios_b_crossing_split": sum(
            1 for b in {x["scenario_b"] for x in alerts}
            if len({x["scenario_c"] in test_scen for x in alerts if x["scenario_b"] == b}) > 1),
        "label_conflict_total": sum(pl.st[s]["label_conflict"] for s in cg.SOURCE_ORDER),
        "files": files,
        "test_zip_sha256": sha256_file(zpath),
        "scripts_sha256": {n_: sha256_file(os.path.join(here, n_)) for n_ in ("count_gate.py", "export_alerts.py")},
        "stix_sha256": cg.STIX_SHA256,
    }
    with open(os.path.join(a.out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False, sort_keys=True)
    print(json.dumps({k: manifest[k] for k in ("alerts_total", "alerts", "scenarios_c", "scenarios_b_crossing_split",
                                                "test_zip_sha256")}, sort_keys=True))


if __name__ == "__main__":
    main()
