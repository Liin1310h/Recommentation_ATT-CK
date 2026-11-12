"""export_extras_run4.py - so dem bo sung cho windows_run4 (C4, D2 QD 93). Chi in / ghi so dem, khong gia tri field.

 python -I scripts/survey/export_extras_run4.py <cung tham so voi lenh C3> --manifest <windows_run4/manifest.json>
   [--extras-out C:\\survey_review\\run4_extras.json]

Goi export_alerts_v3.export_core(...) voi dung tham so C3 (du lieu chi nam trong bo nho; khong ghi vao --out-dir,
khong doc / giai nen test.zip). Kiem sha256 + so dong tung file payload_run4 trung manifest.json; lech -> dung.
 (a) field thieu: theo (phia, nguon, nhom event) x field; thieu = vang hoac rong. Chi in o ma field co xuat hien
     (la khoa trong fields) o it nhat mot alert cung nhom event tren toan run4.
 (b) pheu theo technique: runs_labeled / runs_with_alert (run gan voi alert qua run_code cua ban dai dien) /
     alerts_dev / alerts_test.
"""
import argparse
import collections
import hashlib
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import count_gate as cg  # noqa: E402
import export_alerts as ea  # noqa: E402
import export_alerts_v3 as v3  # noqa: E402

FIELDS = ("Image", "CommandLine", "ParentImage", "ParentCommandLine", "TargetFilename", "TargetObject",
          "ImageLoaded", "ScriptBlockText", "NewProcessName")


def parse_jsonl(data):
    return [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]


def verify_manifest(payload, manifest):
    """-> danh sach loi (rong = khop): sha256 + so dong tung file payload so voi manifest['files']."""
    got, want = v3.file_hashes(payload), manifest["files"]
    problems = [f"thieu trong manifest: {k}" for k in got if k not in want]
    problems += [f"thieu trong payload: {k}" for k in want if k not in got]
    for k in got:
        if k in want and (got[k]["sha256"] != want[k]["sha256"] or got[k]["lines"] != want[k]["lines"]):
            problems.append(f"lech: {k}")
    return problems


def is_missing(v):
    return all(x is None or x == "" for x in cg.values(v)) if v is not None else True


def missing_fields(payload):
    """-> list dict(side, source, group, field, n_alerts, n_missing), chi o ma field ap dung cho nhom."""
    cells = collections.defaultdict(lambda: [0, 0])  # (side, src, group, field) -> [n_alerts, n_missing]
    n_alerts = collections.Counter()
    applies = set()  # (group, field): field la khoa o it nhat mot alert cua nhom
    for side in ("dev", "test"):
        for a in parse_jsonl(payload[side]["alerts.jsonl"]):
            group = v3.EVENT_GROUPS.get(a["event_id"], "?")
            n_alerts[(side, a["source"], group)] += 1
            for fld in FIELDS:
                if fld in a["fields"]:
                    applies.add((group, fld))
                c = cells[(side, a["source"], group, fld)]
                c[1] += 1 if is_missing(a["fields"].get(fld)) else 0
    out = []
    for (side, src, group), n in sorted(n_alerts.items()):
        for fld in FIELDS:
            if (group, fld) in applies:
                out.append({"side": side, "source": src, "group": group, "field": fld, "n_alerts": n,
                            "n_missing": cells[(side, src, group, fld)][1]})
    return out


def funnel(payload, run_labels, sample, seed):
    """run_labels: {run_id: (src, labels)}. -> list dict(technique, runs_labeled, runs_with_alert, alerts_dev,
    alerts_test) theo nhan DA XU LY (cung ham chuan hoa voi export)."""
    alert_runs, n_side = set(), {"dev": collections.Counter(), "test": collections.Counter()}
    for side in ("dev", "test"):
        for r in parse_jsonl(payload[side]["scenarios.jsonl"]):
            alert_runs.add(r["run_code"])
        for r in parse_jsonl(payload[side]["labels.jsonl"]):
            for t in r["labels"]:
                n_side[side][t] += 1
    labeled, with_alert = collections.Counter(), collections.Counter()
    for run_id, (_, labels) in run_labels.items():
        code = cg.run_code(seed, run_id)
        if code not in sample:
            continue
        for t in labels:
            labeled[t] += 1
            if code in alert_runs:
                with_alert[t] += 1
    techs = sorted(set(labeled) | set(n_side["dev"]) | set(n_side["test"]))
    return [{"technique": t, "runs_labeled": labeled[t], "runs_with_alert": with_alert[t],
             "alerts_dev": n_side["dev"][t], "alerts_test": n_side["test"][t]} for t in techs]


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    cg.add_common_args(ap)
    for a in ("run3-review-dir", "run3-sample", "run3-manifest", "run4-review-dir", "run4-sample", "out-dir",
              "manifest"):
        ap.add_argument("--" + a, required=True)
    ap.add_argument("--split-seed", type=int, required=True)
    ap.add_argument("--dev-fraction", type=float, required=True)
    ap.add_argument("--dedup-mode", choices=("old", "envelope_free"), required=True)
    ap.add_argument("--envelope-fields", default=None)
    ap.add_argument("--pid-alive", choices=("off", "on"), required=True)
    ap.add_argument("--extras-out", default=r"C:\survey_review\run4_extras.json")
    a = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    hashes = {n: ea.sha256_file(os.path.join(here, n)) for n in ("count_gate.py", "export_alerts.py",
                                                                 "export_alerts_v3.py", "export_extras_run4.py")}
    bad = [n for n, h in v3.PINNED.items() if hashes[n] != h]
    if bad:
        print("SCRIPT LECH HASH DA PIN:", bad, "- DUNG")
        sys.exit(2)
    outd, extras = os.path.abspath(a.out_dir), os.path.abspath(a.extras_out)
    if os.path.commonpath([outd, extras]) == outd or os.path.exists(extras):
        print("--extras-out nam trong --out-dir hoac da ton tai - DUNG")
        sys.exit(2)
    envelope = []
    if a.dedup_mode == "envelope_free":
        if not a.envelope_fields:
            print("--envelope-fields bat buoc khi envelope_free")
            sys.exit(2)
        with open(a.envelope_fields, encoding="utf-8") as fh:
            envelope = json.load(fh)
    cg.check_stix(a.stix)
    stix = cg.Stix(a.stix)
    with open(a.run3_sample, encoding="utf-8-sig") as fh:
        s3 = set(json.load(fh)["sampled_codes"])
    with open(a.run4_sample, encoding="utf-8-sig") as fh:
        s4 = set(json.load(fh)["sampled_codes"])
    with open(a.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    run3 = {"sample": s3, "reviews": cg.load_reviews(a.run3_review_dir)}
    run4 = {"sample": s4, "reviews": cg.load_reviews(a.run4_review_dir)}
    run_labels = {}

    def tap(gen):
        for item in gen:
            src, run_id, raw, _ = item
            run_labels[run_id] = (src, cg.normalize_labels(stix, raw)[0])
            yield item

    tmp = tempfile.mkdtemp(prefix="export_extras_")
    st_dummy = {s: collections.Counter() for s in cg.SOURCE_ORDER}
    try:
        res = v3.export_core(tap(cg.iter_runs(a, st_dummy, tmp)), stix, a.seed, a.split_seed, a.dev_fraction,
                             run3, run4, a.dedup_mode, envelope, a.pid_alive == "on")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    problems = verify_manifest(res["payload_run4"], manifest)
    if problems:
        print(f"KIEM MANIFEST THAT BAI ({len(problems)} loi) - KHONG IN SO DEM, KHONG GHI GI")
        sys.exit(2)
    print(f"manifest khop: {len(manifest['files'])} file (sha256 + so dong)")
    pay = res["payload_run4"]
    miss = missing_fields(pay)
    fun = funnel(pay, run_labels, s4, a.seed)
    zero = [r["technique"] for r in fun if r["runs_labeled"] > 0 and r["alerts_dev"] + r["alerts_test"] == 0]
    out = {"manifest_check": {"files": len(manifest["files"]), "match": True},
           "run_counts": {"runs_seen": len(run_labels),
                          "runs_in_sample": sum(1 for r in run_labels if cg.run_code(a.seed, r) in s4),
                          "sample_codes": len(s4)},
           "missing_fields": miss, "funnel": fun, "funnel_zero_alert": zero}
    with open(extras, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False, sort_keys=True)
    print("run da doc:", out["run_counts"])
    print("o (phia,nguon,nhom,field):", len(miss), "| technique:", len(fun),
          "| technique co run nhan nhung 0 alert:", len(zero))
    print("sha256 export_extras_run4.py", hashes["export_extras_run4.py"])
    print("sha256 export_alerts_v3.py", hashes["export_alerts_v3.py"])
    print("sha256 run4_extras.json", ea.sha256_file(extras))


if __name__ == "__main__":
    main()
