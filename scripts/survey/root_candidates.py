"""root_candidates.py - de xuat tien trinh goc cho tung run va tao file duyet (D2 3.1, quyet dinh 52, 53).

Chay:
 python -I scripts/survey/root_candidates.py --splunk ... --otrf ... --evtx ... --sheet ... --stix ... \
 --review-dir <thu muc duyet> --budget <so dong ung vien toi da> [--seed 42]

Dau ra trong --review-dir (chi tren may khao sat):
- <ma run>.csv : moi run mot file de NGUOI DUYET mo bang Excel. Ma run = sha256(seed:run_id)[:12], khong chua
 ten file / thu muc / nhan. Technique ID va tag attack.* trong cac cot van ban da bi che thanh <ID> / <TAG>.
 Cot quyet_dinh: ghi chap_nhan cho tien trinh goc, bac cho ung vien sai; co the ghi chap_nhan cho bat ky
 dong nao khac (them goc). Run duoc coi la DA DUYET khi co it nhat mot dong co quyet_dinh.
- _run_map.csv : doi chieu ma run <-> nguon/run. NGUOI DUYET KHONG MO FILE NAY.
- _stats.json : thong ke (chi so dem); _sample.json : danh sach ma run duoc chon de duyet.

Quy tac ung vien (cau truc cha-con, khong dung Sigma / detection rule): tien trinh co cha thuoc PARENT_IMAGES,
khong co to tien thuoc EXCLUDE_ANCESTORS; chi giu ung vien tren cung.
Run khong con nhan sau chuan hoa, hoac khong co event tao tien trinh (Sysmon 1 / Security 4688): khong tao file.
Neu tong so ung vien > --budget: chon mau run TAT DINH, phan tang theo nguon (quota ti le voi so ung vien cua
nguon), trong moi nguon xep run theo sha256(seed:run_id) va lay den khi du quota.
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import shutil
import statistics
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import count_gate as cg  # noqa: E402

PARENT_IMAGES = {"cmd.exe", "powershell.exe", "pwsh.exe", "explorer.exe", "wscript.exe", "cscript.exe",
                 "mshta.exe", "rundll32.exe", "python.exe"}
EXCLUDE_ANCESTORS = {"services.exe", "svchost.exe", "wininit.exe", "smss.exe", "csrss.exe", "lsass.exe"}
RE_TAG = re.compile(r"attack\.[a-z0-9._-]+", re.I)
MAX_TEXT = 2000


def mask(s):
    s = cg.RE_LEAK1.sub("<ID>", s or "")
    s = RE_TAG.sub("<TAG>", s)
    return s[:MAX_TEXT]


def stratified_sample(runs, budget, seed):
    """runs: list (src, run_id, code, n_cand). -> set ma run duoc chon."""
    total = sum(r[3] for r in runs)
    if total <= budget:
        return {r[2] for r in runs}
    by_src = collections.defaultdict(list)
    for r in runs:
        by_src[r[0]].append(r)
    chosen = set()
    for src, lst in sorted(by_src.items()):
        quota = budget * sum(r[3] for r in lst) / total
        acc = 0
        for r in sorted(lst, key=lambda r: hashlib.sha256(f"{seed}:{r[1]}".encode()).hexdigest()):
            if acc >= quota:
                break
            chosen.add(r[2])
            acc += r[3]
    return chosen


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    cg.add_common_args(ap)
    ap.add_argument("--review-dir", required=True)
    ap.add_argument("--budget", type=int, required=True)
    a = ap.parse_args()
    cg.check_stix(a.stix)
    stix = cg.Stix(a.stix)
    os.makedirs(a.review_dir, exist_ok=True)
    if any(n.endswith(".csv") and not n.startswith("_") for n in os.listdir(a.review_dir)):
        print("review-dir da co file duyet - DUNG (khong ghi de ket qua duyet)")
        sys.exit(2)
    st = {s: collections.Counter() for s in cg.SOURCE_ORDER}
    stats = {s: collections.Counter() for s in cg.SOURCE_ORDER}
    runs, tables = [], {}
    tmp = tempfile.mkdtemp(prefix="root_cand_")
    try:
        for src, run_id, raw, events in cg.iter_runs(a, st, tmp):
            stats[src]["runs"] += 1
            labels, _, _ = cg.normalize_labels(stix, raw)
            if not labels:
                stats[src]["runs_no_label_after_norm"] += 1
                continue
            t = cg.ProcessTable()
            for f in events:
                t.add_event(f)
            t.finalize()
            if not t.procs:
                stats[src]["runs_no_process_events"] += 1
                continue
            cand = t.candidates(PARENT_IMAGES, EXCLUDE_ANCESTORS)
            code = cg.run_code(a.seed, run_id)
            stats[src]["runs_with_processes"] += 1
            stats[src]["processes"] += len(t.procs)
            stats[src]["candidates"] += len(cand)
            if not cand:
                stats[src]["runs_zero_candidates"] += 1
            runs.append((src, run_id, code, len(cand)))
            tables[code] = (t, cand)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    chosen = stratified_sample(runs, a.budget, a.seed)
    with open(os.path.join(a.review_dir, "_run_map.csv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["code", "source", "run_id", "candidates", "sampled"])
        for src, run_id, code, n in runs:
            w.writerow([code, src, run_id, n, int(code in chosen)])
    for src, run_id, code, n in runs:
        if code not in chosen:
            continue
        t, cand = tables[code]
        order = sorted(t.procs.values(), key=lambda r: (r["start"] is None, r["start"] or cg.datetime.datetime.min,
                                                        r["key"]))
        rowno = {r["key"]: i for i, r in enumerate(order, 1)}
        with open(os.path.join(a.review_dir, code + ".csv"), "w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["dong", "dong_cha", "thoi_gian", "image", "image_cha", "command_line", "ung_vien",
                        "quyet_dinh", "process_key"])
            for r in order:
                w.writerow([rowno[r["key"]], rowno.get(r["parent_key_known"], ""),
                            r["start"].isoformat() if r["start"] else "", mask(r["image"]), mask(r["parent_image"]),
                            mask(r["cmd"]), 1 if r["key"] in cand else 0, "", r["key"]])

    per_run = [n for _, _, code, n in runs if code in chosen]
    summary = {
        "by_source": {s: dict(stats[s]) for s in cg.SOURCE_ORDER},
        "read_counters": {s: dict(st[s]) for s in cg.SOURCE_ORDER},
        "total_candidates": sum(r[3] for r in runs),
        "budget": a.budget,
        "sampling_applied": len(chosen) < len(runs),
        "runs_for_review": len(chosen),
        "candidates_for_review": sum(per_run),
        "candidates_per_reviewed_run": {
            "median": statistics.median(per_run) if per_run else None,
            "p90": sorted(per_run)[int(len(per_run) * .9)] if per_run else None,
            "max": max(per_run) if per_run else None},
        "runs_for_review_by_source": dict(collections.Counter(src for src, _, c, _ in runs if c in chosen)),
        "parent_images": sorted(PARENT_IMAGES), "exclude_ancestors": sorted(EXCLUDE_ANCESTORS), "seed": a.seed,
    }
    with open(os.path.join(a.review_dir, "_stats.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    with open(os.path.join(a.review_dir, "_sample.json"), "w", encoding="utf-8") as fh:
        json.dump({"sampled_codes": sorted(chosen)}, fh, indent=2)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
