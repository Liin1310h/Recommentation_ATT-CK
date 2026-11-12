"""prepare_run4_review.py - chuan bi duyet TOAN BO run (D2 QD 76). Chi in so dem va ma run.

 python -I scripts/survey/prepare_run4_review.py --run3-dir C:\\survey_review\\run3 --run4-dir C:\\survey_review\\run4 \
   --agreement-dir <moi, rong> --batch-dir <moi, rong> [--batch-size 50] [--seed 42]

Thu tu (loi o buoc nao thi dung, khong ghi tiep):
 1. CSV cu == CSV moi o moi cot tru quyet_dinh (102 ma trong run3/_sample.json).
 2. Bo 20 run duyet tay mu -> --agreement-dir (quyet_dinh trong); ma ghi vao run4/_agreement_codes.json.
 3. Chep quyet_dinh cu vao run4 + run4/_root_selection_run3.csv.
 4. Chia lo Gemini (run moi, chi file <ma>.csv, quyet_dinh trong).
"""
import argparse
import csv
import hashlib
import json
import os
import shutil
import statistics
import sys

COLS = ["dong", "dong_cha", "thoi_gian", "image", "image_cha", "command_line", "ung_vien", "quyet_dinh",
        "process_key"]


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def write_csv(path, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        w.writerows({k: r.get(k, "") for k in COLS} for r in rows)


def need_empty(d, name):
    if os.path.isdir(d) and os.listdir(d):
        sys.exit(f"LOI: {name} khong rong - DUNG")
    os.makedirs(d, exist_ok=True)


def key(ma):
    return hashlib.sha256(("agree:42:" + ma).encode()).hexdigest()


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--run3-dir", required=True)
    ap.add_argument("--run4-dir", required=True)
    ap.add_argument("--agreement-dir", required=True)
    ap.add_argument("--batch-dir", required=True)
    ap.add_argument("--batch-size", type=int, default=50)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    r3, r4 = a.run3_dir, a.run4_dir
    for d, n in ((a.agreement_dir, "agreement-dir"), (a.batch_dir, "batch-dir")):
        if os.path.isdir(d) and os.listdir(d):
            sys.exit(f"LOI: {n} khong rong - DUNG")

    old = sorted(json.load(open(os.path.join(r3, "_sample.json"), encoding="utf-8-sig"))["sampled_codes"])
    all4 = sorted(n[:-4] for n in os.listdir(r4) if n.endswith(".csv") and not n.startswith("_"))
    oldset = set(old)
    # file khong doc duoc (vd Defender chan): bo qua, ghi vao run4/_excluded.json (apply_review_v2 doc file nay)
    excluded = []
    for c in list(all4):
        try:
            with open(os.path.join(r4, c + ".csv"), "rb") as fh:
                fh.read()
        except OSError:
            excluded.append(c)
    if set(excluded) & oldset:
        sys.exit("LOI: file cua run cu khong doc duoc - DUNG")
    all4 = [c for c in all4 if c not in set(excluded)]
    with open(os.path.join(r4, "_excluded.json"), "w", encoding="utf-8") as fh:
        json.dump({"unreadable_codes": excluded}, fh, indent=2)
    print("bo qua file khong doc duoc:", len(excluded), excluded)

    # B2.1
    ok = bad = 0
    for c in old:
        p3, p4 = os.path.join(r3, c + ".csv"), os.path.join(r4, c + ".csv")
        same = False
        if os.path.exists(p4) and os.path.exists(p3):
            x, y = read_csv(p3), read_csv(p4)
            same = len(x) == len(y) and all(
                all(rx.get(k, "") == ry.get(k, "") for k in COLS if k != "quyet_dinh") for rx, ry in zip(x, y))
        ok, bad = (ok + 1, bad) if same else (ok, bad + 1)
    print(f"B2.1 CSV cu/moi khop: {ok} | lech: {bad}")
    if bad:
        sys.exit("LOI: CSV cu khac CSV moi - DUNG (du lieu/script khac lan 3)")
    missing = oldset - set(all4)
    if missing:
        sys.exit("LOI: thieu file run4 cho ma cu - DUNG")

    # B2.2 (truoc khi chep quyet dinh cu)
    def has_cand(c):
        return any(r["ung_vien"] == "1" for r in read_csv(os.path.join(r4, c + ".csv")))
    new = [c for c in all4 if c not in oldset]
    pick_old = sorted((c for c in old if has_cand(c)), key=key)[:10]
    pick_new = sorted((c for c in new if has_cand(c)), key=key)[:10]
    if len(pick_old) < 10 or len(pick_new) < 10:
        sys.exit(f"LOI: khong du run co ung vien (cu {len(pick_old)}, moi {len(pick_new)}) - DUNG")
    os.makedirs(a.agreement_dir, exist_ok=True)
    for c in pick_old + pick_new:
        rows = read_csv(os.path.join(r4, c + ".csv"))
        for r in rows:
            r["quyet_dinh"] = ""
        write_csv(os.path.join(a.agreement_dir, c + ".csv"), rows)
    with open(os.path.join(r4, "_agreement_codes.json"), "w", encoding="utf-8") as fh:
        json.dump({"old": pick_old, "new": pick_new}, fh, indent=2)
    print("B2.2 bo dong thuan: cu", len(pick_old), "moi", len(pick_new))

    # B2.3
    for c in old:
        r3rows = {r["dong"]: r for r in read_csv(os.path.join(r3, c + ".csv"))}
        rows = read_csv(os.path.join(r4, c + ".csv"))
        for r in rows:
            r["quyet_dinh"] = r3rows[r["dong"]].get("quyet_dinh", "")
        write_csv(os.path.join(r4, c + ".csv"), rows)
    shutil.copyfile(os.path.join(r3, "_root_selection.csv"), os.path.join(r4, "_root_selection_run3.csv"))
    print("B2.3 da chep quyet dinh cu:", len(old), "file")

    # B2.4
    os.makedirs(a.batch_dir, exist_ok=True)
    nb = 0
    for i in range(0, len(new), a.batch_size):
        nb += 1
        d = os.path.join(a.batch_dir, f"lo_{nb:03d}")
        os.makedirs(d)
        for c in new[i:i + a.batch_size]:
            shutil.copyfile(os.path.join(r4, c + ".csv"), os.path.join(d, c + ".csv"))
    # B2.5
    ncand = {c: sum(1 for r in read_csv(os.path.join(r4, c + ".csv")) if r["ung_vien"] == "1") for c in new}
    vals = sorted(ncand.values())
    src = {}
    mp = os.path.join(r4, "_run_map.csv")
    if os.path.exists(mp):
        for r in read_csv(mp):
            if r["code"] in ncand:
                src[r["source"]] = src.get(r["source"], 0) + 1
    print(f"run cu: {len(old)} | run moi: {len(new)} | so lo: {nb} | run moi 0 ung vien: {vals.count(0)}")
    if vals:
        print(f"ung vien/run moi: trung vi {statistics.median(vals)} | p90 {vals[int(len(vals) * .9)]} | max {vals[-1]}")
    print("run moi theo nguon:", src)


if __name__ == "__main__":
    main()
