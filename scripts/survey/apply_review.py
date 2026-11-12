"""apply_review.py - ghi ket qua duyet (bang tong hop) vao cot quyet_dinh cua cac file <ma run>.csv.

Chay tren may khao sat:
 python -I scripts/survey/apply_review.py --review-dir C:\\survey_review\\run3 --decisions <bang.csv> [--dry-run]

Bang dau vao (CSV, UTF-8): cot ma_run, dong, quyet_dinh, ly_do. quyet_dinh chi nhan chap_nhan / bac.
Kiem tra truoc khi ghi (sai bat ky dieu nao -> khong ghi gi, exit 2):
- ma_run phai co file <ma_run>.csv trong review-dir; dong phai ton tai trong file do;
- moi (ma_run, dong) chi xuat hien mot lan; o quyet_dinh trong file phai dang trong (khong ghi de);
- moi file duoc chon de duyet (_sample.json) phai co it nhat mot dong trong bang.
Ghi them _root_selection.csv (ma_run, dong, process_key, quyet_dinh, ly_do, ngay) vao review-dir.
Khong doc _run_map.csv. Chi in so dem.
"""
import argparse
import csv
import datetime
import json
import os
import sys

COLS = ["dong", "dong_cha", "thoi_gian", "image", "image_cha", "command_line", "ung_vien", "quyet_dinh",
        "process_key"]
VALID = {"chap_nhan", "bac"}


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--review-dir", required=True)
    ap.add_argument("--decisions", required=True)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    sampled = set(json.load(open(os.path.join(a.review_dir, "_sample.json"), encoding="utf-8-sig"))["sampled_codes"])
    files = {n[:-4] for n in os.listdir(a.review_dir) if n.endswith(".csv") and not n.startswith("_")}
    errors, seen, by_code = [], set(), {}
    for i, r in enumerate(read_csv(a.decisions), 2):
        code, dong = (r.get("ma_run") or "").strip(), (r.get("dong") or "").strip()
        qd = (r.get("quyet_dinh") or "").strip().lower()
        if code not in files:
            errors.append(f"dong {i}: ma_run khong co file")
            continue
        if qd not in VALID:
            errors.append(f"dong {i}: quyet_dinh khong hop le")
            continue
        if (code, dong) in seen:
            errors.append(f"dong {i}: trung (ma_run, dong)")
            continue
        seen.add((code, dong))
        by_code.setdefault(code, {})[dong] = (qd, (r.get("ly_do") or "").strip())

    tables = {}
    for code, dec in by_code.items():
        rows = read_csv(os.path.join(a.review_dir, code + ".csv"))
        idx = {r["dong"]: r for r in rows}
        for dong in dec:
            if dong not in idx:
                errors.append(f"{code}: dong {dong} khong ton tai")
            elif (idx[dong].get("quyet_dinh") or "").strip():
                errors.append(f"{code}: dong {dong} da co quyet_dinh (khong ghi de)")
        tables[code] = rows
    missing = sorted(sampled - set(by_code))
    if missing:
        errors.append(f"{len(missing)} file duoc chon chua co dong nao trong bang: {', '.join(missing)}")
    if errors:
        print(f"LOI: {len(errors)} - KHONG GHI GI")
        for e in errors:
            print(" ", e)
        sys.exit(2)

    n_acc = sum(1 for d in by_code.values() for qd, _ in d.values() if qd == "chap_nhan")
    n_rej = sum(1 for d in by_code.values() for qd, _ in d.values() if qd == "bac")
    runs_with_root = sum(1 for d in by_code.values() if any(qd == "chap_nhan" for qd, _ in d.values()))
    print(f"files: {len(by_code)} | chap_nhan: {n_acc} | bac: {n_rej} | run co goc: {runs_with_root} "
          f"| run khong goc: {len(by_code) - runs_with_root}")
    if a.dry_run:
        print("DRY RUN - khong ghi")
        return

    today = datetime.date.today().isoformat()
    sel = []
    for code, rows in tables.items():
        for r in rows:
            if r["dong"] in by_code[code]:
                qd, why = by_code[code][r["dong"]]
                r["quyet_dinh"] = qd
                sel.append([code, r["dong"], r["process_key"], qd, why, today])
        with open(os.path.join(a.review_dir, code + ".csv"), "w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=COLS)
            w.writeheader()
            w.writerows({k: r.get(k, "") for k in COLS} for r in rows)
    # ten bat dau bang "_" de count_gate.load_reviews bo qua
    with open(os.path.join(a.review_dir, "_root_selection.csv"), "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ma_run", "dong", "process_key", "quyet_dinh", "ly_do", "ngay"])
        w.writerows(sel)
    print("da ghi", len(tables), "file + _root_selection.csv")


if __name__ == "__main__":
    main()
