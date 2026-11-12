"""apply_review_v2.py - ghi ket qua duyet run4 (ban sao co chinh sua cua apply_review.py, D2 QD 76).

 python -I scripts/survey/apply_review_v2.py --review-dir C:\\survey_review\\run4 --decisions decisions_run4.csv [--dry-run]

Khac v1: file co san it nhat mot quyet_dinh = DA DUYET TRUOC (run cu) -> ma do co trong bang = loi;
moi ma trong _sample.json phai da duyet truoc hoac co dong trong bang; _root_selection.csv gom
quyet dinh cu (_root_selection_run3.csv) + moi, them cot dot = run3/run4. Chi in so dem.
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
    xp = os.path.join(a.review_dir, "_excluded.json")
    excl = set(json.load(open(xp, encoding="utf-8-sig"))["unreadable_codes"]) if os.path.exists(xp) else set()
    sampled -= excl
    files = {n[:-4] for n in os.listdir(a.review_dir) if n.endswith(".csv") and not n.startswith("_")} - excl
    def has_decision(c):
        p = os.path.join(a.review_dir, c + ".csv")
        with open(p, encoding="utf-8-sig", newline="") as fh:
            for r in csv.DictReader(fh):
                if (r.get("quyet_dinh") or "").strip():
                    return True
        return False
    pre = {c for c in files if has_decision(c)}
    errors, seen, by_code = [], set(), {}
    for i, r in enumerate(read_csv(a.decisions), 2):
        code, dong = (r.get("ma_run") or "").strip(), (r.get("dong") or "").strip()
        qd = (r.get("quyet_dinh") or "").strip().lower()
        if code not in files:
            errors.append(f"dong {i}: ma_run khong co file")
            continue
        if code in pre:
            errors.append(f"dong {i}: ma_run {code} da duyet truoc (khong ghi de)")
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
        tables[code] = rows
    missing = sorted(sampled - pre - set(by_code))
    if missing:
        errors.append(f"{len(missing)} ma moi chua co dong nao trong bang: {', '.join(missing)}")
    if errors:
        print(f"LOI: {len(errors)} - KHONG GHI GI")
        for e in errors:
            print(" ", e)
        sys.exit(2)

    n_acc = sum(1 for d in by_code.values() for qd, _ in d.values() if qd == "chap_nhan")
    n_rej = sum(1 for d in by_code.values() for qd, _ in d.values() if qd == "bac")
    with_root = sum(1 for d in by_code.values() if any(qd == "chap_nhan" for qd, _ in d.values()))
    old_sel = read_csv(os.path.join(a.review_dir, "_root_selection_run3.csv"))
    old_by = {}
    for r in old_sel:
        old_by.setdefault(r["ma_run"], []).append(r["quyet_dinh"])
    old_root = sum(1 for v in old_by.values() if "chap_nhan" in v)
    print(f"da duyet truoc: {len(pre)} | run moi ghi: {len(by_code)} | chap_nhan: {n_acc} | bac: {n_rej}")
    print(f"dot run3: run co goc {old_root} | run khong goc {len(pre) - old_root}")
    print(f"dot run4: run co goc {with_root} | run khong goc {len(by_code) - with_root}")
    if a.dry_run:
        print("DRY RUN - khong ghi")
        return

    today = datetime.date.today().isoformat()
    sel = [[r["ma_run"], r["dong"], r["process_key"], r["quyet_dinh"], r["ly_do"], r["ngay"], "run3"]
           for r in old_sel]
    for code, rows in tables.items():
        for r in rows:
            if r["dong"] in by_code[code]:
                qd, why = by_code[code][r["dong"]]
                r["quyet_dinh"] = qd
                sel.append([code, r["dong"], r["process_key"], qd, why, today, "run4"])
        with open(os.path.join(a.review_dir, code + ".csv"), "w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=COLS)
            w.writeheader()
            w.writerows({k: r.get(k, "") for k in COLS} for r in rows)
    with open(os.path.join(a.review_dir, "_root_selection.csv"), "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ma_run", "dong", "process_key", "quyet_dinh", "ly_do", "ngay", "dot"])
        w.writerows(sel)
    print("da ghi", len(tables), "file + _root_selection.csv")


if __name__ == "__main__":
    main()
