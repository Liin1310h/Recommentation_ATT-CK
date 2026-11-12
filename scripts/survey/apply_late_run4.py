"""apply_late_run4.py - ghi quyet dinh cho MOT run duyet muon (vd 4cf9159c1b41 bi Defender xoa file duyet), D2 QD 90+.

 python -I scripts/survey/apply_late_run4.py --run4-dir C:\\survey_review\\run4 --code 4cf9159c1b41 \
   --file <ban da dien> [--dry-run] [--decisions-out <file>]

Kiem (sai -> dung, khong ghi gi): file co du dong, trung run4/<ma>.csv o moi cot tru quyet_dinh (xuong dong CRLF/LF coi
nhu nhau), quyet_dinh chi chap_nhan/bac, >= 1 dong co quyet_dinh, run4/<ma>.csv chua co quyet_dinh nao, ma chua co
dong trong _root_selection.csv. Ghi: sao luu vao run4/_gemini_backup (khong ghi de), thay cot quyet_dinh trong
run4/<ma>.csv, noi dong moi vao _root_selection.csv (dot = run4_muon, thay_the = 0), bo ma khoi
run4/_excluded.json, ghi decisions_run4_muon.csv o thu muc cha run4. Chi in so dem.
"""
import argparse
import csv
import datetime
import json
import os
import shutil
import sys

COLS = ["dong", "dong_cha", "thoi_gian", "image", "image_cha", "command_line", "ung_vien", "quyet_dinh",
        "process_key"]
VALID = {"chap_nhan", "bac"}


def read_csv(p):
    with open(p, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def norm(v):
    return (v or "").replace("\r\n", "\n").replace("\r", "\n")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--run4-dir", required=True)
    ap.add_argument("--code", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--decisions-out", default=None)
    a = ap.parse_args()
    r4, c = a.run4_dir, a.code
    out_dec = a.decisions_out or os.path.join(os.path.dirname(os.path.abspath(r4)), "decisions_run4_muon.csv")
    bk = os.path.join(r4, "_gemini_backup")
    p4, sp, xp = os.path.join(r4, c + ".csv"), os.path.join(r4, "_root_selection.csv"), os.path.join(r4, "_excluded.json")
    errors = []
    for p in (a.file, p4, sp):
        if not os.path.exists(p):
            errors.append(f"thieu file: {os.path.basename(p)}")
    if errors:
        print("LOI:", errors, "- KHONG GHI GI")
        sys.exit(2)
    hn, h4, sel = read_csv(a.file), read_csv(p4), read_csv(sp)
    vals = [(r.get("quyet_dinh") or "").strip().lower() for r in hn]
    if len(hn) != len(h4):
        errors.append("khac so dong")
    elif any(any(norm(x.get(k)) != norm(y.get(k)) for k in COLS if k != "quyet_dinh") for x, y in zip(hn, h4)):
        errors.append("khac file run4 o cot ngoai quyet_dinh")
    if not any(vals):
        errors.append("chua duyet (khong co quyet_dinh)")
    if any(v and v not in VALID for v in vals):
        errors.append("quyet_dinh khong hop le")
    if any((r.get("quyet_dinh") or "").strip() for r in h4):
        errors.append("run4/<ma>.csv da co quyet_dinh (khong ghi de)")
    if any(r["ma_run"] == c for r in sel):
        errors.append("ma da co dong trong _root_selection.csv")
    for n in (c + ".csv", "_root_selection_truoc_muon.csv", "_excluded_truoc_muon.json"):
        if os.path.exists(os.path.join(bk, n)):
            errors.append(f"backup da ton tai: {n} (khong ghi de)")
    if errors:
        print(f"LOI: {len(errors)} - KHONG GHI GI")
        for e in errors:
            print(" ", e)
        sys.exit(2)
    n_acc, n_rej = vals.count("chap_nhan"), vals.count("bac")
    print(f"ma {c}: dong {len(hn)} | chap_nhan: {n_acc} | bac: {n_rej} | co goc: {'co' if n_acc else 'khong'}")
    if a.dry_run:
        print("DRY RUN - khong ghi")
        return

    os.makedirs(bk, exist_ok=True)
    shutil.copyfile(p4, os.path.join(bk, c + ".csv"))
    shutil.copyfile(sp, os.path.join(bk, "_root_selection_truoc_muon.csv"))
    if os.path.exists(xp):
        shutil.copyfile(xp, os.path.join(bk, "_excluded_truoc_muon.json"))
    today = datetime.date.today().isoformat()
    new_rows, dec_rows = [], []
    for r, v in zip(h4, vals):
        r["quyet_dinh"] = v
        if v:
            new_rows.append([c, r["dong"], r["process_key"], v, "", today, "run4_muon", 0])
            dec_rows.append([c, r["dong"], v, ""])
    with open(p4, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        w.writerows({k: r.get(k, "") for k in COLS} for r in h4)
    with open(sp, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ma_run", "dong", "process_key", "quyet_dinh", "ly_do", "ngay", "dot", "thay_the"])
        for r in sel:
            w.writerow([r["ma_run"], r["dong"], r["process_key"], r["quyet_dinh"], r["ly_do"], r["ngay"], r["dot"],
                        r.get("thay_the", 0) or 0])
        w.writerows(new_rows)
    if os.path.exists(xp):
        with open(xp, encoding="utf-8-sig") as fh:
            ex = json.load(fh)
        ex["unreadable_codes"] = [x for x in ex.get("unreadable_codes", []) if x != c]
        with open(xp, "w", encoding="utf-8") as fh:
            json.dump(ex, fh, indent=2)
    with open(out_dec, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ma_run", "dong", "quyet_dinh", "ly_do"])
        w.writerows(dec_rows)
    print("da ghi 1 file + _root_selection.csv + _excluded.json + backup +", os.path.basename(out_dec))


if __name__ == "__main__":
    main()
