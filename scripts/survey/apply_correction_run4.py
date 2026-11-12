"""apply_correction_run4.py - thay quyet dinh Gemini bang quyet dinh nguoi cho 55 run khong goc (C2, D2 QD 90).

 python -I scripts/survey/apply_correction_run4.py --run4-dir C:\\survey_review\\run4 --nguoi-dir C:\\survey_review\\run4_nguoi \
   --codes C:\\survey_review\\run4\\_nguoi_codes.json [--dry-run] [--decisions-out <file>]

Kiem (sai -> dung, khong ghi gi): moi ma co file trong nguoi-dir, >= 1 dong co quyet_dinh, gia tri chi chap_nhan/bac,
file nguoi == run4/<ma>.csv o moi cot tru quyet_dinh. Ghi: sao luu run4/<ma>.csv -> run4/_gemini_backup/<ma>.csv
(khong ghi de backup co san), thay cot quyet_dinh, ghi lai _root_selection.csv (dong Gemini cua cac ma nay giu,
thay_the = 1; dong nguoi moi dot = run4_nguoi), va decisions_run4_nguoi.csv (mac dinh o thu muc cha cua run4, de
khong lan voi file run). Chi in so dem.
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
    # Excel doi CRLF/LF khi luu; chi chuan hoa xuong dong khi so sanh, khong sua du lieu.
    return (v or "").replace("\r\n", "\n").replace("\r", "\n")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--run4-dir", required=True)
    ap.add_argument("--nguoi-dir", required=True)
    ap.add_argument("--codes", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--decisions-out", default=None)
    a = ap.parse_args()
    r4, nd = a.run4_dir, a.nguoi_dir
    out_dec = a.decisions_out or os.path.join(os.path.dirname(os.path.abspath(r4)), "decisions_run4_nguoi.csv")
    codes = sorted(json.load(open(a.codes, encoding="utf-8-sig"))["codes"])
    bk = os.path.join(r4, "_gemini_backup")

    errors, human = [], {}
    for c in codes:
        pn, p4 = os.path.join(nd, c + ".csv"), os.path.join(r4, c + ".csv")
        if not os.path.exists(pn):
            errors.append(f"{c}: thieu file nguoi")
            continue
        if not os.path.exists(p4):
            errors.append(f"{c}: thieu file run4")
            continue
        hn, h4 = read_csv(pn), read_csv(p4)
        if len(hn) != len(h4):
            errors.append(f"{c}: khac so dong")
            continue
        vals = [(r.get("quyet_dinh") or "").strip().lower() for r in hn]
        if not any(vals):
            errors.append(f"{c}: nguoi chua duyet")
        if any(v and v not in VALID for v in vals):
            errors.append(f"{c}: quyet_dinh khong hop le")
        if any(any(norm(x.get(k)) != norm(y.get(k)) for k in COLS if k != "quyet_dinh") for x, y in zip(hn, h4)):
            errors.append(f"{c}: khac file run4 o cot ngoai quyet_dinh")
            continue
        if os.path.exists(os.path.join(bk, c + ".csv")):
            errors.append(f"{c}: backup da ton tai (khong ghi de)")
        human[c] = (h4, vals)
    if errors:
        print(f"LOI: {len(errors)} - KHONG GHI GI")
        for e in errors:
            print(" ", e)
        sys.exit(2)

    src = {}
    mp = os.path.join(r4, "_run_map.csv")
    if os.path.exists(mp):
        with open(mp, encoding="utf-8", newline="") as fh:
            src = {r["code"]: r["source"] for r in csv.DictReader(fh)}
    sel = read_csv(os.path.join(r4, "_root_selection.csv"))
    had_root = {c: any(r["ma_run"] == c and r["dot"] == "run4" and r["quyet_dinh"] == "chap_nhan" for r in sel)
                for c in codes}
    n_acc = sum(v == "chap_nhan" for _, vs in human.values() for v in vs)
    n_rej = sum(v == "bac" for _, vs in human.values() for v in vs)
    trans = {}
    for c, (_, vs) in human.items():
        s = src.get(c, "?")
        k = ("khong_goc->co_goc" if "chap_nhan" in vs else "van_khong_goc") if not had_root[c] else (
            "co_goc->co_goc" if "chap_nhan" in vs else "co_goc->khong_goc")
        trans.setdefault(s, {}).setdefault(k, 0)
        trans[s][k] += 1
    with_root = {}
    for c, (_, vs) in human.items():
        s = src.get(c, "?")
        with_root[s] = with_root.get(s, 0) + (1 if "chap_nhan" in vs else 0)
    print(f"run ghi: {len(human)} | chap_nhan: {n_acc} | bac: {n_rej}")
    print("run co goc sau sua theo nguon:", dict(sorted(with_root.items())))
    print("doi trang thai theo nguon:", {s: dict(sorted(v.items())) for s, v in sorted(trans.items())})
    if a.dry_run:
        print("DRY RUN - khong ghi")
        return

    os.makedirs(bk, exist_ok=True)
    shutil.copyfile(os.path.join(r4, "_root_selection.csv"), os.path.join(bk, "_root_selection_truoc_sua.csv"))
    today = datetime.date.today().isoformat()
    new_rows, dec_rows = [], []
    for c, (rows, vs) in human.items():
        shutil.copyfile(os.path.join(r4, c + ".csv"), os.path.join(bk, c + ".csv"))
        for r, v in zip(rows, vs):
            r["quyet_dinh"] = v
            if v:
                new_rows.append([c, r["dong"], r["process_key"], v, "", today, "run4_nguoi", ""])
                dec_rows.append([c, r["dong"], v, ""])
        with open(os.path.join(r4, c + ".csv"), "w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=COLS)
            w.writeheader()
            w.writerows({k: r.get(k, "") for k in COLS} for r in rows)
    hs = set(human)
    with open(os.path.join(r4, "_root_selection.csv"), "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ma_run", "dong", "process_key", "quyet_dinh", "ly_do", "ngay", "dot", "thay_the"])
        for r in sel:
            w.writerow([r["ma_run"], r["dong"], r["process_key"], r["quyet_dinh"], r["ly_do"], r["ngay"], r["dot"],
                        1 if (r["ma_run"] in hs and r["dot"] == "run4") else 0])
        w.writerows(new_rows)
    with open(out_dec, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ma_run", "dong", "quyet_dinh", "ly_do"])
        w.writerows(dec_rows)
    print("da ghi", len(human), "file + _root_selection.csv + backup +", os.path.basename(out_dec))


if __name__ == "__main__":
    main()
