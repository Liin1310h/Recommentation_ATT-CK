"""agreement.py - dong thuan nguoi (duyet tay mu) vs Gemini. Chi in so dem va ma run.

 python -I scripts/survey/agreement.py --agreement-dir <20 file nguoi duyet> --run4-dir C:\\survey_review\\run4 \
   --run3-dir C:\\survey_review\\run3 [--codes run4/_agreement_codes.json]
Gemini cua 10 run cu doc tu run3, 10 run moi doc tu run4 (chay SAU apply_review_v2.py).
"""
import argparse
import csv
import json
import os
import sys


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def acc(path):
    """-> (set dong chap_nhan, set dong ung vien)"""
    rows = read_csv(path)
    return ({r["dong"] for r in rows if (r.get("quyet_dinh") or "").strip().lower() == "chap_nhan"},
            {r["dong"] for r in rows if r.get("ung_vien") == "1"}, {r["dong"] for r in rows})


def kappa(t11, t10, t01, t00):
    n = t11 + t10 + t01 + t00
    if n == 0:
        return float("nan")
    po = (t11 + t00) / n
    pe = ((t11 + t10) * (t11 + t01) + (t01 + t00) * (t10 + t00)) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def report(name, codes, hdir, gdir):
    t = [0, 0, 0, 0]  # [both accept, human only, Gemini only, neither]
    exact = 0
    jac = []
    h_only = g_only = extra = 0
    for c in codes:
        h, cand, allr = acc(os.path.join(hdir, c + ".csv"))
        g, _, _ = acc(os.path.join(gdir, c + ".csv"))
        for d in cand:
            i = (0 if d in h else 1) * 2 + (0 if d in g else 1)
            t[i] += 1
        extra += len((h | g) - cand)
        exact += h == g
        u = h | g
        jac.append(1.0 if not u else len(h & g) / len(u))
        h_only += bool(h) and not g
        g_only += bool(g) and not h
    # t index: 0 = (h,g) both acc; 1 = h acc, g not; 2 = h not, g acc; 3 = neither
    n = sum(t)
    print(f"[{name}] run: {len(codes)} | dong ung vien: {n}")
    print(f"  2x2 nguoi x Gemini: cham-cham {t[0]} | nguoi-chap/G-khong {t[1]} | nguoi-khong/G-chap {t[2]} | "
          f"khong-khong {t[3]}")
    if n:
        print(f"  dong y {(t[0] + t[3]) / n:.3f} | Cohen kappa {kappa(*t):.3f}")
    print(f"  run tap goc trung hoan toan {exact}/{len(codes)} | Jaccard TB {sum(jac) / max(1, len(jac)):.3f} | "
          f"nguoi co goc/G khong {h_only} | G co goc/nguoi khong {g_only}")
    print(f"  dong khong phai ung vien ma nguoi hoac G chap nhan: {extra}")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--agreement-dir", required=True)
    ap.add_argument("--run4-dir", required=True)
    ap.add_argument("--run3-dir", required=True)
    ap.add_argument("--codes", default=None)
    a = ap.parse_args()
    codes = json.load(open(a.codes or os.path.join(a.run4_dir, "_agreement_codes.json"), encoding="utf-8"))
    report("run cu (Gemini run3)", codes["old"], a.agreement_dir, a.run3_dir)
    report("run moi (Gemini run4)", codes["new"], a.agreement_dir, a.run4_dir)


if __name__ == "__main__":
    main()
