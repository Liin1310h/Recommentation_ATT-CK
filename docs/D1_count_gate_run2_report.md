# D1 – Kết quả run 2 (sửa `otrf_ids`, tải LFS có chọn lọc, chạy lại)

Không diễn giải số liệu; phân tích làm ở nơi khác. Số liệu là cận trên (`upper bound: process-tree filter not applied`).

## 1. Diff của count_gate.py (phần sửa ở mục A)
```diff
diff --git a/scripts/survey/count_gate.py b/scripts/survey/count_gate.py
index 3dfeb65..e083dc6 100644
--- a/scripts/survey/count_gate.py
+++ b/scripts/survey/count_gate.py
@@ -493,19 +493,32 @@ def run_evtx(pl, root, sheet_rows, tmpdir):
             pl.process(src, run_id, labels, reason, flatten_xml(el, st))
 
 
-def otrf_ids(doc):
+RE_FULL_SUB = re.compile(r"^T\d{4}\.\d{3}$", re.I)
+
+
+def otrf_ids(doc, counters=None):
+    if counters is None:
+        counters = collections.Counter()
     out = []
     for m in doc.get("attack_mappings") or []:
         if not isinstance(m, dict):
             continue
-        t = (m.get("technique") or "").strip()
+        t = (m.get("technique") or "").strip().upper()
         if not t:
             continue
         s = (m.get("sub-technique") or "").strip()
-        if s and s.lower() != "none" and s.isdigit():
-            out.append(t.upper() + "." + s.zfill(3))
+        if not s or s.lower() == "none":
+            out.append(t)
+        elif s.isdigit() and len(s) <= 3:
+            out.append(t + "." + s.zfill(3))
+        elif RE_FULL_SUB.match(s):
+            s = s.upper()
+            if s.split(".")[0] != t:
+                counters["otrf_sub_not_under_technique"] += 1
+            out.append(s)
         else:
-            out.append(t.upper())
+            counters["otrf_sub_unparsed"] += 1
+            out.append(t)
     return out
 
 
@@ -532,7 +545,7 @@ def run_otrf(pl, root):
         if not any(str(p).strip().lower() == "windows" for p in plat):
             st["skipped_non_windows_meta"] += 1
             continue
-        raw = otrf_ids(doc)
+        raw = otrf_ids(doc, st)
         labels, reason = pl.register_run(src, raw)
         run_id = "otrf:" + str(doc.get("id") or os.path.basename(mp))
         paths = []
@@ -681,7 +694,13 @@ def build_report(pl, extra):
         "scenarios_c>=30": {"value": sc_c["total"]["scenarios"],
                             "result": "ĐẠT" if sc_c["total"]["scenarios"] >= 30 else "KHÔNG ĐẠT"},
     }
+    by_src = {s: collections.Counter() for s in SOURCE_ORDER}
+    for run, labels, s in pl.dedup.values():
+        for t in labels:
+            by_src[s][t] += 1
     return {
+        "alerts_per_technique_id_by_source": {
+            s: {k: by_src[s][k] for k in sorted(by_src[s])} for s in SOURCE_ORDER},
         "note": NOTE,
         "sources": src_out,
         "alerts_total": alerts,
```

## 2. Kết quả 6 điểm kiểm tra (dữ liệu giả, đã xoá sau khi chạy)
| # | Kiểm tra | Kết quả | Output |
|---|---|---|---|
| 1 | sub-technique `T1003.001` → `T1003.001` | ĐẠT | `['T1003.001']` |
| 2 | sub-technique `010` (không nháy) → `T1003.010` | ĐẠT | `['T1003.010']` |
| 3 | sub-technique `none` → `T1003` | ĐẠT | `['T1003']` |
| 4 | technique `T1003`, sub-technique `T1055.001` → `T1055.001`, `otrf_sub_not_under_technique`=1 | ĐẠT | `['T1055.001']`, `{'otrf_sub_not_under_technique': 1}` |
| 5 | sub-technique `abc` → `T1003`, `otrf_sub_unparsed`=1 | ĐẠT | `['T1003']`, `{'otrf_sub_unparsed': 1}` |
| 6 | Chạy lại 10 điểm kiểm tra lần trước | ĐẠT | kết quả như lần trước |

## 3. Tải LFS (attack_data)
- `git lfs version`: git-lfs/3.7.1.
- B.3 (ước lượng trước khi tải): 726 file, tổng 3,934 GB, file lớn nhất 378,1 MB.
- B.4: 15 lô (50 đường dẫn/lô), thời gian tải 2733,7 giây. Lô lỗi: lô 3 và lô 11 (mã 2, Windows Defender chặn file; không đặt exclusion). Lần chạy đầu 15/15 lô lỗi do sai cú pháp tham số, đã chạy lại đúng.
- B.5 (sau khi tải, trên 726 file của danh sách): 724 có nội dung thật, 2 vẫn là con trỏ, 0 không tồn tại.
- B.6: `git -C attack_data status --porcelain` = 17 dòng.

## 4. Kết quả chạy lại
- File: `docs/survey_output/count_gate_run2.json`
- Thời gian chạy: 554,4 giây
- Tổng alert: 332251 (evtx 844, otrf 128733, splunk 202674)
- Số ID có ≥5 alert: 161 (92 là sub-technique)
- Scenario (c): 413 | Scenario (b): 122
- Gate: alerts ≥200 ĐẠT; ID ≥30 ĐẠT; scenario (c) ≥30 ĐẠT
