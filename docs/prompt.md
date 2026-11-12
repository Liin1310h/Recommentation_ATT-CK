# Prompt cho AI trên máy khảo sát — lượt 2: duyệt lại 55 run, export windows_run4 (2026-11-11)

Bạn là kỹ sư dữ liệu trên máy khảo sát của dự án "Gợi ý technique MITRE ATT&CK cho alert Windows". Lượt này có 3
phần, làm đúng thứ tự: (C1) chuẩn bị bảng 55 run cho người duyệt; (C2) ghi quyết định người duyệt; (C3) export
`windows_run4` bằng `export_alerts_v3.py`. Không làm C3 khi C2 chưa xong.

## Ràng buộc bắt buộc (giữ nguyên các lượt trước)

-**Không sửa** `count_gate.py`, `export_alerts.py`, `export_alerts_v3.py`, `root_candidates.py`, `apply_review.py`,
`apply_review_v2.py`. Công cụ mới là file mới.

- Không ghi vào thư mục `run3`, không ghi đè `windows_run3`. Không mở `test.zip` nào.
- Không in giá trị field, hostname, username, command line, tên dataset. Chỉ in số đếm và mã run.
- Chạy bằng `python -I`. Không cài gói, không truy cập mạng, không dùng git. **Không khôi phục** 17 file Splunk đang
  rỗng (D2 QĐ 91): kiểm sha256 cả 17 file vẫn = `e3b0c442…b855` trước C3; khác → dừng.
- Ghi sha256 của mọi script đã chạy và mọi file đầu vào chính vào output.

## C1. Bảng 55 run không gốc cho người duyệt (D2 QĐ 90)

1. Từ `run4/_root_selection.csv`, lấy các mã `dot = run4` không có dòng `chap_nhan` nào. Kỳ vọng 55 mã (evtx 7,
   otrf 16, splunk 32); lệch → dừng, báo.
2. Tạo thư mục mới, rỗng `C:\survey_review\run4_nguoi`: chép `run4/<ma>.csv` của 55 mã, **xoá trắng cột
   `quyet_dinh`** trong bản chép (người duyệt không thấy quyết định Gemini). Không chép file bắt đầu bằng `_`.
3. Ghi `run4/_nguoi_codes.json` (danh sách 55 mã) ở thư mục `run4`, không để trong `run4_nguoi`.
4. In: số mã theo nguồn, phân bố số dòng ứng viên (trung vị, max), số run có 0 ứng viên.

Sau đó **dừng**, để người dùng duyệt tay `run4_nguoi` theo tiêu chí D2 QĐ 57 (giống lượt 1b, mục B5): ghi
`chap_nhan` / `bac` vào cột `quyet_dinh`; run không có gốc → `bac` ít nhất một dòng.

## C2. Script `scripts/survey/apply_correction_run4.py`

Tham số: `--run4-dir`, `--nguoi-dir`, `--codes <run4/_nguoi_codes.json>`, `--dry-run`.

1. Kiểm: mọi mã trong `_nguoi_codes.json` có file trong `--nguoi-dir`, mỗi file có ≥ 1 dòng có `quyet_dinh`, giá trị
   chỉ `chap_nhan` / `bac`; file trong `--nguoi-dir` trùng `run4/<ma>.csv` ở mọi cột trừ `quyet_dinh`. Sai → dừng.
2. Với mỗi mã: **thay** cột `quyet_dinh` của `run4/<ma>.csv` bằng cột của bản người duyệt (cả file, vì đây là quyết
   định thay thế cho run này). Trước khi ghi, sao lưu `run4/<ma>.csv` thành `run4/_gemini_backup/<ma>.csv`.
3. Ghi lại `_root_selection.csv`: giữ dòng Gemini của 55 mã nhưng thêm cột `thay_the` = 1; thêm dòng mới của người
   với `dot = run4_nguoi`. Ghi bảng `decisions_run4_nguoi.csv` (`ma_run, dong, quyet_dinh, ly_do`).
4. In: số run được ghi, `chap_nhan`, `bac`, số run có gốc sau sửa theo nguồn, và bảng đổi trạng thái của 55 run
   (không gốc → có gốc / vẫn không gốc).

Kiểm trên dữ liệu giả trước: (a) dừng khi bản người khác bản run4 ở cột ngoài `quyet_dinh`; (b) có backup;
(c) `--dry-run` không ghi gì.

## C3. Export windows_run4 (D2 QĐ 74, 77, 89, 90, 91)

1.**File phong bì:** ghi `C:\survey_review\envelope_fields.json` = danh sách JSON 17 tên field phong bì đã tính ở
A1 lượt 1 (chỉ tên field). In sha256. 2.**Kiểm mẫu:** `run4/_sample.json` phải chứa đủ 102 mã `run3/_sample.json`. Mã `4cf9159c1b41` (bị Defender xoá,
`run4/_excluded.json`): nếu còn trong `_sample.json` thì báo rõ script đối xử thế nào với run này (bị bỏ vì
không có file duyệt, hay lỗi); **không tự sửa** `_sample.json` nếu không cần. Nếu script lỗi vì mã này, dừng và
báo. 3.**Chạy** (thư mục out mới, rỗng):

```
python -I scripts/survey/export_alerts_v3.py <tham số nguồn như lượt trước> --seed 42 ^
--run3-review-dir <run3> --run3-sample <run3/_sample.json> --run3-manifest <windows_run3/manifest.json> ^
--run4-review-dir <run4> --run4-sample <run4/_sample.json> --split-seed 42 --dev-fraction 0.5 ^
--dedup-mode envelope_free --envelope-fields C:\survey_review\envelope_fields.json --pid-alive off ^
--out-dir C:\survey_review\windows_run4
```

`--pid-alive off`: A3 lượt 1 cho thấy 0 alert bị ảnh hưởng, giữ cách nối cũ. 4. Script tự kiểm và **không ghi gì** nếu: A không tái lập manifest run3, A2 ≠ A, hoặc có alert dev run3 trong test
run4. Gặp lỗi → gửi nguyên output JSON, không sửa script, không thử lại với tham số khác. 5.**Không giải nén `test.zip`.** Chỉ băm.

## Output gửi về máy làm việc (chỉ số đếm và sha256)

1. C1: số mã theo nguồn. C2: output in của `apply_correction_run4.py` (dry-run và chạy thật), sha256 script,
   sha256 `decisions_run4_nguoi.csv` và `_root_selection.csv` mới.
2. C3: toàn bộ output JSON của `export_alerts_v3.py`, gồm `steps`, `split_run4` (đặc biệt
   `composition.counts` và `flagged_lt_0_25` theo phía, nguồn, nhóm event — dùng cho QĐ 89), `a2_equals_a`,
   `old_dev_in_new_test`, `run3_reproduced`, `test_zip_sha256`; sha256 `envelope_fields.json`; kết quả kiểm 17 file
   rỗng; cách xử lý mã `4cf9159c1b41`.
3. Chép về máy làm việc: `windows_run4/manifest.json`, thư mục `windows_run4/dev/`, và `windows_run4/test.zip`
   (niêm phong, không mở). Cùng script `apply_correction_run4.py`.

Không gửi CSV duyệt, `_run_map.csv`, `_sample.json`, log gốc.
