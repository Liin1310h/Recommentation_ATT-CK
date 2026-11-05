# D1 – Count gate: kết quả chạy và cách xử lý chỗ đặc tả chưa rõ

Ghi chú: số liệu là CẬN TRÊN (`upper bound: process-tree filter not applied`). Tài liệu này chỉ ghi lại, không diễn giải.

## Tệp liên quan
- Mã nguồn: `scripts/survey/count_gate.py`
- Kết quả: `docs/survey_output/count_gate.json`
- Lệnh: `python -I scripts/survey/count_gate.py --splunk attack_data --otrf Security-Datasets --evtx EVTX-ATTACK-SAMPLES --sheet "EVTX-ATT&CK - Content Summary - Mapping.csv" --stix <enterprise-attack-20.0.json> --out docs/survey_output/count_gate.json`

## Thông tin chạy
- sha256 file sheet: `2d6c1f1b74736cb6661dcdff0a6002cb52a284b94d87ab52dcd3fa619d10a881`
- Thời gian chạy: 159,6 giây
- STIX `enterprise-attack-20.0.json`: 55271014 byte, sha256 `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352` (khớp đặc tả)
- Python 3.12.10, PyYAML 6.0.3

## Kết quả 10 điểm kiểm tra (dữ liệu giả, đã xoá sau khi chạy)
| # | Điểm kiểm tra | Kết quả | Bằng chứng |
|---|---|---|---|
| 1 | Namespace + `Data[@Name]` | ĐẠT | field `CommandLine`, `ProcessGuid` có mặt; `Provider_Name` có giá trị |
| 2 | `New Value` → thêm `NewValue` | ĐẠT | có cả `New Value` và `NewValue` |
| 3 | Sysmon EID 2 bị loại; `security` 4624 được giữ | ĐẠT | `drop_filter_type`=1; 4624 qua 4.1 |
| 4 | T1088→T1548.002; T1064/T1587.001/T0000 bị bỏ | ĐẠT | `moved`, `deprecated`, `pre`, `unknown` |
| 5 | OTRF `010` → T1003.010 | ĐẠT | `otrf_ids` trả `['T1003.010']` |
| 6 | RuleName bị strip; `attack.t1059` bị chặn; "execution" đơn lẻ không bị chặn | ĐẠT | `drop_leak`=1, chỉ field `CommandLine` |
| 7 | Khác ProcessGuid+timestamp → dedup; khác CommandLine → không | ĐẠT | `drop_duplicate`=1 |
| 8 | Ba run A/B/C → (c)=2, (b)=1 | ĐẠT | c=2, b=1 |
| 9 | `sysmon_1_ftp.evtx` không gắn nhãn cho `exec_sysmon_1_ftp.evtx` | ĐẠT | `{'T1059'}` vs `set()` |
| 10 | Output không lộ giá trị field | ĐẠT | không tìm thấy chuỗi đặc trưng giả trong stdout và JSON |

Lần chạy đầu của điểm 7 sai do lỗi dữ liệu giả của harness (event 1 có thêm `New Value`); đã sửa dữ liệu giả và chạy lại.

## Chỗ đặc tả chưa rõ / không khớp dữ liệu và cách xử lý
| Vấn đề | Cách xử lý |
|---|---|
| Đặc tả ghi metadata OTRF ở `atomic/windows/**/_metadata/`; thực tế không có thư mục đó. Metadata nằm ở `atomic/_metadata/` (104 file, lẫn aws/linux/windows) | Dừng và hỏi; người dùng chọn cách 1: dùng `atomic/_metadata/*.yaml`, chỉ giữ entry có `platform` chứa Windows (4 entry không phải Windows bị bỏ) |
| 39 basename zip OTRF trùng giữa `host/` và `network/` | Đọc mọi zip khớp basename, mỗi đường dẫn một lần; đếm `zip_multi_match` (70 lượt) |
| Zip `network/` chứa log Zeek, không có Channel/EventID | Vẫn đọc theo đặc tả; bị loại ở 4.1 nên làm tăng `events_read` |
| `Channel` khác hoa/thường giữa nguồn (`security` vs `Security`) khi dedup | Đưa `Channel` về chữ thường trước khi băm |
| Đặc tả không nêu nhóm lỗi cho dòng JSON hỏng, file không đọc được | Thêm bộ đếm `json_error`, `read_error`, `yaml_error` (không in nội dung) |
| 726 file log Splunk là con trỏ Git LFS, 15 file thiếu | Đếm `lfs_pointer`, `missing` và bỏ qua theo đặc tả; chỉ 30 file log được đọc |
| Một thư mục Splunk có >1 YAML | Run định danh theo đường dẫn YAML (không gộp theo thư mục) |
| Thứ tự khi vừa bị `revoked` vừa `deprecated` | Không có object nào mang cả hai cờ trong STIX 20.0 nên không phát sinh |
| Lỗi parse | 3 file `.evtx` → `wevtutil_error`; 2 đoạn XML Splunk → `xml_error`; 14 dòng JSON OTRF → `json_error` |
| In tiếng Việt (ĐẠT/KHÔNG ĐẠT) qua pipe | `sys.stdout.reconfigure(encoding="utf-8")` |

## Lần chạy 2 (sau sửa `otrf_ids` và tải LFS có chọn lọc)
- Sửa `otrf_ids`: sub-technique dạng đầy đủ không còn bị bỏ; thêm bộ đếm `otrf_sub_not_under_technique`, `otrf_sub_unparsed` và bảng `alerts_per_technique_id_by_source`. 6/6 điểm kiểm tra ĐẠT.
- LFS: 726 file con trỏ, 3,934 GB, file lớn nhất 378,1 MB. Tải 15 lô (50 đường dẫn/lô); lô 3 và 11 trả mã 2 (Windows Defender chặn file sau khi tải; không đặt exclusion). Sau tải: 724 có nội dung thật, 2 vẫn là con trỏ, 0 không tồn tại. `git status --porcelain` của attack_data: 17 dòng.
- Kết quả: `docs/survey_output/count_gate_run2.json`; thời gian chạy 554,4 giây.
