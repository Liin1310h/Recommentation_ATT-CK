# D1 – Khảo sát OTRF Security-Datasets

Ngày khảo sát: 2026-11-03. Nguồn: https://github.com/OTRF/Security-Datasets
Bản khảo sát: clone cục bộ do người dùng tự tải tại `Security-Datasets/`, commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` (2023-09-20).
Phạm vi: chỉ đọc cấu trúc và thống kê. Không giải nén ra đĩa, chưa gán label, chưa chọn event, chưa chạm dev/test.
Mục "chưa kiểm chứng" là chưa đo.

## 1. Quy mô (đã đo)

| Mục | Giá trị |
|---|---|
| File trong clone | 731 (~594 MB, chưa tính `.git`) |
| Dataset có metadata YAML | 113 (104 `atomic`, 9 `compound`) |
| File `.zip` cục bộ | 207 (~487 MB); không có zip hỏng |
| Nội dung zip | 148 `.json`, 174 `.log`, 64 pcap/cap (`.cap`, `.pcap`, `.pcapng`), 1 `.csv`, 8 `.sha1sum` |
| Event trong 148 file `.json` | ~1.92 triệu event; mỗi file median 2,205, p90 25,993, max 587,286 |
| Platform (theo YAML) | Windows 109, Linux 3, AWS 2, Azure 1 |
| Ngày commit cuối | 2023-09-20 |

Không có scenario nào cho Mobile hay ICS. Dữ liệu Windows chiếm hầu hết; Linux chỉ 3 dataset, không đủ cho đánh giá riêng.

## 2. Label (điểm mạnh so với EVTX-ATTACK-SAMPLES)

- Mỗi dataset có YAML với trường `attack_mappings` có cấu trúc: `technique`, `sub-technique`, `tactics` (ID dạng TA00xx). 113/113 YAML có `attack_mappings`, không dataset nào thiếu.
- Số mapping mỗi dataset: median 1, max 10. Label ở **mức dataset (scenario)**, không phải mức event. Một dataset chứa hàng nghìn event, phần lớn là event nền.
- Số ID: 52 technique khác nhau, 48 sub-technique khác nhau.
- Số dataset mỗi ID: technique có ≥1 / ≥3 / ≥5 dataset là 52 / 17 / 12. Sub-technique có ≥1 / ≥3 / ≥5 dataset là 48 / 13 / 7.
- Top technique theo số dataset: T1003 (26), T1021 (15), T1218 (10), T1055 (8), T1562/T1587/T1608/T1204/T1082/T1033 (7 mỗi ID), T1047 (6), T1041 (6).
- Tactic xuất hiện nhiều: TA0005 (Defense Evasion) 38, TA0006 32, TA0007 29, TA0008 26, TA0002 26.
- Mapping dùng dạng tách `technique` + `sub-technique`, tức đã theo ATT&CK mới. Chưa kiểm tra có ID deprecated/revoked nào còn sót hay không; cần đối chiếu STIX đã pin.
- Mapping do tác giả gán, chưa có kiểm chứng độc lập. Với một annotator, label vẫn phải được gán thủ công lại ở D6.

## 3. Định dạng log

- Windows: JSON dòng-một-event (NDJSON) nằm trong zip. Đã đọc streaming tối đa 3,000 dòng/file `.json`: 258,458 event Windows-style (không phải toàn bộ ~1.92 triệu).
- Channel (trong phần đã đọc): Sysmon/Operational 165,013; Security 53,001 (+7,938 ghi `security` viết thường); Windows PowerShell 17,091; PowerShell/Operational 13,504; Application 1,517. Lưu ý `Security` và `security` là hai giá trị khác nhau, cần normalize.
- Event ID nhiều nhất: Sysmon 10 (71,788), Sysmon 12 (37,721), Sysmon 7 (33,475), PowerShell 800, PowerShell 4103, Sysmon 13, Security 4658/4656/5156.
- Event có `CommandLine`: 1,512 / 258,458 (<1%). Sysmon 1 và 4688 (process creation) ít; phần lớn event là truy cập handle, load image, registry.
- Schema: các field như `Hostname`, `SourceName`, `Message` (chuỗi render đầy đủ), cùng field riêng của Sysmon (`Image`, `ParentImage`, `CommandLine`, `Hashes`...). Có cả field nhiễu của Nxlog (`port`, `EventReceivedTime`, `SourceModuleName`...).
- pcap/Zeek: không phù hợp đề tài (alert dạng host log). Bỏ qua.

## 4. Rủi ro leakage / bất biến

- Trường `tags`: mọi giá trị trong phần đã đọc là `["mordorDataset"]` (142,296 event). Không phải technique, nhưng lộ nguồn dữ liệu; nên strip.
- Trường `RuleName` (Sysmon): 443 event có giá trị khác `-` trong phần đã đọc. Các giá trị thấy được là `MsMpEng`, tên rule firewall, `atomic testing`... Không thấy chuỗi `technique_id=` trong top 12 giá trị, nhưng **chưa quét toàn bộ**, nên chưa kết luận.
- Trường `Message` chứa nội dung render lặp lại các field (kể cả `RuleName`). Nếu strip field riêng mà quên `Message`, vẫn lộ. Cần test.
- Đường dẫn file, tên dataset, `title`, `description`, `tags`, `adversary_view` trong YAML chứa tên công cụ/kỹ thuật. Chỉ dùng để lấy label, không được vào alert.
- Hostname/user: tập trung vào ít môi trường lab (nhiều scenario dùng chung hostname). Split theo scenario/source cần xét điều này để tránh rò rỉ qua hostname. Chưa đo.
- Event nền chiếm đa số, nhiều event lặp. Cần dedup near-duplicate trước split (bất biến 4).

## 5. License

- Repo: MIT License (Copyright 2021 Open Threat Research Forge), đọc từ file `LICENSE`. Permissive hơn GPL v3 của EVTX-ATTACK-SAMPLES. Chưa kiểm chứng điều khoản riêng cho dữ liệu; nên coi như cùng license repo. [Ước đoán]

## 6. Khả năng dùng làm benchmark (đánh giá thẳng)

| Tiêu chí | Đánh giá |
|---|---|
| Domain | Chủ yếu Windows/Enterprise. Linux 3 dataset (không đủ cho metric). Không có Mobile/ICS. |
| Label | Có technique + sub-technique + tactic có cấu trúc, ở mức dataset. Tốt hơn EVTX về tính máy đọc được; vẫn cần gán tay do một annotator. |
| Technique ≥5 dataset | 12 technique (cha), 7 sub-technique. Vẫn thấp hơn nhiều so với mục tiêu ≥30 technique có ≥5 alert. |
| Quy mô event | Rất lớn (~1.9 triệu), nhưng đa số là event nền. Số alert thực dùng được phụ thuộc bộ lọc viết trước. |
| Chọn event | Rủi ro lớn nhất. Chọn event mang tính tấn công trong dataset mà không dùng Sigma (bất biến 2) đòi hỏi bộ lọc tay (event ID, process, field). Chưa có bộ lọc. |
| Sigma-match | Có Sysmon/Security/PowerShell Windows phù hợp logsource Sigma. Chưa chạy thử. |
| Cluster bootstrap | ~113 scenario; một số là campaign (LSASS_campaign_01..07 gần như lặp lại cùng kịch bản, apt29 chứa nhiều bước). Phải cluster theo campaign, không theo dataset. |

## 7. So sánh nhanh với EVTX-ATTACK-SAMPLES (đã đo cả hai)

| | EVTX-ATTACK-SAMPLES | OTRF Security-Datasets |
|---|---|---|
| Scenario | 278 file `.evtx` (277 tên khác nhau); 163 file khớp sheet | 113 dataset (YAML) |
| Event | 4,633 trong CSV tác giả (chưa đếm toàn bộ `.evtx`) | ~1.92 triệu (JSON) |
| Label | Sheet ngoài repo, ID cũ, nhiều lỗi | YAML có cấu trúc, ID mới |
| Technique ≥5 đơn vị | 9 ID (theo file, ID cũ chưa normalize) | 12 technique / 7 sub-technique (theo dataset) |
| Event nền | Ít | Rất nhiều |
| License | GPL v3 | MIT |

Hai nguồn bổ sung cho nhau: EVTX có event ngắn, tập trung vào hành vi; OTRF có label sạch hơn nhưng nhiều nhiễu. Chưa nên kết luận "đủ" cho gate 200 alert / 30 technique. Chưa hợp nhất hai nguồn để tính. [Ước đoán]

## 8. Chưa kiểm chứng

1. Quét toàn bộ event để tìm chuỗi leakage (`technique_id=`, tên rule có kỹ thuật).
2. Ánh xạ/kiểm tra ID deprecated qua STIX pin.
3. Đọc toàn bộ ~1.92 triệu event (mới đọc tối đa 3,000 dòng đầu mỗi file).
4. Sigma-match chạy được trên format JSON này hay không (gate tuần 1).
5. Mức chồng lấp hostname/user giữa dataset, để thiết kế split.
6. Xác định quy tắc lọc event tấn công mà không dùng Sigma.
7. Chưa ghép từng YAML với zip cục bộ (113 YAML so với 207 zip). Chưa biết dataset nào thiếu dữ liệu cục bộ, hay có zip nào thuộc nhiều dataset.

## 9. Tái lập

- `python -I scripts/survey_otrf.py Security-Datasets` (cần PyYAML; đã có trên máy này)
- `python -I scripts/survey_otrf_events.py Security-Datasets`
- Dữ liệu tại `Security-Datasets/` chưa được copy vào `data/raw/` và chưa có checksum manifest.
