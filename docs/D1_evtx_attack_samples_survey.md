# D1 – Khảo sát EVTX-ATTACK-SAMPLES

Ngày khảo sát: 2026-11-03. Nguồn: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
Phiên bản khảo sát: shallow clone, commit `4ceed2f4706daf601c212a8f91c113dd85349a2c` (2023-01-24).
Phạm vi: chỉ đọc cấu trúc và thống kê. Chưa gán label, chưa chọn event, chưa chạm dev/test.
Số liệu bên dưới do script đo trên bản clone. Mục nào ghi "chưa kiểm chứng" là chưa đo.

## 1. Quy mô (đã đo)

| Mục | Giá trị |
|---|---|
| File `.evtx` | 278 (README ghi "200 EVTX examples", đã lỗi thời) |
| Dung lượng tổng | ~46.5 MB |
| Kích thước file | median 68 KB, p90 68 KB, max 10.1 MB (`CA_PetiPotam_etw_rpc_efsr_5_6.evtx`). Nhiều file ~1.1 MB. |
| `evtx_data.csv` | 4,633 event từ 249 file (29 file `.evtx` không có trong CSV) |
| Event/file (CSV) | min 1, median 5, p90 27, max 869; 128/249 file có ≤5 event |
| Ngày commit cuối | 2023-01-24 (repo không còn cập nhật) |

**Đúng kích thước:** repo là corpus nhỏ, thưa. 4.6k event tổng cộng, chia cho 249 file. Mục tiêu 300–500 alert, cap 15/technique khó đạt nếu chỉ dùng nguồn này. [Có khả năng cao]

## 2. Cấu trúc và label

- Thư mục cấp 1 = **tactic** (Command and Control, Credential Access, Defense Evasion, Discovery, Execution, Lateral Movement, Persistence, Privilege Escalation) cộng `AutomatedTestingTools` và `Other`. Không có thư mục Initial Access, Collection, Exfiltration, Impact.
- Số file theo thư mục: Privilege Escalation 66, Lateral Movement 47, Credential Access 39, Defense Evasion 36, Execution 34, Persistence 22, Discovery 11, AutomatedTestingTools 8, Other 8, Command and Control 6.
- **Không có technique ID có cấu trúc.** Chỉ 3/278 tên file chứa ID (`t1098`, `T1186`, `t1178`). README nói mapping "ở mức technique", nhưng bảng mapping nằm ở Google Sheet ngoài repo (link bit.ly trong README). Sheet đã được xuất ra CSV và phân tích ở mục 7.
- Hệ quả: label technique phải tạo thủ công theo tên file, kèm đọc nội dung event. Đây là một annotator, đúng giới hạn đã nêu trong đề cương. Label ở mức scenario (một file = một scenario), không phải mức event.
- `CA_`, `DE_`, `LM_`... trong tên file là tiền tố tactic, không phải technique.
- Công cụ gán nhãn: không có label sẵn nào ngoài tactic. Tactic từ thư mục chưa kiểm chứng độ đúng (một số file nằm sai thư mục có thể có, chưa đo).

## 3. Định dạng log

- File gốc `.evtx` (binary). Python: cần thư viện parse (vd. `python-evtx`); thư mục `EVTX_ATT&CK_Metadata/Evtx` có bản vendored. **Chưa thử** parse file nào ngoài CSV.
- `evtx_data.csv` là bản flatten sẵn: 1 dòng/event, cột rộng (~350 cột, thưa), có `EVTX_FileName`, `EVTX_Tactic`, `Channel`, `EventID`. Tiện cho pilot nhưng là phiên bản của tác giả, không đầy đủ (249/278 file).
- Phân bố channel (CSV): Sysmon/Operational 2,401; Security 1,496; Application 393; TerminalServices-RemoteConnectionManager 228; RdpCoreTS 61; còn lại nhỏ.
- 179/249 file có event Sysmon.
- Event ID nhiều nhất: Security 5145 (950, chủ yếu từ vài file), Sysmon 1 (841), Sysmon 7 (613), Sysmon 11 (185), Application 1040/1042, Sysmon 13/3/10.
- Event có `CommandLine`: 841 (= Sysmon 1). `ScriptBlockText`: chỉ 3 dòng. Windows gần như 100%; không có Linux, Mobile, ICS. Chỉ Enterprise/Windows.

## 4. Rủi ro leakage / bất biến

- **Cột `RuleName` (Sysmon) có 213 dòng non-empty, một số chứa tag trực tiếp** như `technique_id=T1003,technique_name=Credential Dumping`, `technique_id=T1130,...`. Phải strip toàn bộ trước pipeline (bất biến 3), cần test. Các RuleName khác ("DLL Hijack - ...", "Valid Account - ...") là tên rule tự đặt, cũng phải strip. [Chắc chắn]
- Tên file chứa tactic prefix, từ khóa technique (`mimikatz`, `dcsync`, `bluekeep`...), đôi khi ID. Tên file và đường dẫn không được đi vào alert.
- Tên máy/scenario có thể trùng giữa các file (`PC02.example.corp`). Chưa đo cluster scenario để split.
- Dedup near-duplicate: nhiều file có event lặp (5145 hàng trăm dòng). Cần dedup trước split (bất biến 4). Chưa làm.

## 5. License

- GPL v3 (xem mục 9). Chưa kiểm chứng điều kiện khi phát hành lại benchmark; nên dùng cục bộ và không phân phối lại raw. [Ước đoán]

## 6. Khả năng dùng làm benchmark (đánh giá thẳng)

| Tiêu chí | Đánh giá |
|---|---|
| Domain | Chỉ Enterprise/Windows. Đủ cho evaluation chính, không cho Mobile/ICS smoke test. |
| Quy mô | 249–278 scenario nhưng ~4.6k event; sau lọc theo bộ lọc viết trước và dedup, số alert thực dùng chưa biết. |
| Số technique ≥5 alert | Theo sheet của tác giả: 9 ID có ≥5 file (chưa normalize ID cũ→mới, tính theo file chứ không phải alert). Xem mục 7. |
| Gate cuối tuần 2 | Khả năng cao phải bổ sung nguồn thứ hai (OTRF/Splunk). |
| Sigma-match | Phần lớn là Sysmon 1/7/11/13 và Security 4624/4663/5145 → khớp với logsource Sigma Windows. Chạy thật chưa thử (gate cuối tuần 1). |
| Label | Chỉ tactic có sẵn; technique cần gán tay. Một annotator. |
| Chất lượng event | Nhiều event nền (noise) lẫn trong file; cần filtering rule viết trước. Chưa có rule. |

## 7. Sheet mapping của tác giả (đã đo, cập nhật 2026-11-03)

Nguồn: `EVTX-ATT&CK - Content Summary - Mapping.csv` (xuất từ Google Sheet; 198 dòng, 4 cột: Tactic, Technique, ID, Procedure related detection traces). Sheet nằm ngoài repo nên không có commit pin. Cần ghi checksum khi đưa vào `data/`.

| Mục | Giá trị |
|---|---|
| Số ID khác nhau | 59 |
| Dạng cột ID | 184 dòng một ID, 7 dòng nhiều ID, 7 dòng NA/trống |
| Dòng không có tên file `.evtx` (chỉ mô tả detection) | 31 |
| Số file repo khớp ≥1 dòng | 163 / 277 (277 vì tên trùng hoa/thường, xem mục 9) |
| File repo không có dòng nào trong sheet | 114 |
| Tên file trong sheet không có trong repo | 13 (sai tên/thiếu tiền tố, vd. `sysmon_1_ftp.evtx` ↔ `exec_sysmon_1_ftp.evtx`); 4 trong số đó không tìm được file gần (`eventid_1`, `hijack`, `juicypotato`, `logonid`) |
| ID có ≥1 / ≥3 / ≥5 file khớp | 54 / 14 / 9 (tính theo file/scenario, ID chưa normalize) |
| Top ID theo số file | T1088 (27), T1003 (15), T1134 (13), T1089 (10), T1055 (7) |

Vấn đề chất lượng của sheet:
- ID thuộc phiên bản ATT&CK cũ (T1088, T1089, T1085, T1086, T1117, T1064, T1084, T1038, T1138, T1196, T1223...). Phải normalize qua STIX đã pin. Bảng ánh xạ tôi nhớ (vd. T1088→T1548.002) **chưa được đối chiếu STIX**. [Có khả năng cao]
- Mapping ở mức technique cha, nên không dùng sheet này để đánh giá ở mức sub-technique mà không gán tay.
- Lỗi trong sheet: dòng DCShadow ghi "Valid Accounts / T1138" (T1138 là Application Shimming); có dòng NA; một số tactic/technique đáng ngờ (PowerCat reverse shell ở "Lateral Movement"). Label từ sheet chỉ là candidate.
- Tactic trong sheet có giá trị đa tactic ("Defense Evasion, Execution"; 12 giá trị khác nhau).
- Mất cân bằng: T1088 chiếm 27 file, nhiều ID chỉ 1–2 file.

## 8. Kiểm tra toàn vẹn file (đã đo)

- 277 tên khác nhau / 278 file `.evtx`: tất cả có magic `ElfFile` hợp lệ, không có file bị flag dirty; tổng 513 chunk.
- `UACME_59_Sysmon.evtx` xuất hiện 2 lần (thư mục gốc và `Privilege Escalation/`), cùng kích thước và hash: **duplicate chính xác**, phải dedup trước split (bất biến 4).
- Chưa parse nội dung event bằng thư viện `.evtx`. Chưa cài `python-evtx`, vì chưa có lệnh cài package.

## 9. License (đã đọc)

`LICENSE.GPL` là **GNU GPL v3** (29 June 2007). Điều khoản hệ quả khi phân phối lại raw log chưa được tư vấn pháp lý. Dùng cục bộ trong nghiên cứu thường không kích hoạt nghĩa vụ phân phối, nhưng chưa kiểm chứng. [Ước đoán]

## 10. Kết luận khảo sát

- **Dùng được:** làm nguồn Enterprise/Windows cho dev/test, cùng nguồn thứ hai.
- **Không đủ một mình:** 9 ID (chưa normalize) có ≥5 file so với yêu cầu ≥30 technique có ≥5 alert. Gate cuối tuần 2 gần như chắc chắn kích hoạt nguồn thứ hai. [Có khả năng cao]
- **Việc phải làm trước khi dùng:** normalize ID qua STIX, sửa tên file lệch, dedup file trùng, quyết định xử lý file không có dòng trong sheet (114) và dòng NA, strip `RuleName` và tên file khỏi alert, filtering rule viết trước, blind labeling thủ công.
- **Rủi ro:** scenario ít (~163 có label) làm khoảng tin cậy cluster bootstrap rộng; một annotator.

## 11. Chưa kiểm chứng

1. Ánh xạ ID cũ→mới qua STIX pin (chưa tải STIX).
2. Parse nội dung `.evtx` trực tiếp và đối chiếu với `evtx_data.csv` (29 file không có trong CSV).
3. Sigma-match chạy được trên log nào (gate tuần 1).
4. Độ đúng của tactic theo thư mục và của label trong sheet.
5. 114 file không có dòng trong sheet, và 4 tên không tìm được file gần.

## 12. Cách tái lập

- Nguồn: `git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git`, rồi `git checkout 4ceed2f4706daf601c212a8f91c113dd85349a2c`. Dữ liệu đã copy vào `data/raw/evtx-attack-samples/`, checksum trong `data/evtx_manifest.sha256`.
- `python -I scripts/survey_evtx.py data/raw/evtx-attack-samples`
- `python -I scripts/analyze_mapping.py "<mapping.csv>" data/raw/evtx-attack-samples`
- `python -I scripts/check_evtx_integrity.py data/raw/evtx-attack-samples "<mapping.csv>"`
