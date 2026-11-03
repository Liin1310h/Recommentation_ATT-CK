# D1 – Chọn nguồn dữ liệu (đề xuất, chờ người dùng quyết định)

Ngày: 2026-11-03. Dựa trên 3 báo cáo khảo sát: `D1_evtx_attack_samples_survey.md`, `D1_otrf_security_datasets_survey.md`, `D1_splunk_attack_data_survey.md`.
Giới hạn: mọi số liệu là mức metadata/mẫu. Chưa ai đếm số alert thật, chưa lọc event, chưa gán label. Đơn vị đếm của 3 nguồn khác nhau, nên các con số dưới đây chỉ so sánh định tính.

## 1. Tiêu chí (từ đề cương)

- Gate cuối tuần 2: benchmark ≥200 alert và ≥30 technique có ≥5 alert; nếu không, phải có nguồn thứ hai.
- Chỉ Enterprise, chủ yếu Windows; Linux chỉ khi đủ mẫu.
- Không dùng Sigma để chọn event; phải strip tag/ID/rule name; split theo scenario/source.
- Một annotator, 5 tuần, máy cá nhân 16 GB RAM, không GPU.
- Nơi làm việc cấm clone repo log tấn công, nên dữ liệu chỉ ở máy cá nhân.

## 2. So sánh (số liệu đã đo ở các báo cáo)

| Tiêu chí | EVTX-ATTACK-SAMPLES | OTRF Security-Datasets | Splunk attack_data |
|---|---|---|---|
| Technique cha ≥5 đơn vị | 9 (ID cũ, chưa normalize; đơn vị = file) | 12 (đơn vị = dataset) | 39 Windows, 56 toàn bộ (đơn vị = thư mục) |
| Label | Sheet ngoài repo, ID cũ, có lỗi; 114 file không có dòng | YAML đầy đủ, ID mới | YAML, ID mới; 361/1,414 thiếu |
| Mật độ tấn công trong event | Cao (file nhỏ, 5 event median) | Thấp (nhiều event nền; CommandLine <1% trong mẫu) | Chưa đo; log nhỏ (mẫu: 32 event) |
| Format | EVTX (cần parser) | JSON, dễ đọc | XML (cần parser), auditd |
| Cần tải/xử lý | 46 MB | 487 MB zip | 3.94 GB (756 log Windows attack_techniques); 12.15 GB toàn bộ LFS |
| Linux | Không | 3 dataset | 8 technique cha ≥5 thư mục (mỏng) |
| License | GPL v3 | MIT | Apache 2.0 |
| Rủi ro riêng | Sheet sai/ID cũ | Lọc event rất tốn công | Tên thư mục = nhãn; Defender chặn file; trùng lab |

## 3. Đề xuất

**Nguồn chính: Splunk attack_data (tập con Windows `XmlWinEventLog`, thư mục `attack_techniques`).** [Có khả năng cao]
- Lý do: duy nhất có triển vọng đạt ≥30 technique ≥5 đơn vị (39 là cận trên), ID mới nên normalize qua STIX nhẹ hơn, và có Linux để dùng khi đủ mẫu.
- Chỉ tải tập con Windows (756 log, ~3.94 GB, trong đó 14 file >50 MB). Có thể bỏ qua 14 file lớn ban đầu. Thư mục `FuckThatPacker/` đã bị loại do Defender.

**Nguồn bổ sung: EVTX-ATTACK-SAMPLES.** [Có khả năng cao]
- Lý do: nhỏ (46 MB), event ngắn và tập trung hành vi, license đã rõ; dùng để tăng mẫu cho technique mà Splunk mỏng và để kiểm tra chéo giữa các nguồn (ít nhất có hai nguồn độc lập).
- Điều kiện: phải sửa sheet (ID cũ→mới qua STIX, tên file lệch, dòng NA) và dedup `UACME_59_Sysmon.evtx`.

**OTRF Security-Datasets: không đưa vào kế hoạch ban đầu; dự phòng.** [Ước đoán]
- Lý do: 12 technique cha ≥5 dataset, quá nhiều event nền (chưa có quy tắc lọc event tấn công mà không dùng Sigma), và 5 tuần một người không đủ thời gian cho thêm một pipeline lọc.
- Giữ làm dự phòng: nếu gate cuối tuần 2 thất bại với Splunk + EVTX thì dùng thêm; hoặc dùng riêng cho smoke test nếu cần.
- Điểm cộng nếu dùng sau: YAML sạch, JSON dễ đọc, MIT.

## 4. Giả định và điểm chưa chắc

- 39 technique là **cận trên**: đếm theo thư mục YAML, không phải alert độc lập. Nhiều thư mục cùng lab, cùng tác giả. Số thật sau khi lọc và dedup có thể thấp hơn nhiều. [Chắc chắn là cận trên; mức giảm chưa biết]
- Chưa biết mỗi thư mục cho bao nhiêu alert sau lọc. Phải đo trước khi tin gate.
- Có thể có chồng lấp scenario giữa Splunk và EVTX hoặc OTRF (cùng công cụ Atomic Red Team, Mimikatz...). Cần dedup xuyên nguồn trước split, và split theo source.
- Linux và Mobile/ICS: Splunk Linux chỉ 8 technique cha ≥5 thư mục. Mobile/ICS chưa có nguồn. Smoke test Mobile/ICS (10 alert mỗi domain) cần nguồn khác hoặc tự tạo; chưa giải quyết ở D1.
- Quyết định đầu vào (raw event hay có rule name/description) đang chờ mentor, ảnh hưởng đến việc strip `RuleName`; đề xuất này không phụ thuộc vào quyết định đó.

## 5. Kiểm tra cần làm trước khi chốt (theo thứ tự rẻ nhất trước)

1. Tải 20–30 log Splunk Windows nhỏ rải rác theo technique và đếm event, ước lượng alert/thư mục.
2. Quét leakage (`RuleName`, `Message`, đường dẫn) trên mẫu đó.
3. Đối chiếu ID deprecated qua STIX đã pin (cần tải STIX, thuộc D3).
4. Thử Sigma-match trên Sysmon XML và EVTX (gate cuối tuần 1; bất biến 2 chỉ cho phép dùng để gán leakage tier, không dùng để chọn event).

## 5b. Kết quả kiểm tra mẫu Splunk (đã chạy 2026-11-03)

Mẫu: 30 log Windows (`XmlWinEventLog`) trong `attack_techniques`, mỗi technique cha một file, kích thước 5–300 KB, chọn theo thứ tự đường dẫn (danh sách trong `data/splunk_sample_paths.txt`). **Không phải mẫu ngẫu nhiên**: lệch về file nhỏ và về các ID đứng đầu theo thứ tự, nên không đại diện cho cả nguồn.

| Mục | Giá trị |
|---|---|
| File tải được / bị Defender chặn | 26 / 4 (3 trong số 4 file trỏ cùng một object LFS; đường dẫn `T1027.010`, `T1033`, `T1069.001`, `T1087.001`) |
| Tổng event trong 26 file | 481 |
| Event/file | min 4, median 9, max 65; 5/26 file có ≤5 event |
| Channel | Sysmon 257, Security 149, PowerShell/Operational 65, System 10 |
| Event ID nhiều nhất | Sysmon 1 (72), PowerShell 4104 (65), Sysmon 10 (63), Security 5140 (56), Sysmon 7 (29) |
| Event có field `CommandLine` | 86 |

Nhận xét:
- **Mật độ event cao, ít nhiễu hơn OTRF** trong mẫu này: file nhỏ, median 9 event. Mỗi thư mục cho ~10 event, nên cần nhiều thư mục mới đạt vài chục alert/technique. Gate ≥5 alert/technique khả thi hơn chỉ ở những technique có nhiều thư mục. [Có khả năng cao cho mẫu; chưa suy ra cho toàn nguồn]
- **Leakage thật:** 3/26 file có chuỗi giống ATT&CK ID trong nội dung (ví dụ `T1099`, `T1105`, `T1137.006` trong dữ liệu event). `T1099` xuất hiện trong `RuleName` và là ID cũ (Timestomp), còn `RuleName` khác trong mẫu gồm `RDP`, `InvDB`, `EXE`, `DLL`, `Downloads` — cũng là tên rule do cấu hình Sysmon đặt. Phải strip `RuleName` và test (bất biến 3). Đã xác nhận là có, nhưng mới trên 26 file.
- Bị Defender chặn 4/30 file (≈13%) trong mẫu này. Nếu tỷ lệ tương tự trên 756 log thì sẽ mất một số technique; chưa đo.
- Số event/alert thật của toàn nguồn vẫn chưa biết. Mẫu 481 event không cho phép ước lượng gate.

## 6a. Quyết định đã chốt (2026-11-03)

Người dùng trả lời "chốt" cho đề xuất ở mục 3 và 6. Tôi hiểu là chấp nhận đề xuất của tôi:
- Nguồn chính: Splunk attack_data (Windows `XmlWinEventLog`, `attack_techniques`). Nguồn bổ sung: EVTX-ATTACK-SAMPLES. OTRF để dự phòng.
- File bị Defender chặn: bỏ qua, không thêm ngoại lệ. Thư mục/file bị chặn được ghi nhận là thiếu, không tìm cách lấy lại.
- Chưa chốt (mục 4–5): cách xử lý Mobile/ICS smoke test, đếm alert thật, normalize ID qua STIX.

## 6. Các việc cần người dùng quyết định (ghi lại trước khi chốt)

- Chấp nhận Splunk (Windows) làm nguồn chính và EVTX làm bổ sung, hay chọn khác.
- Có cho phép tôi tải mẫu log Splunk (mục 5.1) hay không; mỗi lần tải tôi sẽ báo trước dung lượng.
- Nếu Defender chặn thêm file, bỏ qua thư mục đó hay thêm ngoại lệ (quyết định của người dùng).
