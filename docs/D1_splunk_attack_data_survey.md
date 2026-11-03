# D1 – Khảo sát Splunk attack_data

Ngày khảo sát: 2026-11-03. Nguồn: https://github.com/splunk/attack_data
Bản khảo sát: clone cục bộ `attack_data/`, commit `3a25034e7446cbdd108b87e848d5296530545c80` (2026-11-02).
Phạm vi: đọc metadata YAML và kích thước con trỏ LFS. Chỉ tải 3 file log nhỏ (mỗi file 65–78 KB) để xem định dạng. Chưa gán label, chưa chọn event, chưa chạm dev/test.
Mục "chưa kiểm chứng" là chưa đo.

## 0. Tình trạng clone (quan trọng)

- Lần clone đầu bị Windows Defender chặn file `datasets/attack_techniques/T1027/FuckThatPacker/aurora-edr.log` (báo "virus or potentially unwanted software"), checkout dở dang.
- Đã xử lý bằng sparse-checkout loại thư mục `FuckThatPacker/` và `GIT_LFS_SKIP_SMUDGE=1`. Kết quả: 3,806 file trên đĩa (index có 3,808; chênh 2 file, tôi suy ra do thư mục bị loại, chưa kiểm tra).
- **Hầu hết file log mới chỉ là con trỏ LFS** (2,339 con trỏ, 18 file dữ liệu thật). Tổng dung lượng LFS là 12.15 GB; mới tải 3 file mẫu.
- Dữ liệu ở `attack_data/` chưa được copy vào `data/raw/` và chưa có manifest checksum.
- Defender có thể chặn thêm file khác khi tải tiếp. Thư mục `FuckThatPacker/` bị loại khỏi mọi thống kê dưới đây (không có nội dung).

## 1. Quy mô (đã đo, từ YAML và con trỏ LFS)

| Mục | Giá trị |
|---|---|
| YAML metadata | 1,414 (0 file lỗi parse) |
| Log file được liệt kê | 1,505 |
| Phân bố thư mục | attack_techniques 1,255; malware 105; suspicious_behaviour 24; emerging_threats 6; còn lại < 10 mỗi thư mục (cisco_*, m365_copilot, mcp, ollama, honeypots, apt_simulations, aws_bedrock_claude) |
| Dung lượng log (theo con trỏ) | 12.15 GB; median 0.01 MB, p90 11.3 MB, max 477 MB |
| Phần mở rộng dữ liệu | `.log` 2,172; `.json` 168; `.ndjson` 7; còn lại ít |
| License | Apache License 2.0 (đọc từ `LICENSE`) |

Số event chưa đếm (chưa tải log). Hai file mẫu: Sysmon XML 32 event / 65 KB; Linux auditd 241 dòng / 78 KB. Mỗi log nhỏ, nên số event/scenario thấp. [Có khả năng cao]

## 2. Label

- Mỗi YAML có `mitre_technique` (danh sách ID, gồm cả sub-technique), `environment`, và danh sách `datasets` (name, path, sourcetype, source).
- 317 ID khác nhau (195 dạng sub-technique), tương ứng 140 technique cha. ID dùng chuẩn mới.
- Số "dataset-dir" (thư mục YAML) mỗi ID: ≥3 là 122 ID, ≥5 là 66 ID. Theo technique cha: ≥3 là 81, ≥5 là 56.
- Cùng thống kê chỉ cho **Windows** (`sourcetype` = `XmlWinEventLog`): 121 technique cha; ≥3 dir: 63; ≥5 dir: 39. Cho **Linux** (`sysmon:linux`, `auditd`): 45 technique cha; ≥5 dir: 8.
- Top technique cha toàn bộ: T1059 (60), T1548 (54), T1098 (50), T1562 (49), T1021 (37), T1078 (35), T1053 (32), T1190 (30), T1110 (28), T1218 (27).
- **Đơn vị đếm là thư mục, không phải scenario độc lập.** Nhiều thư mục cùng do một tác giả, cùng lab `attack_range`, cùng ngày. Một thư mục `atomic_red_team` có thể gộp nhiều test. Con số 39 technique Windows ≥5 dir là cận trên, chưa phải số alert.
- Vấn đề chất lượng metadata:
  - 361/1,414 YAML không có `mitre_technique` (224 trong số đó nằm dưới `attack_techniques`, nơi tên thư mục là ID). Chưa đo lý do.
  - Có placeholder `T1XXX.XXX`.
  - Trường `environment` không nhất quán (`attack_range`, `attackrange`, `attack range`, `NA`, `custom`...).
  - Label do tác giả gán theo thư mục, chưa kiểm chứng độc lập. Vẫn cần blind labeling.

## 3. Định dạng log

- Windows: XML của `XmlWinEventLog` (Sysmon, Security, PowerShell/Operational), 889 file. Đa số một dòng XML mỗi event. Nguồn: Sysmon/Operational 589, Security 190, PowerShell/Operational 81.
- Linux: `sysmon:linux` 117 file, `auditd` 101 file. Dữ liệu auditd dạng `type=SYSCALL msg=audit(...)` (nhiều dòng cho mỗi sự kiện).
- Cloud/SaaS khác: o365 (51), Azure AD (45), AWS CloudTrail (40+25), VMware syslog (24). Không thuộc phạm vi đánh giá Windows của đề tài; xem là ngoài phạm vi.
- Không có Mobile hay ICS rõ ràng. Chưa kiểm tra riêng các thư mục nhỏ (`mcp`, `ollama`, `m365_copilot`).
- Format XML khác OTRF (JSON) và EVTX (binary). Cần một normalizer riêng cho XML; chưa viết.
- Trường Sysmon `RuleName` trong mẫu là `-`. Chưa quét hết.

## 4. Rủi ro leakage / bất biến

- **Tên thư mục là technique ID** (`datasets/attack_techniques/T1003.001/...`) và cả `mitre_technique` trong YAML. Đường dẫn và tên file (`windows-sysmon_creddump.log`, `linux_auditd_copy_fail`) không được đi vào alert.
- Dữ liệu được tạo để kiểm thử detection của Splunk, không phải Sigma. Chọn event bằng Splunk là không dùng Sigma, nên bất biến 2 không bị vi phạm. Tuy vậy, YAML không chỉ ra event nào là tấn công, chỉ gán nhãn cả file; vẫn cần bộ lọc event viết trước.
- Event nền lẫn trong log; dedup near-duplicate trước split.
- Hostname lab giống nhau (`*.attackrange.local`) giữa nhiều thư mục: split theo scenario/source cần xét tránh rò rỉ qua hostname. Chưa đo mức chồng lấp.
- Một số log được tạo bằng Atomic Red Team (cũng là nguồn tên kỹ thuật); không phải leakage trực tiếp, nhưng nội dung command line có thể chứa tên công cụ.

## 5. Sigma-match

Phần lớn event Windows là Sysmon 1/10/11/13 và Security, hợp với logsource Sigma. Sysmon Linux và auditd cũng có logsource trong Sigma. Chưa chạy thử (gate tuần 1).

## 6. So sánh với hai nguồn đã khảo sát (số liệu đã đo cho từng nguồn)

| | EVTX-ATTACK-SAMPLES | OTRF Security-Datasets | Splunk attack_data |
|---|---|---|---|
| Đơn vị | 278 file | 113 dataset | 1,414 YAML / 1,505 log |
| Technique cha ≥5 đơn vị | 9 ID (ID cũ) | 12 technique | 56 (toàn bộ), 39 (Windows) |
| Label | Sheet ngoài repo, ID cũ, nhiều lỗi | YAML có cấu trúc, ID mới | YAML có cấu trúc, ID mới, 361 thiếu |
| Format | EVTX | JSON (NDJSON) | XML / auditd / JSON |
| Platform | Windows | Windows chủ yếu | Windows + Linux + cloud |
| Event/đơn vị | ít–vừa | rất nhiều, phần lớn nền | ít (log nhỏ) |
| License | GPL v3 | MIT | Apache 2.0 |
| Kích thước | ~46 MB | ~487 MB zip | ~12 GB LFS |

Đơn vị đếm của ba nguồn khác nhau (file, dataset, thư mục), nên không so sánh trực tiếp từng con số.

## 7. Đánh giá

- **Mạnh nhất về độ phủ technique:** nhiều technique Windows nhất, cùng Linux dùng được cho phần "Linux khi đủ mẫu" (chỉ 8 technique cha ≥5 dir; vẫn mỏng).
- **Rủi ro:** thư mục nhỏ, lặp lab, label theo thư mục; tên thư mục là nhãn; cần normalizer XML; 12 GB LFS và Defender chặn file.
- Có khả năng đáp ứng gate (≥200 alert, ≥30 technique ≥5 alert) trên Windows nếu gộp alert từ nhiều log file trong cùng thư mục, nhưng chưa tính được vì chưa đếm event và chưa lọc. [Ước đoán]

## 8. Chưa kiểm chứng

1. Số event thật mỗi file và tổng event (chưa tải log).
2. Quét leakage (`RuleName`, field có tên kỹ thuật) trên dữ liệu đầy đủ.
3. 361 YAML thiếu `mitre_technique`: dùng được không.
4. Hostname/user chồng lấp giữa thư mục.
5. Tính toàn vẹn nội dung các file bị Defender chặn (có thể còn file khác).
6. Sigma-match trên XML.
7. Nội dung của các thư mục nhỏ (`mcp`, `ollama`, `m365_copilot`...) có liên quan đề tài không.

## 9. Tái lập

- `python -I scripts/survey_splunk.py attack_data` (cần PyYAML; đã có trên máy này)
- Số liệu Windows/Linux (mục 2) được tính bằng một đoạn lệnh chạy một lần, chưa lưu thành script trong `scripts/`.
- Clone: sparse-checkout loại `datasets/attack_techniques/T1027/FuckThatPacker/`, `GIT_LFS_SKIP_SMUDGE=1`.
