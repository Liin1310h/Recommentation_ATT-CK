# Prompt gửi Gemini — duyệt tiến trình gốc (run4)

> Dán nguyên phần trong khung dưới đây vào Gemini, rồi đính kèm **đúng các file CSV của một lô** (`lo_001`, `lo_002`, …).
> Mỗi lô gửi trong một phiên riêng. Không đính kèm file nào khác (không `_run_map.csv`, `_sample.json`, `_stats.json`, tên dataset, nhãn).

---

## PROMPT

Bạn là chuyên gia phân tích tiến trình Windows. Nhiệm vụ: với mỗi file CSV tôi gửi, xác định **tiến trình gốc** của hành vi tấn công trong run đó.

### Dữ liệu

Mỗi file CSV là một run, tên file là mã run (ví dụ `0062ade32b52.csv`). Mỗi dòng là một tiến trình, xếp theo thời gian bắt đầu. Các cột:

- `dong`: số thứ tự dòng trong file. Đây là khóa để bạn trả lời.
- `dong_cha`: số `dong` của tiến trình cha, nếu cha có trong file. Để trống nghĩa là không có cha trong file.
- `thoi_gian`: thời điểm tiến trình bắt đầu.
- `image`, `image_cha`: đường dẫn tiến trình và tiến trình cha.
- `command_line`: dòng lệnh. Mã technique và tag đã bị che thành `<ID>` / `<TAG>`.
- `ung_vien`: 1 nếu một thuật toán cấu trúc đề xuất dòng này là ứng viên gốc, 0 nếu không. Đây **chỉ là gợi ý**, bạn không bắt buộc theo.
- `quyet_dinh`: để trống, bạn không cần điền vào file.
- `process_key`: bỏ qua.

### Tiêu chí chọn tiến trình gốc

1. **Gốc** là tiến trình cao nhất tự thực hiện hoặc trực tiếp khởi chạy hành vi tấn công.
2. Nếu một shell (cmd, powershell…) chỉ được sinh ra để chạy lệnh tấn công, thì chọn **chính shell đó** làm gốc.
3. **Không chọn** tiến trình còn sinh ra hoạt động nền hoặc hoạt động hệ thống thông thường (ví dụ `explorer.exe`, trình điều khiển test, các dịch vụ/host như `svchost.exe`, `dllhost.exe`, `winrshost.exe`, và host COM bị lợi dụng như `mmc.exe -Embedding`).
4. Tiến trình **con** của một gốc đã chọn thì **không** phải gốc, chỉ chọn lại khi nó là điểm bắt đầu độc lập của một hành vi tấn công khác.
5. Nếu cùng một phiên/lệnh lặp lại nhiều lần giống hệt nhau, chỉ chọn **một** dòng đại diện (dòng đầu tiên), các dòng lặp còn lại ghi `bac`.
6. Một tiến trình không có cha trong file (`dong_cha` trống) mà tự thực hiện hành vi tấn công độc lập thì tự nó là gốc của hành vi đó.
7. Có thể có nhiều gốc trong một run, hoặc không có gốc nào.
8. **Không chắc thì ghi `bac`.** Không đoán technique ATT&CK, không dựa vào tên dataset hay nhãn.

### Cách trả lời

- Chỉ dùng hai giá trị: `chap_nhan` (dòng là tiến trình gốc) và `bac` (dòng không phải gốc).
- Ghi `chap_nhan` cho mỗi tiến trình gốc (là ứng viên hoặc bất kỳ dòng nào).
- Ghi `bac` cho các dòng ứng viên (`ung_vien = 1`) mà bạn cho là sai.
- Dòng không phải ứng viên và không phải gốc thì **không cần** ghi.
- **Mỗi run phải có ít nhất một dòng trong kết quả.** Nếu run không có gốc nào, hãy ghi `bac` cho ít nhất một dòng (ưu tiên một ứng viên).
- Không ghi cả `chap_nhan` và `bac` cho cùng một dòng.

### Định dạng kết quả

Trả về **một bảng CSV duy nhất** (UTF-8, dòng đầu là tiêu đề), gộp mọi file của lô, với đúng 4 cột:

```
ma_run,dong,quyet_dinh,ly_do
0062ade32b52,12,chap_nhan,shell chạy lệnh tấn công trực tiếp
0062ade32b52,13,bac,tiến trình con của dòng 12
```

- `ma_run`: tên file bỏ đuôi `.csv`.
- `dong`: số trong cột `dong` của file đó.
- `ly_do`: một câu ngắn (tối đa 15 từ), không chép lại nguyên dòng lệnh, không nêu technique.
- Không thêm lời dẫn, giải thích hay định dạng khác ngoài bảng CSV. Nếu bảng dài, chia thành nhiều khối nhưng giữ cùng một tiêu đề.
- Trước khi gửi, kiểm tra: mỗi file trong lô có ít nhất một dòng; không có cặp (`ma_run`, `dong`) trùng; `quyet_dinh` chỉ là `chap_nhan` hoặc `bac`.

---

## Ghi chú cho người dùng (không dán vào Gemini)

- Nguyên văn prompt lần 3 không còn trong repo. Prompt này dựa trên tiêu chí B5 (D2 QĐ 57) nên **khác prompt lần 3**; ghi rõ điều này trong báo cáo.
- Các điểm 3 (host/dịch vụ, mmc), 5 (chọn đại diện cho phiên lặp) và 6 (tiến trình không cha) bổ sung từ quy ước bạn dùng khi duyệt tay. Nếu muốn khớp chặt với lần 3, bỏ các mục đó.
- Gom bảng trả về của 10 lô thành `decisions_run4.csv` rồi chạy `apply_review_v2.py --dry-run`.
