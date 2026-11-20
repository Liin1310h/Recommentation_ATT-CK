# QĐ 117 – So sánh embedding: multilingual-e5-large (E5) vs bge-small-en-v1.5 (R0)

## 1. Kết luận theo tiêu chí khai báo trước

Tiêu chí (khai báo trước, không đổi sau khi xem số): "đạt" khi và chỉ khi khoảng tin cậy 95% của hiệu Top-K của **hybrid** nằm hoàn toàn trên 0. Tiêu chí được ghi trong đầu `experiments/configs/emb_e5_large*/retrieval.yaml`, ngày 2026-11-19.

Ba lần chạy E5 đều **KHÔNG ĐẠT**:

| Lần chạy | Cấu hình | Hiệu hybrid Top-3 | CI 95% | p | Kết luận |
|---|---|---|---|---|---|
| E5a | không tiền tố, fusion của bge (w=0.25, rrf_k=30) | −0.0086 | [−0.0589, +0.0337] | 0.772 | KHÔNG ĐẠT |
| E5b | có tiền tố `query: / passage: ` | −0.0016 | [−0.0325, +0.0280] | 0.977 | KHÔNG ĐẠT |
| E5c | có tiền tố + tune fusion (w=0.25, rrf_k=10) | +0.0094 | [−0.0131, +0.0330] | 0.436 | KHÔNG ĐẠT |

- Dense-only của E5 **tốt hơn bge-small có ý nghĩa** khi có tiền tố: +0.0546, CI [+0.0131, +0.0980], p = 0.006. Tiêu chí chỉ áp dụng cho hybrid, nên điều này không đủ để đổi model.
- Kết luận: **giữ bge-small làm model embedding.** E5 không đạt tiêu chí ở bất kỳ cấu hình nào đã thử trên dev.

## 2. Kết quả theo hệ thống

Quần thể: tier 2∪3, capped_in, evidence_event_groups (1283 alert, 172 scenario). Top-K = Top-3 (exact id). Bootstrap theo scenario, 10000 lần, seed 42. Mốc là bge-small (R0) với cấu hình gốc (k=30).

### 2.1. Ba lần chạy E5 so với bge-small

| Hệ thống | Top-3 bge | E5a (không tiền tố) | E5b (tiền tố) | E5c (tiền tố + tune) |
|---|---|---|---|---|
| bm25 | 0.2494 | 0.2494 (0) | 0.2494 (0) | 0.2494 (0) |
| dense | 0.1512 | 0.1372 (−0.0140) | **0.2058 (+0.0546)** | 0.2058 (+0.0546) |
| hybrid | 0.2463 | 0.2377 (−0.0086) | 0.2447 (−0.0016) | 0.2557 (+0.0094) |
| hybrid+graph:full | 0.2541 | 0.2354 (−0.0187) | 0.2479 (−0.0062) | 0.2634 (+0.0094) |

### 2.2. CI 95% và p

| Hệ thống | Lần chạy | Hiệu | CI 95% | p |
|---|---|---|---|---|
| dense | E5a | −0.0140 | [−0.0533, +0.0238] | 0.479 |
| dense | E5b / E5c | **+0.0546** | **[+0.0131, +0.0980]** | **0.006** |
| hybrid | E5a | −0.0086 | [−0.0589, +0.0337] | 0.772 |
| hybrid | E5b | −0.0016 | [−0.0325, +0.0280] | 0.977 |
| hybrid | E5c | +0.0094 | [−0.0131, +0.0330] | 0.436 |
| hybrid+graph:full | E5a | −0.0187 | [−0.0647, +0.0226] | 0.396 |
| hybrid+graph:full | E5b | −0.0062 | [−0.0339, +0.0206] | 0.681 |
| hybrid+graph:full | E5c | +0.0094 | [−0.0101, +0.0316] | 0.397 |

### 2.3. Hit@10 và Hit@50 (bge → E5c)

| Hệ thống | Hit@10 | Hit@50 |
|---|---|---|
| dense | 0.2502 → 0.3624 | 0.5807 → 0.6072 |
| hybrid | 0.3819 → 0.3913 | 0.6376 → 0.6407 |
| hybrid+graph:full | 0.3975 → 0.4162 | 0.6563 → 0.6672 |

E5 đưa đúng technique vào danh sách rộng hơn ở cả dense và hybrid, nhưng Top-3 của hybrid chỉ tăng nhẹ.

### 2.4. Tác dụng của tiền tố

Tiền tố `query: ` và `passage: ` là yếu tố quan trọng nhất đối với dense:

- Dense Top-3: 0.137 (không tiền tố) → 0.206 (có tiền tố), tăng +0.069.
- Hit@10 của dense: 0.302 → 0.362.

Việc không có tiền tố làm E5 kém đi rõ rệt. Các kết luận về E5 trong báo cáo này áp dụng cho cấu hình có tiền tố.

## 3. Tune fusion cho E5 (chỉ trên dev)

Tune bằng `scripts/eval/tune_dev.py --step hybrid` trên cấu hình E5 có tiền tố. Lưới khai báo sẵn trong script: w_dense ∈ {0.25, 0.5, 0.75, 1.0} × rrf_k ∈ {10, 30, 60}, ngưỡng hoà 0.005. Kết quả `experiments/tune/e5_prefix_hybrid.json`.

| w_dense | rrf_k | Top-3 hybrid |
|---|---|---|
| **0.25** | **10** | **0.2557** (được chọn) |
| 0.5 | 10 | 0.2502 |
| 0.25 | 30 | 0.2447 (giá trị khởi đầu) |
| 0.75 | 10 | 0.2432 |
| 1.0 | 10 | 0.2416 |
| 0.25 | 60 | 0.2393 |
| 1.0 | 30 | 0.2369 |
| 0.5 | 30 | 0.2346 |
| 0.75 | 30 | 0.2346 |
| 1.0 | 60 | 0.2338 |
| 0.75 | 60 | 0.2323 |
| 0.5 | 60 | 0.2292 |

- Chọn w=0.25, rrf_k=10. Không có điểm nào khác nằm trong ngưỡng hoà 0.005 quanh điểm tốt nhất, nên không cần quy tắc phụ.
- Tune làm hybrid tăng từ 0.2447 lên 0.2557 (+0.011). Đây là mức tăng lạc quan, vì được chọn trên chính dev.

## 4. Điều kiện chạy và khả năng tái lập

- Chỉ đổi mô hình embedding và tiền tố. Giữ nguyên `max_tokens` 512, `query_budget` waterfill, `doc_chunking` head_repeat, BM25, nhãn dev và nhóm loại trừ.
- Cấu hình:
  - E5a: `experiments/configs/emb_e5_large/` (không tiền tố, sao từ cấu hình jina chưa tune).
  - E5b: `experiments/configs/emb_e5_large_prefix/` (`query_instruction: "query: "`, `doc_instruction: "passage: "`).
  - E5c: `experiments/configs/emb_e5_large_prefix_tuned/` (E5b với `rrf_k: 10`).
- `model`: `intfloat/multilingual-e5-large`. `model_revision`: `3d7cfbdacd47fdda877c5cd8a79fbcc4f2a574f3`. fastembed tự tải, không dùng bản tải tay.
- Thời gian:
  - E5a: khoảng 82 phút (21:35–22:57), gồm khoảng 5 phút tải model.
  - E5b: khoảng 72 phút (23:04–00:16). Cache tài liệu của E5b là khoá mới vì có `doc_instruction`.
  - Tune hybrid (12 điểm): khoảng 10 phút, nhờ cache BM25 và dense dùng chung.
  - E5c: chạy `eval_dev` đầy đủ (cache tài liệu đã có).
- Thay đổi code cho tiền tố: `src/attackrec/retrieval/dense.py`. Thêm `query_instruction` và `doc_instruction`, mặc định rỗng để cấu hình cũ không đổi hành vi. Khoá cache chỉ thêm `doc_instruction` khi có giá trị, nên khoá cũ không đổi. Thêm `kind` vào `encode` và cập nhật bốn file test giả lập. Toàn bộ 303 test pass.
- `verify_sources`: có chạy trước các lần đánh giá dev (dòng `verify_sources: OK` trong log).
- `run_seconds`, `config_hash` và `code_hash` của lần chạy E5 **chưa được ghi lại** trong báo cáo này. Cần lấy từ `experiments/log.jsonl` nếu muốn đối chiếu như báo cáo R1.

## 5. Hạn chế cần lưu ý

1. **Đây là ba lần thử trên dev, cộng với tune trên dev.** Mỗi lần thử làm kết quả lạc quan hơn. Hiệu hybrid của E5c (+0.0094) chưa được đánh giá trên dữ liệu chưa thấy. Tập test không được dùng trong bất kỳ bước nào.
2. **Không đối xứng về tham số.** bge giữ k=30 và w=0.25 (cấu hình R0). E5c dùng k=10. Với bge cùng k=10, Top-3 hybrid là 0.2510 (xem `emb_R1_bao_cao.md`, mục A3), thấp hơn E5c 0.0047. Khoảng cách thật giữa E5c và bge cùng k=10 nhỏ hơn con số +0.0094 ở trên.
3. **Tham số graph không được tune riêng.** Mức tăng của hybrid+graph (E5c) chủ yếu đến từ `rrf_k` mới.
4. **Tokenizer và giới hạn độ dài.** Chúng tôi đặt `max_tokens` = 512 cho E5, cùng mức với bge và jina, để giữ điều kiện so sánh. Tiền tố `passage: ` thêm vài token vào mỗi tài liệu, có thể làm một số tài liệu dài bị cắt thêm ở cuối. Chưa đo mức ảnh hưởng này.
5. **Nhãn dev do LLM gán**, không phải nhãn người. Quần thể có 172 scenario nên CI rộng.
6. **Mã nguồn `src/` và `tests/` chưa được git theo dõi.** Kết quả E5b và E5c phụ thuộc vào thay đổi trong `dense.py` (mục 4). Nếu không đưa mã nguồn vào repo thì không thể tái lập từ GitHub.
7. **Records jsonl (khoảng 42 MB mỗi file) và cache embedding (.npy) không nằm trong git.** Chúng là dữ liệu dẫn xuất, cần giữ ở nơi khác nếu muốn kiểm tra lại.

## 6. Khuyến nghị

- **Không đổi model.** Giữ bge-small theo tiêu chí đã khai báo.
- Nếu muốn tiếp tục E5, cần đánh giá E5c trên một tập dữ liệu chưa dùng để tune, hoặc chạy lại bge với k=10 để so sánh đối xứng, trước khi đưa ra quyết định.
- Dense của E5 có tiền tố tốt hơn bge có ý nghĩa thống kê. Nếu cần một hệ dense mạnh hơn, có thể xem xét E5 cho riêng nhánh dense, nhưng điều đó cần một quyết định mới theo QĐ 117, không thể dựa trên tiêu chí hybrid hiện tại.

## 7. Danh sách file kết quả

- Kết quả đánh giá: `experiments/dev/emb_E5_large.json` (E5a), `emb_E5_prefix.json` (E5b), `emb_E5_prefix_tuned.json` (E5c).
- So sánh với bge-small: `experiments/dev/emb_E5_vs_R0.json` (E5a), `emb_E5p_vs_R0.json` (E5b), `emb_E5pt_vs_R0.json` (E5c). Log so sánh: `emb_E5_compare.log`, `emb_E5p_compare.log`, `emb_E5pt_compare.log`.
- Log chạy: `experiments/dev/emb_E5_large_run.log`, `emb_E5_prefix_run.log`, `emb_E5_prefix_tuned_run.log`.
- Tune: `experiments/tune/e5_prefix_hybrid.json`, `e5_prefix_hybrid.log`, `e5_prefix_hybrid_progress.txt`.
- Config: `experiments/configs/emb_e5_large/`, `emb_e5_large_prefix/`, `emb_e5_large_prefix_tuned/`.
- Records (không đưa lên git): `experiments/dev/emb_E5_large_records.jsonl`, `emb_E5_prefix_records.jsonl`, `emb_E5_prefix_tuned_records.jsonl`.
- Báo cáo này: `experiments/dev/emb_E5_bao_cao.md`.

---

Ghi chú về ngữ cảnh: báo cáo này cho E5 được viết theo cấu trúc của `emb_R1_bao_cao.md` (jina). Mốc so sánh là bge-small R0 trong cả hai báo cáo.
