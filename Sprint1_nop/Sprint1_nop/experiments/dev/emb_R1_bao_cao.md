# QĐ 117 – So sánh embedding: jina-embeddings-v2-base-code (R1) vs bge-small-en-v1.5 (R0)

## 1. Kết luận theo tiêu chí khai báo trước

Tiêu chí (khai báo trước, không đổi sau khi xem số): "đạt" khi và chỉ khi khoảng tin cậy 95% của hiệu Top-K của **hybrid** nằm hoàn toàn trên 0.

- Hybrid: hiệu Top-3 = +0.0156, CI 95% [-0.0175, +0.0519], p = 0.369. CI chứa 0.
- **Kết luận: KHÔNG ĐẠT.**
- Dense-only tốt hơn có ý nghĩa (+0.0382, CI [0.0056, 0.0730], p = 0.022). Theo tiêu chí đã định, dense tốt hơn nhưng hybrid không tốt hơn thì vẫn là "không đạt".

## 2. Kết quả theo hệ thống

Quần thể: tier 2∪3, capped_in, evidence_event_groups (1283 alert, 172 scenario). Top-K = Top-3 (exact id). Bootstrap theo scenario, seed 42.

| Hệ thống | Top-3 base (bge) | Top-3 new (jina) | Hiệu | CI 95% | p | Hit@10 base → new | Hit@50 base → new |
|---|---|---|---|---|---|---|---|
| bm25 | 0.2494 | 0.2494 | 0.0000 | [0.0000, 0.0000] | 1.000 | 0.3866 → 0.3866 | 0.6376 → 0.6376 |
| dense | 0.1512 | 0.1894 | +0.0382 | [0.0056, 0.0730] | 0.022 | 0.2502 → 0.3554 | 0.5807 → 0.6204 |
| hybrid | 0.2463 | 0.2619 | +0.0156 | [-0.0175, 0.0519] | 0.369 | 0.3819 → 0.3897 | 0.6376 → 0.6383 |
| hybrid+graph:full | 0.2541 | 0.2595 | +0.0055 | [-0.0281, 0.0432] | 0.779 | 0.3975 → 0.4178 | 0.6563 → 0.6687 |

Kiểm tra BM25: cả 14 khóa metric `bm25|...` trong `emb_R0_bge_small.json` và `emb_R1_jina_code.json` giống hệt nhau, hiệu bằng 0. Đổi embedding không ảnh hưởng nhánh BM25, đúng như kỳ vọng.

Tỷ lệ alert mà BM25-only / dense-only / cả hai tìm đúng (đầu ra `rieng_base`, `rieng_new` của `compare_embedding.py`):

| | chỉ BM25 | chỉ dense | cả hai |
|---|---|---|---|
| bge (base) | 0.1442 | 0.0460 | 0.1052 |
| jina (new) | 0.1263 | 0.0663 | 0.1231 |

Jina bổ sung thêm phần dense-only (0.046 → 0.066) và phần trùng với BM25 (0.105 → 0.123). Nhưng phần đó đã được BM25 phủ gần hết nên hybrid tăng ít.

## 3. Tham số dense (jina vs bge)

| Chỉ số | bge | jina |
|---|---|---|
| docs_chunked | 62 | 48 |
| doc_vectors_over_budget | 0 | 118 |
| queries_budgeted | 33 | 132 |
| queries_over_budget | 0 | 136 |

Hai model dùng tokenizer khác nhau, nên cùng `max_tokens` = 512 (token_budget 510) vẫn cho số tài liệu bị chia đoạn và số query vượt ngân sách khác nhau. Jina có 136 query vẫn vượt ngân sách sau khi áp ngân sách. Việc này có thể làm dense của jina bị cắt bớt thông tin. Tôi không chỉnh gì để giữ nguyên điều kiện so sánh.

## 4. Điều kiện chạy và khả năng tái lập

- Chỉ đổi mô hình embedding. Giữ nguyên `max_tokens` 512, `query_budget` waterfill, `doc_chunking` head_repeat, trọng số fusion (embedding 0.25), `rrf_k` 30 và graph.
- `model_revision` (jina): `516f4baf13dec4ddddda8631e019b5737c8bc250`. Model tải từ Hugging Face ngày 2026-11-19, file `onnx/model.onnx` 641,517,466 byte.
- `config_hash` (R1): `801fed7fb15d92a955d0ac4faf4817ae5a206ce0643c3bb3530714d636dc0f8f`.
- `code_hash`: `319be8c145a67c61814e3a5b93f3081eb288e8efee2a0f7f5b245193d6461045`. Trùng với các lần chạy trước nên không sinh snapshot mới.
- Máy: Windows 11 (10.0.26300), CPU Intel Core i7-13650HX, không GPU (ONNX CPU).
- Phiên bản: Python 3.14.6, fastembed 0.9.1, onnxruntime 1.31.1, tokenizers 0.23.3, numpy 2.5.4.
- `verify_sources`: OK (mọi giá trị khớp `SOURCES.lock`).
- Thời gian:
  - `run_seconds` do script ghi: 1038.7 s (R1) so với 838.6 s (R0).
  - Thời gian thực tế của lệnh jina là khoảng 210 phút, chủ yếu do tính embedding tài liệu bằng jina-base trên CPU. Hai số này lệch nhau và tôi chưa kiểm tra nguyên nhân (nhiều khả năng bước tạo cache embedding nằm ngoài đoạn tính `run_seconds`).
- BM25, dữ liệu dev, nhãn và nhóm loại trừ (49 alert `label_set_too_large`) giống R0.

## 5. Hạn chế cần lưu ý

1. **Trọng số fusion thiên về bge.** Trọng số embedding 0.25 và `rrf_k` 30 được chỉnh cho bge, nên so sánh hybrid hơi có lợi cho bge. Đây là giới hạn đã biết và tôi không chỉnh lại. Hybrid của jina có thể tốt hơn nếu tuning riêng.
2. **Nhãn dev do LLM gán**, không phải nhãn người: Gemini, và từ 17/11 có thêm Claude và DeepSeek. Kết quả chỉ mang tính chỉ dẫn.
3. **Cỡ mẫu hiệu dụng nhỏ.** Phép bootstrap theo scenario có 172 scenario trong quần thể, nên CI rộng. Hiệu hybrid +0.0156 nhỏ hơn nhiều so với độ rộng CI (~0.07).
4. **Bước 2 (chạy lại bge) đã bỏ qua** theo xác nhận của người dùng, vì ở thời điểm đó dữ liệu máy cá nhân chưa đủ để qua `verify_sources`. Baseline dùng `emb_R0_bge_small_records.jsonl` gốc, chưa được đối chiếu lại bằng lần chạy lại trên máy này. Yêu cầu "khớp ≤ 0.001" của bước 2 vì vậy chưa được kiểm chứng. Về sau dữ liệu đã đủ và `verify_sources` đã OK, nên có thể chạy lại bước 2 nếu cần.
5. **Pytest còn lỗi do thiếu dữ liệu** tại thời điểm bước 0 (11 error ở `tests/test_kg.py` và 1 fail ở `tests/test_pin_export.py::test_matches_real_run3_lock`). Chưa chạy lại bộ test sau khi bổ sung dữ liệu.
6. **Windows Defender chặn một số file mẫu trong `data/raw/sigma-master/regression_data`.** Chúng được phục hồi sau khi người dùng thêm exclusion cho thư mục này. Hash `sigma_rules_dir_hash` khớp lock sau khi phục hồi.
7. `data/test/` không bị đọc hay giải nén. Hai file `test.zip` chỉ được chép như file nhị phân để `verify_sources` kiểm hash.

## 6. Danh sách file kết quả

- `experiments/dev/emb_R1_jina_code.json`
- `experiments/dev/emb_R1_jina_code_records.jsonl`
- `experiments/dev/emb_R1_vs_R0.json`
- `experiments/dev/emb_R1_bao_cao.md` (file này)
- `experiments/dev/emb_R1_run.log`, `emb_R1_compare.log`
- `experiments/log_may_ca_nhan.jsonl` (2 dòng mới của `experiments/log.jsonl`: lần chạy eval_dev và compare_embedding)
- `experiments/configs/emb_jina_code/retrieval.yaml` (đã điền `model_revision`)
- `experiments/cache/embeddings_jina_code/` (cache embedding jina, tùy chọn)
- `emb_R0_bge_small_rerun.json`: không có (bước 2 bỏ qua).
