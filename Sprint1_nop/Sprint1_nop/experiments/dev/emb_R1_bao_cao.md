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

---

# Phụ lục A (bổ sung theo yêu cầu): đo độ dài token, chọn lại max_tokens, tune lại hybrid

Phần này nằm ngoài ràng buộc ban đầu của QĐ 117 ("chỉ đổi model, giữ fusion và max_tokens"). Nó được chạy theo yêu cầu bổ sung của người dùng. Kết luận ở mục 1 (R1, chưa tune) vẫn đúng cho điều kiện đó.

## A1. Độ dài token của văn bản dense (dev run4, chưa chia đoạn, chưa áp ngân sách)

Script `experiments/dev/qd117_do_do_dai_token.py`, kết quả `experiments/dev/qd117_do_dai_token.json`.

| Tokenizer / loại | n | max | p50 | p90 | p95 | p99 | >510 | >1024 | >2048 | >4096 | >8190 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| jina / tài liệu | 3034 | **9774** | 94 | 274 | 368 | 641 | 60 | 18 | 9 | 4 | 1 |
| jina / truy vấn | 11562 | **4734** | 45 | 105 | 151 | 303 | 76 | 29 | 17 | 1 | 0 |
| bge / tài liệu | 3034 | 3258 | 93 | 268 | 364 | 659 | 62 | 16 | 6 | 0 | 0 |
| bge / truy vấn | 11562 | 2420 | 53 | 105 | 155 | 292 | 18 | 5 | 1 | 0 | 0 |

- Phần lớn văn bản ngắn: p95 dưới 400 token. Chỉ khoảng 2% tài liệu và 0.7% truy vấn dài hơn 510 token.
- Văn bản dài nhất (theo tokenizer jina): tài liệu 9774 token, truy vấn 4734 token. Tài liệu dài nhất vượt cả giới hạn 8192 của model.
- Giới hạn 512 không phải của model: `model_max_length` của jina là 8192 và fastembed cắt theo giá trị đó. Mức 512 đến từ `max_tokens` trong config.
- Jina có nhiều truy vấn dài hơn 510 token hơn bge (76 so với 18), vì tokenizer của jina tách đường dẫn, GUID, hash thành nhiều token hơn.

## A2. Chọn lại max_tokens

Quy tắc đặt trước khi xem số: với `max_tokens` ∈ {512, 1024, 2048}, chạy `tune_dev.py --step hybrid` (lưới w_dense ∈ {0.25, 0.5, 0.75, 1.0} × rrf_k ∈ {10, 30, 60}, ngưỡng hoà 0.005, hoà thì chọn điểm gần cấu hình khởi đầu). Chọn `max_tokens` có Top-3 hybrid sau tune cao nhất. Nếu hoà trong 0.005 thì chọn mức nhỏ hơn. Quần thể P_chinh, 1283 alert.

| max_tokens | Top-3 tại (w=0.25, k=30) | Top-3 thô cao nhất | Điểm được chọn | Top-3 tại điểm chọn |
|---|---|---|---|---|
| 512 | 0.2619 | 0.2736 (w=0.5, k=10) | w=0.25, k=10 | 0.2689 |
| 1024 | 0.2619 | 0.2712 (w=0.5, k=10) | w=0.25, k=10 | 0.2705 |
| 2048 | 0.2595 | 0.2712 (w=0.5, k=10) | w=0.25, k=10 | 0.2681 |

- Ba mức chênh nhau tối đa 0.0024, nhỏ hơn ngưỡng hoà 0.005. **Giữ `max_tokens` = 512.** Tăng ngân sách token không cải thiện hybrid đáng kể.
- File: `experiments/tune/qd117_hybrid_jina_mt{512,1024,2048}.json` kèm `.log`.
- Hai mức 1024 và 2048 lần đầu chạy bị hết bộ nhớ khi embed tài liệu với batch mặc định 256 của fastembed. Lỗi: `BFCArena::AllocateRawInternal Failed to allocate memory for requested buffer of size 11897929728`. Tôi không sửa `src/`. Tôi dựng cache vector tài liệu bằng `experiments/dev/qd117_warm_cache.py` (batch nhỏ, cùng khoá cache của pipeline) rồi chạy lại. Batch nhỏ chỉ đổi phần đệm (padding), không đổi văn bản. Nếu có sai lệch số học thì rất nhỏ, và tôi chưa kiểm tra riêng điều này.

## A3. Tune lại hybrid (max_tokens = 512), so với bge

Top-3 trên P_chinh, cùng lưới cho hai model.

| w_dense | rrf_k | jina | bge |
|---|---|---|---|
| 0.25 | 10 | 0.2689 | 0.2510 |
| 0.25 | 30 | 0.2619 | 0.2463 |
| 0.25 | 60 | 0.2557 | 0.2424 |
| 0.5 | 10 | **0.2736** | 0.2494 |
| 0.5 | 30 | 0.2549 | 0.2408 |
| 0.5 | 60 | 0.2533 | 0.2369 |
| 0.75 | 10 | 0.2611 | 0.2455 |
| 0.75 | 30 | 0.2494 | 0.2299 |
| 0.75 | 60 | 0.2486 | 0.2253 |
| 1.0 | 10 | 0.2541 | 0.2346 |
| 1.0 | 30 | 0.2510 | 0.2214 |
| 1.0 | 60 | 0.2494 | 0.2167 |

- Jina: giá trị thô cao nhất 0.2736 (w=0.5, k=10). Theo quy tắc hoà, điểm được chọn là w=0.25, k=10 (0.2689), vì nằm trong 0.005 và gần cấu hình khởi đầu hơn.
- Bge: cấu hình đã chọn trước đó là w=0.25, k=30 (0.2463). Giá trị thô cao nhất là 0.2510 (w=0.25, k=10). Bge chưa được đổi sang k=10 trong baseline R0.
- Jina cao hơn bge ở cả 12 điểm lưới. Tune nâng Top-3 hybrid của jina từ 0.2619 lên 0.2689 (+0.007).

## A4. Đánh giá đầy đủ: jina đã tune (R2) vs baseline bge R0

Cấu hình `experiments/configs/emb_jina_code_tuned/` (max_tokens 512, w=0.25, rrf_k=10, graph giữ nguyên). File: `emb_R2_jina_code_tuned.json`, `emb_R2_jina_code_tuned_records.jsonl`, `emb_R2_vs_R0.json`, `emb_R2_run.log`, `emb_R2_compare.log`. Baseline bge (R0) giữ nguyên w=0.25, k=30.

| Hệ thống | Top-3 bge | Top-3 jina (tune) | Hiệu | CI 95% | p | Hit@10 bge → jina | Hit@50 bge → jina |
|---|---|---|---|---|---|---|---|
| bm25 | 0.2494 | 0.2494 | 0.0000 | [0.0000, 0.0000] | 1.000 | 0.3866 → 0.3866 | 0.6376 → 0.6376 |
| dense | 0.1512 | 0.1894 | +0.0382 | [0.0056, 0.0730] | 0.022 | 0.2502 → 0.3554 | 0.5807 → 0.6204 |
| hybrid | 0.2463 | 0.2689 | **+0.0226** | **[-0.0047, +0.0560]** | 0.117 | 0.3819 → 0.3858 | 0.6376 → 0.6477 |
| hybrid+graph:full | 0.2541 | 0.2744 | +0.0203 | [-0.0039, +0.0522] | 0.127 | 0.3975 → 0.4100 | 0.6563 → 0.6758 |

- `run_seconds` = 1036.0 s (cache vector tài liệu đã có sẵn). `config_hash` R2: `676a245165b2135e9c91b4eb3107971d3ee729fbb3db12611a514c45380e0652`. `code_hash` không đổi: `319be8c145a67c61814e3a5b93f3081eb288e8efee2a0f7f5b245193d6461045`. `model_revision` như mục 4.
- BM25 và dense giống hệt R1, vì chỉ trọng số fusion đổi.

### Kết luận sau khi tune

- Tiêu chí đặt trước, không đổi: "đạt" khi CI 95% hiệu Top-K của hybrid nằm hoàn toàn trên 0.
- Hybrid sau tune: +0.0226, CI [-0.0047, +0.0560]. Cận dưới vẫn âm, nên **vẫn KHÔNG ĐẠT**, nhưng sát ngưỡng (p = 0.117; trước tune là p = 0.369).

### Lưu ý khi đọc

1. Cấu hình jina được chọn trên chính dev rồi đánh giá trên dev, nên con số sau tune hơi lạc quan. CI không tính việc chọn trong 12 điểm lưới.
2. So sánh chưa hoàn toàn đối xứng: bge giữ cấu hình R0 (k=30), còn jina dùng k=10. Nếu bge cũng dùng k=10 thì Top-3 hybrid của bge là 0.2510 và khoảng cách thu hẹp còn khoảng 0.018. Tôi chưa chạy lại eval đầy đủ và CI cho trường hợp đó.
3. Chỉ tune trọng số fusion và `rrf_k`. Tham số graph không được tune lại. Mức tăng của hybrid+graph chủ yếu là hệ quả của k=10 mới.
4. Tăng `max_tokens` lên 1024 hoặc 2048 không giúp ích.
5. Nhãn dev do LLM gán, quần thể có 172 scenario nên CI rộng. Số liệu chỉ mang tính chỉ dẫn.
