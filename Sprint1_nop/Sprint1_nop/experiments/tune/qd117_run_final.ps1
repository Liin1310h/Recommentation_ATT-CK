Set-Location "E:\tài liệu linh\AI_VIN\SOC\Sprint1_nop\Sprint1_nop"
$t=Get-Date
.\.venv\Scripts\python.exe scripts\eval\eval_dev.py --systems bm25,dense,hybrid,hybrid+graph:full --config experiments\configs\emb_jina_code_tuned\default.yaml --split-dir data\interim\windows_run4\dev --out experiments\dev\emb_R2_jina_code_tuned.json *> experiments\dev\emb_R2_run.log
"eval exit $LASTEXITCODE min $(((Get-Date)-$t).TotalMinutes)" | Add-Content experiments\tune\qd117_progress3.txt
.\.venv\Scripts\python.exe scripts\eval\compare_embedding.py --base experiments\dev\emb_R0_bge_small_records.jsonl --new experiments\dev\emb_R2_jina_code_tuned_records.jsonl --out experiments\dev\emb_R2_vs_R0.json *> experiments\dev\emb_R2_compare.log
"compare exit $LASTEXITCODE" | Add-Content experiments\tune\qd117_progress3.txt
