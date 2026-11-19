$ErrorActionPreference="Continue"
Set-Location "E:\tài liệu linh\AI_VIN\SOC\Sprint1_nop\Sprint1_nop"
foreach($c in @(@('emb_jina_code',512),@('emb_jina_code_mt1024',1024),@('emb_jina_code_mt2048',2048))){
  $t=Get-Date
  .\.venv\Scripts\python.exe scripts\eval\tune_dev.py --step hybrid --config "experiments\configs\$($c[0])\default.yaml" --split-dir data\interim\windows_run4\dev --out "experiments\tune\qd117_hybrid_jina_mt$($c[1]).json" *> "experiments\tune\qd117_hybrid_jina_mt$($c[1]).log"
  "mt$($c[1]) exit $LASTEXITCODE min $(((Get-Date)-$t).TotalMinutes)" | Add-Content experiments\tune\qd117_progress.txt
}
