Set-Location "E:\tài liệu linh\AI_VIN\SOC\Sprint1_nop\Sprint1_nop"
foreach($c in @(@('emb_jina_code_mt1024',1024,8),@('emb_jina_code_mt2048',2048,4))){
  $t=Get-Date; $n=$c[1]
  .\.venv\Scripts\python.exe experiments\dev\qd117_warm_cache.py "experiments\configs\$($c[0])\default.yaml" $c[2] *> "experiments\tune\qd117_warm_mt$n.log"
  "warm mt$n exit $LASTEXITCODE min $(((Get-Date)-$t).TotalMinutes)" | Add-Content experiments\tune\qd117_progress2.txt
  Move-Item "experiments\tune\qd117_hybrid_jina_mt$n.json" "experiments\tune\qd117_hybrid_jina_mt$n.fail.json" -ErrorAction SilentlyContinue
  .\.venv\Scripts\python.exe scripts\eval\tune_dev.py --step hybrid --config "experiments\configs\$($c[0])\default.yaml" --split-dir data\interim\windows_run4\dev --out "experiments\tune\qd117_hybrid_jina_mt$n.json" *> "experiments\tune\qd117_hybrid_jina_mt$n.log"
  "tune mt$n exit $LASTEXITCODE min $(((Get-Date)-$t).TotalMinutes)" | Add-Content experiments\tune\qd117_progress2.txt
}
