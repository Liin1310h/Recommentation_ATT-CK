"""Đo độ dài token (tokenizer jina và bge) của văn bản dense: tài liệu (nguyên văn, chưa chia đoạn) và truy vấn
(chưa áp ngân sách). Chỉ đọc dev. Chạy: python experiments/dev/qd117_do_do_dai_token.py"""
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.stdout.reconfigure(encoding="utf-8")

from tokenizers import Tokenizer  # noqa: E402

from attackrec.evaluation.label_policy import apply_label_policy  # noqa: E402
from attackrec.paths import load_config, load_yaml, resolve  # noqa: E402
from attackrec.pipeline import WindowsPipeline  # noqa: E402
from attackrec.platforms.windows.retrieval import windows_dense_parts  # noqa: E402
from attackrec.retrieval.dense import query_values  # noqa: E402
from attackrec.retrieval.bm25 import query_exclude_fields  # noqa: E402
from attackrec.platforms.windows.retrieval import PLATFORM  # noqa: E402

cfg = load_config(str(ROOT / "experiments/configs/emb_jina_code/default.yaml"))
lock = load_yaml(resolve(cfg["paths"]["sources_lock"]))
pipe = WindowsPipeline(cfg, lock, ["dense"])
emb = cfg["retrieval"]["embedding"]
parts = windows_dense_parts(cfg, lock, pipe.engine, pipe.normalizer, resolve(lock["sigma"]["extracted_dir"]), ROOT)
doc_texts = [p.full() for _, p in parts]

split = ROOT / "data/interim/windows_run4/dev"
alerts = [json.loads(x) for x in open(split / "alerts.jsonl", encoding="utf-8") if x.strip()]
labels = {x["alert_id"]: x["labels"] for x in map(json.loads, open(split / "labels.jsonl", encoding="utf-8"))}
kept = apply_label_policy(labels, cfg).kept
excl = query_exclude_fields(cfg, PLATFORM)
stack = frozenset(emb.get("query_stack_module_fields") or ())
queries = ["\n".join(query_values(a["fields"], excl, stack)) for a in alerts if a["alert_id"] in kept]

toks = {"jina": Tokenizer.from_str(pipe.dense.encoder.model.model.tokenizer.to_str()),
        "bge": Tokenizer.from_file(str(ROOT / "models/fastembed/bge-small-en-v1.5-onnx-Q/tokenizer.json"))}
for t in toks.values():
    t.no_truncation()
    t.no_padding()
TH = [510, 1024, 2048, 4096, 8190]
out = {}
for name, tok in toks.items():
    for kind, texts in (("tai_lieu", doc_texts), ("truy_van", queries)):
        n = np.array([len(tok.encode(t, add_special_tokens=False).ids) for t in texts])
        out[f"{name}/{kind}"] = {"n": int(len(n)), "max": int(n.max()), "mean": round(float(n.mean()), 1),
                                 **{f"p{p}": int(np.percentile(n, p)) for p in (50, 90, 95, 99)},
                                 **{f">{t}": int((n > t).sum()) for t in TH}}
        print(name, kind, json.dumps(out[f"{name}/{kind}"]), flush=True)
Path(ROOT / "experiments/dev/qd117_do_dai_token.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
