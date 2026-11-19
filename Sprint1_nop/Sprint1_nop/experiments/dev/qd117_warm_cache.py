"""Dựng trước cache vector tài liệu (cùng khoá cache như pipeline) bằng batch nhỏ để tránh hết RAM khi max_tokens lớn.
Không sửa src/: chỉ thay encode() trong tiến trình này. Dùng: python qd117_warm_cache.py <config> <batch>"""
import sys
from pathlib import Path
import numpy as np
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from attackrec.paths import load_config, load_yaml, resolve
from attackrec.retrieval import dense
from attackrec.pipeline import WindowsPipeline
bs = int(sys.argv[2])
def encode(self, texts):
    return dense._l2(np.array(list(self.model.embed(texts, batch_size=bs)), dtype=np.float64))
dense.FastEmbedEncoder.encode = encode
cfg = load_config(sys.argv[1])
WindowsPipeline(cfg, load_yaml(resolve(cfg["paths"]["sources_lock"])), ["dense"])
print("cache OK", cfg["retrieval"]["embedding"]["max_tokens"])
