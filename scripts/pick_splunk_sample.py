"""Pick one small Windows log per parent technique (deterministic: sorted by path). Prints repo-relative paths."""
import glob, os, re, sys, yaml

root, limit = sys.argv[1], int(sys.argv[2])
chosen = {}
for p in sorted(glob.glob(os.path.join(root, 'datasets', 'attack_techniques', '**', '*.yml'), recursive=True)):
    try:
        d = yaml.safe_load(open(p, encoding='utf-8')) or {}
    except Exception:
        continue
    ts = [str(t).split('.')[0] for t in (d.get('mitre_technique') or []) if re.fullmatch(r'T\d{4}(\.\d{3})?', str(t))]
    for ds in d.get('datasets') or []:
        if str(ds.get('sourcetype')) != 'XmlWinEventLog':
            continue
        f = os.path.join(root, str(ds.get('path', '')).lstrip('/').replace('/', os.sep))
        if 'FuckThatPacker' in f or not os.path.isfile(f):
            continue
        head = open(f, 'rb').read(300)
        m = re.search(rb'size (\d+)', head) if head.startswith(b'version https://git-lfs') else None
        size = int(m[1]) if m else os.path.getsize(f)
        if not 5_000 <= size <= 300_000:
            continue
        for t in ts[:1]:
            if t not in chosen and len(chosen) < limit:
                chosen[t] = os.path.relpath(f, root).replace('\\', '/')
for t, f in chosen.items():
    print(f)
