"""Read-only metadata survey of splunk/attack_data. Uses YAML + LFS pointer sizes; downloads nothing."""
import collections, glob, os, re, statistics, sys
import yaml

root = sys.argv[1]
ymls = [p for p in glob.glob(os.path.join(root, 'datasets', '**', '*.yml'), recursive=True)]
print('yml files', len(ymls))
meta = []; broken = 0
for p in ymls:
    try:
        d = yaml.safe_load(open(p, encoding='utf-8')) or {}
    except Exception:
        broken += 1; continue
    d['_dir'] = os.path.relpath(os.path.dirname(p), root).replace('\\', '/')
    meta.append(d)
print('unparseable yml', broken)
print('top-level dataset folders', dict(collections.Counter(m['_dir'].split('/')[1] for m in meta if '/' in m['_dir'])))
print('environment', dict(collections.Counter(m.get('environment') for m in meta)))
no_t = [m for m in meta if not m.get('mitre_technique')]
print('yml without mitre_technique', len(no_t), '| of which under attack_techniques', sum('attack_techniques' in m['_dir'] for m in no_t))

tech = collections.defaultdict(set)
for m in meta:
    for t in m.get('mitre_technique') or []:
        tech[str(t).strip()].add(m['_dir'])
parent = collections.defaultdict(set)
for t, s in tech.items():
    parent[t.split('.')[0]] |= s
print('distinct technique/sub-technique IDs', len(tech), '| sub-technique forms', sum('.' in t for t in tech), '| distinct parents', len(parent))
for th in (1, 3, 5):
    print(f'IDs with >={th} dataset-dirs', sum(len(v) >= th for v in tech.values()), '| parents', sum(len(v) >= th for v in parent.values()))
print('top parents by dataset-dirs', sorted(((k, len(v)) for k, v in parent.items()), key=lambda x: -x[1])[:12])
print('IDs not matching T####(.###)', [t for t in tech if not re.fullmatch(r'T\d{4}(\.\d{3})?', t)][:10])

src = collections.Counter(); st = collections.Counter(); nds = []
for m in meta:
    ds = m.get('datasets') or []
    nds.append(len(ds))
    for d in ds:
        src[str(d.get('source'))[:70]] += 1; st[str(d.get('sourcetype'))] += 1
print('datasets (log files) listed', sum(nds), 'per-yml median', statistics.median(nds) if nds else 0)
print('sourcetype', st.most_common(8))
print('source', src.most_common(10))

sizes = []; ptr = 0; real = 0; ext = collections.Counter()
for p in glob.glob(os.path.join(root, 'datasets', '**', '*'), recursive=True):
    if not os.path.isfile(p) or p.endswith('.yml'):
        continue
    ext[os.path.splitext(p)[1].lower()] += 1
    if os.path.getsize(p) < 300:
        t = open(p, 'rb').read(200)
        if t.startswith(b'version https://git-lfs'):
            ptr += 1
            m = re.search(rb'size (\d+)', open(p, 'rb').read())
            if m:
                sizes.append(int(m[1]))
            continue
    real += 1
print('data file ext', dict(ext.most_common(8)))
print('LFS pointers', ptr, 'non-pointer data files', real)
if sizes:
    s = sorted(sizes)
    print('log size MB median/p90/max', round(s[len(s)//2]/1e6, 2), round(s[int(len(s)*.9)]/1e6, 2), round(s[-1]/1e6, 1), '| total GB', round(sum(s)/1e9, 2))
