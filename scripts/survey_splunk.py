"""Read-only metadata survey of splunk/attack_data. Uses YAML + LFS pointer sizes; downloads nothing.

Fix log (2026-11-04):
- mitre_technique given as a plain string is treated as a 1-element list (before: iterated per character);
  number of such yml printed.
- IDs not matching T\\d{4}(\\.\\d{3})? (e.g. placeholder T1XXX.XXX) are excluded from all statistics and
  printed separately with occurrence counts.
- Unparseable yml: path + exception name recorded, up to 5 printed.
- One shared stats function runs for 3 sets: all, windows (a dataset with sourcetype XmlWinEventLog),
  linux (sourcetype sysmon:linux or auditd). Each prints IDs / sub-technique IDs / parents, counts with
  >=1/3/5 dataset dirs, top 12 parents.
- Prints ALL IDS (sorted, valid IDs only).
"""
import collections, glob, os, re, statistics, sys
import yaml

root = sys.argv[1]
ymls = [p for p in glob.glob(os.path.join(root, 'datasets', '**', '*.yml'), recursive=True)]
print('yml files', len(ymls))
meta = []; broken = []
for p in ymls:
    try:
        with open(p, encoding='utf-8') as fh:
            d = yaml.safe_load(fh) or {}
    except Exception as ex:
        broken.append((os.path.relpath(p, root).replace('\\', '/'), type(ex).__name__)); continue
    d['_dir'] = os.path.relpath(os.path.dirname(p), root).replace('\\', '/')
    meta.append(d)
print('unparseable yml', len(broken), broken[:5])
print('top-level dataset folders', dict(collections.Counter(m['_dir'].split('/')[1] for m in meta if '/' in m['_dir'])))
print('environment', dict(collections.Counter(m.get('environment') for m in meta)))
no_t = [m for m in meta if not m.get('mitre_technique')]
print('yml without mitre_technique', len(no_t), '| of which under attack_techniques', sum('attack_techniques' in m['_dir'] for m in no_t))

ID_RE = re.compile(r'T\d{4}(\.\d{3})?')


def tech_list(m):
    v = m.get('mitre_technique')
    if not v:
        return []
    if isinstance(v, str):
        return [v]
    return list(v)


print('yml with mitre_technique as string', sum(isinstance(m.get('mitre_technique'), str) and bool(m.get('mitre_technique')) for m in meta))

invalid = collections.Counter()
for m in meta:
    m['_ids'] = []
    for t in tech_list(m):
        t = str(t).strip()
        if ID_RE.fullmatch(t):
            m['_ids'].append(t)
        else:
            invalid[t] += 1
print('excluded IDs not matching T####(.###)', sum(invalid.values()), dict(invalid))


def sourcetypes(m):
    return {str(d.get('sourcetype')) for d in (m.get('datasets') or []) if isinstance(d, dict)}


def stats(label, subset):
    tech = collections.defaultdict(set)
    for m in subset:
        for t in m['_ids']:
            tech[t].add(m['_dir'])
    parent = collections.defaultdict(set)
    for t, s in tech.items():
        parent[t.split('.')[0]] |= s
    print(f'[{label}] yml', len(subset), '| distinct IDs', len(tech), '| sub-technique IDs', sum('.' in t for t in tech),
          '| distinct parents', len(parent))
    for th in (1, 3, 5):
        print(f'[{label}] IDs with >={th} dataset-dirs', sum(len(v) >= th for v in tech.values()),
              '| parents', sum(len(v) >= th for v in parent.values()))
    print(f'[{label}] top 12 parents by dataset-dirs', sorted(((k, len(v)) for k, v in parent.items()), key=lambda x: (-x[1], x[0]))[:12])
    return tech


all_tech = stats('all', meta)
stats('windows', [m for m in meta if 'XmlWinEventLog' in sourcetypes(m)])
stats('linux', [m for m in meta if sourcetypes(m) & {'sysmon:linux', 'auditd'}])
print('ALL IDS', sorted(all_tech))

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
