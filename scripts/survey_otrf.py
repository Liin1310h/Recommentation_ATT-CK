"""Read-only survey of OTRF Security-Datasets: YAML metadata + zip contents (streamed, nothing extracted)."""
import collections, glob, json, os, re, statistics, sys, zipfile

try:
    import yaml
except ImportError:
    sys.exit('PyYAML not installed (install needs explicit approval)')

root = sys.argv[1]
ymls = sorted(glob.glob(os.path.join(root, 'datasets', '**', '_metadata', '*.yaml'), recursive=True))
print('yaml files', len(ymls))
meta = []
for p in ymls:
    d = yaml.safe_load(open(p, encoding='utf-8')) or {}
    d['_path'] = os.path.relpath(p, root)
    meta.append(d)

print('type', dict(collections.Counter(m.get('type') for m in meta)))
plat = collections.Counter(pl for m in meta for pl in (m.get('platform') or []))
print('platform', dict(plat))
print('no attack_mappings', sum(1 for m in meta if not m.get('attack_mappings')))
print('no files entry', sum(1 for m in meta if not m.get('files')))

tech = collections.defaultdict(set); sub = collections.defaultdict(set); tac = collections.Counter()
nmap = []
for m in meta:
    ams = m.get('attack_mappings') or []
    nmap.append(len(ams))
    for a in ams:
        t = str(a.get('technique') or '').strip()
        s = str(a.get('sub-technique') or '').strip()
        if not t:
            continue
        tech[t].add(m['id'])
        if s and s.lower() != 'none':
            sub[f'{t}.{s.zfill(3)}'].add(m['id'])
        for ta in a.get('tactics') or []:
            tac[ta] += 1
print('mappings per dataset: median', statistics.median(nmap), 'max', max(nmap))
print('distinct techniques', len(tech), 'distinct sub-techniques', len(sub))
for th in (1, 3, 5):
    print(f'techniques with >={th} datasets', sum(len(v) >= th for v in tech.values()),
          '| sub-techniques', sum(len(v) >= th for v in sub.values()))
print('top techniques by datasets', sorted(((k, len(v)) for k, v in tech.items()), key=lambda x: -x[1])[:12])
print('tactics', dict(tac.most_common(14)))

# zip contents: stream-count lines, no extraction
local_zips = glob.glob(os.path.join(root, 'datasets', '**', '*.zip'), recursive=True)
print('local zips', len(local_zips), 'MB', round(sum(os.path.getsize(z) for z in local_zips) / 2**20, 1))
member_ext = collections.Counter(); lines = []; bad = 0; first = {}
for z in local_zips:
    try:
        with zipfile.ZipFile(z) as zf:
            for i in zf.infolist():
                member_ext[os.path.splitext(i.filename)[1].lower()] += 1
                if i.filename.lower().endswith('.json'):
                    n = 0
                    with zf.open(i) as fh:
                        for ln in fh:
                            n += 1
                            if n == 1 and z not in first:
                                first[z] = ln[:1200].decode('utf-8', 'replace')
                    lines.append((z, i.filename, n))
    except zipfile.BadZipFile:
        bad += 1
print('zip members by ext', dict(member_ext), 'bad zips', bad)
cnt = [n for _, _, n in lines]
if cnt:
    print('json members', len(cnt), 'events total', sum(cnt), 'median/p90/max', statistics.median(cnt),
          sorted(cnt)[int(len(cnt) * .9)], max(cnt))
# distinct yaml ids with local zip present
print('sample first line (1 file):', next(iter(first.values()), '')[:600])
chan = collections.Counter()
for z, fn, n in lines[:400]:
    pass
