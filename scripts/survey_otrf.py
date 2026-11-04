"""Read-only survey of OTRF Security-Datasets: YAML metadata + zip contents (streamed, nothing extracted).

Fix log (2026-11-04):
- YAML is read with yaml.BaseLoader (every scalar is a string). yaml.safe_load parsed
  'sub-technique: 010' as octal 8 -> T1003.008 instead of T1003.010.
- sub-technique accepts full form (T1003.001; must start with '<technique>.', else recorded in
  bad values but still counted) or digits only (<=3 digits -> '<technique>.<zfill(3)>');
  empty / 'none' skipped; anything else -> bad values (no guessing).
- technique not matching T\\d{4} -> bad values, mapping skipped.
- Prints 'unparsed technique/sub-technique values', ALL_TECHNIQUE_IDS, ALL_SUBTECHNIQUE_IDS (sorted).
- Corrupt zips (zipfile.BadZipFile): skipped, counted, up to 5 relative paths printed.
- Removed the 'sample first line' print (it printed raw log content; output must be stats only).
"""
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
    with open(p, encoding='utf-8') as fh:
        d = yaml.load(fh, Loader=yaml.BaseLoader) or {}
    d['_path'] = os.path.relpath(p, root).replace('\\', '/')
    meta.append(d)

print('type', dict(collections.Counter(m.get('type') for m in meta)))
plat = collections.Counter(pl for m in meta for pl in (m.get('platform') or []))
print('platform', dict(plat))
print('no attack_mappings', sum(1 for m in meta if not m.get('attack_mappings')))
print('no files entry', sum(1 for m in meta if not m.get('files')))

TECH_RE = re.compile(r'T\d{4}')
SUBFULL_RE = re.compile(r'T\d{4}\.\d{3}')
tech = collections.defaultdict(set); sub = collections.defaultdict(set); tac = collections.Counter()
nmap = []; bad_values = []
for m in meta:
    ams = m.get('attack_mappings') or []
    nmap.append(len(ams))
    for a in ams:
        t = str(a.get('technique') or '').strip()
        s = str(a.get('sub-technique') or '').strip()
        if not TECH_RE.fullmatch(t):
            bad_values.append((m['_path'], 'technique', t))
            continue
        tech[t].add(m['id'])
        if s and s.lower() != 'none':
            if SUBFULL_RE.fullmatch(s):
                if not s.startswith(t + '.'):
                    bad_values.append((m['_path'], 'sub-technique', s))
                sub[s].add(m['id'])
            elif s.isdigit() and len(s) <= 3:
                sub[f'{t}.{s.zfill(3)}'].add(m['id'])
            else:
                bad_values.append((m['_path'], 'sub-technique', s))
        for ta in a.get('tactics') or []:
            tac[ta] += 1
print('mappings per dataset: median', statistics.median(nmap), 'max', max(nmap))
print('distinct techniques', len(tech), 'distinct sub-techniques', len(sub))
for th in (1, 3, 5):
    print(f'techniques with >={th} datasets', sum(len(v) >= th for v in tech.values()),
          '| sub-techniques', sum(len(v) >= th for v in sub.values()))
print('top techniques by datasets', sorted(((k, len(v)) for k, v in tech.items()), key=lambda x: -x[1])[:12])
print('tactics', dict(tac.most_common(14)))
print('unparsed technique/sub-technique values', len(bad_values), bad_values)
print('ALL_TECHNIQUE_IDS', sorted(tech))
print('ALL_SUBTECHNIQUE_IDS', sorted(sub))

# zip contents: stream-count lines, no extraction
local_zips = glob.glob(os.path.join(root, 'datasets', '**', '*.zip'), recursive=True)
print('local zips', len(local_zips), 'MB', round(sum(os.path.getsize(z) for z in local_zips) / 2**20, 1))
member_ext = collections.Counter(); lines = []; bad_zips = []; first = {}
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
        bad_zips.append(os.path.relpath(z, root).replace('\\', '/'))
print('zip members by ext', dict(member_ext), 'bad zips', len(bad_zips))
print('bad zip paths (max 5)', bad_zips[:5])
cnt = [n for _, _, n in lines]
if cnt:
    print('json members', len(cnt), 'events total', sum(cnt), 'median/p90/max', statistics.median(cnt),
          sorted(cnt)[int(len(cnt) * .9)], max(cnt))
