"""Survey of EVTX-ATTACK-SAMPLES (evtx files + evtx_data.csv), read-only.

Fix log (2026-11-04):
- Two-way name match between evtx_data.csv and the repo (case-insensitive file names):
  'csv names not in repo' AND 'repo names not in csv', each with count and first 10 names.
- Medians use statistics.median (before: sorted[len//2]).
- .git directory is pruned from the walk.
"""
import csv, os, re, sys, statistics, collections
root = sys.argv[1]
files = []
for dp, dirs, fn in os.walk(root):
    dirs[:] = [d for d in dirs if d != '.git']
    for f in fn:
        if f.lower().endswith('.evtx'):
            files.append(os.path.join(dp, f))
sz = sorted(os.path.getsize(f) for f in files)
print('evtx', len(files), 'totalMB', round(sum(sz) / 2**20, 1), 'median KB', round(statistics.median(sz) / 1024, 1),
      'p90 KB', round(sz[int(len(sz)*.9)] / 1024, 1), 'max KB', round(sz[-1] / 1024, 1))
tid = re.compile(r'T\d{4}(?:[._]\d{3})?', re.I)
withid = [f for f in files if tid.search(os.path.basename(f))]
print('filenames containing T-id:', len(withid))
csv.field_size_limit(10**9)
rows = 0
per_file = collections.Counter(); chan = collections.Counter(); eid = collections.Counter(); tac = collections.Counter()
file_tac = {}; file_chan = collections.defaultdict(collections.Counter)
has = collections.Counter()
cols = ['CommandLine', 'Image', 'ScriptBlockText', 'RuleName', 'ParentImage', 'TargetObject']
with open(os.path.join(root, 'evtx_data.csv'), encoding='utf-8', errors='replace', newline='') as fh:
    for r in csv.DictReader(fh):
        rows += 1
        fn = r['EVTX_FileName']; per_file[fn] += 1; chan[r['Channel']] += 1
        eid[(r['Channel'], r['EventID'])] += 1
        file_tac[fn] = r['EVTX_Tactic']; file_chan[fn][r['Channel']] += 1
        for c in cols:
            if r.get(c) not in (None, '', '-'):
                has[c] += 1
print('csv rows', rows, 'distinct files in csv', len(per_file))
csv_names = {n.lower() for n in per_file}
repo_names = {os.path.basename(f).lower() for f in files}
csv_only = sorted(csv_names - repo_names); repo_only = sorted(repo_names - csv_names)
print('csv names not in repo:', len(csv_only), csv_only[:10])
print('repo names not in csv:', len(repo_only), repo_only[:10])
for fn, t in file_tac.items():
    tac[t] += 1
print('files per tactic (csv):', dict(tac))
v = sorted(per_file.values())
print('events/file min/median/p90/max', v[0], statistics.median(v), v[int(len(v)*.9)], v[-1], 'files<=5 events', sum(1 for x in v if x <= 5))
print('top channels', chan.most_common(8))
print('top (channel,eid)', eid.most_common(15))
print('rows with field non-empty:', dict(has))
sysmon = sum(1 for fn in per_file if any('Sysmon' in c for c in file_chan[fn]))
print('files with Sysmon channel events:', sysmon)
print('RuleName present rows:', has['RuleName'])
