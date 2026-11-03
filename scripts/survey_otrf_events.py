"""Event-level survey of OTRF Windows JSON events (streamed from zips; reads at most MAXN lines per member)."""
import collections, glob, json, os, sys, zipfile

root = sys.argv[1]
MAXN = 3000
chan = collections.Counter(); eid = collections.Counter(); keys = collections.Counter()
leak = collections.Counter(); has_cmd = 0; n_ev = 0; hosts = collections.Counter(); sample = None
for z in glob.glob(os.path.join(root, 'datasets', '**', '*.zip'), recursive=True):
    with zipfile.ZipFile(z) as zf:
        for i in zf.infolist():
            if not i.filename.lower().endswith('.json'):
                continue
            with zf.open(i) as fh:
                for k, ln in enumerate(fh):
                    if k >= MAXN:
                        break
                    try:
                        e = json.loads(ln)
                    except ValueError:
                        continue
                    if 'Channel' not in e:
                        continue
                    n_ev += 1
                    chan[e.get('Channel')] += 1
                    eid[(e.get('Channel'), e.get('EventID'))] += 1
                    for kk in e:
                        keys[kk] += 1
                    if e.get('CommandLine'):
                        has_cmd += 1
                    for lk in ('RuleName', 'tags', 'rule', 'Tags', 'technique_id', 'mitre'):
                        if e.get(lk) not in (None, '', '-'):
                            leak[lk] += 1
                    if sample is None and e.get('EventID') == 1:
                        sample = {k: str(v)[:80] for k, v in list(e.items())[:30]}
print('windows-style events read', n_ev, '(first', MAXN, 'per member)')
print('channels', chan.most_common(8))
print('top (channel,eventid)', eid.most_common(12))
print('events with CommandLine', has_cmd)
print('possible leakage-bearing fields present', dict(leak))
print('top field keys', keys.most_common(25))
print('sample Sysmon 1:', json.dumps(sample, ensure_ascii=False)[:1500])
