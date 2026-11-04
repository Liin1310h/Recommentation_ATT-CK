"""Event-level survey of OTRF Windows JSON events (streamed from zips; reads at most MAXN lines per member).

Usage: survey_otrf_events.py <Security-Datasets> [MAXN=3000]

Fix log (2026-11-04):
- Corrupt zips (zipfile.BadZipFile): skipped, counted, up to 5 relative paths printed.
- 'tags' (list or string): values are now counted, top 10 printed (before: presence only).
- Counts events with non-empty RuleName ('-' placeholder counted separately) and how many have the
  RuleName value verbatim inside Message.
- Hostname (lowercase) counted by number of distinct zips containing it: number of hostnames, number
  present in >=2 / >=3 / >=5 zips, top 10.
- Sysmon 1 sample: first event with EventID == 1 AND Channel containing 'sysmon' (case-insensitive).
- MAXN is now the 2nd command-line argument (default 3000).
"""
import collections, glob, json, os, sys, zipfile

root = sys.argv[1]
MAXN = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
chan = collections.Counter(); eid = collections.Counter(); keys = collections.Counter()
leak = collections.Counter(); has_cmd = 0; n_ev = 0; sample = None
tag_vals = collections.Counter()
rule_nonempty = 0; rule_dash = 0; rule_in_msg = 0
host_zips = collections.defaultdict(set)
bad_zips = []
for z in glob.glob(os.path.join(root, 'datasets', '**', '*.zip'), recursive=True):
    zrel = os.path.relpath(z, root).replace('\\', '/')
    try:
        zf_ctx = zipfile.ZipFile(z)
    except zipfile.BadZipFile:
        bad_zips.append(zrel)
        continue
    with zf_ctx as zf:
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
                    if not isinstance(e, dict) or 'Channel' not in e:
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
                    tg = e.get('tags')
                    if isinstance(tg, list):
                        for v in tg:
                            tag_vals[str(v)] += 1
                    elif tg not in (None, ''):
                        tag_vals[str(tg)] += 1
                    rn = e.get('RuleName')
                    if rn not in (None, ''):
                        rn = str(rn)
                        if rn == '-':
                            rule_dash += 1
                        else:
                            rule_nonempty += 1
                            if rn in str(e.get('Message') or ''):
                                rule_in_msg += 1
                    h = e.get('Hostname')
                    if h not in (None, ''):
                        host_zips[str(h).lower()].add(zrel)
                    if sample is None and str(e.get('EventID')) == '1' and 'sysmon' in str(e.get('Channel') or '').lower():
                        sample = {k: str(v)[:80] for k, v in list(e.items())[:30]}
print('windows-style events read', n_ev, '(first', MAXN, 'per member)')
print('bad zips', len(bad_zips), bad_zips[:5])
print('channels', chan.most_common(8))
print('top (channel,eventid)', eid.most_common(12))
print('events with CommandLine', has_cmd)
print('possible leakage-bearing fields present', dict(leak))
print('tags values top 10', tag_vals.most_common(10))
print('events with non-empty RuleName (excluding "-")', rule_nonempty, '| RuleName == "-"', rule_dash,
      '| of non-empty, RuleName verbatim in Message', rule_in_msg)
hz = sorted(((h, len(s)) for h, s in host_zips.items()), key=lambda x: (-x[1], x[0]))
print('hostnames (lowercase)', len(hz), '| in >=2 zips', sum(c >= 2 for _, c in hz),
      '| >=3', sum(c >= 3 for _, c in hz), '| >=5', sum(c >= 5 for _, c in hz))
print('top 10 hostnames by zip count', hz[:10])
print('top field keys', keys.most_common(25))
print('sample Sysmon 1:', json.dumps(sample, ensure_ascii=False)[:1500])
