"""Event counts + leakage scan on the downloaded Splunk sample (read-only; paths from data/splunk_sample_paths.txt)."""
import collections, os, re, statistics, sys

root, plist = sys.argv[1], sys.argv[2]
paths = [l.strip() for l in open(plist, encoding='utf-8-sig') if l.strip()]
ev_re = re.compile(r'<Event[ >]')
chan_re = re.compile(r'<Channel>([^<]+)</Channel>')
eid_re = re.compile(r'<EventID[^>]*>(\d+)</EventID>')
rule_re = re.compile(r"<Data Name='RuleName'>([^<]*)</Data>")
leak_re = re.compile(r'technique_id=T\d{4}|\bT1\d{3}(?:\.\d{3})?\b|attack\.t1\d{3}|mitre', re.I)

stat = collections.Counter(); per = []; chan = collections.Counter(); eid = collections.Counter()
rules = collections.Counter(); leak_files = []; cmd = 0; total = 0
for rel in paths:
    f = os.path.join(root, rel.replace('/', os.sep))
    b = open(f, 'rb').read()
    if b.startswith(b'version https://git-lfs') or len(b) == 0:
        stat['blocked_or_pointer'] += 1; continue
    t = b.decode('utf-8', 'replace')
    n = len(ev_re.findall(t))
    stat['ok'] += 1; total += n
    tech = rel.split('/')[2]
    per.append((tech, n, len(b)))
    for c in chan_re.findall(t): chan[c] += 1
    for e in eid_re.findall(t): eid[e] += 1
    for r in rule_re.findall(t):
        if r not in ('', '-'): rules[r[:60]] += 1
    cmd += t.count("Name='CommandLine'")
    if leak_re.search(t.replace(rel, '')):
        m = leak_re.search(t)
        leak_files.append((rel.split('/')[2], m.group(0)))
print('status', dict(stat), 'events total', total)
ns = sorted(n for _, n, _ in per)
if ns:
    print('events/file min/median/max', ns[0], statistics.median(ns), ns[-1], '| files with <=5 events', sum(n <= 5 for n in ns))
print('per technique', sorted(((t, n) for t, n, _ in per), key=lambda x: -x[1])[:12])
print('channels', chan.most_common(5))
print('eventid', eid.most_common(8))
print('events with CommandLine field', cmd)
print('non-empty RuleName values', rules.most_common(8))
print('files with ATT&CK-like strings in content', len(leak_files), leak_files[:8])
