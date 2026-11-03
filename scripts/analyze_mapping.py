"""Survey of the author's mapping sheet vs. the evtx files in the repo (read-only, no labeling)."""
import collections, csv, os, re, sys

sheet, evtx_root = sys.argv[1], sys.argv[2]
repo = {}
for dp, _, fn in os.walk(evtx_root):
    for f in fn:
        if f.lower().endswith('.evtx'):
            repo.setdefault(f.lower().strip(), []).append(os.path.relpath(os.path.join(dp, f), evtx_root))

rows = list(csv.DictReader(open(sheet, encoding='utf-8-sig', newline='')))
print('sheet rows', len(rows))
fname_re = re.compile(r'([\w\-\. \(\)\[\]]+?\.evtx)', re.I)
ids = collections.Counter(); matched = collections.defaultdict(set)
no_file_rows = 0; unmatched = []; id_forms = collections.Counter()
for r in rows:
    raw_id = r['ID'].strip()
    id_forms['NA' if raw_id.upper() in ('NA', '') else ('multi' if re.search(r'[,;&/ ]', raw_id) else 'single')] += 1
    tids = re.findall(r'T\d{4}(?:\.\d{3})?', raw_id)
    text = ' '.join(r['Procedure related detection traces'].lower().split())
    names = [n for n in repo if ' '.join(n.split()) in text]
    mentioned = [m.strip().lower().lstrip('(') for m in re.findall(r'[\w\-\.\(]+\.evtx', text)]
    if not names and not mentioned:
        no_file_rows += 1
    for n in names:
        for t in tids or ['NA']:
            matched[t].add(n)
    unmatched += [m for m in mentioned if m not in repo and not any(m in n or n in m for n in names)]
    for t in tids:
        ids[t] += 1
print('ID field forms', dict(id_forms))
print('rows without any .evtx name in text', no_file_rows)
all_matched = set().union(*matched.values()) if matched else set()
print('distinct repo files matched', len(all_matched), 'of', len(repo), '| unmatched names', len(set(unmatched)))
print('distinct IDs in sheet', len(ids))
cnt = {t: len(s) for t, s in matched.items()}
print('IDs with >=1 matched file', len(cnt), '| >=3', sum(v >= 3 for v in cnt.values()), '| >=5', sum(v >= 5 for v in cnt.values()))
print('top IDs by matched files', sorted(cnt.items(), key=lambda x: -x[1])[:15])
print('unmatched sample', sorted(set(unmatched))[:12])
print('repo files not in any sheet row', len(set(repo) - all_matched))
tac = collections.Counter(r['Tactic'].strip() for r in rows)
print('tactic field values', len(tac), tac.most_common(12))
