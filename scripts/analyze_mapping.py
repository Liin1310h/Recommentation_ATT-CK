"""Survey of the author's mapping sheet vs. the evtx files in the repo (read-only, no labeling).

Fix log (2026-11-04):
- ID column 'NA' or empty is NOT an ID: no 'NA' key in ID statistics. ID forms: NA / multi / single.
- IDs extracted with re.findall(r'T\\d{4}(?:\\.\\d{3})?', raw_id.upper()).
- evtx file names in 'Procedure related detection traces' are matched on name boundaries
  (regex (?<![\\w\\-]) + re.escape(name)), not as substrings (sysmon_1_ftp.evtx no longer matches
  inside exec_sysmon_1_ftp.evtx). Whitespace normalised and lowercased before comparing.
- Files matched only through rows without an ID are counted separately.
- Prints ALL IDS (sorted).
"""
import collections, csv, os, re, sys

sheet, evtx_root = sys.argv[1], sys.argv[2]
repo = {}
for dp, _, fn in os.walk(evtx_root):
    for f in fn:
        if f.lower().endswith('.evtx'):
            repo.setdefault(f.lower().strip(), []).append(os.path.relpath(os.path.join(dp, f), evtx_root))

rows = list(csv.DictReader(open(sheet, encoding='utf-8-sig', newline='')))
print('sheet rows', len(rows))
name_res = {n: re.compile(r'(?<![\w\-])' + re.escape(' '.join(n.split()))) for n in repo}
ids = collections.Counter(); matched = collections.defaultdict(set); noid_files = set(); id_files = set()
no_file_rows = 0; unmatched = []; id_forms = collections.Counter()
for r in rows:
    raw_id = r['ID'].strip()
    id_forms['NA' if raw_id.upper() in ('NA', '') else ('multi' if re.search(r'[,;&/ ]', raw_id) else 'single')] += 1
    tids = re.findall(r'T\d{4}(?:\.\d{3})?', raw_id.upper())
    text = ' '.join(r['Procedure related detection traces'].lower().split())
    names = [n for n, rx in name_res.items() if rx.search(text)]
    mentioned = [m.strip().lower().lstrip('(') for m in re.findall(r'[\w\-\.\(]+\.evtx', text)]
    if not names and not mentioned:
        no_file_rows += 1
    for n in names:
        if tids:
            id_files.add(n)
            for t in tids:
                matched[t].add(n)
        else:
            noid_files.add(n)
    unmatched += [m for m in mentioned if m not in repo and not any(m in n or n in m for n in names)]
    for t in tids:
        ids[t] += 1
print('ID field forms', dict(id_forms))
print('rows without any .evtx name in text', no_file_rows)
all_matched = id_files | noid_files
print('distinct repo files matched', len(all_matched), 'of', len(repo), '| unmatched names', len(set(unmatched)))
only_noid = sorted(noid_files - id_files)
print('matched only via rows without ID', len(only_noid), only_noid[:10])
print('distinct IDs in sheet', len(ids))
cnt = {t: len(s) for t, s in matched.items()}
print('IDs with >=1 matched file', len(cnt), '| >=3', sum(v >= 3 for v in cnt.values()), '| >=5', sum(v >= 5 for v in cnt.values()))
print('top IDs by matched files', sorted(cnt.items(), key=lambda x: (-x[1], x[0]))[:15])
print('unmatched sample', sorted(set(unmatched))[:12])
print('repo files not in any sheet row', len(set(repo) - all_matched))
tac = collections.Counter(r['Tactic'].strip() for r in rows)
print('tactic field values', len(tac), tac.most_common(12))
print('ALL IDS', sorted(ids))
