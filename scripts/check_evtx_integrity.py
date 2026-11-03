"""Header-level sanity check of .evtx files (no parsing, no dependencies) + fuzzy match of sheet names."""
import difflib, os, struct, sys, csv, re, collections

root, sheet = sys.argv[1], sys.argv[2]
bad = []; chunks = []; names = {}
for dp, _, fn in os.walk(root):
    for f in fn:
        if f.lower().endswith('.evtx'):
            p = os.path.join(dp, f); names[f.lower()] = os.path.relpath(p, root)
            with open(p, 'rb') as fh:
                h = fh.read(4096)
            if h[:8] != b'ElfFile\x00':
                bad.append(f); continue
            # header: chunk count at offset 42 (uint16), flags at 120 (dirty=1, full=2)
            chunks.append((struct.unpack_from('<H', h, 42)[0], struct.unpack_from('<I', h, 120)[0] & 1))
print('files', len(names), 'bad magic', len(bad), bad[:5])
print('total chunks', sum(c for c, _ in chunks), 'dirty-flag files', sum(d for _, d in chunks))

dup = collections.Counter()
for dp, _, fn in os.walk(root):
    for f in fn:
        if f.lower().endswith('.evtx'):
            dup[f.lower()] += 1
print('case-insensitive duplicate names', [k for k, v in dup.items() if v > 1])

text = ' '.join(r['Procedure related detection traces'].lower()
                for r in csv.DictReader(open(sheet, encoding='utf-8-sig', newline='')))
mentioned = {m.lstrip('(') for m in re.findall(r'[\w\-\.\(]+\.evtx', text)}
for m in sorted(mentioned - set(names)):
    print('sheet name not in repo:', m, '-> closest:', difflib.get_close_matches(m, names, n=1, cutoff=0.6))

folder_tactic = {k: os.path.relpath(v, root).split(os.sep)[0] if os.sep in v else '(root)' for k, v in names.items()}
print('files per top-level folder', dict(collections.Counter(folder_tactic.values())))
