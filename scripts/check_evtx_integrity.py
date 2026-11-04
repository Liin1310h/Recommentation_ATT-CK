"""Header-level sanity check of .evtx files (no parsing, no dependencies) + fuzzy match of sheet names.

Fix log (2026-11-04):
- Files per top-level folder now uses the relative path already stored (before: relpath applied a
  second time, result depended on the working directory).
- Every file is kept in a list (before: dict keyed by file name silently overwrote same-name files).
- sha256 of every file; prints same-name groups (case-insensitive name) and identical-content groups
  (same sha256).
- Kept: magic b'ElfFile\\x00', chunk count (offset 42, uint16 LE), dirty flag (offset 120, bit 0).
"""
import difflib, hashlib, os, struct, sys, csv, re, collections

root, sheet = sys.argv[1], sys.argv[2]
bad = []; chunks = []; entries = []   # entries: (relative path with '/', lowercase name, sha256)
for dp, _, fn in os.walk(root):
    for f in fn:
        if f.lower().endswith('.evtx'):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace('\\', '/')
            sha = hashlib.sha256()
            with open(p, 'rb') as fh:
                h = fh.read(4096)
                sha.update(h)
                for blk in iter(lambda: fh.read(1 << 20), b''):
                    sha.update(blk)
            entries.append((rel, f.lower(), sha.hexdigest()))
            if h[:8] != b'ElfFile\x00' or len(h) < 124:
                bad.append(rel); continue
            # header: chunk count at offset 42 (uint16), flags at 120 (dirty=1, full=2)
            chunks.append((struct.unpack_from('<H', h, 42)[0], struct.unpack_from('<I', h, 120)[0] & 1))
print('files', len(entries), 'bad magic', len(bad), bad[:5])
print('total chunks', sum(c for c, _ in chunks), 'dirty-flag files', sum(d for _, d in chunks))

by_name = collections.defaultdict(list); by_sha = collections.defaultdict(list)
for rel, name, sha in entries:
    by_name[name].append(rel); by_sha[sha].append(rel)
same_name = {k: sorted(v) for k, v in by_name.items() if len(v) > 1}
same_sha = [sorted(v) for v in by_sha.values() if len(v) > 1]
print('same-name groups', len(same_name), same_name)
print('identical-content groups', len(same_sha), sorted(same_sha))

names = sorted(by_name)
text = ' '.join(r['Procedure related detection traces'].lower()
                for r in csv.DictReader(open(sheet, encoding='utf-8-sig', newline='')))
mentioned = {m.lstrip('(') for m in re.findall(r'[\w\-\.\(]+\.evtx', text)}
for m in sorted(mentioned - set(names)):
    print('sheet name not in repo:', m, '-> closest:', difflib.get_close_matches(m, names, n=1, cutoff=0.6))

top = collections.Counter(rel.split('/')[0] if '/' in rel else '(root)' for rel, _, _ in entries)
print('files per top-level folder', dict(top))
