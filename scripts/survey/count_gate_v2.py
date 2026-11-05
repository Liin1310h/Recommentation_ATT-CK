"""count_gate.py (v2) - dem du lieu Windows co nhan ATT&CK (Splunk, OTRF, EVTX).

Chi DOC du lieu va chi IN thong ke (so dem + technique ID + ten field).
Khong bao gio in/ghi gia tri field cua event, hostname, username, duong dan log.

Chay:
 python -I scripts/survey/count_gate_v2.py --splunk ... --otrf ... --evtx ... --sheet ... --stix ... \
 --out docs/survey_output/count_gate_runN.json [--review-dir <thu muc file duyet>]

- Khong co --review-dir: CAN TREN (chua loc theo cay tien trinh), nhu lan 1.
- Co --review-dir: loc buoc 2 theo cay tien trinh tu tien trinh goc da duyet (D2 3.1, quyet dinh 52).

Thay doi so voi v1 (2026-11-05):
- otrf_ids: nhan sub-technique dang day du (T1003.001) va dang so; dem otrf_sub_not_under_technique,
 otrf_sub_unparsed.
- Them alerts_per_technique_id_by_source.
- Doc du lieu theo tung run (dung chung voi root_candidates.py); them loc theo cay tien trinh.
"""
import argparse
import collections
import csv
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

import yaml

STIX_SHA256 = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
STIX_SIZE = 55271014

KEEP = {
    "microsoft-windows-sysmon/operational": {"1", "3", "7", "8", "10", "11", "12", "13", "22"},
    "security": {"4688", "4624", "4648", "4672", "4698", "4720", "5140", "5145"},
    "microsoft-windows-powershell/operational": {"4104", "4103"},
    "windows powershell": {"800"},
}
STRIP = ["RuleName", "Message", "tags", "@timestamp", "@version", "port", "host",
         "EventReceivedTime", "SourceModuleName", "SourceModuleType", "Severity",
         "SeverityValue"]
PRE_PHASES = {"reconnaissance", "resource-development"}
SOURCE_ORDER = ["evtx", "otrf", "splunk"]
SYSMON = "microsoft-windows-sysmon/operational"

DROP_DEDUP = set("""TimeCreated_SystemTime UtcTime CreationUtcTime PreviousCreationUtcTime
EventRecordID RecordNumber Execution_ProcessID Execution_ThreadID ExecutionProcessID ThreadID
Computer Correlation_ActivityID Correlation_RelatedActivityID EventTime ProcessGuid
ParentProcessGuid LogonGuid SourceProcessGUID TargetProcessGUID SourceProcessGuid
TargetProcessGuid LogonId TargetLogonId SubjectLogonId ProcessId ParentProcessId NewProcessId
SourceProcessId TargetProcessId SourceThreadId""".split())
MASKS = [
    (re.compile(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?"), "<GUID>"),
    (re.compile(r"S-1-5-21-\d+-\d+-\d+(-\d+)?"), "<SID>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?"), "<TS>"),
    (re.compile(r"0x[0-9a-fA-F]+"), "<HEX>"),
    (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"), "<IP>"),
    (re.compile(r"\\Users\\[^\\]+", re.I), "\\Users\\<USER>"),
]

RE_EVENT = re.compile(r"<Event[\s>].*?</Event>", re.S)
RE_TID = re.compile(r"T\d{4}(?:\.\d{3})?")
RE_SUBFULL = re.compile(r"^T\d{4}\.\d{3}$", re.I)
RE_VALID_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
RE_LEAK1 = re.compile(r"(?<![A-Za-z0-9])[Tt]\d{4}(?:\.\d{3})?(?![0-9])")
RE_LEAK2 = re.compile(r"attack\.t\d{4}", re.I)
RE_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def local(tag):
    return tag.rsplit("}", 1)[-1]


def first(v):
    if isinstance(v, list):
        return v[0] if v else ""
    return v if isinstance(v, str) else ""


# ---------------------------------------------------------------- STIX
class Stix:
    def __init__(self, path):
        with open(path, encoding="utf-8") as fh:
            objs = json.load(fh)["objects"]
        self.by_ext, self.by_id, self.revoked_by, tactics = {}, {}, {}, set()
        for o in objs:
            t = o.get("type")
            if t == "attack-pattern":
                ext = next((r["external_id"] for r in o.get("external_references", [])
                            if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
                rec = {"id": o["id"], "ext": ext, "revoked": bool(o.get("revoked")),
                       "deprecated": bool(o.get("x_mitre_deprecated")),
                       "phases": [p.get("phase_name") for p in o.get("kill_chain_phases", [])]}
                self.by_id[o["id"]] = rec
                if ext:
                    self.by_ext[ext] = rec
            elif t == "relationship" and o.get("relationship_type") == "revoked-by":
                self.revoked_by[o["source_ref"]] = o["target_ref"]
            elif t == "x-mitre-tactic" and o.get("x_mitre_shortname"):
                tactics.add(o["x_mitre_shortname"])
        self.leak3 = re.compile(r"attack\.(" + "|".join(re.escape(s) for s in sorted(tactics))
                                + r")(?![a-z0-9_-])", re.I)
        self.cache = {}

    def norm(self, tid):
        if tid not in self.cache:
            self.cache[tid] = self._norm(tid)
        return self.cache[tid]

    def _norm(self, tid):
        cur = self.by_ext.get(tid)
        if cur is None:
            return None, "unknown"
        seen = set()
        while cur["revoked"]:
            if cur["id"] in seen:
                return None, "unreachable"
            seen.add(cur["id"])
            cur = self.by_id.get(self.revoked_by.get(cur["id"]))
            if cur is None:
                return None, "unreachable"
        if cur["deprecated"]:
            return None, "deprecated" if cur["ext"] == tid else "unreachable"
        if cur["phases"] and all(p in PRE_PHASES for p in cur["phases"]):
            return None, "pre"
        return cur["ext"], ("ok" if cur["ext"] == tid else "moved")


def normalize_labels(stix, raw_ids):
    details, final = [], set()
    for r in sorted(raw_ids):
        f, k = stix.norm(r)
        details.append((r, f, k))
        if f:
            final.add(f)
    if final:
        return frozenset(final), None, details
    if not details:
        return frozenset(), "no_label", details
    if all(k == "pre" for _, _, k in details):
        return frozenset(), "pre_only", details
    return frozenset(), "all_dropped", details


# ---------------------------------------------------------------- flatten
def flatten_xml(elem, counters):
    f, sysnames, data_list, ed = {}, set(), [], {}
    for child in elem:
        tag = local(child.tag)
        if tag == "System":
            for e in child:
                n = local(e.tag)
                txt = (e.text or "").strip()
                if txt:
                    f[n] = txt
                    sysnames.add(n)
                for a, v in e.attrib.items():
                    k = n + "_" + local(a)
                    f[k] = v
                    sysnames.add(k)
        elif tag == "EventData":
            for d in child:
                if local(d.tag) != "Data":
                    continue
                name = d.get("Name")
                if name is None:
                    data_list.append(d.text or "")
                else:
                    ed[name] = d.text or ""
        elif tag == "UserData":
            for sub in child:
                for e in sub:
                    ed[local(e.tag)] = e.text or ""
    for k, v in ed.items():
        if k in sysnames:
            counters["name_conflict"] += 1
            continue
        f[k] = v
    if data_list:
        f["Data"] = data_list
    for k in list(f):
        if " " in k and k.replace(" ", "") not in f:
            f[k.replace(" ", "")] = f[k]
    return f


def flatten_json(obj):
    f = {}
    for k, v in obj.items():
        k = {"Hostname": "Computer", "SourceName": "Provider_Name"}.get(k, k)
        if v is None:
            v = ""
        elif isinstance(v, (list, tuple)):
            v = [("" if x is None else str(x)) for x in v]
        else:
            v = str(v)
        f[k] = v
    return f


def values(v):
    return v if isinstance(v, list) else [v]


# ---------------------------------------------------------------- helpers
def norm_host(f):
    h = first(f.get("Computer", "")).strip().lower().split(".")[0]
    return h or "<none>"


def event_time(f):
    """datetime UTC (naive) cua event; doc truoc khi strip. None neu khong doc duoc."""
    for k in ("TimeCreated_SystemTime", "@timestamp", "UtcTime", "EventTime"):
        s = first(f.get(k)).strip()
        if not s:
            continue
        try:
            d = datetime.datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T", 1))
        except ValueError:
            continue
        if d.tzinfo is not None:
            d = d.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return d
    return None


def event_day(f):
    d = event_time(f)
    if d is not None:
        return d.date().isoformat()
    for k in ("TimeCreated_SystemTime", "@timestamp", "EventTime"):
        m = RE_DATE.match(first(f.get(k)).strip())
        if m:
            return m.group(1)
    return "<none>"


def event_key(f):
    return first(f.get("Channel", "")).strip().lower(), first(f.get("EventID", "")).strip()


def to_pid(v):
    s = first(v).strip()
    if not s:
        return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def basename(path):
    return re.split(r"[\\/]", first(path).strip())[-1].lower()


_host_re = {}


def dedup_digest(f, channel, eid, host):
    rx = None
    if len(host) >= 3 and host != "<none>":
        rx = _host_re.setdefault(host, re.compile(re.escape(host), re.I))

    def clean(s):
        for pat, repl in MASKS:
            s = pat.sub(lambda m, r=repl: r, s)
        return rx.sub("<HOST>", s) if rx else s

    out = {k: ([clean(x) for x in v] if isinstance(v, list) else clean(v))
           for k, v in f.items() if k not in DROP_DEDUP and k not in ("Channel", "EventID")}
    blob = json.dumps({"Channel": channel, "EventID": eid, "fields": out}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8", "replace")).digest()


class UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


# ---------------------------------------------------------------- cay tien trinh
class ProcessTable:
    """Tien trinh cua mot run, dung tu Sysmon 1 va Security 4688.

    key tien trinh: Sysmon -> "g:<ProcessGuid lowercase>"; Security 4688 -> "s:<host>:<pid>:<thoi gian ISO>".
    Cha cua tien trinh 4688: tien trinh (Sysmon hoac 4688) cung host, cung pid = ProcessId cua event, bat dau
    gan nhat truoc thoi diem tao con.
    """

    def __init__(self):
        self.procs = {}  # key -> dict
        self.by_host_pid = collections.defaultdict(list)  # (host, pid) -> [(start, key)]

    def add_event(self, f):
        ch, eid = event_key(f)
        host, t = norm_host(f), event_time(f)
        if ch == SYSMON and eid == "1":
            g = first(f.get("ProcessGuid")).strip().lower()
            if not g:
                return
            key = "g:" + g
            pg = first(f.get("ParentProcessGuid")).strip().lower()
            rec = dict(key=key, host=host, pid=to_pid(f.get("ProcessId")), start=t,
                       image=first(f.get("Image")), cmd=first(f.get("CommandLine")),
                       parent_image=first(f.get("ParentImage")), parent_key=("g:" + pg) if pg else None,
                       parent_pid=to_pid(f.get("ParentProcessId")))
        elif ch == "security" and eid == "4688":
            pid = to_pid(f.get("NewProcessId"))
            if pid is None:
                return
            key = f"s:{host}:{pid}:{t.isoformat() if t else '?'}"
            rec = dict(key=key, host=host, pid=pid, start=t, image=first(f.get("NewProcessName")),
                       cmd=first(f.get("CommandLine")), parent_image=first(f.get("ParentProcessName")),
                       parent_key=None, parent_pid=to_pid(f.get("ProcessId")))
        else:
            return
        if key in self.procs:
            return
        self.procs[key] = rec
        if rec["pid"] is not None:
            self.by_host_pid[(host, rec["pid"])].append((t, key))

    def finalize(self):
        for lst in self.by_host_pid.values():
            lst.sort(key=lambda x: (x[0] is None, x[0] or datetime.datetime.min))
        for rec in self.procs.values():
            if rec["parent_key"] is None and rec["parent_pid"] is not None:
                rec["parent_key"] = self.lookup_pid(rec["host"], rec["parent_pid"], rec["start"])
            if rec["parent_key"] not in self.procs:
                rec["parent_key_known"] = None
            else:
                rec["parent_key_known"] = rec["parent_key"]
        self.children = collections.defaultdict(list)
        for k, rec in self.procs.items():
            if rec["parent_key_known"]:
                self.children[rec["parent_key_known"]].append(k)

    def lookup_pid(self, host, pid, t):
        """Tien trinh cung host + pid, bat dau gan nhat <= t (khong co thoi gian -> moi nhat)."""
        lst = self.by_host_pid.get((host, pid))
        if not lst:
            return None
        if t is None:
            return lst[-1][1]
        best = None
        for start, key in lst:
            if start is None or start <= t:
                best = key
            else:
                break
        return best

    def ancestors(self, key):
        out, seen = [], set()
        cur = self.procs[key]["parent_key_known"]
        while cur and cur not in seen:
            seen.add(cur)
            out.append(cur)
            cur = self.procs[cur]["parent_key_known"]
        return out

    def candidates(self, parent_images, exclude_ancestors):
        """Ung vien goc: cha (theo ten image) thuoc parent_images, khong to tien nao thuoc exclude_ancestors.
        Chi giu ung vien tren cung (khong co to tien la ung vien)."""
        raw = set()
        for k, rec in self.procs.items():
            if basename(rec["parent_image"]) not in parent_images:
                continue
            anc_imgs = {basename(self.procs[a]["image"]) for a in self.ancestors(k)}
            anc_imgs.add(basename(rec["parent_image"]))
            if anc_imgs & exclude_ancestors:
                continue
            raw.add(k)
        return {k for k in raw if not any(a in raw for a in self.ancestors(k))}

    def subtree(self, roots):
        out, stack = set(), [r for r in roots if r in self.procs]
        while stack:
            k = stack.pop()
            if k in out:
                continue
            out.add(k)
            stack.extend(self.children.get(k, ()))
        return out

    def link(self, f):
        """-> key tien trinh cua event, hoac None neu khong noi duoc (ambiguous)."""
        ch, eid = event_key(f)
        host, t = norm_host(f), event_time(f)
        if ch == SYSMON:
            fld = "SourceProcessGuid" if eid in ("8", "10") else "ProcessGuid"
            g = first(f.get(fld)).strip().lower() or first(f.get(fld.replace("Guid", "GUID"))).strip().lower()
            return ("g:" + g) if g and ("g:" + g) in self.procs else None
        if ch == "security" and eid == "4688":
            pid = to_pid(f.get("NewProcessId"))
            key = f"s:{host}:{pid}:{t.isoformat() if t else '?'}"
            return key if key in self.procs else None
        if (ch, eid) in (("microsoft-windows-powershell/operational", "4104"),
                         ("microsoft-windows-powershell/operational", "4103"), ("windows powershell", "800")):
            pid = to_pid(f.get("Execution_ProcessID"))
            if pid is None:
                pid = to_pid(f.get("ExecutionProcessID"))
            return self.lookup_pid(host, pid, t) if pid is not None else None
        return None


# ---------------------------------------------------------------- sheet
def load_sheet(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def evtx_raw_labels(rows, filename):
    rx = re.compile(r"(?<![\w\-.])" + re.escape(filename), re.I)
    ids = set()
    for r in rows:
        if rx.search(r.get("Procedure related detection traces") or ""):
            ids.update(RE_TID.findall((r.get("ID") or "").upper()))
    return ids


def otrf_ids(doc, st):
    out = []
    for m in doc.get("attack_mappings") or []:
        if not isinstance(m, dict):
            continue
        t = (m.get("technique") or "").strip().upper()
        if not t:
            continue
        s = (m.get("sub-technique") or "").strip()
        if not s or s.lower() == "none":
            out.append(t)
        elif s.isdigit() and len(s) <= 3:
            out.append(t + "." + s.zfill(3))
        elif RE_SUBFULL.match(s):
            if s.upper().split(".")[0] != t:
                st["otrf_sub_not_under_technique"] += 1
            out.append(s.upper())
        else:
            st["otrf_sub_unparsed"] += 1
            out.append(t)
    return out


# ---------------------------------------------------------------- doc theo run
def iter_runs(args, st_by_src, tmpdir):
    """Sinh (src, run_id, raw_ids, events) theo thu tu evtx, otrf, splunk; events la list dict da phang."""
    rows = load_sheet(args.sheet)
    # EVTX
    st = st_by_src["evtx"]
    files = []
    for r, dirs, fs in os.walk(args.evtx):
        dirs.sort()
        files += [os.path.join(r, n) for n in sorted(fs) if n.lower().endswith(".evtx")]
    for i, fp in enumerate(sorted(files)):
        raw = sorted(evtx_raw_labels(rows, os.path.basename(fp)))
        run_id = "evtx:" + os.path.relpath(fp, args.evtx)
        out = os.path.join(tmpdir, "e%05d.xml" % i)
        events = []
        try:
            with open(out, "wb") as oh:
                rc = subprocess.run(["wevtutil", "qe", fp, "/lf:true", "/f:xml"],
                                    stdout=oh, stderr=subprocess.DEVNULL).returncode
            if rc != 0:
                st["wevtutil_error"] += 1
            else:
                with open(out, "rb") as fh:
                    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", fh.read().decode("utf-8", "replace"))
                tree = ET.fromstring("<Events>" + body + "</Events>")
                st["files_read"] += 1
                events = [flatten_xml(el, st) for el in tree]
        except (ET.ParseError, OSError):
            st["wevtutil_error"] += 1
        finally:
            try:
                os.remove(out)
            except OSError:
                pass
        yield "evtx", run_id, raw, events
    # OTRF
    st = st_by_src["otrf"]
    ds_root = os.path.join(args.otrf, "datasets")
    zips = collections.defaultdict(list)
    for r, dirs, fs in os.walk(ds_root):
        dirs.sort()
        for n in sorted(fs):
            if n.lower().endswith(".zip"):
                zips[n].append(os.path.join(r, n))
    mdir = os.path.join(ds_root, "atomic", "_metadata")
    for n in sorted(os.listdir(mdir)):
        if not n.endswith(".yaml"):
            continue
        with open(os.path.join(mdir, n), encoding="utf-8") as fh:
            doc = yaml.load(fh, Loader=yaml.BaseLoader)
        plat = doc.get("platform") or []
        plat = [plat] if isinstance(plat, str) else plat
        if not any(str(p).strip().lower() == "windows" for p in plat):
            st["skipped_non_windows_meta"] += 1
            continue
        raw = otrf_ids(doc, st)
        run_id = "otrf:" + str(doc.get("id") or n)
        paths = []
        for fe in doc.get("files") or []:
            link = (fe.get("link") or "") if isinstance(fe, dict) else ""
            if not link.lower().split("?")[0].endswith(".zip"):
                continue
            cands = zips.get(link.split("?")[0].rsplit("/", 1)[-1])
            if not cands:
                st["zip_not_found"] += 1
                continue
            if len(cands) > 1:
                st["zip_multi_match"] += 1
            paths += [c for c in cands if c not in paths]
        events = []
        for zp in paths:
            try:
                zf = zipfile.ZipFile(zp)
                names = sorted(x for x in zf.namelist() if x.lower().endswith(".json"))
            except (zipfile.BadZipFile, OSError):
                st["bad_zip"] += 1
                continue
            st["zips_read"] += 1
            with zf:
                for nm in names:
                    try:
                        with zf.open(nm) as fh:
                            for line in fh:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    obj = json.loads(line)
                                except ValueError:
                                    st["json_error"] += 1
                                    continue
                                if isinstance(obj, dict):
                                    events.append(flatten_json(obj))
                                else:
                                    st["json_error"] += 1
                    except (zipfile.BadZipFile, OSError, RuntimeError):
                        st["bad_zip"] += 1
        yield "otrf", run_id, raw, events
    # Splunk
    st = st_by_src["splunk"]
    base = os.path.join(args.splunk, "datasets", "attack_techniques")
    yamls = []
    for r, dirs, fs in os.walk(base):
        dirs.sort()
        yamls += [os.path.join(r, n) for n in sorted(fs) if n.endswith((".yml", ".yaml"))]
    for y in sorted(yamls):
        try:
            with open(y, encoding="utf-8") as fh:
                doc = yaml.load(fh, Loader=yaml.BaseLoader)
        except Exception:
            st["yaml_error"] += 1
            continue
        if not isinstance(doc, dict):
            st["yaml_error"] += 1
            continue
        ds = [d for d in (doc.get("datasets") or []) if isinstance(d, dict) and d.get("sourcetype") == "XmlWinEventLog"]
        if not ds:
            continue
        mt = doc.get("mitre_technique")
        raw = [] if mt is None else (mt if isinstance(mt, list) else [mt])
        raw = [str(x).strip() for x in raw if str(x).strip()]
        run_id = "splunk:" + os.path.relpath(y, args.splunk)
        events = []
        for d in ds:
            p = (d.get("path") or "").lstrip("/")
            fp = os.path.join(args.splunk, *p.split("/"))
            if not p or not os.path.isfile(fp):
                st["missing"] += 1
                continue
            try:
                with open(fp, "rb") as fh:
                    data = fh.read()
            except OSError:
                st["read_error"] += 1
                continue
            if data.startswith(b"version https://git-lfs"):
                st["lfs_pointer"] += 1
                continue
            st["files_read"] += 1
            for m in RE_EVENT.finditer(data.decode("utf-8", "replace")):
                try:
                    events.append(flatten_xml(ET.fromstring(m.group(0)), st))
                except ET.ParseError:
                    st["xml_error"] += 1
        yield "splunk", run_id, raw, events


def run_code(seed, run_id):
    return hashlib.sha256(f"{seed}:{run_id}".encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------- doc ket qua duyet
def load_reviews(review_dir):
    """-> {code: set(process key chap_nhan)} cho cac run DA DUYET (it nhat mot dong co quyet_dinh)."""
    out = {}
    for n in sorted(os.listdir(review_dir)):
        if not n.endswith(".csv") or n.startswith("_"):
            continue
        with open(os.path.join(review_dir, n), encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
        decided = [r for r in rows if (r.get("quyet_dinh") or "").strip()]
        if not decided:
            continue
        code = n[:-4]
        out[code] = {r["process_key"] for r in decided if r["quyet_dinh"].strip().lower() == "chap_nhan"}
    return out


# ---------------------------------------------------------------- pipeline
class Pipeline:
    def __init__(self, stix):
        self.stix = stix
        self.st = {s: collections.Counter() for s in SOURCE_ORDER}
        self.leak_fields = collections.Counter()
        self.dedup = {}
        self.alerts_per_run = collections.Counter()
        self.run_pairs = {s: collections.defaultdict(set) for s in SOURCE_ORDER}
        self.run_hosts = {s: collections.defaultdict(set) for s in SOURCE_ORDER}
        self.eventtype = collections.Counter()
        self.label_details = {s: set() for s in SOURCE_ORDER}
        self.runs_seen = collections.Counter()
        self.runs_no_label = collections.Counter()
        self.tree_status = collections.Counter()  # (src, trang thai, channel/eid) -> so event

    def register_run(self, src, raw_ids):
        self.runs_seen[src] += 1
        labels, reason, details = normalize_labels(self.stix, raw_ids)
        self.label_details[src].update(details)
        if reason == "no_label":
            self.runs_no_label[src] += 1
        return labels, reason

    def process(self, src, run_id, labels, reason, f, tree_ok=None):
        """tree_ok: None = khong loc cay; True/False/'ambiguous'/'unreviewed'/'not_sampled'/'no_tree'."""
        st = self.st[src]
        st["events_read"] += 1
        channel, eid = event_key(f)
        if src == "otrf" and channel == SYSMON and eid in ("12", "13", "14"):
            et = f.get("EventType")
            if isinstance(et, str):
                self.eventtype[et] += 1
        if eid not in KEEP.get(channel, ()):  # 4.1
            st["drop_filter_type"] += 1
            return
        st["pass_4_1"] += 1
        if tree_ok is not None:  # 4.1b (buoc 2)
            self.tree_status[(src, str(tree_ok), f"{channel}/{eid}")] += 1
            if tree_ok is not True:
                st["drop_tree_" + ("not_in_tree" if tree_ok is False else str(tree_ok))] += 1
                return
            st["pass_tree"] += 1
        if not labels:  # 4.2
            st["drop_" + reason] += 1
            return
        st["pass_4_2"] += 1
        host, day = norm_host(f), event_day(f)
        for k in STRIP:  # 4.3
            f.pop(k, None)
        hit = [k for k, v in f.items()  # 4.4
               if any(RE_LEAK1.search(x) or RE_LEAK2.search(x) or self.stix.leak3.search(x) for x in values(v))]
        if hit:
            st["drop_leak"] += 1
            for k in hit:
                self.leak_fields[k] += 1
            return
        st["pass_4_4"] += 1
        self.run_pairs[src][run_id].add((host, day))
        self.run_hosts[src][run_id].add(host)
        dg = dedup_digest(f, channel, eid, host)  # 4.7
        cur = self.dedup.get(dg)
        if cur is not None:
            st["drop_duplicate"] += 1
            if cur[1] != labels:
                st["label_conflict"] += 1
                cur[1] = cur[1] | labels
            return
        st["pass_4_7"] += 1
        self.dedup[dg] = [run_id, labels, src]
        self.alerts_per_run[run_id] += 1


def scenarios(pl, mode):
    res = {}
    for src in SOURCE_ORDER:
        uf, keyrun = UF(), {}
        table = pl.run_pairs[src] if mode == "c" else pl.run_hosts[src]
        for run, keys in table.items():
            uf.find(run)
            for k in keys:
                if k in keyrun:
                    uf.union(keyrun[k], run)
                else:
                    keyrun[k] = run
        comp = collections.Counter()
        for run in table:
            comp[uf.find(run)] += pl.alerts_per_run.get(run, 0)
        res[src] = {"scenarios": len(comp), "largest_alerts": max(comp.values(), default=0)}
    res["total"] = {"scenarios": sum(res[s]["scenarios"] for s in SOURCE_ORDER),
                    "largest_alerts": max(res[s]["largest_alerts"] for s in SOURCE_ORDER)}
    return res


def multiplatform_stats(root):
    agg = collections.defaultdict(lambda: {"yaml": 0, "ids": set(), "env": set()})
    bad = 0
    for r, dirs, fs in os.walk(os.path.join(root, "datasets")):
        dirs.sort()
        for n in sorted(fs):
            if not n.endswith((".yml", ".yaml")):
                continue
            try:
                with open(os.path.join(r, n), encoding="utf-8") as fh:
                    doc = yaml.load(fh, Loader=yaml.BaseLoader)
            except Exception:
                bad += 1
                continue
            if not isinstance(doc, dict):
                bad += 1
                continue
            mt = doc.get("mitre_technique")
            ids = [] if mt is None else (mt if isinstance(mt, list) else [mt])
            ids = {str(x).strip() for x in ids if RE_VALID_ID.match(str(x).strip())}
            for s in {d.get("sourcetype") for d in (doc.get("datasets") or [])
                      if isinstance(d, dict) and d.get("sourcetype")}:
                a = agg[s]
                a["yaml"] += 1
                a["ids"] |= ids
                if doc.get("environment"):
                    a["env"].add(str(doc.get("environment")))
    return {"by_sourcetype": {s: {"yaml_files": a["yaml"], "distinct_valid_ids": len(a["ids"]),
                                  "distinct_environments": len(a["env"])} for s, a in sorted(agg.items())},
            "yaml_parse_errors": bad}


def build_report(pl, extra, note, gate_cfg):
    src_out, tot = {}, collections.Counter()
    for s in SOURCE_ORDER:
        c = dict(sorted(pl.st[s].items()))
        c["runs_registered"] = pl.runs_seen[s]
        c["runs_without_mitre_label"] = pl.runs_no_label[s]
        src_out[s] = c
        tot.update(pl.st[s])
    src_out["total"] = dict(sorted(tot.items()))
    all_raw, moved, dropped, pre = set(), set(), {}, set()
    for s in SOURCE_ORDER:
        for r, f, k in pl.label_details[s]:
            all_raw.add(r)
            if k == "moved":
                moved.add((r, f))
            elif k == "pre":
                pre.add(r)
            elif k in ("deprecated", "unknown", "unreachable"):
                dropped[r] = k
    per_id, per_src_id, per_src = collections.Counter(), {s: collections.Counter() for s in SOURCE_ORDER}, collections.Counter()
    for _, labels, s in pl.dedup.values():
        per_src[s] += 1
        for t in labels:
            per_id[t] += 1
            per_src_id[s][t] += 1
    ids5 = [t for t, n in per_id.items() if n >= gate_cfg["min_alerts_per_technique"]]
    alerts = len(pl.dedup)
    sc_c, sc_b = scenarios(pl, "c"), scenarios(pl, "b")

    def res(ok):
        return "ĐẠT" if ok else "KHÔNG ĐẠT"

    tree = collections.defaultdict(lambda: collections.defaultdict(dict))
    for (s, status, ce), n in sorted(pl.tree_status.items()):
        tree[s][status][ce] = n
    return {
        "note": note,
        "sources": src_out,
        "alerts_total": alerts,
        "alerts_by_source": dict(sorted(per_src.items())),
        "leak_blocked_by_field_name": dict(sorted(pl.leak_fields.items())),
        "labels": {"distinct_raw_ids": len(all_raw), "moved": [f"{a}->{b}" for a, b in sorted(moved)],
                   "dropped": {k: dropped[k] for k in sorted(dropped)}, "pre": sorted(pre), "pre_count": len(pre)},
        "alerts_per_technique_id": {k: per_id[k] for k in sorted(per_id)},
        "alerts_per_technique_id_by_source": {s: {k: v for k, v in sorted(per_src_id[s].items())} for s in SOURCE_ORDER},
        "ids_with_ge5_alerts": len(ids5),
        "subtechnique_ids_with_ge5_alerts": sum(1 for t in ids5 if "." in t),
        "scenarios_c": sc_c,
        "scenarios_b": sc_b,
        "process_tree_status_by_event_type": {s: {k: dict(v) for k, v in d.items()} for s, d in tree.items()},
        "otrf_sysmon_12_13_14_eventtype_top10": [[k, v] for k, v in pl.eventtype.most_common(10)],
        "gate": {
            "alerts": {"value": alerts, "min": gate_cfg["min_alerts"], "result": res(alerts >= gate_cfg["min_alerts"])},
            "ids_with_min_alerts": {"value": len(ids5), "min": gate_cfg["min_techniques"],
                                    "result": res(len(ids5) >= gate_cfg["min_techniques"])},
            "scenarios_c": {"value": sc_c["total"]["scenarios"], "min": gate_cfg["min_scenarios"],
                            "result": res(sc_c["total"]["scenarios"] >= gate_cfg["min_scenarios"])},
        },
        "multiplatform_splunk_all_yaml": extra,
    }


def check_stix(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    if os.path.getsize(path) != STIX_SIZE or h.hexdigest() != STIX_SHA256:
        print("STIX sha256/size LECH - DUNG")
        sys.exit(2)


def add_common_args(ap):
    for a in ("splunk", "otrf", "evtx", "sheet", "stix"):
        ap.add_argument("--" + a, required=True)
    ap.add_argument("--seed", type=int, default=42)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    add_common_args(ap)
    ap.add_argument("--out", required=True)
    ap.add_argument("--review-dir", default=None, help="thu muc file duyet (tu root_candidates.py)")
    ap.add_argument("--sample", default=None, help="_sample.json cua root_candidates.py (neu co chon mau)")
    a = ap.parse_args()
    check_stix(a.stix)
    stix = Stix(a.stix)
    pl = Pipeline(stix)
    reviews = load_reviews(a.review_dir) if a.review_dir else None
    sampled = set(json.load(open(a.sample, encoding="utf-8"))["sampled_codes"]) if a.sample else None
    gate_cfg = {"min_alerts": 200, "min_techniques": 30, "min_alerts_per_technique": 5, "min_scenarios": 30}
    tmp = tempfile.mkdtemp(prefix="count_gate_")
    try:
        for src, run_id, raw, events in iter_runs(a, pl.st, tmp):
            labels, reason = pl.register_run(src, raw)
            if reviews is None:
                for f in events:
                    pl.process(src, run_id, labels, reason, f)
                continue
            code = run_code(a.seed, run_id)
            table = ProcessTable()
            for f in events:
                table.add_event(f)
            table.finalize()
            if sampled is not None and code not in sampled:
                status_all = "not_sampled"
            elif not table.procs:
                status_all = "no_tree"
            elif code not in reviews:
                status_all = "unreviewed"
            else:
                status_all = None
            keep = table.subtree(reviews.get(code, ())) if status_all is None else set()
            for f in events:
                if status_all is not None:
                    tree_ok = status_all
                else:
                    k = table.link(f)
                    tree_ok = "ambiguous" if k is None else (k in keep)
                pl.process(src, run_id, labels, reason, f, tree_ok)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    note = ("process-tree filter applied (step 2); ambiguous events excluded" if reviews is not None
            else "upper bound: process-tree filter not applied")
    rep = build_report(pl, multiplatform_stats(a.splunk), note, gate_cfg)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2, ensure_ascii=False, sort_keys=True)
    print("NOTE:", rep["note"])
    for s in SOURCE_ORDER + ["total"]:
        print(f"[{s}]", json.dumps(rep["sources"][s], sort_keys=True))
    print("alerts_total:", rep["alerts_total"], rep["alerts_by_source"])
    print("ids>=5:", rep["ids_with_ge5_alerts"], "| sub-technique:", rep["subtechnique_ids_with_ge5_alerts"])
    print("scenarios (c):", json.dumps(rep["scenarios_c"]["total"]), "(b):", json.dumps(rep["scenarios_b"]["total"]))
    for k, g in rep["gate"].items():
        print(f"GATE {k}: {g['value']} (min {g['min']}) -> {g['result']}")


if __name__ == "__main__":
    main()
