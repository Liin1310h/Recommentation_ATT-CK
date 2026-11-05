"""count_gate.py - dem du lieu Windows co nhan ATT&CK (Splunk, OTRF, EVTX).

Chi DOC du lieu va chi IN thong ke (so dem + technique ID + ten field).
Khong bao gio in/ghi gia tri field cua event, hostname, username, duong dan log.
Chay: python -I scripts/survey/count_gate.py --splunk ... --otrf ... --evtx ...
      --sheet ... --stix ... --out docs/survey_output/count_gate.json
"""
import argparse
import csv
import collections
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
NOTE = "upper bound: process-tree filter not applied"

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

DROP_DEDUP = set("""TimeCreated_SystemTime UtcTime CreationUtcTime PreviousCreationUtcTime
EventRecordID RecordNumber Execution_ProcessID Execution_ThreadID ExecutionProcessID ThreadID
Computer Correlation_ActivityID Correlation_RelatedActivityID EventTime ProcessGuid
ParentProcessGuid LogonGuid SourceProcessGUID TargetProcessGUID SourceProcessGuid
TargetProcessGuid LogonId TargetLogonId SubjectLogonId ProcessId ParentProcessId NewProcessId
SourceProcessId TargetProcessId SourceThreadId""".split())
RE_GUID = re.compile(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?")
RE_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+(-\d+)?")
RE_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?")
RE_HEX = re.compile(r"0x[0-9a-fA-F]+")
RE_IP = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
RE_USER = re.compile(r"\\Users\\[^\\]+", re.I)

RE_EVENT = re.compile(r"<Event[\s>].*?</Event>", re.S)
RE_TID = re.compile(r"T\d{4}(?:\.\d{3})?")
RE_VALID_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
RE_LEAK1 = re.compile(r"(?<![A-Za-z0-9])[Tt]\d{4}(?:\.\d{3})?(?![0-9])")
RE_LEAK2 = re.compile(r"attack\.t\d{4}", re.I)
RE_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def local(tag):
    return tag.rsplit("}", 1)[-1]


# ---------------------------------------------------------------- STIX
class Stix:
    def __init__(self, path):
        with open(path, encoding="utf-8") as fh:
            objs = json.load(fh)["objects"]
        self.by_ext = {}
        self.by_id = {}
        self.revoked_by = {}
        self.tactics = []
        for o in objs:
            t = o.get("type")
            if t == "attack-pattern":
                ext = None
                for r in o.get("external_references", []):
                    if r.get("source_name") == "mitre-attack" and r.get("external_id"):
                        ext = r["external_id"]
                        break
                rec = {
                    "id": o["id"], "ext": ext,
                    "revoked": bool(o.get("revoked")),
                    "deprecated": bool(o.get("x_mitre_deprecated")),
                    "phases": [p.get("phase_name") for p in o.get("kill_chain_phases", [])],
                }
                self.by_id[o["id"]] = rec
                if ext:
                    self.by_ext[ext] = rec
            elif t == "relationship" and o.get("relationship_type") == "revoked-by":
                self.revoked_by[o["source_ref"]] = o["target_ref"]
            elif t == "x-mitre-tactic" and o.get("x_mitre_shortname"):
                self.tactics.append(o["x_mitre_shortname"])
        self.tactics = sorted(set(self.tactics))
        self.leak3 = re.compile(
            r"attack\.(" + "|".join(re.escape(s) for s in self.tactics) + r")(?![a-z0-9_-])", re.I)
        self.cache = {}

    def norm(self, tid):
        """-> (final_id or None, kind) ; kind in ok/moved/deprecated/unknown/unreachable/pre"""
        if tid in self.cache:
            return self.cache[tid]
        res = self._norm(tid)
        self.cache[tid] = res
        return res

    def _norm(self, tid):
        cur = self.by_ext.get(tid)
        if cur is None:
            return None, "unknown"
        seen = set()
        while cur["revoked"]:
            if cur["id"] in seen:
                return None, "unreachable"
            seen.add(cur["id"])
            nxt = self.by_id.get(self.revoked_by.get(cur["id"]))
            if nxt is None:
                return None, "unreachable"
            cur = nxt
        if cur["deprecated"]:
            return None, "deprecated" if cur["ext"] == tid else "unreachable"
        final = cur["ext"]
        if cur["phases"] and all(p in PRE_PHASES for p in cur["phases"]):
            return None, "pre"
        return final, ("ok" if final == tid else "moved")


def normalize_labels(stix, raw_ids):
    """-> (final frozenset, reason_if_empty, list of (raw, final, kind))"""
    details = []
    final = set()
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
    f = {}
    sysnames = set()
    data_list = []
    ed = {}
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
    for k in list(f.keys()):
        if " " in k:
            k2 = k.replace(" ", "")
            if k2 not in f:
                f[k2] = f[k]
    return f


def flatten_json(obj):
    f = {}
    for k, v in obj.items():
        if k == "Hostname":
            k = "Computer"
        elif k == "SourceName":
            k = "Provider_Name"
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
    h = f.get("Computer", "")
    if isinstance(h, list):
        h = h[0] if h else ""
    h = h.strip().lower().split(".")[0]
    return h or "<none>"


def event_day(f):
    for k in ("TimeCreated_SystemTime", "@timestamp", "EventTime"):
        v = f.get(k)
        if not v or isinstance(v, list):
            continue
        s = v.strip()
        try:
            d = datetime.datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T", 1))
            if d.tzinfo is not None:
                d = d.astimezone(datetime.timezone.utc)
            return d.date().isoformat()
        except ValueError:
            m = RE_DATE.match(s)
            if m:
                return m.group(1)
    return "<none>"


def event_key(f):
    ch = f.get("Channel", "")
    ch = ch if isinstance(ch, str) else ""
    eid = f.get("EventID", "")
    eid = eid if isinstance(eid, str) else ""
    return ch.strip().lower(), eid.strip()


_host_re = {}


def dedup_digest(f, channel, eid, host):
    rx = None
    if len(host) >= 3 and host != "<none>":
        rx = _host_re.get(host)
        if rx is None:
            rx = _host_re[host] = re.compile(re.escape(host), re.I)

    def clean(s):
        s = RE_GUID.sub("<GUID>", s)
        s = RE_SID.sub("<SID>", s)
        s = RE_TS.sub("<TS>", s)
        s = RE_HEX.sub("<HEX>", s)
        s = RE_IP.sub("<IP>", s)
        s = RE_USER.sub(lambda m: "\\Users\\<USER>", s)
        if rx:
            s = rx.sub("<HOST>", s)
        return s

    out = {}
    for k, v in f.items():
        if k in DROP_DEDUP or k in ("Channel", "EventID"):
            continue
        out[k] = [clean(x) for x in v] if isinstance(v, list) else clean(v)
    blob = json.dumps({"Channel": channel, "EventID": eid, "fields": out},
                      sort_keys=True, ensure_ascii=False)
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


# ---------------------------------------------------------------- pipeline
class Pipeline:
    def __init__(self, stix):
        self.stix = stix
        self.st = {s: collections.Counter() for s in SOURCE_ORDER}
        self.leak_fields = collections.Counter()
        self.dedup = {}          # digest -> [run_id, labels]
        self.alerts_per_run = collections.Counter()
        self.run_pairs = {s: collections.defaultdict(set) for s in SOURCE_ORDER}
        self.run_hosts = {s: collections.defaultdict(set) for s in SOURCE_ORDER}
        self.run_source = {}
        self.eventtype = collections.Counter()
        self.label_stats = {s: {"raw": set(), "details": set()} for s in SOURCE_ORDER}
        self.runs_seen = {s: 0 for s in SOURCE_ORDER}
        self.runs_no_label = {s: 0 for s in SOURCE_ORDER}

    def register_run(self, src, raw_ids):
        self.runs_seen[src] += 1
        labels, reason, details = normalize_labels(self.stix, raw_ids)
        for r, f, k in details:
            self.label_stats[src]["raw"].add(r)
            self.label_stats[src]["details"].add((r, f, k))
        if reason == "no_label":
            self.runs_no_label[src] += 1
        return labels, reason

    def process(self, src, run_id, labels, reason, f):
        st = self.st[src]
        st["events_read"] += 1
        channel, eid = event_key(f)
        if src == "otrf" and channel == "microsoft-windows-sysmon/operational" and eid in ("12", "13", "14"):
            et = f.get("EventType")
            if isinstance(et, str):
                self.eventtype[et] += 1
        # 4.1
        if eid not in KEEP.get(channel, ()):
            st["drop_filter_type"] += 1
            return
        st["pass_4_1"] += 1
        # 4.2
        if not labels:
            st["drop_" + reason] += 1
            return
        st["pass_4_2"] += 1
        host = norm_host(f)
        day = event_day(f)       # truoc khi strip
        # 4.3
        for k in STRIP:
            f.pop(k, None)
        # 4.4
        hit = []
        for k, v in f.items():
            for x in values(v):
                if RE_LEAK1.search(x) or RE_LEAK2.search(x) or self.stix.leak3.search(x):
                    hit.append(k)
                    break
        if hit:
            st["drop_leak"] += 1
            for k in hit:
                self.leak_fields[k] += 1
            return
        st["pass_4_4"] += 1
        self.run_source[run_id] = src
        self.run_pairs[src][run_id].add((host, day))
        self.run_hosts[src][run_id].add(host)
        # 4.7
        dg = dedup_digest(f, channel, eid, host)
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


def parse_fragment(text, st):
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        st["xml_error"] += 1
        return None


# ---------------------------------------------------------------- sources
def run_splunk(pl, root):
    src = "splunk"
    base = os.path.join(root, "datasets", "attack_techniques")
    yamls = []
    for r, dirs, files in os.walk(base):
        dirs.sort()
        for n in sorted(files):
            if n.endswith((".yml", ".yaml")):
                yamls.append(os.path.join(r, n))
    yamls.sort()
    st = pl.st[src]
    for y in yamls:
        try:
            with open(y, encoding="utf-8") as fh:
                doc = yaml.load(fh, Loader=yaml.BaseLoader)
        except Exception:
            st["yaml_error"] += 1
            continue
        if not isinstance(doc, dict):
            st["yaml_error"] += 1
            continue
        ds = [d for d in (doc.get("datasets") or [])
              if isinstance(d, dict) and d.get("sourcetype") == "XmlWinEventLog"]
        if not ds:
            continue
        mt = doc.get("mitre_technique")
        raw = [] if mt is None else (mt if isinstance(mt, list) else [mt])
        raw = [str(x).strip() for x in raw if str(x).strip()]
        labels, reason = pl.register_run(src, raw)
        run_id = "splunk:" + os.path.relpath(y, root)
        for d in ds:
            p = (d.get("path") or "").lstrip("/")
            fp = os.path.join(root, *p.split("/"))
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
            text = data.decode("utf-8", "replace")
            for m in RE_EVENT.finditer(text):
                el = parse_fragment(m.group(0), st)
                if el is None:
                    st["events_read"] += 1
                    continue
                pl.process(src, run_id, labels, reason, flatten_xml(el, st))


def run_evtx(pl, root, sheet_rows, tmpdir):
    src = "evtx"
    st = pl.st[src]
    files = []
    for r, dirs, fs in os.walk(root):
        dirs.sort()
        for n in sorted(fs):
            if n.lower().endswith(".evtx"):
                files.append(os.path.join(r, n))
    files.sort()
    for i, fp in enumerate(files):
        raw = sorted(evtx_raw_labels(sheet_rows, os.path.basename(fp)))
        labels, reason = pl.register_run(src, raw)
        run_id = "evtx:" + os.path.relpath(fp, root)
        out = os.path.join(tmpdir, "e%05d.xml" % i)
        try:
            with open(out, "wb") as oh:
                rc = subprocess.run(["wevtutil", "qe", fp, "/lf:true", "/f:xml"],
                                    stdout=oh, stderr=subprocess.DEVNULL).returncode
            if rc != 0:
                st["wevtutil_error"] += 1
                continue
            with open(out, "rb") as fh:
                body = fh.read().decode("utf-8", "replace")
            body = re.sub(r"^\s*<\?xml[^>]*\?>", "", body)
            tree = ET.fromstring("<Events>" + body + "</Events>")
        except (ET.ParseError, OSError):
            st["wevtutil_error"] += 1
            continue
        finally:
            try:
                os.remove(out)
            except OSError:
                pass
        st["files_read"] += 1
        for el in tree:
            pl.process(src, run_id, labels, reason, flatten_xml(el, st))


RE_FULL_SUB = re.compile(r"^T\d{4}\.\d{3}$", re.I)


def otrf_ids(doc, counters=None):
    if counters is None:
        counters = collections.Counter()
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
        elif RE_FULL_SUB.match(s):
            s = s.upper()
            if s.split(".")[0] != t:
                counters["otrf_sub_not_under_technique"] += 1
            out.append(s)
        else:
            counters["otrf_sub_unparsed"] += 1
            out.append(t)
    return out


def run_otrf(pl, root):
    src = "otrf"
    st = pl.st[src]
    ds_root = os.path.join(root, "datasets")
    zips = collections.defaultdict(list)
    for r, dirs, fs in os.walk(ds_root):
        dirs.sort()
        for n in sorted(fs):
            if n.lower().endswith(".zip"):
                zips[n].append(os.path.join(r, n))
    metas = []
    mdir = os.path.join(ds_root, "atomic", "_metadata")
    for n in sorted(os.listdir(mdir)):
        if n.endswith(".yaml"):
            metas.append(os.path.join(mdir, n))
    for mp in metas:
        with open(mp, encoding="utf-8") as fh:
            doc = yaml.load(fh, Loader=yaml.BaseLoader)
        plat = doc.get("platform") or []
        plat = [plat] if isinstance(plat, str) else plat
        if not any(str(p).strip().lower() == "windows" for p in plat):
            st["skipped_non_windows_meta"] += 1
            continue
        raw = otrf_ids(doc, st)
        labels, reason = pl.register_run(src, raw)
        run_id = "otrf:" + str(doc.get("id") or os.path.basename(mp))
        paths = []
        for fe in doc.get("files") or []:
            link = (fe.get("link") or "") if isinstance(fe, dict) else ""
            if not link.lower().split("?")[0].endswith(".zip"):
                continue
            base = link.split("?")[0].rsplit("/", 1)[-1]
            cands = zips.get(base)
            if not cands:
                st["zip_not_found"] += 1
                continue
            if len(cands) > 1:
                st["zip_multi_match"] += 1
            for c in cands:
                if c not in paths:
                    paths.append(c)
        for zp in paths:
            try:
                zf = zipfile.ZipFile(zp)
                names = sorted(n for n in zf.namelist() if n.lower().endswith(".json"))
            except (zipfile.BadZipFile, OSError):
                st["bad_zip"] += 1
                continue
            st["zips_read"] += 1
            with zf:
                for n in names:
                    try:
                        with zf.open(n) as fh:
                            for line in fh:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    obj = json.loads(line)
                                except ValueError:
                                    st["json_error"] += 1
                                    continue
                                if not isinstance(obj, dict):
                                    st["json_error"] += 1
                                    continue
                                pl.process(src, run_id, labels, reason, flatten_json(obj))
                    except (zipfile.BadZipFile, OSError, RuntimeError):
                        st["bad_zip"] += 1


def multiplatform_stats(root):
    base = os.path.join(root, "datasets")
    agg = collections.defaultdict(lambda: {"yaml": 0, "ids": set(), "env": set()})
    bad = 0
    for r, dirs, fs in os.walk(base):
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
            env = doc.get("environment")
            sts = {d.get("sourcetype") for d in (doc.get("datasets") or [])
                   if isinstance(d, dict) and d.get("sourcetype")}
            for s in sts:
                a = agg[s]
                a["yaml"] += 1
                a["ids"] |= ids
                if env:
                    a["env"].add(str(env))
    out = {s: {"yaml_files": a["yaml"], "distinct_valid_ids": len(a["ids"]),
               "distinct_environments": len(a["env"])} for s, a in sorted(agg.items())}
    return {"by_sourcetype": out, "yaml_parse_errors": bad}


# ---------------------------------------------------------------- report
def scenarios(pl, mode):
    res = {}
    for src in SOURCE_ORDER:
        uf = UF()
        keyrun = {}
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


def build_report(pl, extra):
    src_out = {}
    tot = collections.Counter()
    for s in SOURCE_ORDER:
        c = dict(sorted(pl.st[s].items()))
        c["runs_registered"] = pl.runs_seen[s]
        c["runs_without_mitre_label"] = pl.runs_no_label[s]
        src_out[s] = c
        for k, v in pl.st[s].items():
            tot[k] += v
    src_out["total"] = dict(sorted(tot.items()))

    ls = {}
    all_raw, moved, dropped, pre = set(), set(), {}, set()
    for s in SOURCE_ORDER:
        for r, f, k in pl.label_stats[s]["details"]:
            all_raw.add(r)
            if k == "moved":
                moved.add((r, f))
            elif k == "pre":
                pre.add(r)
            elif k in ("deprecated", "unknown", "unreachable"):
                dropped[r] = k
    ls["distinct_raw_ids"] = len(all_raw)
    ls["moved"] = [f"{a}->{b}" for a, b in sorted(moved)]
    ls["dropped"] = {k: dropped[k] for k in sorted(dropped)}
    ls["pre"] = sorted(pre)
    ls["pre_count"] = len(pre)

    per_id = collections.Counter()
    per_src_alerts = collections.Counter()
    for run, labels, s in pl.dedup.values():
        per_src_alerts[s] += 1
        for t in labels:
            per_id[t] += 1
    ids5 = [t for t, n in per_id.items() if n >= 5]
    alerts = len(pl.dedup)
    sc_c, sc_b = scenarios(pl, "c"), scenarios(pl, "b")
    gate = {
        "alerts>=200": {"value": alerts, "result": "ĐẠT" if alerts >= 200 else "KHÔNG ĐẠT"},
        "ids_with>=5_alerts>=30": {"value": len(ids5), "result": "ĐẠT" if len(ids5) >= 30 else "KHÔNG ĐẠT"},
        "scenarios_c>=30": {"value": sc_c["total"]["scenarios"],
                            "result": "ĐẠT" if sc_c["total"]["scenarios"] >= 30 else "KHÔNG ĐẠT"},
    }
    by_src = {s: collections.Counter() for s in SOURCE_ORDER}
    for run, labels, s in pl.dedup.values():
        for t in labels:
            by_src[s][t] += 1
    return {
        "alerts_per_technique_id_by_source": {
            s: {k: by_src[s][k] for k in sorted(by_src[s])} for s in SOURCE_ORDER},
        "note": NOTE,
        "sources": src_out,
        "alerts_total": alerts,
        "alerts_by_source": dict(sorted(per_src_alerts.items())),
        "leak_blocked_by_field_name": dict(sorted(pl.leak_fields.items())),
        "labels": ls,
        "alerts_per_technique_id": {k: per_id[k] for k in sorted(per_id)},
        "ids_with_ge5_alerts": len(ids5),
        "subtechnique_ids_with_ge5_alerts": sum(1 for t in ids5 if "." in t),
        "scenarios_c": sc_c,
        "scenarios_b": sc_b,
        "otrf_sysmon_12_13_14_eventtype_top10": [
            [k, v] for k, v in pl.eventtype.most_common(10)],
        "otrf_sysmon_12_13_14_eventtype_distinct": len(pl.eventtype),
        "gate": gate,
        "multiplatform_splunk_all_yaml": extra,
    }


def print_summary(rep):
    print("NOTE:", rep["note"])
    for s in SOURCE_ORDER + ["total"]:
        print(f"[{s}]", json.dumps(rep["sources"][s], sort_keys=True))
    print("alerts_total:", rep["alerts_total"], rep["alerts_by_source"])
    print("leak_blocked_by_field_name:", rep["leak_blocked_by_field_name"])
    L = rep["labels"]
    print("labels: distinct_raw", L["distinct_raw_ids"], "moved", L["moved"],
          "dropped", L["dropped"], "pre", L["pre_count"], L["pre"])
    print("alerts per technique id:")
    for k, v in rep["alerts_per_technique_id"].items():
        print(f"  {k}: {v}")
    print("ids>=5:", rep["ids_with_ge5_alerts"], "sub-technique among them:",
          rep["subtechnique_ids_with_ge5_alerts"])
    print("scenarios (c):", json.dumps(rep["scenarios_c"]))
    print("scenarios (b):", json.dumps(rep["scenarios_b"]))
    print("otrf eventtype top10:", rep["otrf_sysmon_12_13_14_eventtype_top10"])
    for k, g in rep["gate"].items():
        print(f"GATE {k}: {g['value']} -> {g['result']}")
    print("multiplatform (all splunk yaml):",
          json.dumps(rep["multiplatform_splunk_all_yaml"], sort_keys=True))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    for a in ("splunk", "otrf", "evtx", "sheet", "stix", "out"):
        ap.add_argument("--" + a, required=True)
    a = ap.parse_args()

    size = os.path.getsize(a.stix)
    h = hashlib.sha256()
    with open(a.stix, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    if size != STIX_SIZE or h.hexdigest() != STIX_SHA256:
        print("STIX sha256/size LECH - DUNG")
        sys.exit(2)
    stix = Stix(a.stix)
    rows = load_sheet(a.sheet)
    pl = Pipeline(stix)
    tmp = tempfile.mkdtemp(prefix="count_gate_")
    try:
        run_evtx(pl, a.evtx, rows, tmp)
        run_otrf(pl, a.otrf)
        run_splunk(pl, a.splunk)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    rep = build_report(pl, multiplatform_stats(a.splunk))
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2, ensure_ascii=False, sort_keys=True)
    print_summary(rep)


if __name__ == "__main__":
    main()
