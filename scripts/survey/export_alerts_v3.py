"""export_alerts_v3.py - xuat windows_run4: duyet toan bo run, dedup/noi PID moi, split mo rong (D2 QD 74, 76, 77).

Viet va test o may lam viec (tests/test_export_v3.py, du lieu gia); chay tren may khao sat:
 python -I scripts/survey/export_alerts_v3.py --splunk ... --otrf ... --evtx ... --sheet ... --stix ... --seed 42 \
 --run3-review-dir <run3> --run3-sample <run3/_sample.json> --run3-manifest <windows_run3/manifest.json> \
 --run4-review-dir <run4> --run4-sample <run4/_sample.json> --split-seed 42 --dev-fraction 0.5 \
 --dedup-mode {old,envelope_free} [--envelope-fields <json>] --pid-alive {off,on} --out-dir <thu muc moi, rong>

Mot lan doc du lieu, bon cau hinh chay song song (QD 77):
 A : mau run3 + logic cu bang chinh cg.Pipeline (ban da pin) -> phai tai lap dung 6 file cua manifest run3
 A2 : mau run3 + logic cu bang Collector cua file nay -> phai trung A tung alert (kiem Collector)
 B : mau run3 + dedup / noi PID moi -> so dem
 C : toan bo run + dedup / noi PID moi -> XUAT run4
Split run4 (QD 74): scenario chi co run cu cung phia -> giu phia; scenario chi co run moi -> trong tung nguon, xep
theo sha256(split_seed:run_code nho nhat) roi gan xen ke test, dev, ...; scenario gop: co run dev cu -> dev, chi
run test cu (+ run moi) -> test. Nhom alert trung co ban thuoc run dev cu -> giu ban do. Alert run4 phia test co
noi dung trung mot alert dev run3 (ban thuoc run dev da bi loai) -> loai khoi run4, dem rieng.
Kiem bat buoc: 0 alert dev run3 nam trong test run4; A tai lap manifest run3; A2 == A. Sai -> khong ghi gi, exit 2.
Noi PID moi (--pid-alive on): event PowerShell noi theo PID vao tien trinh da ket thuc (Sysmon 5 / Security 4689)
truoc thoi diem event -> ambiguous. KHONG doi cach noi cha-con cua cay (giu nguyen ung vien va file duyet).
Khong in gia tri field, hostname, username, duong dan log.
"""
import argparse
import collections
import hashlib
import json
import os
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import count_gate as cg # noqa: E402
import export_alerts as ea # noqa: E402

# sha256 cua ban da sinh windows_run3 tren may khao sat (manifest run3); main() kiem truoc khi chay
PINNED = {"count_gate.py": "5f1b08758c29eb164a82b3048af87e15ec78066ab2b17c90970e304e7dd28136",
          "export_alerts.py": "b3214bc42d385e981ab981b5ab1f959372ab4fe8db61e0d9f25b24d017e6ef42"}
POWERSHELL = {("microsoft-windows-powershell/operational", "4104"),
              ("microsoft-windows-powershell/operational", "4103"), ("windows powershell", "800")}
# Nhom event (D2 QD 60; trung config event_groups.windows - test o may lam viec kiem)
EVENT_GROUPS = {"1": "process", "4688": "process", "7": "image_load", "12": "registry", "13": "registry",
                "3": "network", "22": "network", "11": "file", "8": "process_access", "10": "process_access",
                "4103": "powershell", "4104": "powershell", "800": "powershell",
                **{e: "security_other" for e in ("4624", "4648", "4672", "4698", "4720", "5140", "5145")}}
NEVER_ENVELOPE = {"Channel", "EventID"} # luon nam trong khoa (dedup_digest xu ly rieng)
REBALANCE_MIN = 0.25 # QD 63/75: chi kiem, khong chia lai


# ---------------------------------------------------------------- cay tien trinh co thoi diem ket thuc
class AliveTable(cg.ProcessTable):
    """ProcessTable + thoi diem ket thuc (Sysmon 5 theo ProcessGuid, Security 4689 theo host + PID).
    `link` (ke thua) giu nguyen hanh vi cu; `link_alive` chi khac voi event PowerShell."""

    def __init__(self):
        super().__init__()
        self._ends = []
        self.end = {}

    def add_event(self, f):
        ch, eid = cg.event_key(f)
        if ch == cg.SYSMON and eid == "5":
            g, t = cg.first(f.get("ProcessGuid")).strip().lower(), cg.event_time(f)
            if g and t is not None:
                self._ends.append(("g", "g:" + g, None, t))
            return
        if ch == "security" and eid == "4689":
            pid, t = cg.to_pid(f.get("ProcessId")), cg.event_time(f)
            if pid is not None and t is not None:
                self._ends.append(("s", cg.norm_host(f), pid, t))
            return
        super().add_event(f)

    def finalize(self):
        super().finalize()
        for kind, a, pid, t in self._ends:
            key = a if kind == "g" else self.lookup_pid(a, pid, t)
            if key in self.procs and (key not in self.end or t < self.end[key]):
                self.end[key] = t

    def link_alive(self, f):
        k = self.link(f)
        if k is None or cg.event_key(f) not in POWERSHELL:
            return k
        t, e = cg.event_time(f), self.end.get(k)
        return None if (t is not None and e is not None and e < t) else k


# ---------------------------------------------------------------- thu thap (logic cg.Pipeline.process toi 4.4)
@dataclass
class Occ:
    seq: int
    src: str
    run_id: str
    labels: frozenset
    channel: str
    eid: str
    fields: dict
    old_key: bytes
    new_key: bytes


class Collector:
    """Giong cg.Pipeline.process cho toi buoc leak (4.4); thay dedup tuc thi bang luu moi lan xuat hien, de chon ban
    dai dien SAU khi biet phia run3 cua tung run. mode 'old': khoa = cg.dedup_digest; 'envelope_free': bo them field
    phong bi khoi khoa."""

    def __init__(self, stix, mode="old", envelope=()):
        if mode not in ("old", "envelope_free"):
            raise ValueError(mode)
        self.stix, self.mode = stix, mode
        self.envelope = set(envelope) - NEVER_ENVELOPE
        self.st = {s: collections.Counter() for s in cg.SOURCE_ORDER}
        self.run_pairs = {s: collections.defaultdict(set) for s in cg.SOURCE_ORDER}
        self.run_hosts = {s: collections.defaultdict(set) for s in cg.SOURCE_ORDER}
        self.occ = []

    def process(self, src, run_id, labels, reason, f, tree_ok, seq):
        st = self.st[src]
        st["events_read"] += 1
        channel, eid = cg.event_key(f)
        if eid not in cg.KEEP.get(channel, ()):
            st["drop_filter_type"] += 1
            return
        st["pass_4_1"] += 1
        if tree_ok is not None:
            if tree_ok is not True:
                st["drop_tree_" + ("not_in_tree" if tree_ok is False else str(tree_ok))] += 1
                return
        st["pass_tree"] += 1
        if not labels:
            st["drop_" + reason] += 1
            return
        st["pass_4_2"] += 1
        host, day = cg.norm_host(f), cg.event_day(f)
        for k in cg.STRIP:
            f.pop(k, None)
        if any(any(cg.RE_LEAK1.search(x) or cg.RE_LEAK2.search(x) or self.stix.leak3.search(x) for x in cg.values(v))
               for v in f.values()):
            st["drop_leak"] += 1
            return
        st["pass_4_4"] += 1
        self.run_pairs[src][run_id].add((host, day))
        self.run_hosts[src][run_id].add(host)
        old = cg.dedup_digest(f, channel, eid, host)
        new = old if self.mode == "old" else cg.dedup_digest(
            {k: v for k, v in f.items() if k not in self.envelope}, channel, eid, host)
        self.occ.append(Occ(seq, src, run_id, labels, channel, eid, f, old, new))


def build_alerts(col, key_attr, prefer_runs=frozenset()):
    """Gom lan xuat hien theo khoa -> {khoa: dict(rep, labels, occs)}; dem label_conflict giong cg (so voi nhan dang
    gop, theo nguon cua ban trung). Dai dien: lan dau tien thuoc prefer_runs, neu khong co thi lan dau tien."""
    groups = collections.OrderedDict()
    for o in sorted(col.occ, key=lambda o: o.seq):
        groups.setdefault(getattr(o, key_attr), []).append(o)
    out, conflict = {}, collections.Counter()
    for k, occs in groups.items():
        lab = occs[0].labels
        for o in occs[1:]:
            if o.labels != lab:
                conflict[o.src] += 1
                lab = lab | o.labels
        rep = next((o for o in occs if o.run_id in prefer_runs), occs[0])
        out[k] = {"rep": rep, "labels": lab, "occs": occs}
    return out, conflict


# ---------------------------------------------------------------- doc mot lan, chay cac cau hinh
def _status(code, sample, reviews, table):
    if code not in sample:
        return "not_sampled"
    if not table.procs:
        return "no_tree"
    if code not in reviews:
        return "unreviewed"
    return None


def run_pass(runs, stix, seed, run3, configs):
    """runs: iterable (src, run_id, raw_ids, events). run3: dict(sample, reviews) cho cau hinh A (cg.Pipeline).
    configs: {ten: dict(collector, sample, reviews, alive)}. -> (pipeline A, kept A)."""
    pl = cg.Pipeline(stix)
    kept, seq = {}, 0
    for src, run_id, raw, events in runs:
        labels, reason = pl.register_run(src, raw)
        code = cg.run_code(seed, run_id)
        base, alive = cg.ProcessTable(), AliveTable()
        for f in events:
            base.add_event(f)
            alive.add_event(f)
        base.finalize()
        alive.finalize()
        links_old = [base.link(f) for f in events]
        links_new = [alive.link_alive(f) for f in events]
        # A: dung cg.Pipeline (logic export_alerts.py v2)
        sa = _status(code, run3["sample"], run3["reviews"], base)
        keep_a = base.subtree(run3["reviews"].get(code, ())) if sa is None else set()
        for f, k in zip(events, links_old):
            tree_ok = sa if sa is not None else ("ambiguous" if k is None else (k in keep_a))
            before = pl.st[src]["pass_4_7"]
            ff = dict(f)
            pl.process(src, run_id, labels, reason, ff, tree_ok)
            if pl.st[src]["pass_4_7"] > before:
                kept[next(reversed(pl.dedup))] = {"fields": ff, "channel": cg.event_key(f)[0],
                                                  "event_id": cg.event_key(f)[1]}
        for name, c in configs.items():
            table = alive if c["alive"] else base
            links = links_new if c["alive"] else links_old
            s = _status(code, c["sample"], c["reviews"], table)
            keep = table.subtree(c["reviews"].get(code, ())) if s is None else set()
            for i, (f, k) in enumerate(zip(events, links)):
                tree_ok = s if s is not None else ("ambiguous" if k is None else (k in keep))
                c["collector"].process(src, run_id, labels, reason, dict(f), tree_ok, seq + i)
        seq += len(events)
    return pl, kept


# ---------------------------------------------------------------- dung alert + scenario + split
def sid(seed, rep):
    return hashlib.sha256(f"{seed}:{rep}".encode("utf-8")).hexdigest()[:12]


def components_all(run_pairs, run_hosts):
    comp_c, comp_b = {}, {}
    for s in cg.SOURCE_ORDER:
        comp_c.update(ea.components(run_pairs[s]))
        comp_b.update(ea.components(run_hosts[s]))
    return comp_c, comp_b


def rows_from(alert_items, comp_c, comp_b, seed):
    """alert_items: iterable (key bytes, src, run_id, channel, eid, fields, labels)."""
    return [{"alert_id": k.hex(), "source": src, "channel": ch, "event_id": eid, "fields": fields,
             "labels": sorted(labels), "run_code": cg.run_code(seed, run_id), "run_id": run_id,
             "scenario_c": sid(seed, comp_c[run_id]), "scenario_b": sid(seed, comp_b[run_id])}
            for k, src, run_id, ch, eid, fields, labels in alert_items]


def rebuild_run3(pl, kept, seed, split_seed, dev_fraction):
    """Dung lai dung export_alerts.py v2 -> (rows, side theo scenario_c, side theo run_id, payload bytes)."""
    comp_c, comp_b = components_all(pl.run_pairs, pl.run_hosts)
    items = [(dg, src, run_id, kept[dg]["channel"], kept[dg]["event_id"], kept[dg]["fields"], labels)
             for dg, (run_id, labels, src) in pl.dedup.items()]
    rows = rows_from(items, comp_c, comp_b, seed)
    scen = sorted({r["scenario_c"] for r in rows},
                  key=lambda s: hashlib.sha256(f"{split_seed}:{s}".encode("utf-8")).hexdigest())
    n_test = round(len(scen) * (1 - dev_fraction))
    side_sc = {s: ("test" if i < n_test else "dev") for i, s in enumerate(scen)}
    side_run = {run: side_sc[sid(seed, rep)] for run, rep in comp_c.items() if sid(seed, rep) in side_sc}
    return rows, side_sc, side_run, payload(rows, side_sc)


def payload(rows, side_sc, extra=None):
    parts = {"dev": [], "test": []}
    for r in rows:
        parts[side_sc[r["scenario_c"]]].append(r)
    out = {}
    for side, rs in parts.items():
        rs.sort(key=lambda x: x["alert_id"])
        out[side] = {
            "alerts.jsonl": ea.jsonl({k: x[k] for k in ("alert_id", "source", "channel", "event_id", "fields")}
                                     for x in rs),
            "labels.jsonl": ea.jsonl({"alert_id": x["alert_id"], "labels": x["labels"]} for x in rs),
            "scenarios.jsonl": ea.jsonl({k: x[k] for k in ("alert_id", "run_code", "scenario_c", "scenario_b")}
                                        for x in rs),
        }
        if extra:
            out[side].update(extra.get(side, {}))
    return out


def extension_split(run_pairs, comp_c, side_run3, seed, split_seed):
    """QD 74 -> ({scenario_c: side}, {scenario_c: origin}). Scenario tinh trong tung nguon (components)."""
    by_comp = collections.defaultdict(set)
    src_of = {}
    for s in cg.SOURCE_ORDER:
        for run in run_pairs[s]:
            by_comp[comp_c[run]].add(run)
            src_of[comp_c[run]] = s
    side, origin, new = {}, {}, collections.defaultdict(list)
    for rep, runs in by_comp.items():
        sc = sid(seed, rep)
        olds = [side_run3[r] for r in runs if r in side_run3]
        has_new = len(olds) < len(runs)
        if "dev" in olds:
            side[sc] = "dev"
        elif "test" in olds:
            side[sc] = "test"
        else:
            key = min(cg.run_code(seed, r) for r in runs)
            new[src_of[rep]].append((hashlib.sha256(f"{split_seed}:{key}".encode("utf-8")).hexdigest(), sc))
            origin[sc] = "new"
            continue
        origin[sc] = "old_keep" if (not has_new and len(set(olds)) == 1) else "merged"
    for s in sorted(new):
        for i, (_, sc) in enumerate(sorted(new[s])):
            side[sc] = "test" if i % 2 == 0 else "dev"
    return side, origin


def map_run3_to_run4(rows3, side3, col_c, alerts_c, side4_by_alert):
    """Anh xa alert run3 (khoa cu) -> alert run4 (khoa moi) qua lan xuat hien trong C."""
    old2new = collections.defaultdict(set)
    for o in col_c.occ:
        old2new[o.old_key.hex()].add(o.new_key.hex())
    res, cnt = [], collections.Counter()
    for r in rows3:
        news = old2new.get(r["alert_id"], set())
        s3 = side3[r["scenario_c"]]
        if not news:
            res.append({"run3_alert_id": r["alert_id"], "run4_alert_id": None, "run3_side": s3, "run4_side": None})
            cnt[f"{s3}_dropped"] += 1
            continue
        if len(news) > 1:
            cnt["anomaly_old_key_to_many_new"] += 1
        n = sorted(news)[0]
        s4 = side4_by_alert[n]
        res.append({"run3_alert_id": r["alert_id"], "run4_alert_id": n, "run3_side": s3, "run4_side": s4})
        cnt[f"{s3}_to_{s4}"] += 1
    return res, cnt


def composition(rows, side_sc):
    t = collections.Counter((side_sc[r["scenario_c"]], r["source"], EVENT_GROUPS.get(r["event_id"], "?"))
                            for r in rows)
    groups = sorted({g for _, _, g in t})
    flagged = []
    for g in groups:
        d = sum(n for (s, _, gg), n in t.items() if gg == g and s == "dev")
        te = sum(n for (s, _, gg), n in t.items() if gg == g and s == "test")
        tot = d + te
        if tot and min(d, te) / tot < REBALANCE_MIN:
            flagged.append({"group": g, "dev": d, "test": te})
    return {"counts": [[s, src, g, n] for (s, src, g), n in sorted(t.items())], "flagged_lt_0_25": flagged}


def gate(rows):
    per = collections.Counter(t for r in rows for t in r["labels"])
    return {"alerts": len(rows), "ids_ge5": sum(1 for n in per.values() if n >= 5),
            "subtechnique_ids_ge5": sum(1 for t, n in per.items() if n >= 5 and "." in t),
            "scenarios_c": len({r["scenario_c"] for r in rows}),
            "alerts_by_source": dict(collections.Counter(r["source"] for r in rows))}


def summarize_col(col, alerts, conflict):
    return {"sources": {s: dict(sorted(col.st[s].items())) for s in cg.SOURCE_ORDER},
            "alerts": len(alerts), "label_conflict": dict(conflict)}


# ---------------------------------------------------------------- toan bo (khong doc dia; test duoc)
def export_core(runs, stix, seed, split_seed, dev_fraction, run3, run4, mode, envelope, pid_alive):
    """-> dict ket qua (payload run4, manifest, kiem tra). Khong ghi dia."""
    cols = {"A2": Collector(stix, "old"), "B": Collector(stix, mode, envelope),
            "C": Collector(stix, mode, envelope)}
    configs = {"A2": dict(collector=cols["A2"], sample=run3["sample"], reviews=run3["reviews"], alive=False),
               "B": dict(collector=cols["B"], sample=run3["sample"], reviews=run4["reviews"], alive=pid_alive),
               "C": dict(collector=cols["C"], sample=run4["sample"], reviews=run4["reviews"], alive=pid_alive)}
    pl, kept = run_pass(runs, stix, seed, run3, configs)
    rows3, side3, side_run3, pay3 = rebuild_run3(pl, kept, seed, split_seed, dev_fraction)

    # A2 == A
    a2, conf_a2 = build_alerts(cols["A2"], "old_key")
    a2_ok = (set(a2) == set(pl.dedup) and all(
        a2[k]["labels"] == pl.dedup[k][1] and a2[k]["rep"].run_id == pl.dedup[k][0]
        and a2[k]["rep"].fields == kept[k]["fields"] for k in a2))

    # B (chi so dem)
    b_alerts, conf_b = build_alerts(cols["B"], "new_key", frozenset(r for r, s in side_run3.items() if s == "dev"))

    # C -> run4
    col = cols["C"]
    prefer = frozenset(r for r, s in side_run3.items() if s == "dev")
    c_alerts, conf_c = build_alerts(col, "new_key", prefer)
    comp_c, comp_b = components_all(col.run_pairs, col.run_hosts)
    items = [(k, a["rep"].src, a["rep"].run_id, a["rep"].channel, a["rep"].eid, a["rep"].fields, a["labels"])
             for k, a in c_alerts.items()]
    rows4 = rows_from(items, comp_c, comp_b, seed)
    side4, origin4 = extension_split(col.run_pairs, comp_c, side_run3, seed, split_seed)
    # QD 74 (5): alert run4 o phia test ma co noi dung trung alert dev run3 (ban thuoc run dev bi loai, vd do noi
    # PID moi) -> loai khoi run4, dem rieng; khong de noi dung da xem vao test.
    dev3 = {r["alert_id"] for r in rows3 if side3[r["scenario_c"]] == "dev"}
    seen_in_dev = {r["alert_id"] for r in rows4 if side4[r["scenario_c"]] == "test"
                   and any(o.old_key.hex() in dev3 for o in c_alerts[bytes.fromhex(r["alert_id"])]["occs"])}
    rows4 = [r for r in rows4 if r["alert_id"] not in seen_in_dev]
    side4_by_alert = {r["alert_id"]: side4[r["scenario_c"]] for r in rows4}
    side4_by_alert.update({a: "excluded_seen_in_dev" for a in seen_in_dev})
    mapping, map_cnt = map_run3_to_run4(rows3, side3, col, c_alerts, side4_by_alert)
    extra = {"dev": {"run3_to_run4_alert_map.jsonl": ea.jsonl(m for m in mapping if m["run3_side"] == "dev")},
             "test": {"run3_to_run4_alert_map.jsonl": ea.jsonl(m for m in mapping if m["run3_side"] == "test")}}
    pay4 = payload(rows4, side4, extra)
    origin_cnt = collections.Counter((origin4[s], side4[s]) for s in side4)
    return {
        "payload_run3": pay3, "payload_run4": pay4, "a2_equals_a": a2_ok,
        "old_dev_in_new_test": map_cnt.get("dev_to_test", 0),
        "steps": {
            "A_run3_old_logic": {"alerts": len(pl.dedup), **gate(rows3),
                                 "label_conflict": {s: pl.st[s]["label_conflict"] for s in cg.SOURCE_ORDER}},
            "B_run3_sample_new_logic": {**summarize_col(cols["B"], b_alerts, conf_b)},
            "C_all_runs_new_logic": {**summarize_col(col, c_alerts, conf_c), **gate(rows4)},
        },
        "split_run4": {"scenarios_by_origin_side": {f"{o}|{s}": n for (o, s), n in sorted(origin_cnt.items())},
                       "alerts": dict(collections.Counter(side4_by_alert.values())),
                       "excluded_test_alerts_seen_in_dev": len(seen_in_dev),
                       "run3_to_run4": dict(map_cnt), "composition": composition(rows4, side4),
                       "scenarios_b_crossing_split": sum(
                           1 for b in {r["scenario_b"] for r in rows4}
                           if len({side4[r["scenario_c"]] for r in rows4 if r["scenario_b"] == b}) > 1)},
        "params": {"seed": seed, "split_seed": split_seed, "dev_fraction": dev_fraction, "dedup_mode": mode,
                   "envelope_fields": sorted(set(envelope) - NEVER_ENVELOPE), "pid_alive": pid_alive},
    }


def file_hashes(pay):
    return {f"{side}/{name}": {"sha256": hashlib.sha256(data).hexdigest(), "lines": data.count(b"\n")}
            for side, files in pay.items() for name, data in files.items()}


def check_run3(pay3, manifest3):
    got = file_hashes(pay3)
    return {k: (got.get(k, {}).get("sha256") == v["sha256"]) for k, v in manifest3["files"].items()}


def write_outputs(res, out_dir, script_hashes, manifest3_sha):
    pay = res["payload_run4"]
    os.makedirs(os.path.join(out_dir, "dev"))
    files = {}
    for name, data in pay["dev"].items():
        with open(os.path.join(out_dir, "dev", name), "wb") as fh:
            fh.write(data)
    zpath = os.path.join(out_dir, "test.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(pay["test"].items()):
            info = zipfile.ZipInfo("test/" + name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    files.update(file_hashes(pay))
    manifest = {"export": "windows_run4", "files": files, "test_zip_sha256": ea.sha256_file(zpath),
                "scripts_sha256": script_hashes, "run3_manifest_sha256": manifest3_sha,
                **{k: res[k] for k in ("steps", "split_run4", "params", "a2_equals_a", "old_dev_in_new_test")}}
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False, sort_keys=True)
    return manifest


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    cg.add_common_args(ap)
    for a in ("run3-review-dir", "run3-sample", "run3-manifest", "run4-review-dir", "run4-sample", "out-dir"):
        ap.add_argument("--" + a, required=True)
    ap.add_argument("--split-seed", type=int, required=True)
    ap.add_argument("--dev-fraction", type=float, required=True)
    ap.add_argument("--dedup-mode", choices=("old", "envelope_free"), required=True)
    ap.add_argument("--envelope-fields", default=None, help="JSON list ten field phong bi (bat buoc khi envelope_free)")
    ap.add_argument("--pid-alive", choices=("off", "on"), required=True)
    a = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    hashes = {n: ea.sha256_file(os.path.join(here, n)) for n in ("count_gate.py", "export_alerts.py",
                                                                 "export_alerts_v3.py")}
    bad = [n for n, h in PINNED.items() if hashes[n] != h]
    if bad:
        print("SCRIPT LECH HASH DA PIN:", bad, "- DUNG")
        sys.exit(2)
    if os.path.exists(a.out_dir) and os.listdir(a.out_dir):
        print("--out-dir da ton tai va khong rong - DUNG")
        sys.exit(2)
    envelope = []
    if a.dedup_mode == "envelope_free":
        if not a.envelope_fields:
            print("--envelope-fields bat buoc khi --dedup-mode envelope_free")
            sys.exit(2)
        with open(a.envelope_fields, encoding="utf-8") as fh:
            envelope = json.load(fh)
        hashes["envelope_fields.json"] = ea.sha256_file(a.envelope_fields)
    cg.check_stix(a.stix)
    stix = cg.Stix(a.stix)
    with open(a.run3_sample, encoding="utf-8-sig") as fh:
        s3 = set(json.load(fh)["sampled_codes"])
    with open(a.run4_sample, encoding="utf-8-sig") as fh:
        s4 = set(json.load(fh)["sampled_codes"])
    with open(a.run3_manifest, encoding="utf-8") as fh:
        man3 = json.load(fh)
    run3 = {"sample": s3, "reviews": cg.load_reviews(a.run3_review_dir)}
    run4 = {"sample": s4, "reviews": cg.load_reviews(a.run4_review_dir)}
    if not s3 <= s4:
        print("mau run3 khong nam trong mau run4 - DUNG")
        sys.exit(2)
    tmp = tempfile.mkdtemp(prefix="export_v3_")
    st_dummy = {s: collections.Counter() for s in cg.SOURCE_ORDER}
    try:
        res = export_core(cg.iter_runs(a, st_dummy, tmp), stix, a.seed, a.split_seed, a.dev_fraction, run3, run4,
                          a.dedup_mode, envelope, a.pid_alive == "on")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    run3_check = check_run3(res["payload_run3"], man3)
    problems = []
    if not all(run3_check.values()):
        problems.append(f"A khong tai lap manifest run3: {run3_check}")
    if not res["a2_equals_a"]:
        problems.append("A2 (Collector) khac A (cg.Pipeline)")
    if res["old_dev_in_new_test"]:
        problems.append(f"{res['old_dev_in_new_test']} alert dev run3 nam trong test run4")
    summary = {k: res[k] for k in ("steps", "split_run4", "params", "a2_equals_a", "old_dev_in_new_test")}
    summary["run3_reproduced"] = run3_check
    summary["read_counters"] = {s: dict(st_dummy[s]) for s in cg.SOURCE_ORDER}
    if problems:
        print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True, default=str))
        print("KIEM TRA THAT BAI - KHONG GHI GI:", problems)
        sys.exit(2)
    man3_sha = ea.sha256_file(a.run3_manifest)
    manifest = write_outputs(res, a.out_dir, hashes, man3_sha)
    print(json.dumps({k: manifest[k] for k in ("steps", "split_run4", "a2_equals_a", "old_dev_in_new_test",
                                               "test_zip_sha256")}, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
