"""survey_fix_diag.py - luot 1: CHI DO (A0-A5). Khong sua du lieu, khong export lai, khong mo test.zip.

Chay (python -I), cung tham so voi export_alerts.py + --manifest/--out:
 python -I scripts/survey/survey_fix_diag.py --splunk ... --otrf ... --evtx ... --sheet ... --stix ... \
 --review-dir ... --sample ... --seed 42 --split-seed 42 --dev-fraction 0.5 --manifest <manifest.json> --out <file.json>

Chi in/ghi: so dem, ten field, technique ID, ma bam, ten channel/event_id, va (A5) duong dan tuong doi trong attack_data.
Khong in/ghi gia tri field, hostname, username, command line.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECT_SHA = {
    "count_gate.py": "5f1b08758c29eb164a82b3048af87e15ec78066ab2b17c90970e304e7dd28136",
    "export_alerts.py": "b3214bc42d385e981ab981b5ab1f959372ab4fe8db61e0d9f25b24d017e6ef42",
}
cg = None  # count_gate (gan trong load_modules)
ea = None  # export_alerts

XML_SYSTEM = ["Provider_Name", "Provider_Guid", "EventID_Qualifiers", "Version", "Level", "Task", "Opcode",
              "Keywords", "TimeCreated_SystemTime", "EventRecordID", "Correlation_ActivityID",
              "Correlation_RelatedActivityID", "Execution_ProcessID", "Execution_ThreadID", "Computer",
              "Security_UserID"]
EVENT_GROUPS = {
    "process": {"1", "4688"}, "image_load": {"7"}, "registry": {"12", "13"}, "network": {"3", "22"},
    "file": {"11"}, "process_access": {"8", "10"}, "powershell": {"4103", "4104", "800"},
    "security_other": {"4624", "4648", "4672", "4698", "4720", "5140", "5145"},
}
EID2GROUP = {e: g for g, es in EVENT_GROUPS.items() for e in es}
PS_KEYS = {("microsoft-windows-powershell/operational", "4104"), ("microsoft-windows-powershell/operational", "4103"),
           ("windows powershell", "800")}
SPLUNK_STASH = """datasets/attack_techniques/T1021.003/lateral_movement/windows-powershell-xml.log
datasets/attack_techniques/T1021.006/lateral_movement_psh/windows-powershell-xml.log
datasets/attack_techniques/T1021.006/lateral_movement_pssession/windows-powershell-xml.log
datasets/attack_techniques/T1027.010/manual_b64_decode_pwsh/manual_b64_decode_pwsh.log
datasets/attack_techniques/T1033/AD_discovery/windows-powershell-xml.log
datasets/attack_techniques/T1059.001/asyncrat_crypto_pwh_namespace/windows-powershell-xml.log
datasets/attack_techniques/T1059.001/malicious_cmd_line_samples/windows-sysmon.log
datasets/attack_techniques/T1059.001/trickbot_cmd_powershell/windows-sysmon.log
datasets/attack_techniques/T1069.001/atomic_red_team/windows-powershell-xml.log
datasets/attack_techniques/T1087.001/AD_discovery/windows-powershell-xml.log
datasets/attack_techniques/T1112/vip_big_env_variable/vip_INTERNAL_DB_CACHE.log
datasets/attack_techniques/T1140/snapattack/snapattack.log
datasets/attack_techniques/T1201/pwd_policy_discovery/windows-powershell-xml.log
datasets/attack_techniques/T1546.003/wmi_event_subscription/windows-sysmon.log
datasets/attack_techniques/T1546.015/pwh_com_object/windows-powershell-xml.log
datasets/attack_techniques/T1608/snapattack/snapattack.log
datasets/attack_techniques/t1592/pwh_av_recon/windows-powershell-xml.log""".split()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def load_modules():
    """Kiem sha256 truoc khi import; lech thi dung (exit 2)."""
    global cg, ea
    for n, want in EXPECT_SHA.items():
        got = sha256_file(os.path.join(HERE, n))
        if got != want:
            print(f"SHA256 {n} LECH ({got}) - DUNG")
            sys.exit(2)
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import count_gate
    import export_alerts
    cg, ea = count_gate, export_alerts


# ------------------------------------------------------------------ A3 helpers
class Ends:
    """Thoi diem ket thuc tien trinh cua mot run: Sysmon 5 (theo ProcessGuid), Security 4689 (theo host, pid)."""

    def __init__(self, events):
        self.g = {}
        self.p = collections.defaultdict(list)
        for f in events:
            ch, eid = cg.event_key(f)
            if ch == cg.SYSMON and eid == "5":
                g = cg.first(f.get("ProcessGuid")).strip().lower()
                t = cg.event_time(f)
                if g and t is not None and ("g:" + g) not in self.g:
                    self.g["g:" + g] = t
            elif ch == "security" and eid == "4689":
                pid, t = cg.to_pid(f.get("ProcessId")), cg.event_time(f)
                if pid is not None and t is not None:
                    self.p[(cg.norm_host(f), pid)].append(t)
        for v in self.p.values():
            v.sort()
        self.any = bool(self.g or self.p)

    def end_of(self, table, key):
        if key in self.g:
            return self.g[key]
        rec = table.procs[key]
        for e in self.p.get((rec["host"], rec["pid"]), ()):
            if rec["start"] is None or e >= rec["start"]:
                return e
        return None


def ps_pid_check(table, ends, f):
    """-> (key, state) cho event PowerShell. state: None neu khong noi duoc; 'no_time'; 'ended'; 'alive'."""
    if cg.event_key(f) not in PS_KEYS:
        return None, None
    k = table.link(f)
    if k is None:
        return None, None
    t = cg.event_time(f)
    if t is None:
        return k, "no_time"
    e = ends.end_of(table, k)
    return k, ("ended" if e is not None and e < t else "alive")


# ------------------------------------------------------------------ doc du lieu mot lan
def scan(a):
    pl = cg.Pipeline(cg.Stix(a.stix))
    reviews = cg.load_reviews(a.review_dir)
    with open(a.sample, encoding="utf-8-sig") as fh:
        sampled = set(json.load(fh)["sampled_codes"])
    kept = {}
    a3 = {s: collections.Counter() for s in cg.SOURCE_ORDER}
    tmp = tempfile.mkdtemp(prefix="survey_fix_diag_")
    try:
        for src, run_id, raw, events in cg.iter_runs(a, pl.st, tmp):
            labels, reason = pl.register_run(src, raw)
            code = cg.run_code(a.seed, run_id)
            table = cg.ProcessTable()
            for f in events:
                table.add_event(f)
            table.finalize()
            if code not in sampled:
                status_all = "not_sampled"
            elif not table.procs:
                status_all = "no_tree"
            elif code not in reviews:
                status_all = "unreviewed"
            else:
                status_all = None
            keep = table.subtree(reviews.get(code, ())) if status_all is None else set()
            ends = Ends(events) if status_all is None else None
            c3, run_ps = a3[src], 0
            if ends is not None:
                c3["runs_reviewed"] += 1
                if not ends.any:
                    c3["runs_without_end_events"] += 1
            for f in events:
                bad = None
                if status_all is not None:
                    tree_ok = status_all
                else:
                    k = table.link(f)
                    tree_ok = "ambiguous" if k is None else (k in keep)
                    pk, state = ps_pid_check(table, ends, f)
                    if state is not None:
                        run_ps += 1
                        c3["ps_linked_by_pid"] += 1
                        if state == "no_time":
                            c3["ps_no_time_unchecked"] += 1
                        elif state == "ended":
                            c3["ps_linked_to_ended_proc"] += 1
                            if pk in keep:
                                c3["ps_ended_in_kept_tree"] += 1
                                bad = True
                            else:
                                c3["ps_ended_not_in_kept_tree"] += 1
                before = pl.st[src]["pass_4_7"]
                channel, eid = cg.event_key(f)
                names_before = set(f)
                pl.process(src, run_id, labels, reason, f, tree_ok)
                if pl.st[src]["pass_4_7"] > before:
                    dg = next(reversed(pl.dedup))
                    kept[dg] = {"fields": dict(f), "channel": channel, "event_id": eid,
                                "stripped": sorted(names_before & set(cg.STRIP))}
                    if bad:
                        c3["alerts_affected"] += 1
            if ends is not None and not ends.any and run_ps:
                c3["runs_without_end_events_but_ps_linked"] += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return pl, kept, a3


# ------------------------------------------------------------------ A0
def rebuild(pl, kept, seed, split_seed, dev_fraction):
    """Dung lai danh sach alert, scenario, split va bytes dung nhu export_alerts.main (khong ghi dia)."""
    comp_c, comp_b = {}, {}
    for s in cg.SOURCE_ORDER:
        comp_c.update(ea.components(pl.run_pairs[s]))
        comp_b.update(ea.components(pl.run_hosts[s]))

    def sid(rep):
        return hashlib.sha256(f"{seed}:{rep}".encode("utf-8")).hexdigest()[:12]

    alerts = []
    for dg, (run_id, labels, src) in pl.dedup.items():
        k = kept[dg]
        alerts.append({"alert_id": dg.hex(), "source": src, "channel": k["channel"], "event_id": k["event_id"],
                       "fields": k["fields"], "labels": sorted(labels), "run_code": cg.run_code(seed, run_id),
                       "scenario_c": sid(comp_c[run_id]), "scenario_b": sid(comp_b[run_id])})
    scen = sorted({x["scenario_c"] for x in alerts},
                  key=lambda s: hashlib.sha256(f"{split_seed}:{s}".encode("utf-8")).hexdigest())
    n_test = round(len(scen) * (1 - dev_fraction))
    test_scen = set(scen[:n_test])
    parts = {"dev": [], "test": []}
    for x in alerts:
        x["side"] = "test" if x["scenario_c"] in test_scen else "dev"
        parts[x["side"]].append(x)
    payload = {}
    for side, rows in parts.items():
        rows.sort(key=lambda x: x["alert_id"])
        payload[side] = {
            "alerts.jsonl": ea.jsonl({k: x[k] for k in ("alert_id", "source", "channel", "event_id", "fields")}
                                     for x in rows),
            "labels.jsonl": ea.jsonl({"alert_id": x["alert_id"], "labels": x["labels"]} for x in rows),
            "scenarios.jsonl": ea.jsonl({k: x[k] for k in ("alert_id", "run_code", "scenario_c", "scenario_b")}
                                        for x in rows),
        }
    return alerts, parts, payload, (len(scen) - n_test, n_test)


def a0_check(alerts, parts, payload, scen_counts, manifest):
    files, ok_all = {}, True
    for side in ("dev", "test"):
        for name, data in payload[side].items():
            key = f"{side}/{name}"
            want = manifest["files"].get(key, {})
            sha, lines = sha256_bytes(data), data.count(b"\n")
            match = want.get("sha256") == sha and want.get("lines") == lines
            ok_all &= match
            files[key] = {"match": match, "sha256": sha, "lines": lines}
    totals_ok = (len(alerts) == manifest["alerts_total"]
                 and {s: len(r) for s, r in parts.items()} == manifest["alerts"]
                 and {"dev": scen_counts[0], "test": scen_counts[1]} == manifest["scenarios_c"])
    return {"alerts_total": len(alerts), "dev": len(parts["dev"]), "test": len(parts["test"]),
            "scenarios_c": {"dev": scen_counts[0], "test": scen_counts[1]},
            "files": files, "files_matched": sum(v["match"] for v in files.values()),
            "totals_match_manifest": totals_ok, "ok": bool(ok_all and totals_ok)}


# ------------------------------------------------------------------ A1
def a1_fields(alerts, kept_stripped):
    cnt = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    n = collections.defaultdict(collections.Counter)
    for x in alerts:
        side = "otrf" if x["source"] == "otrf" else "xml"
        key = (x["channel"], x["event_id"])
        n[key][side] += 1
        for name in x["fields"]:
            cnt[key][side][name] += 1
    out, otrf_only_names = {}, set()
    for key in sorted(n):
        o, xm = cnt[key]["otrf"], cnt[key]["xml"]
        both = bool(n[key]["otrf"] and n[key]["xml"])
        rec = {"otrf_alerts": n[key]["otrf"], "xml_alerts": n[key]["xml"], "both_sides": both}
        if both:
            oo = {k: v for k, v in sorted(o.items()) if k not in xm}
            xo = {k: v for k, v in sorted(xm.items()) if k not in o}
            rec["otrf_only_fields"] = {k: v for k, v in oo.items() if k not in cg.DROP_DEDUP and k not in cg.STRIP}
            rec["xml_only_fields"] = {k: v for k, v in xo.items() if k not in cg.DROP_DEDUP and k not in cg.STRIP}
            rec["otrf_only_already_excluded"] = {k: v for k, v in oo.items() if k in cg.DROP_DEDUP or k in cg.STRIP}
            rec["xml_only_already_excluded"] = {k: v for k, v in xo.items() if k in cg.DROP_DEDUP or k in cg.STRIP}
            otrf_only_names |= set(oo)
        out[f"{key[0]}|{key[1]}"] = rec
    stripped = collections.defaultdict(collections.Counter)
    for x, st in zip(alerts, kept_stripped):
        for k in st:
            stripped[x["source"]][k] += 1
    return {"by_channel_event": out, "otrf_only_names_union": sorted(otrf_only_names),
            "strip_fields_seen_before_strip_by_source": {s: dict(sorted(c.items())) for s, c in sorted(stripped.items())},
            "strip_list": sorted(cg.STRIP), "drop_dedup_list": sorted(cg.DROP_DEDUP)}


# ------------------------------------------------------------------ A2
def a2_overlap(alerts, otrf_only_names):
    E = set(XML_SYSTEM) | set(otrf_only_names) | set(cg.STRIP) | set(cg.DROP_DEDUP)
    groups = collections.defaultdict(list)
    for x in alerts:
        f = {k: v for k, v in x["fields"].items() if k not in E}
        groups[cg.dedup_digest(f, x["channel"], x["event_id"], cg.norm_host(x["fields"]))].append(x)
    multi = [g for g in groups.values() if len(g) >= 2]
    by_ev, by_pair = collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
    res = collections.Counter()
    for g in multi:
        srcs = sorted({x["source"] for x in g})
        res["groups"] += 1
        res["alerts_in_groups"] += len(g)
        res["alerts_removed_if_merged"] += len(g) - 1
        res["cross_source_groups"] += len(srcs) > 1
        res["cross_scenario_groups"] += len({x["scenario_c"] for x in g}) > 1
        res["cross_split_groups"] += len({x["side"] for x in g}) > 1
        res["label_conflict_groups"] += len({tuple(x["labels"]) for x in g}) > 1
        k = f"{g[0]['channel']}|{g[0]['event_id']}"
        by_ev[k]["groups"] += 1
        by_ev[k]["alerts"] += len(g)
        by_pair["+".join(srcs)]["groups"] += 1
        by_pair["+".join(srcs)]["alerts"] += len(g)
    return {"envelope_fields_removed": sorted(E), "alerts": len(alerts), "distinct_replacement_keys": len(groups),
            **{k: res[k] for k in ("groups", "alerts_in_groups", "alerts_removed_if_merged", "cross_source_groups",
                                   "cross_scenario_groups", "cross_split_groups", "label_conflict_groups")},
            "by_channel_event": {k: dict(v) for k, v in sorted(by_ev.items())},
            "by_source_pair": {k: dict(v) for k, v in sorted(by_pair.items())}}


# ------------------------------------------------------------------ A4
def a4_balance(alerts, thresh=0.25):
    cnt = collections.defaultdict(collections.Counter)  # (side, source, group)
    for x in alerts:
        g = EID2GROUP.get(x["event_id"], "other")
        cnt[(x["source"], g)][x["side"]] += 1
    table = {f"{s}|{g}": dict(c) for (s, g), c in sorted(cnt.items())}
    tot = collections.defaultdict(collections.Counter)
    for (s, g), c in cnt.items():
        tot[g].update(c)

    def ratio(c):
        n = c["dev"] + c["test"]
        return {"dev": c["dev"], "test": c["test"], "dev_ratio": round(c["dev"] / n, 4),
                "test_ratio": round(c["test"] / n, 4), "flagged": min(c["dev"], c["test"]) / n < thresh}
    groups = {g: ratio(c) for g, c in sorted(tot.items())}
    by_src = {f"{s}|{g}": ratio(c) for (s, g), c in sorted(cnt.items())}
    return {"threshold": thresh, "counts_by_source_group": table, "by_group": groups,
            "flagged_groups": [g for g, r in groups.items() if r["flagged"]],
            "by_source_group": by_src,
            "flagged_source_groups": [g for g, r in by_src.items() if r["flagged"]]}


# ------------------------------------------------------------------ A5
def ci_exists(root, rel):
    cur = root
    for part in [p for p in rel.replace("\\", "/").split("/") if p]:
        try:
            names = os.listdir(cur)
        except OSError:
            return None
        hit = next((n for n in names if n == part), None) or next((n for n in names if n.lower() == part.lower()), None)
        if hit is None:
            return None
        cur = os.path.join(cur, hit)
    return cur if os.path.isfile(cur) else None


def a5_splunk(a, st_missing):
    out = {"stash_sha256": {}, "missing": []}
    for rel in SPLUNK_STASH:
        p = os.path.join(a.splunk, *rel.split("/"))
        out["stash_sha256"][rel] = sha256_file(p) if os.path.isfile(p) else "<absent>"
    base = os.path.join(a.splunk, "datasets", "attack_techniques")
    yamls = []
    for r, dirs, fs in os.walk(base):
        dirs.sort()
        yamls += [os.path.join(r, n) for n in sorted(fs) if n.endswith((".yml", ".yaml"))]
    miss, index = [], None
    for y in sorted(yamls):
        try:
            with open(y, encoding="utf-8") as fh:
                doc = cg.yaml.load(fh, Loader=cg.yaml.BaseLoader)
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        for d in doc.get("datasets") or []:
            if not (isinstance(d, dict) and d.get("sourcetype") == "XmlWinEventLog"):
                continue
            ps = (d.get("path") or "")
            p = ps.lstrip("/")
            if p and os.path.isfile(os.path.join(a.splunk, *p.split("/"))):
                continue
            miss.append((os.path.relpath(y, a.splunk).replace("\\", "/"), ps))
    cats = collections.Counter()
    if miss:
        index = collections.defaultdict(list)
        for r, dirs, fs in os.walk(os.path.join(a.splunk, "datasets")):
            for n in fs:
                index[n.lower()].append(os.path.relpath(os.path.join(r, n), a.splunk).replace("\\", "/"))
    for yrel, ps in miss:
        p = ps.lstrip("/").replace("\\", "/")
        if not p:
            cat, extra = "other_empty_path", None
        else:
            norm = p
            if "://" in norm:
                tail = norm.split("datasets/", 1)
                norm = ("datasets/" + tail[1]) if len(tail) == 2 else norm.split("://", 1)[1]
            for pref in ("attack_data/", "master/", "blob/master/"):
                while norm.startswith(pref):
                    norm = norm[len(pref):]
            if norm != p and os.path.isfile(os.path.join(a.splunk, *norm.split("/"))):
                cat, extra = "exists_after_normalizing_prefix_or_url", norm
            elif ci_exists(a.splunk, p) or (norm != p and ci_exists(a.splunk, norm)):
                cat, extra = "exists_ignoring_case", None
            elif index.get(p.rsplit("/", 1)[-1].lower()):
                cands = index[p.rsplit("/", 1)[-1].lower()]
                cat, extra = "same_filename_in_other_dir", {"candidates": len(cands), "first": cands[0]}
            else:
                cat, extra = "not_exist", None
        cats[cat] += 1
        rec = {"yaml": yrel, "yaml_dataset_path": ps, "category": cat}
        if extra is not None:
            rec["detail"] = extra
        out["missing"].append(rec)
    out["missing_count_replayed"] = len(miss)
    out["missing_count_from_iter_runs"] = st_missing
    out["missing_categories"] = dict(sorted(cats.items()))
    return out


# ------------------------------------------------------------------ main
def main():
    t0 = time.time()
    sys.stdout.reconfigure(encoding="utf-8")
    load_modules()
    ap = argparse.ArgumentParser()
    cg.add_common_args(ap)
    ap.add_argument("--review-dir", required=True)
    ap.add_argument("--sample", required=True)
    ap.add_argument("--dev-fraction", type=float, required=True)
    ap.add_argument("--split-seed", type=int, required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    with open(a.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    cg.check_stix(a.stix)
    pl, kept, a3 = scan(a)
    res = {"meta": {"python": sys.version.split()[0],
                    "sha256": {"survey_fix_diag.py": sha256_file(os.path.abspath(__file__)),
                               "count_gate.py": sha256_file(os.path.join(HERE, "count_gate.py")),
                               "export_alerts.py": sha256_file(os.path.join(HERE, "export_alerts.py"))},
                    "params": {"seed": a.seed, "split_seed": a.split_seed, "dev_fraction": a.dev_fraction},
                    "platform": platform.platform()}}
    alerts, parts, payload, sc = rebuild(pl, kept, a.seed, a.split_seed, a.dev_fraction)
    res["A0"] = a0_check(alerts, parts, payload, sc, manifest)
    for s, fn in res["A0"]["files"].items():
        print(f"A0 {s}: {'KHOP' if fn['match'] else 'LECH'}")
    print(f"A0 tong {res['A0']['alerts_total']} dev {res['A0']['dev']} test {res['A0']['test']} ok={res['A0']['ok']}")

    def dump():
        res["meta"]["elapsed_seconds"] = round(time.time() - t0, 1)
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2, ensure_ascii=False, sort_keys=True)

    if not res["A0"]["ok"]:
        print("A0 LECH - DUNG, khong tinh A1-A5")
        dump()
        sys.exit(2)
    dg_order = list(pl.dedup)
    by_id = {x["alert_id"]: x for x in alerts}
    stripped = [kept[dg]["stripped"] for dg in dg_order]
    ordered = [by_id[dg.hex()] for dg in dg_order]
    res["A1"] = a1_fields(ordered, stripped)
    res["A2"] = a2_overlap(ordered, res["A1"]["otrf_only_names_union"])
    res["A3"] = {s: dict(sorted(c.items())) for s, c in a3.items()}
    res["A4"] = a4_balance(ordered)
    res["A5"] = a5_splunk(a, pl.st["splunk"]["missing"])
    dump()
    a2 = res["A2"]
    print("A2", {k: a2[k] for k in ("groups", "alerts_in_groups", "cross_source_groups", "cross_scenario_groups",
                                    "cross_split_groups", "label_conflict_groups")})
    print("A3", json.dumps(res["A3"], sort_keys=True))
    print("A4 flagged", res["A4"]["flagged_groups"], res["A4"]["flagged_source_groups"])
    print("A5 missing", res["A5"]["missing_categories"])


if __name__ == "__main__":
    main()
