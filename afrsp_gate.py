#!/usr/bin/env python3
"""
AFR-SP CI/CD gate (Phase 4) -- two checks, one exit code.

  1. Privacy Linter: static check (Python ast) that no logging/print call receives a field the
     Phase-2 schema marks as 'drop' (PII), a literal e-mail/IPv4, or a whole payload object.
  2. Forensic Admissibility Test: logs a short trace with the AFR-SP logger (afrsp_poc.py),
     checks that the clean chain verifies and that an altered and a deleted record are reported.

Usage:
  python3 afrsp_gate.py --target path/to/file_or_dir   # run the gate on code, exit 1 if it fails
  python3 afrsp_gate.py --demo                          # three simulated sprints
  python3 afrsp_gate.py --eval                          # linter evaluation on labelled snippets
  python3 afrsp_gate.py --all                           # demo + eval, writes gate_results.json
"""
import argparse, ast, json, os, pathlib, random, re, sys, time
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

LOG_METHODS = {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}
LOG_OBJECTS = {"logger", "log", "logging", "LOG"}
WHOLE_OBJECTS = {"raw", "payload", "reading", "request", "body", "data", "record"}
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def load_pii(schema_path=HERE / "schema.json"):
    sch = json.load(open(schema_path))["fields"]
    names = set()
    for f, d in sch.items():
        if d["decision"] == "drop":
            names.add(f.lower()); names.update(a.lower() for a in d.get("aliases", []))
    return names

def is_log_call(n):
    if not isinstance(n, ast.Call): return False
    f = n.func
    if isinstance(f, ast.Name) and f.id == "print": return True
    return (isinstance(f, ast.Attribute) and f.attr in LOG_METHODS
            and isinstance(f.value, ast.Name) and f.value.id in LOG_OBJECTS)

def scan_expr(n, pii, out, line):
    """Walk one argument expression. Calls to state_hash(...) are the sanctioned way to log state."""
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "state_hash":
        return
    if isinstance(n, ast.Name):
        if n.id.lower() in pii: out.append((line, "R1", f"personal field '{n.id}' passed to log call"))
        elif n.id in WHOLE_OBJECTS: out.append((line, "R3", f"whole object '{n.id}' passed to log call"))
    elif isinstance(n, ast.Attribute):
        if n.attr.lower() in pii: out.append((line, "R1", f"personal field '.{n.attr}' passed to log call"))
        if isinstance(n.value, ast.Name): return          # reading.temp_c: a single field, not the whole object
    elif isinstance(n, ast.Subscript):
        k = n.slice
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            if k.value.lower() in pii:
                out.append((line, "R1", f"personal field ['{k.value}'] passed to log call"))
            if isinstance(n.value, ast.Name): return      # reading["temp_c"]: a single field, not the whole object
    elif isinstance(n, ast.Dict):
        for k in n.keys:
            if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value.lower() in pii:
                out.append((line, "R1", f"personal field key '{k.value}' in log call"))
    elif isinstance(n, ast.Constant) and isinstance(n.value, str):
        if EMAIL.search(n.value): out.append((line, "R2", "literal e-mail address in log call"))
        if IPV4.search(n.value): out.append((line, "R2", "literal IPv4 address in log call"))
    for c in ast.iter_child_nodes(n):
        scan_expr(c, pii, out, line)

def lint_source(src, pii):
    out = []
    for n in ast.walk(ast.parse(src)):
        if is_log_call(n):
            for a in list(n.args) + [k.value for k in n.keywords]:
                scan_expr(a, pii, out, n.lineno)
            for k in n.keywords:
                if k.arg and k.arg.lower() in pii:
                    out.append((n.lineno, "R1", f"personal field keyword '{k.arg}' in log call"))
    return sorted(set(out))

def lint_path(target, pii):
    p = pathlib.Path(target); files = [p] if p.is_file() else sorted(p.rglob("*.py"))
    res = []
    for f in files:
        for ln, rule, msg in lint_source(f.read_text(), pii):
            res.append((str(f.name), ln, rule, msg))
    return res

def admissibility(n=600, seed=11):
    import afrsp_poc as P
    rng = random.Random(seed); t0 = 1_767_225_600
    enc = P.Enclave(seed); node = P.Node(enc); recs, cps = [], []
    for i in range(n):
        node.log(P.raw_event(i, rng, t0), (t0 + i) * 1_000_000)
        if (i + 1) % P.CHECKPOINT_EVERY == 0:
            b, cp = node.flush((t0 + i) * 1_000_000); recs += b; cps.append(cp)
    k, pk = enc.escrow_key(), enc.pk
    clean = not P.verify(recs, cps, k, pk)
    r = list(recs); b = bytearray(r[100]); b[30] ^= 1; r[100] = bytes(b)
    altered = bool(P.verify(r, cps, k, pk))
    deleted = bool(P.verify(recs[:200] + recs[201:], cps, k, pk))
    return dict(events=n, clean_chain_verifies=clean, altered_detected=altered, deleted_detected=deleted,
                passed=clean and altered and deleted)

def run_gate(target, pii):
    t = time.perf_counter()
    viol = lint_path(target, pii); lint_s = time.perf_counter() - t
    t = time.perf_counter(); adm = admissibility(); adm_s = time.perf_counter() - t
    return dict(target=os.path.relpath(str(target), str(HERE)), violations=viol, lint_passed=not viol, admissibility=adm,
                passed=(not viol) and adm["passed"], lint_ms=round(lint_s * 1000, 2),
                admissibility_ms=round(adm_s * 1000, 1))

# ---------------------------------------------------------------- labelled snippets for linter evaluation
VIOLATING_DIRECT = [
    ('f-string with e-mail variable',      'logger.info(f"login ok for {user_email}")'),
    ('dict lookup of patient id',          'logger.info("login %s", reading["patient_id"])'),
    ('.format() with IP address',          'logger.warning("conn from {}".format(src_ip))'),
    ('% formatting with alias username',   'log.error("fail for %s" % username)'),
    ('MAC address in extra dict',          'logger.info("evt", extra={"mac": dev_mac})'),
    ('literal e-mail address',             'logger.debug("contact admin@example.org")'),
    ('whole payload object',               'logger.info(payload)'),
    ('GPS attribute',                      'logger.info(f"pos {user.gps}")'),
    ('literal IPv4 address',               'logger.info("from 10.2.3.4")'),
    ('print of personal field',            'print(user_email)'),
]
CLEAN = [
    ('event id + state hash',              'logger.info(f"event {event_id} state {state_hash(reading)}")'),
    ('allowed numeric field',              'logger.info("temp %s", reading["temp_c"])'),
    ('"name" inside an unrelated word',    'logger.info("rename %s", filename)'),
    ('battery level',                      'logger.info("battery %d", batt_pct)'),
    ('sequence number and timestamp',      'logger.info(f"seq {seq} ts {ts}")'),
    ('result flag in extra dict',          'logger.warning("auth failed", extra={"result": "fail"})'),
    ('firmware version',                   'logger.info("version %s", fw)'),
    ('PII used outside logging',           'x = user_email.lower()'),
]
VIOLATING_INDIRECT = [
    ('PII hidden behind a helper',         'logger.info(describe(user))'),
    ('PII built in a variable first',      'msg = f"hi {user_email}"\nlogger.info(msg)'),
]

def evaluate(pii):
    def hit(src): return bool(lint_source(src, pii))
    d = [(n, hit(s)) for n, s in VIOLATING_DIRECT]
    c = [(n, hit(s)) for n, s in CLEAN]
    i = [(n, hit(s)) for n, s in VIOLATING_INDIRECT]
    return dict(direct_total=len(d), direct_detected=sum(x for _, x in d),
                clean_total=len(c), false_positives=sum(x for _, x in c),
                indirect_total=len(i), indirect_detected=sum(x for _, x in i),
                missed=[n for n, x in d + i if not x], false_positive_cases=[n for n, x in c if x])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target"); ap.add_argument("--demo", action="store_true")
    ap.add_argument("--eval", action="store_true"); ap.add_argument("--all", action="store_true")
    a = ap.parse_args(); pii = load_pii(); results = {}
    if a.target:
        r = run_gate(a.target, pii); results["gate"] = r
        for f, ln, rule, msg in r["violations"]: print(f"  {f}:{ln} [{rule}] {msg}")
        print(f"GATE {'PASSED' if r['passed'] else 'FAILED'}  (lint {r['lint_ms']} ms, admissibility {r['admissibility_ms']} ms)")
        sys.exit(0 if r["passed"] else 1)
    if a.demo or a.all:
        results["sprints"] = []
        for i, f in enumerate(sorted((HERE / "demo").glob("sprint*.py")), 1):
            r = run_gate(f, pii); results["sprints"].append(r)
            print(f"Sprint {i} ({f.name}): GATE {'PASSED' if r['passed'] else 'FAILED'}   "
                  f"[lint {r['lint_ms']} ms, admissibility {r['admissibility_ms']} ms]")
            for _, ln, rule, msg in r["violations"]: print(f"     line {ln} [{rule}] {msg}")
    if a.eval or a.all:
        results["linter_eval"] = e = evaluate(pii)
        print(f"\nLinter evaluation on {e['direct_total'] + e['clean_total'] + e['indirect_total']} labelled snippets")
        print(f"  direct violations detected : {e['direct_detected']}/{e['direct_total']}")
        print(f"  clean snippets flagged     : {e['false_positives']}/{e['clean_total']}  {e['false_positive_cases']}")
        print(f"  indirect violations found  : {e['indirect_detected']}/{e['indirect_total']}  (missed: {e['missed']})")
    if a.all:
        json.dump(results, open("gate_results.json", "w"), indent=2, default=str); print("\nwrote gate_results.json")
    if not (a.target or a.demo or a.eval or a.all): ap.print_help()

if __name__ == "__main__":
    main()
