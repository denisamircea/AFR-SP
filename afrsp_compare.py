#!/usr/bin/env python3
"""
AFR-SP versus classic secure logging -- measured comparison on the same 24-hour synthetic trace.

Four logging schemes process exactly the same 86,400 events (afrsp_poc.raw_event, same seed):
  RAW     verbose JSON, no integrity protection
  SK      Schneier-Kelsey-style secure log (simplified): verbose JSON + forward-secure HMAC chain
          Y_j = HMAC(K_j, Y_{j-1} || seq || payload),  K_{j+1} = SHA-256(K_j)  (old key erased)
  MASK    standard anonymisation: PII fields replaced by '***', then HMAC chain with one fixed key
  AFR-SP  selective cryptographic logging (afrsp_poc.py): 90-byte records + signed Merkle checkpoints

SK is a simplified re-implementation of the key-evolution and chaining idea of Schneier & Kelsey (1999);
it has no per-entry encryption and no trusted-server protocol. The verifier of SK and MASK holds only
the initial key, as in the original model, and no later commitments.

Run:  python3 afrsp_compare.py [--events 86400] [--seed 7]      -> prints a summary, writes compare_results.json
"""
import argparse, hashlib, hmac, json, os, platform, random, statistics, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import afrsp_poc as P

T0 = 1_767_225_600
PII_FIELDS = P.PII_FIELDS
MASK = "***"

def pii_values(ev):
    out = []
    for f in PII_FIELDS:
        v = ev[f]
        out += [str(x) for x in v] if isinstance(v, list) else [str(v)]
    return out

def masked(ev):
    return {k: (MASK if k in PII_FIELDS else v) for k, v in ev.items()}

def evolve(k): return hashlib.sha256(k).digest()

# ------------------------------------------------------------------ chain verifier for SK and MASK
def verify_chain(records, key0, evolving, n_max):
    findings, y_prev, expected = [], b"\x00" * 32, 0
    keys = [key0]
    if evolving:
        for _ in range(n_max + 1): keys.append(evolve(keys[-1]))
    order = [r[0] for r in records]
    if order != sorted(order): findings.append("records out of order")
    seen = set()
    for seq, payload, mac in records:
        if seq in seen: findings.append(f"duplicate seq {seq}")
        seen.add(seq)
        if seq != expected: findings.append(f"seq {seq}: expected {expected} (gap or reorder)")
        k = keys[seq] if evolving else key0
        calc = hmac.new(k, y_prev + struct.pack(">I", seq) + payload, hashlib.sha256).digest()
        if calc != mac: findings.append(f"seq {seq}: MAC mismatch")
        y_prev, expected = mac, seq + 1
    return findings

# ------------------------------------------------------------------ one pass per scheme
def timed_pass(name, n, seed, op, size_of, pii_check):
    rng = random.Random(seed)
    lat, size, pii_hits, store = [], 0, 0, []
    for i in range(n):
        ev = P.raw_event(i, rng, T0)
        vals = pii_values(ev)
        a = time.perf_counter_ns()
        rec = op(i, ev)
        lat.append(time.perf_counter_ns() - a)
        size += size_of(rec)
        pii_hits += pii_check(rec, vals)
        store.append(rec)
    return dict(name=name, lat=lat, size=size, pii=pii_hits, store=store)

def summarize(r, n, raw_size, n_pii_per_event_total):
    lat = sorted(r["lat"]); q = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))] / 1000
    return dict(bytes_per_record=round(r["size"] / n, 1), mb_per_day=round(r["size"] / 1e6, 2),
                reduction_vs_raw_pct=round(100 * (1 - r["size"] / raw_size), 2),
                pii_values_stored=r["pii"], pii_values_total=n_pii_per_event_total,
                latency_us_median=round(q(.5), 2), latency_us_p99=round(q(.99), 2),
                latency_us_mean=round(statistics.mean(lat) / 1000, 2))

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--events", type=int, default=86_400)
    ap.add_argument("--seed", type=int, default=7); a = ap.parse_args(); n, seed = a.events, a.seed
    if n < 2000: sys.exit('--events must be at least 2000 (the tamper scenarios address records by position)')
    rng0 = random.Random(seed); n_pii_total = 0
    for i in range(n): n_pii_total += len(pii_values(P.raw_event(i, rng0, T0)))
    contains = lambda blob, vals: sum(1 for v in vals if v.encode() in blob)

    # RAW
    raw = timed_pass("RAW", n, seed, lambda i, ev: P.serialize_raw(ev), len, lambda rec, vals: contains(rec, vals))
    raw_size = raw["size"]

    # SK
    k_sk0 = bytes(random.Random(1).getrandbits(8) for _ in range(32))
    st = {"k": k_sk0, "y": b"\x00" * 32}
    def sk_op(i, ev):
        payload = P.serialize_raw(ev)
        mac = hmac.new(st["k"], st["y"] + struct.pack(">I", i) + payload, hashlib.sha256).digest()
        st["y"] = mac; st["k"] = evolve(st["k"])
        return (i, payload, mac)
    sk = timed_pass("SK", n, seed, sk_op, lambda r: 4 + len(r[1]) + 32, lambda r, vals: contains(r[1], vals))

    # MASK
    k_m = bytes(random.Random(2).getrandbits(8) for _ in range(32))
    stm = {"y": b"\x00" * 32}
    def mask_op(i, ev):
        payload = P.serialize_raw(masked(ev))
        mac = hmac.new(k_m, stm["y"] + struct.pack(">I", i) + payload, hashlib.sha256).digest()
        stm["y"] = mac
        return (i, payload, mac)
    mk = timed_pass("MASK", n, seed, mask_op, lambda r: 4 + len(r[1]) + 32, lambda r, vals: contains(r[1], vals))

    # AFR-SP (records + checkpoints, flush every CHECKPOINT_EVERY events)
    enc = P.Enclave(seed); node = P.Node(enc); R, C, flush_ns = [], [], []
    rng = random.Random(seed); lat, size, pii = [], 0, 0
    for i in range(n):
        ev = P.raw_event(i, rng, T0); vals = pii_values(ev); ts = (T0 + i) * 1_000_000
        s = time.perf_counter_ns(); rec = node.log(ev, ts); lat.append(time.perf_counter_ns() - s)
        size += len(rec); pii += contains(rec, vals)
        if (i + 1) % P.CHECKPOINT_EVERY == 0:
            s = time.perf_counter_ns(); b, cp = node.flush(ts); flush_ns.append(time.perf_counter_ns() - s)
            R += b; C.append(cp)
    if node.ring:
        b, cp = node.flush((T0 + n) * 1_000_000); R += b; C.append(cp)
    afr = dict(name="AFR-SP", lat=lat, size=size, pii=pii)
    cp_size = sum(map(len, C))

    res = {"platform": dict(machine=platform.machine(), system=platform.platform(), python=platform.python_version()),
           "events": n, "seed": seed}
    res["RAW"] = summarize(raw, n, raw_size, n_pii_total)
    res["SK"] = summarize(sk, n, raw_size, n_pii_total)
    res["MASK"] = summarize(mk, n, raw_size, n_pii_total)
    res["AFR-SP"] = summarize(afr, n, raw_size, n_pii_total)
    res["AFR-SP"]["checkpoint_bytes_total"] = cp_size
    res["AFR-SP"]["mb_per_day_incl_checkpoints"] = round((size + cp_size) / 1e6, 2)
    res["AFR-SP"]["reduction_incl_checkpoints_pct"] = round(100 * (1 - (size + cp_size) / raw_size), 2)
    res["AFR-SP"]["latency_us_mean_incl_checkpoint"] = round((sum(lat) + sum(flush_ns)) / n / 1000, 2)

    # verification time of the full day
    t = time.perf_counter(); f_sk = verify_chain(sk["store"], k_sk0, True, n); res["SK"]["verify_full_day_s"] = round(time.perf_counter() - t, 3)
    t = time.perf_counter(); f_mk = verify_chain(mk["store"], k_m, False, n); res["MASK"]["verify_full_day_s"] = round(time.perf_counter() - t, 3)
    t = time.perf_counter(); f_afr = P.verify(R, C, enc.escrow_key(), enc.pk); res["AFR-SP"]["verify_full_day_s"] = round(time.perf_counter() - t, 3)
    res["clean_verification_findings"] = dict(SK=len(f_sk), MASK=len(f_mk), AFR_SP=len(f_afr))

    # ---------------------------------------------------------------- tamper scenarios
    i = 1234
    def sk_v(recs): return bool(verify_chain(recs, k_sk0, True, n))
    def mk_v(recs): return bool(verify_chain(recs, k_m, False, n))
    def af_v(recs, cps=C): return bool(P.verify(recs, cps, enc.escrow_key(), enc.pk))
    def flip_chain(recs, j):
        r = list(recs); s, p, m = r[j]; p = bytearray(p); p[10] ^= 1; r[j] = (s, bytes(p), m); return r
    def flip_afr(recs, j):
        r = list(recs); b = bytearray(r[j]); b[30] ^= 1; r[j] = bytes(b); return r
    scen = []
    def add(name, sk_r, mk_r, af_r): scen.append(dict(scenario=name, SK=sk_r, MASK=mk_r, AFR_SP=af_r))
    SKs, MKs = sk["store"], mk["store"]
    add("Alter one past record", sk_v(flip_chain(SKs, i)), mk_v(flip_chain(MKs, i)), af_v(flip_afr(R, i)))
    add("Delete one record", sk_v(SKs[:i] + SKs[i+1:]), mk_v(MKs[:i] + MKs[i+1:]), af_v(R[:i] + R[i+1:]))
    sw = lambda L: L[:i] + [L[i+1], L[i]] + L[i+2:]
    add("Swap two adjacent records", sk_v(sw(SKs)), mk_v(sw(MKs)), af_v(sw(R)))
    add("Duplicate (replay) a record", sk_v(SKs[:i] + [SKs[i-5]] + SKs[i:]), mk_v(MKs[:i] + [MKs[i-5]] + MKs[i:]),
        af_v(R[:i] + [R[i-5]] + R[i:]))
    fs = (i, SKs[i][1], os.urandom(32)); fm = (i, MKs[i][1], os.urandom(32)); fa = R[i][:58] + os.urandom(32)
    add("Insert a forged record", sk_v(SKs[:i] + [fs] + SKs[i:]), mk_v(MKs[:i] + [fm] + MKs[i:]), af_v(R[:i] + [fa] + R[i:]))
    add("Truncate the last 30 records", sk_v(SKs[:-30]), mk_v(MKs[:-30]), af_v(R[:-30]))
    add("Delete the entire log", sk_v([]), mk_v([]), af_v([]))
    add("Roll back to an older consistent copy", sk_v(SKs[:n // 2]), mk_v(MKs[:n // 2]), af_v(R[:n // 2]))
    # key compromise: attacker learns the current chain key and rewrites a past record
    kk, j = n // 2, (40_000 if n >= 50_000 else 4 * n // 9)
    k_now = k_sk0
    for _ in range(kk): k_now = evolve(k_now)
    s_, p_, m_ = SKs[j]; p2 = bytearray(p_); p2[10] ^= 1
    y_prev = SKs[j-1][2]
    forged = (s_, bytes(p2), hmac.new(k_now, y_prev + struct.pack(">I", s_) + bytes(p2), hashlib.sha256).digest())
    sk_kc = sk_v(SKs[:j] + [forged] + SKs[j+1:])
    mm = list(MKs); y = MKs[j-1][2]
    for t_ in range(j, n):
        s_, p_, _ = mm[t_]; p_ = bytes(bytearray(p_)[:10] + bytes([p_[10] ^ 1 if t_ == j else p_[10]]) + bytearray(p_)[11:])
        mac = hmac.new(k_m, y + struct.pack(">I", s_) + p_, hashlib.sha256).digest(); mm[t_] = (s_, p_, mac); y = mac
    mk_kc = mk_v(mm)
    ra = list(R); h = R[j-1][58:]
    for t_ in range(j, len(ra)):
        e = bytearray(ra[t_][:58])
        if t_ == j: e[30] ^= 1
        h = hmac.new(enc.escrow_key(), h + bytes(e), hashlib.sha256).digest(); ra[t_] = bytes(e) + h
    af_kc = af_v(ra)
    add("Chain key leaked, past record rewritten (key-compromise)", sk_kc, mk_kc, af_kc)
    res["tamper"] = scen
    res["tamper_detected"] = {k: sum(s[k] for s in scen) for k in ("SK", "MASK", "AFR_SP")}
    res["tamper_total"] = len(scen)
    json.dump(res, open("compare_results.json", "w"), indent=2)

    # ---------------------------------------------------------------- print
    print(f"\nTrace: {n} events, seed {seed}   ({res['platform']['system']}, Python {res['platform']['python']})\n")
    hdr = f"{'':34}{'RAW':>10}{'SK':>10}{'MASK':>10}{'AFR-SP':>10}"
    print(hdr)
    def row(label, key, fmt="{}"):
        print(f"{label:34}" + "".join(f"{fmt.format(res[s][key]):>10}" for s in ('RAW', 'SK', 'MASK', 'AFR-SP')))
    row("bytes per record", "bytes_per_record", "{:.1f}")
    row("volume (MB/day)", "mb_per_day", "{:.2f}")
    row("reduction vs RAW (%)", "reduction_vs_raw_pct", "{:.2f}")
    print(f"{'PII values stored (of ' + str(n_pii_total) + ')':34}" + "".join(f"{res[s]['pii_values_stored']:>10}" for s in ('RAW', 'SK', 'MASK', 'AFR-SP')))
    row("latency median (us)", "latency_us_median", "{:.2f}")
    row("latency p99 (us)", "latency_us_p99", "{:.2f}")
    print(f"AFR-SP incl. checkpoints: {res['AFR-SP']['mb_per_day_incl_checkpoints']} MB/day "
          f"({res['AFR-SP']['reduction_incl_checkpoints_pct']}% less than RAW), mean latency incl. checkpoint "
          f"{res['AFR-SP']['latency_us_mean_incl_checkpoint']} us")
    print(f"Verification of the full day (s): SK {res['SK']['verify_full_day_s']}, MASK {res['MASK']['verify_full_day_s']}, AFR-SP {res['AFR-SP']['verify_full_day_s']}")
    print(f"Clean-log verification findings (must be 0): {res['clean_verification_findings']}\n")
    print(f"{'Tamper scenario':62}{'SK':>6}{'MASK':>6}{'AFR-SP':>8}")
    for s in scen:
        print(f"{s['scenario']:62}{'yes' if s['SK'] else 'NO':>6}{'yes' if s['MASK'] else 'NO':>6}{'yes' if s['AFR_SP'] else 'NO':>8}")
    d = res["tamper_detected"]
    print(f"{'Detected':62}{d['SK']:>4}/{res['tamper_total']}{d['MASK']:>3}/{res['tamper_total']}{d['AFR_SP']:>5}/{res['tamper_total']}")
    print("\nwrote compare_results.json")

if __name__ == "__main__":
    main()
