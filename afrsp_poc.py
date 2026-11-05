#!/usr/bin/env python3
"""
AFR-SP proof-of-concept: selective cryptographic logger + verifier.

Implements, as executable code, the mechanism of Section III.C:
  E_t = Header || EventID || Timestamp || StateHash(S_t \\ P_t)      (1)
  H_t = HMAC_{K_SE}(H_{t-1} || E_t)                                   (2)
  L_t = <E_t, H_t>                                                     (3)
plus periodic Merkle checkpoints signed inside the (emulated) enclave,
a bounded ring buffer on the node, an upstream collector, and a verifier.

Run:  python3 afrsp_poc.py  [--events 86400] [--seed 7]
Outputs results.json and prints a summary. Everything is measured, not assumed.
"""
import argparse, hashlib, hmac, json, os, platform, random, statistics, struct, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------- parameters
CHECKPOINT_EVERY = 60          # events (= 60 s at 1 event/s)
RING_BYTES = 256 * 1024        # log partition reserved on a 1 MB-Flash node
REC_LEN = 90                   # 14 + 4 + 8 + 32 + 32
HDR_FMT = ">BBIBHIB"           # version, type, seq, mode, payload_len, epoch, reserved = 14 B
assert struct.calcsize(HDR_FMT) == 14
PII_FIELDS = ("user_name", "user_email", "patient_id", "src_ip", "mac", "gps")
EV_TELEMETRY, EV_AUTH, EV_OTA, EV_OVERFLOW = 1, 2, 3, 0xFE

# ---------------------------------------------------------------- synthetic workload
FIRST = ["Ana", "Maria", "Ioana", "Andrei", "Mihai", "Elena", "Radu", "Cristina"]
LAST = ["Popescu", "Ionescu", "Dumitru", "Stan", "Matei", "Georgescu"]

def raw_event(i, rng, t0):
    """One verbose JSON record as a conventional logger would store it."""
    fn, ln = rng.choice(FIRST), rng.choice(LAST)
    kind = rng.choices(["telemetry", "auth", "ota"], weights=[96, 3.9, 0.1])[0]
    ev = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t0 + i)) + "Z",
        "device_id": "edge-node-0042",
        "fw": "2.3.1",
        "event": kind,
        "user_name": f"{fn} {ln}",
        "user_email": f"{fn.lower()}.{ln.lower()}@example.org",
        "patient_id": f"P-{rng.randint(100000, 999999)}",
        "src_ip": f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "mac": ":".join(f"{rng.randint(0,255):02x}" for _ in range(6)),
        "gps": [round(44.43 + rng.uniform(-.05, .05), 6), round(26.10 + rng.uniform(-.05, .05), 6)],
        "state": {
            "temp_c": round(rng.uniform(20, 40), 1),
            "hr_bpm": rng.randint(50, 140),
            "batt_pct": rng.randint(5, 100),
            "rssi_dbm": rng.randint(-95, -40),
            "uptime_s": i,
        },
        "hdr": {"proto": "mqtt", "qos": 1, "topic": "site/ward3/telemetry", "msg_id": i},
    }
    if kind == "auth":
        ev["auth"] = {"method": "psk", "result": rng.choice(["ok", "fail"])}
    if kind == "ota":
        ev["ota"] = {"image_sha256": hashlib.sha256(os.urandom(8)).hexdigest(), "signed": rng.random() > .5}
    return ev

def serialize_raw(ev):
    return json.dumps(ev, separators=(",", ":")).encode()

# ---------------------------------------------------------------- emulated enclave
class Enclave:
    """Holds K_SE, the signing key, the monotonic counter and the chain head.
    The only operations exposed are append() and checkpoint(): firmware cannot
    ask for an HMAC over arbitrary input, nor rewind seq/H_prev."""
    def __init__(self, seed):
        r = random.Random(seed)
        self._k_se = bytes(r.getrandbits(8) for _ in range(32))
        self._sk = Ed25519PrivateKey.from_private_bytes(bytes(r.getrandbits(8) for _ in range(32)))
        self.pk = self._sk.public_key()
        self.seq = 0
        self._h_prev = b"\x00" * 32
        self._pending = []          # H values since last checkpoint
        self._cp_prev = b"\x00" * 32
        self.cp_no = 0

    def append(self, etype, mode, ts_us, state_hash):
        hdr = struct.pack(HDR_FMT, 1, etype, self.seq, mode, 44, 1, 0)
        e = hdr + struct.pack(">I", self.seq) + struct.pack(">Q", ts_us) + state_hash
        h = hmac.new(self._k_se, self._h_prev + e, hashlib.sha256).digest()
        self._h_prev = h
        self._pending.append(h)
        self.seq += 1
        return e + h

    def checkpoint(self, ts_us):
        if not self._pending:
            return None
        root = merkle_root(self._pending)
        body = struct.pack(">IIIQ", self.cp_no, self.seq - len(self._pending), self.seq - 1, ts_us) \
            + root + self._h_prev + self._cp_prev
        sig = self._sk.sign(body)
        cp = body + sig
        self._cp_prev = hashlib.sha256(cp).digest()
        self._pending = []
        self.cp_no += 1
        return cp

    def escrow_key(self):           # verification key handed to the investigator (escrow)
        return self._k_se

def merkle_root(leaves):
    lvl = [hashlib.sha256(b"\x00" + h).digest() for h in leaves]
    while len(lvl) > 1:
        if len(lvl) % 2:
            lvl.append(lvl[-1])
        lvl = [hashlib.sha256(b"\x01" + lvl[k] + lvl[k + 1]).digest() for k in range(0, len(lvl), 2)]
    return lvl[0]

def parse_cp(cp):
    cp_no, first, last, ts = struct.unpack(">IIIQ", cp[:20])
    return dict(cp_no=cp_no, first=first, last=last, ts=ts, root=cp[20:52],
                h_last=cp[52:84], prev=cp[84:116], body=cp[:116], sig=cp[116:])

# ---------------------------------------------------------------- node side
class Node:
    def __init__(self, enclave):
        self.enc = enclave
        self.cap = RING_BYTES // REC_LEN
        self.ring = []              # unacknowledged records (bounded by cap)
        self.dropped = 0

    def log(self, raw, ts_us, mode=0):
        state = {k: v for k, v in raw.items() if k not in PII_FIELDS}   # S_t \ P_t
        state.pop("ts", None)       # time is carried in the fixed Timestamp field
        sh = hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).digest()
        et = {"telemetry": EV_TELEMETRY, "auth": EV_AUTH, "ota": EV_OTA}[raw["event"]]
        if len(self.ring) >= self.cap:          # retention policy: oldest unacked record is dropped,
            self.ring.pop(0); self.dropped += 1  # and the drop itself is chained (below)
        rec = self.enc.append(et, mode, ts_us, sh)
        self.ring.append(rec)
        return rec

    def overflow_marker(self, ts_us):
        if self.dropped:
            rec = self.enc.append(EV_OVERFLOW, 0, ts_us, hashlib.sha256(struct.pack(">I", self.dropped)).digest())
            self.ring.append(rec); self.dropped = 0

    def flush(self, ts_us):
        """Checkpoint + upload batch; ring is freed only after the collector accepts it."""
        self.overflow_marker(ts_us)
        cp = self.enc.checkpoint(ts_us)
        batch, self.ring = self.ring, []
        return batch, cp

# ---------------------------------------------------------------- upstream + verifier
def verify(records, checkpoints, k_se, pk):
    """Returns list of findings (empty == log verified)."""
    findings = []
    by_seq = {}
    for r in records:
        seq = struct.unpack(">I", r[2:6])[0]
        if seq in by_seq:
            findings.append(f"duplicate seq {seq}")
        by_seq.setdefault(seq, r)
    order = [struct.unpack(">I", r[2:6])[0] for r in records]
    if order != sorted(order):
        findings.append("records out of order")
    prev_cp = b"\x00" * 32
    expect_cp = 0
    h_prev = b"\x00" * 32
    covered = -1
    for cp in checkpoints:
        c = parse_cp(cp)
        try:
            pk.verify(c["sig"], c["body"])
        except InvalidSignature:
            findings.append(f"checkpoint {c['cp_no']}: bad signature"); continue
        if c["cp_no"] != expect_cp or c["prev"] != prev_cp:
            findings.append(f"checkpoint {c['cp_no']}: missing/replayed predecessor (expected #{expect_cp})")
        if c["first"] != covered + 1:
            findings.append(f"checkpoint {c['cp_no']}: seq gap {covered+1}..{c['first']-1}")
        prev_cp = hashlib.sha256(cp).digest(); expect_cp = c["cp_no"] + 1
        hs, missing = [], []
        # chain continuity across a gap cannot be rechecked; restart from the checkpoint's own data
        for s in range(c["first"], c["last"] + 1):
            r = by_seq.get(s)
            if r is None:
                missing.append(s); hs = None; continue
            e, h = r[:58], r[58:]
            calc = hmac.new(k_se, h_prev + e, hashlib.sha256).digest()
            if calc != h:
                findings.append(f"seq {s}: HMAC mismatch (altered/forged/reordered)")
            h_prev = h
            if hs is not None:
                hs.append(h)
        if missing:
            findings.append(f"checkpoint {c['cp_no']}: {len(missing)} record(s) missing "
                            f"(seq {missing[0]}..{missing[-1]})")
        elif merkle_root(hs) != c["root"] or hs[-1] != c["h_last"]:
            findings.append(f"checkpoint {c['cp_no']}: Merkle root / chain head mismatch")
        covered = c["last"]
    extra = [s for s in by_seq if s > covered]
    if extra:
        findings.append(f"{len(extra)} record(s) not covered by any checkpoint (unverified tail)")
    return findings

# ---------------------------------------------------------------- experiment
def run(n_events, seed):
    rng = random.Random(seed)
    t0 = 1_767_225_600  # 2026-01-01T00:00:00Z
    enc = Enclave(seed)
    node = Node(enc)
    raw_sizes, log_ns, cp_ns = [], [], []
    store_records, store_cps = [], []
    pii_values = set()
    afr_bytes = 0
    for i in range(n_events):
        ev = raw_event(i, rng, t0)
        rb = serialize_raw(ev)
        raw_sizes.append(len(rb))
        for f in PII_FIELDS:
            v = ev[f]
            pii_values.update([str(x) for x in v] if isinstance(v, list) else [str(v)])
        ts_us = (t0 + i) * 1_000_000
        a = time.perf_counter_ns()
        rec = node.log(ev, ts_us)
        log_ns.append(time.perf_counter_ns() - a)
        afr_bytes += len(rec)
        if (i + 1) % CHECKPOINT_EVERY == 0:
            a = time.perf_counter_ns()
            batch, cp = node.flush(ts_us)
            cp_ns.append(time.perf_counter_ns() - a)
            store_records += batch; store_cps.append(cp)
    if node.ring:
        batch, cp = node.flush((t0 + n_events) * 1_000_000)
        store_records += batch; store_cps.append(cp)

    # ---- PII scan of everything that leaves the node (records + checkpoints)
    # A PII string can only occur inside a run of printable bytes at least as long as itself,
    # so every printable run is checked exhaustively against the set of all PII values.
    import re
    blob = b"".join(store_records) + b"".join(store_cps)
    minlen = min(len(v) for v in pii_values)
    vals = {v.encode() for v in pii_values}
    pii_hits = 0
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, blob):
        run_ = m.group()
        for L in range(minlen, len(run_) + 1):
            for s in range(0, len(run_) - L + 1):
                if run_[s:s + L] in vals:
                    pii_hits += 1

    # ---- verification time on the full trace
    a = time.perf_counter()
    base = verify(store_records, store_cps, enc.escrow_key(), enc.pk)
    verify_s = time.perf_counter() - a

    # ---- offline/retention experiment: 60 min without upstream on a 256 KiB ring
    enc2 = Enclave(seed + 1); node2 = Node(enc2); rng2 = random.Random(seed + 1)
    for i in range(3600):
        node2.log(raw_event(i, rng2, t0), (t0 + i) * 1_000_000)
    dropped_before_marker = node2.dropped
    b2, cp2 = node2.flush((t0 + 3600) * 1_000_000)
    ovf = [r for r in b2 if r[1] == EV_OVERFLOW]
    outage = dict(ring_capacity_records=node2.cap, ring_minutes_at_1ev_s=round(node2.cap / 60, 1),
                  events_during_outage=3600, records_dropped=dropped_before_marker,
                  overflow_marker_chained=len(ovf) == 1)

    # ---- tamper scenarios
    scen = tamper_suite(store_records, store_cps, enc, seed)

    lat = sorted(log_ns)
    q = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))] / 1000
    res = dict(
        platform=dict(cpu=platform.processor() or platform.machine(), python=platform.python_version(),
                      openssl=__import__("ssl").OPENSSL_VERSION, os=platform.platform()),
        events=n_events, checkpoint_every=CHECKPOINT_EVERY,
        raw=dict(mean_bytes=round(statistics.mean(raw_sizes), 1), min=min(raw_sizes), max=max(raw_sizes),
                 total_bytes=sum(raw_sizes)),
        afr=dict(record_bytes=REC_LEN, total_record_bytes=afr_bytes,
                 checkpoint_bytes=len(store_cps[0]), checkpoints=len(store_cps),
                 total_with_checkpoints=afr_bytes + sum(map(len, store_cps))),
        reduction_records_pct=round(100 * (1 - afr_bytes / sum(raw_sizes)), 2),
        reduction_with_cp_pct=round(100 * (1 - (afr_bytes + sum(map(len, store_cps))) / sum(raw_sizes)), 2),
        pii=dict(distinct_pii_values=len(pii_values), occurrences_in_output=pii_hits),
        latency_us=dict(median=round(q(.5), 2), p99=round(q(.99), 2), max=round(lat[-1] / 1000, 2),
                        mean=round(statistics.mean(lat) / 1000, 2)),
        checkpoint_us=dict(median=round(statistics.median(cp_ns) / 1000, 1),
                           p99=round(sorted(cp_ns)[int(.99 * len(cp_ns))] / 1000, 1)),
        verify_full_trace_s=round(verify_s, 3), baseline_findings=base,
        outage=outage, tamper=scen,
    )
    return res

def tamper_suite(R, C, enc, seed):
    k, pk = enc.escrow_key(), enc.pk
    out = []
    def case(name, attacker, recs, cps, expected=True):
        f = verify(recs, cps, k, pk)
        out.append(dict(scenario=name, attacker=attacker, detected=bool(f), expected_detect=expected,
                        finding=f[0] if f else "-"))
    i = 1234
    # A1: storage attacker (read/write to log flash or batch at rest; no key access)
    r = list(R); b = bytearray(r[i]); b[30] ^= 0x01; r[i] = bytes(b)
    case("Alter one historical record (StateHash byte)", "A1", r, C)
    r = list(R); b = bytearray(r[i]); b[10:18] = struct.pack(">Q", 0); r[i] = bytes(b)
    case("Alter timestamp of one record", "A1", r, C)
    case("Delete one record from the middle", "A1", R[:i] + R[i + 1:], C)
    r = list(R); r[i], r[i + 1] = r[i + 1], r[i]
    case("Swap (reorder) two adjacent records", "A1", r, C)
    case("Replay/duplicate an earlier record", "A1", R[:i] + [R[i - 5]] + R[i:], C)
    forged = R[i][:58] + hashlib.sha256(b"fake").digest()
    case("Insert a forged record (random HMAC)", "A1", R[:i] + [forged] + R[i:], C)
    cut = len(R) - 30
    case("Truncate tail (last 30 records), checkpoint kept", "A1", R[:cut], C)
    case("Delete entire log, checkpoints kept upstream", "A1", [], C)
    # rollback: present an older consistent snapshot of the log, newer checkpoints exist upstream
    case("Roll back log to an older consistent snapshot", "A1", R[:len(R) // 2], C)
    # A3 (late detection): upstream hid the latest checkpoint; the node later uploads its next one
    nxt = [enc.append(EV_TELEMETRY, 0, 0, hashlib.sha256(b"n%d" % s).digest()) for s in range(60)]
    cp_next = enc.checkpoint(0)
    late = (R[:-60] + nxt, C[:-1] + [cp_next])
    # A2: malicious firmware, can call enclave.append() but cannot read keys/rewind counter;
    # the enclave only extends its own chain, so the attacker obtains a record with a *new* seq
    rec_new = enc.append(EV_TELEMETRY, 0, 0, hashlib.sha256(b"rewrite-seq-0").digest())
    r = list(R); r[0] = rec_new
    case("Rewrite an old record via the enclave append API", "A2", r, C)
    # A3: upstream collector compromise
    case("Upstream deletes latest checkpoint + its records", "A3", R[:-60], C[:-1], expected=False)
    case("  ... detected once the node's next checkpoint arrives", "A3", *late)
    case("Upstream deletes a middle checkpoint", "A3", R, C[:5] + C[6:])
    case("Upstream replays an old checkpoint", "A3", R, C[:10] + [C[3]] + C[10:])
    cpb = bytearray(C[2]); cpb[40] ^= 1
    case("Upstream edits a checkpoint root", "A3", R, C[:2] + [bytes(cpb)] + C[3:])
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--events", type=int, default=86_400)
    ap.add_argument("--seed", type=int, default=7); a = ap.parse_args()
    res = run(a.events, a.seed)
    with open("results.json", "w") as fh:
        json.dump(res, fh, indent=2)
    print(json.dumps({k: v for k, v in res.items() if k != "tamper"}, indent=2))
    for t in res["tamper"]:
        print(f"[{t['attacker']}] {t['scenario']:<52} detected={t['detected']!s:<5}  {t['finding']}")
