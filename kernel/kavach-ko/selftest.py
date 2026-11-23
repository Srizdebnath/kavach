#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Differential self-test: kavach_evaluate (Rust, kavach.ko) vs kv_evaluate (C, eBPF).

Runs as root on the kernel kavach.ko was built for, ideally in a throwaway VM (it mounts fresh
bpffs instances over /sys/fs/bpf). It loads bpf/kavach.bpf.o with bpftool, i.e. libbpf, which
binds module kfuncs (aya, used by kavachd, cannot yet), in two phases:

  1. kavach.ko loaded:   the weak kavach_evaluate resolves; the TC programs call the kfunc.
  2. kavach.ko unloaded: it does not; the verifier removes the call and the C mirror runs.

Each phase installs the same random policies and address sets, runs the same flows through
kavach_tc_ingress with BPF_PROG_TEST_RUN, and records (return code, rule id, verdict) for every
flow from the flow cache. The phases must agree exactly. The translated LSM and TC programs are
also checked for the kfunc call (present in phase 1, absent in phase 2), so a silent fallback
cannot pass.

usage: selftest.py BPF_OBJECT KAVACH_KO [ROUNDS]
"""

import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import time

BPFFS = "/sys/fs/bpf"
PROG_DIR = BPFFS + "/kvko"
KV_MAX_RULES = 1024
POLICY_SIZE = 64 + KV_MAX_RULES * 48
KV_DIR_EGRESS, KV_DIR_INGRESS = 1, 2
KV_POL_F_VALID = 1
FLOWS_PER_ROUND = 200
CALLERS = ["kavach_tc_ingress", "kavach_tc_egress", "kavach_connect", "kavach_sendmsg"]

# Non-overlapping IPv4 prefixes -> address-set bitmap (LPM trie, slot 0).
SETS = [((10, 0, 0, 0), 8, 0b001), ((192, 0, 2, 0), 24, 0b010), ((8, 8, 8, 0), 24, 0b100)]
SRCS = [(10, 1, 2, 3), (192, 0, 2, 9), (8, 8, 8, 8), (172, 16, 0, 1), (203, 0, 113, 5)]
PORTS = [22, 53, 80, 443, 3306, 8080, 9000]


def sh(*args, check=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"selftest: {' '.join(args[:6])} ... failed:\n{r.stdout}\n{r.stderr}")
    return r


def hexargs(b):
    return [f"{x:02x}" for x in b]


def mapped(a):
    return bytes(10) + b"\xff\xff" + bytes(a)


def policy_blob(rng):
    n = rng.randint(1, 40)
    hdr = struct.pack(
        "<IIBB6xQQQQIIQ",
        n,
        KV_POL_F_VALID,
        rng.choice([0, 1, 2]),  # default_egress
        rng.choice([0, 1, 2]),  # default_ingress
        0, 0, 0,  # wild_exe / wild_uid / wild_cgroup (mask is 0 at ingress anyway)
        1,  # serial
        0,  # generation
        0,
        0,  # sel_used
    )
    rules = b""
    for i in range(n):
        lo = rng.choice(PORTS + [0, 1])
        hi = rng.choice([lo, lo, 65535, max(lo, rng.choice(PORTS))])
        rules += struct.pack(
            "<QIIHHBBBBQ16x",
            rng.choice([0, 0, 0, 1]),  # sel (non-zero never matches mask 0)
            1000 + i,  # id
            rng.choice([0, 0, 1, 2, 3, 4]),  # remote_set (4 = empty set)
            lo,
            hi,
            rng.choice([0, 6, 17]),
            rng.choice([KV_DIR_INGRESS] * 4 + [KV_DIR_EGRESS]),
            rng.choice([0, 1, 2, 3, 7]),  # verdict, incl. Punt and an invalid value
            rng.choice([0, 1]),  # fail
            rng.choice([0, 0, 0, 1, (1 << 63)]),  # not_after_ns (1 = expired)
        )
    blob = hdr + rules
    assert len(hdr) == 64
    return blob + bytes(POLICY_SIZE - len(blob))


def packet(src, sport, dport, proto):
    l4 = (
        struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x02, 64240, 0, 0)
        if proto == 6
        else struct.pack(">HHHH", sport, dport, 8, 0)
    )
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, bytes(src), bytes((10, 9, 9, 9))
    )
    eth = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00"
    return eth + ip + l4


def mount_fresh_bpffs():
    sh("mount", "-t", "bpf", "bpf", BPFFS)


def phase(obj, seed, rounds, expect_kfunc):
    mount_fresh_bpffs()
    try:
        sh("bpftool", "prog", "loadall", obj, PROG_DIR)
        prog = PROG_DIR + "/kavach_tc_ingress"
        # Every caller of kv_evaluate (LSM and TC) must have passed the verifier with the kfunc
        # call in place, or without it once the module is gone.
        for name in CALLERS:
            path = PROG_DIR + "/" + name
            xlated = json.loads(sh("bpftool", "-j", "prog", "dump", "xlated", "pinned", path).stdout)
            # Disassembly only: the interleaved source lines always mention kavach_evaluate.
            has_call = any(") call kavach_evaluate#" in i.get("disasm", "") for i in xlated)
            if has_call != expect_kfunc:
                sys.exit(f"selftest: {name}: kfunc call present={has_call}, expected {expect_kfunc}")
        for (a, plen, bits) in SETS:
            key = struct.pack("<II", 32 + 96 + plen, 0) + mapped(a)
            sh("bpftool", "map", "update", "pinned", BPFFS + "/addr_sets", "key", "hex",
               *hexargs(key), "value", "hex", *hexargs(struct.pack("<Q", bits)))
        rng = random.Random(seed)
        results = {}
        sport = 1024
        with tempfile.TemporaryDirectory() as tmp:
            for r in range(rounds):
                # New policy in slot 0; generation stays 0 and every flow is a new 5-tuple, so
                # the flow cache never answers for the evaluator.
                sh("bpftool", "map", "update", "pinned", BPFFS + "/policy_slots", "key", "hex",
                   "00", "00", "00", "00", "value", "hex", *hexargs(policy_blob(rng)))
                for _ in range(FLOWS_PER_ROUND):
                    src = rng.choice(SRCS)
                    dport = rng.choice(PORTS)
                    proto = rng.choice([6, 17])
                    sport += 1
                    path = os.path.join(tmp, "pkt")
                    with open(path, "wb") as f:
                        f.write(packet(src, sport, dport, proto))
                    out = sh("bpftool", "prog", "run", "pinned", prog, "data_in", path).stdout
                    rc = int(out.split("Return value:")[1].split(",")[0])
                    results[(r, src, sport, dport, proto)] = rc
        cache = json.loads(sh("bpftool", "-j", "map", "dump", "pinned", BPFFS + "/flow_cache").stdout)
        rules = {}
        for e in cache:
            v = e.get("formatted", {}).get("value", {})
            k = e.get("formatted", {}).get("key", {})
            if v and k:
                rules[json.dumps(k, sort_keys=True)] = (v.get("rule_id"), v.get("verdict"))
        return results, rules
    finally:
        sh("umount", BPFFS, check=False)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    obj, ko = sys.argv[1], sys.argv[2]
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    seed = int(os.environ.get("KAVACH_SELFTEST_SEED", "20261123"))

    sh("insmod", ko)
    kf, kf_rules = phase(obj, seed, rounds, expect_kfunc=True)
    for _ in range(50):  # programs are freed after an RCU grace period
        if sh("rmmod", "kavach", check=False).returncode == 0:
            break
        time.sleep(0.1)
    else:
        sys.exit("selftest: kavach.ko stayed busy after its programs were unpinned")
    c, c_rules = phase(obj, seed, rounds, expect_kfunc=False)

    diverged = [k for k in kf if kf[k] != c.get(k)]
    for k in diverged[:20]:
        print(f"DIVERGENCE {k}: kfunc={kf[k]} C={c.get(k)}")
    rule_diff = [k for k in kf_rules if kf_rules[k] != c_rules.get(k)]
    for k in rule_diff[:20]:
        print(f"RULE DIVERGENCE {k}: kfunc={kf_rules[k]} C={c_rules.get(k)}")
    drops = sum(1 for v in kf.values() if v == 2)
    print(f"selftest: {len(kf)} flows, {drops} dropped, {len(kf_rules)} cached decisions "
          f"compared; {len(diverged)} verdict and {len(rule_diff)} rule-id divergences")
    if diverged or rule_diff or len(kf) != len(c) or len(kf_rules) != len(c_rules):
        sys.exit(1)
    print("selftest: PASS (kavach_evaluate == kv_evaluate)")


if __name__ == "__main__":
    main()
