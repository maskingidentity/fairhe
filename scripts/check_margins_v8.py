"""Test A6: the actual prime chains keep the
decoding conditions, tolerances and margins of Appendix C.4.

An independent check of what pkg/rlwe.CheckMargins does in Go. The class
bounds and the conditions follow Sections 3.3.1, 3.4.1 and Appendix C.4 of
the paper; the moduli are the actual ones recorded by `go run ./cmd/params` in
results/v8/params.jsonl. Everything is exact (integers and fractions).

Usage: python scripts/check_margins_v8.py   (exit status 1 on a failure)
"""

import json
import math
import sys
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARAMS = ROOT / "results" / "v8" / "params.jsonl"

# Class of the running example (flagship_params.py): d = 30 features plus the
# constant column, n <= 2^10 records, 8-bit features, targets and weights,
# beta = 12 (BFV); CKKS: values in [0, 1], |w_j| <= 16, 2^-20 fixed point.
N_MAX, DD, XB, WB, BETA = 2**10, 31, 255, 2**7, 12
M = DD * (DD + 1) // 2 + DD + 1  # 528
WR, FRAC = 16, 20

S_L1_BFV = M * N_MAX * XB * XB  # ||S||_1, Case 1 BFV operand
WHAT_L1_BFV = (DD * WB + 2**BETA) ** 2  # ||w_hat||_1, Case 2 BFV operand
F_MAX_BFV = N_MAX * (2**BETA * XB + DD * WB * XB) ** 2
S_L1_CKKS = 2**FRAC * M  # ||S||_1 at scale 2^20, Case 1 CKKS operand
WHAT_L1_CKKS = 2**FRAC * (DD * WR + 1) ** 2  # ||w_hat||_1 at scale 2^20, Case 2 CKKS operand
F_MAX_CKKS = Fraction((DD * WR + 1) ** 2)  # |f| <= ||w_hat||_1 max|S|, max|S| <= 1

# Margins of Appendix C.4 and the declared
# CKKS tolerances (log2): (log2 Q min, strict, log2 q_del min, log2 Q/q_del max, log2 tau max).
C4 = {
    "case1_bfv": (133.63, False, 67.5, None, None),
    "case1_ckks": (102.92, False, None, 60.99, -10),
    "case2_bfv": (124, True, None, None, None),
    "case2_ckks": (110.92, False, None, None, -9.999),
}


def latest_rows():
    rows = {}
    for line in PARAMS.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            rows[r["params"]] = r
    return rows


def log2(x):
    x = Fraction(x)
    return math.log2(x.numerator) - math.log2(x.denominator)


def required_sigma(B, lam):
    """Smallest sigma with B 2^lambda_s <= 2^(sigma+1) (Lemma 1, |J| = 1)."""
    t = B << lam
    L = t.bit_length()
    return L - 2 if t == 1 << (L - 1) else L - 1


def check(r):
    name, case, scheme = r["params"], r["case"], r["scheme"]
    N, berr, lam, sigma = r["n"], r["b_err"], r["lambda_s"], r["sigma_fl"]
    Q = math.prod(r["chain"])
    qdel = int(r["q_del"]) if r.get("q_del") else None
    if scheme == "BFV":
        pt = S_L1_BFV if case == 1 else WHAT_L1_BFV
    else:
        pt = S_L1_CKKS if case == 1 else WHAT_L1_CKKS
    # B_tot = ||pt||_1 B_err + (2N+1) B_err (Case 1); B_e = ||pt||_1 B_err + 2N B_err (Case 2).
    B = pt * berr + (2 * N + (1 if case == 1 else 0)) * berr
    flood = 2**sigma
    out = {"name": name, "log2_Q": log2(Q), "log2_B": log2(B), "sigma": sigma, "sigma_req": required_sigma(B, lam)}
    fails = []
    if sigma < out["sigma_req"]:
        fails.append(f"sigma_fl {sigma} below the required {out['sigma_req']}")
    noise = B + flood + (berr if case == 2 else 0)
    if scheme == "BFV":
        t = 2 ** r["log2_t"]
        term = Fraction(t * noise, Q) + Fraction(F_MAX_BFV * (Q % t), Q)
        if case == 1:
            term += Fraction(t * (N + 1), 2 * qdel)
        out["decode_term"] = float(term)
        if term >= Fraction(1, 2):
            fails.append(f"decoding term {float(term):.6f} >= 1/2")
        if t <= 2 * F_MAX_BFV:
            fails.append("t does not exceed 2 f_max")
    else:
        delta = 2 ** (r["log2_scale_enc"] + r["log2_scale_pt"])
        lhs = delta * F_MAX_CKKS + noise
        tau = Fraction(noise, delta)
        if case == 1:
            sw = Fraction((N + 1) * Q, 2 * qdel)
            lhs += sw
            tau += sw / delta
        out["log2_tau"] = log2(tau)
        out["log2_headroom"] = log2(Fraction(Q, 2) / lhs)
        if lhs >= Fraction(Q, 2):
            fails.append("the result wraps around Q/2")
    qmin, strict, qdelmin, ratiomax, taumax = C4[name]
    lq = out["log2_Q"]
    if (strict and not lq > qmin) or (not strict and lq < qmin):
        fails.append(f"log2 Q = {lq:.6f} misses the margin {qmin}")
    if qdelmin is not None and log2(qdel) < qdelmin:
        fails.append(f"log2 q_del = {log2(qdel):.6f} below {qdelmin}")
    if ratiomax is not None and not log2(Fraction(Q, qdel)) < ratiomax:
        fails.append(f"log2 Q/q_del = {log2(Fraction(Q, qdel)):.6f} not below {ratiomax}")
    if taumax is not None and out["log2_tau"] > taumax:
        fails.append(f"tau 2^{out['log2_tau']:.4f} above 2^{taumax}")
    if lq > 218:
        fails.append("log2 Q above the 218 bits of the HE standard at N = 2^13")
    if abs(out["log2_B"] - r["log2_B"]) > 1e-9 or out["sigma_req"] != r["sigma_required"]:
        fails.append("B or the required sigma differs from the Go computation")
    return out, fails


def main():
    rows = latest_rows()
    bad = 0
    for name in ["case1_bfv", "case1_ckks", "case2_bfv", "case2_ckks"]:
        if name not in rows:
            print(f"{name}: missing in {PARAMS}; run `go run ./cmd/params` first")
            bad += 1
            continue
        out, fails = check(rows[name])
        extra = f"decode {out['decode_term']:.6f}" if "decode_term" in out else \
            f"log2 tau {out['log2_tau']:.4f}, headroom 2^{out['log2_headroom']:.2f}"
        print(f"{name:10s} log2 Q {out['log2_Q']:.8f}  log2 B {out['log2_B']:.3f}  sigma {out['sigma']}/{out['sigma_req']}  {extra}  "
              + ("ok" if not fails else "FAIL: " + "; ".join(fails)))
        bad += bool(fails)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
