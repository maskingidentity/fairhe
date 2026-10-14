"""Test G1: the security of the actual prime chains by the lattice
estimator, computed as for Table 2 of the paper (estimator commit 53da598,
LWE.estimate.rough, i.e. core-SVP).

For each parameter set it reads the actual primes from
results/v8/params.jsonl and estimates n = 2^13, a ternary secret
(ND.Uniform(-1, 1, n)) and a discrete Gaussian error of sigma 3.19 at
q = Q (the actual product) and, for comparison with Table 2, at
q = 2^logQ. With --full it also runs LWE.estimate on the actual Q. Rows go
to results/v8/security.jsonl, which scripts/gen_v8_tables.py reads.

Usage, with the Python of a SageMath installation (conda-forge's Sage 10.9
has no `sage -python`; its environment's python imports sage) and the
estimator checked out at --le:
  $PREFIX/miniforge/envs/sage/bin/python scripts/security_v8.py --le $PREFIX/lattice-estimator [--full] [--jobs N]
"""

import argparse
import json
import math
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETS = ["case1_bfv", "case1_ckks", "case2_bfv", "case2_ckks"]


def bits(est):
    return {k: round(math.log2(float(v["rop"])), 1) for k, v in est.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--le", default="le", help="checkout of malb/lattice-estimator")
    ap.add_argument("--full", action="store_true", help="also run LWE.estimate on the actual Q")
    ap.add_argument("--jobs", type=int, default=4, help="parallel jobs of LWE.estimate")
    ap.add_argument("--sets", default=",".join(SETS), help="parameter sets to estimate")
    args = ap.parse_args()
    sys.path.insert(0, args.le)
    from estimator import LWE, ND  # noqa: E402  (needs Sage)

    commit = subprocess.run(["git", "-C", args.le, "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    rows = {}
    for line in (ROOT / "results" / "v8" / "params.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            rows[r["params"]] = r
    out = ROOT / "results" / "v8" / "security.jsonl"
    for name in args.sets.split(","):
        r = rows[name]
        n, Q = r.get("n", 2**13), math.prod(r["chain"])
        row = {"params": name, "n": n, "log2_Q": math.log2(Q), "estimator": commit, "sigma_e": 3.19,
               "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        for label, q in [("actual", Q), ("pow2", 2 ** round(math.log2(Q)))]:
            p = LWE.Parameters(n=n, q=q, Xs=ND.Uniform(-1, 1, n), Xe=ND.DiscreteGaussian(3.19))
            start = time.time()
            row[f"rough_{label}"] = bits(LWE.estimate.rough(p))
            row[f"rough_{label}_s"] = round(time.time() - start, 1)
        row["rough_min"] = min(row["rough_actual"].values())
        row["table2_min"] = min(row["rough_pow2"].values())
        if args.full:
            p = LWE.Parameters(n=n, q=Q, Xs=ND.Uniform(-1, 1, n), Xe=ND.DiscreteGaussian(3.19))
            start = time.time()
            row["full"] = bits(LWE.estimate(p, jobs=args.jobs))
            row["full_s"] = round(time.time() - start, 1)
            row["full_min"] = min(row["full"].values())
        print(json.dumps(row), flush=True)
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")


if __name__ == "__main__":
    main()
