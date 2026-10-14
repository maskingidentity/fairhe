"""Generate the LaTeX fragments of the evaluation.

Reads the JSONL results of the implementation and writes booktabs tables
to results/v8/tex/ (table numbers are those of the full version):

  tab_v8_params.tex  Table 3: N, chains, t or Delta, flood widths, q_del,
                     decoding margins, deliverable (blob elements), accuracy
                     over 1,000 inputs, pre-flood noise, security
  tab_v8_costs.tex   Table 4: per-role times of one exchange (medians of the
                     repeated happy runs) and its communication: ledger
                     calldata, DA values, proofs, blobs
  tab_v8_gas.tex     settlement gas per contract function
  tab_v8_zk.tex      Table 5: proof circuits: constraints, public inputs, setup,
                     prove and verify (medians), proof size, peak memory
  tab_v8_se.tex      option O2: pi_member with straight-line extraction of w
                     (measured) and the cost of extracting the main witness of
                     every other proof (estimated from the gadget's cost)
  tab_v8_o1.tex      option O1: pi_seal and the sealed correctness proofs
                     (constraints against the main proof, setup, prove and
                     verify medians, peak memory)
  tab_v8_o6.tex      option O6: the bulky values as blob data (payloads and
                     blobs per message, blobs and gas per exchange, posting
                     time, the same payloads as calldata)
  tab_v8_o7.tex      option O7: the blob archive (storage, store and read-back
                     costs per claim as means of 200 runs, exchanges decoded
                     from it after W)

Inputs: results/v8/params.jsonl (cmd/params), accuracy.jsonl (A1-A5 tests
with FAIRHE_RECORD=1), security.jsonl (lattice estimator, test G1),
archive.jsonl (TestO7ArchiveCost),
zk.jsonl (ZK measurement tests), e2e.jsonl (cmd/e2e -scale full). Each table
uses the latest run: for e2e the rows of the latest commit per parameter
set. Missing inputs leave a placeholder.

Usage: python scripts/gen_v8_tables.py
"""

import json
import math
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results" / "v8"
OUT = RES / "tex"
SETS = ["case1_bfv", "case1_ckks", "case2_bfv", "case2_ckks"]
LABEL = {"case1_bfv": "Case 1, BFV", "case1_ckks": "Case 1, CKKS", "case2_bfv": "Case 2, BFV", "case2_ckks": "Case 2, CKKS"}


def rows(name):
    path = RES / name
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def latest(rs, key, pred=lambda r: True):
    best = {}
    for r in rs:
        if pred(r):
            best[key(r)] = r
    return best


def e2e_latest(scenario, board="da"):
    """Full-scale rows of a scenario from the latest commit, per set; board
    "blob" selects the runs of option O6 (the others use the DA layer)."""
    rs = [r for r in rows("e2e.jsonl") if r["scale"] == "full" and r["scenario"] == scenario
          and r.get("board", "da") == board]
    out = {}
    for s in SETS:
        mine = [r for r in rs if r["params"] == s]
        if mine:
            commit = mine[-1].get("git_commit")
            out[s] = [r for r in mine if r.get("git_commit") == commit]
    return out


def fmt_s(x):
    if x is None:
        return "--"
    if x < 0.0005:
        return "$<$1\\,ms"
    if x < 1:
        return f"{x * 1000:.0f}\\,ms"
    if x < 100:
        return f"{x:.1f}\\,s"
    return f"{x:.0f}\\,s"


def fmt_s_fine(x):
    """Like fmt_s, with microseconds below 1 ms and one decimal below 10 ms, as
    in Table 4 of the paper. Only for stages timed with pkg/clock (e2e rows
    from be90c7d on); older rows were timed with a clock of about 1 ms."""
    if x is not None and 0 < x < 0.001:
        return f"${x * 1e6:.0f}\\,\\mu$s"
    if x is not None and 0.001 <= x < 0.01:
        return f"{x * 1000:.1f}\\,ms"
    return fmt_s(x)


def fmt_int(x):
    return "--" if x is None else f"{x:,}".replace(",", "{,}")


def fmt_bytes(b):
    if b is None:
        return "--"
    if b < 1024:
        return f"{b}\\,B"
    return f"{b / 1024:.1f}\\,KiB"


def pow2(x, digits=1):
    return f"$2^{{{x:.{digits}f}}}$"


def write(name, body):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(body, encoding="utf-8")
    print(f"wrote {OUT / name}")


def table_params():
    ps = latest(rows("params.jsonl"), lambda r: r["params"])
    acc = latest(rows("accuracy.jsonl"), lambda r: r["params"])
    sec = latest(rows("security.jsonl"), lambda r: r["params"])
    cols = [ps.get(s) for s in SETS]

    def cell(r, f):
        return "--" if r is None else f(r)

    def scale(r):
        if r["scheme"] == "BFV":
            return f"$t_{{\\mathrm{{pt}}}}=2^{{{r['log2_t']}}}$" if "log2_t" in r else "--"
        if "log2_scale_enc" not in r:
            return "--"
        return f"$\\Delta=2^{{{r['log2_scale_enc'] + r['log2_scale_pt']}}}$"

    def deliverable(r):
        if r["case"] == 1:
            return f"{r['deliverable_kib']:.1f}\\,KiB, {fmt_int(r['blob_elements'])} el."
        return f"{r['deliverable_bits']} bits"

    def accuracy(s):
        a = acc.get(s)
        if a is None:
            return "--"
        if s.endswith("bfv"):
            return f"exact ({fmt_int(a['trials'])})" if a.get("exact") else "FAILED"
        return pow2(a["log2_max_abs_error"], 2) + f" ({fmt_int(a['trials'])})"

    def noise(s):
        a = acc.get(s)
        return "--" if a is None else pow2(a["log2_max_noise"]) + " / " + pow2(a["log2_noise_bound"])

    def security(s, r):
        e = sec.get(s)
        if e is not None:
            cell = f"{e['rough_min']:.1f}"
            return cell + (f" ({e['full_min']:.1f})" if "full_min" in e else "")
        return "--" if r is None else f"{r['security_bits_table2']}\\textsuperscript{{a}}"

    lines = [
        "% Generated by scripts/gen_v8_tables.py from results/v8/params.jsonl, accuracy.jsonl and security.jsonl.",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        " & " + " & ".join(LABEL[s] for s in SETS) + " \\\\",
        "\\midrule",
        "Ring degree $N$ & " + " & ".join(cell(r, lambda r: f"$2^{{{int(math.log2(r['n']))}}}$" if "n" in r else "$2^{13}$") for r in cols) + " \\\\",
        "Prime chain (bits) & " + " & ".join(cell(r, lambda r: "$" + "{\\cdot}".join(str(b) for b in r["chain_bits"]) + "$") for r in cols) + " \\\\",
        "$\\log_2 Q$ & " + " & ".join(cell(r, lambda r: f"{r['log2_Q']:.2f}") for r in cols) + " \\\\",
        "$t_{\\mathrm{pt}}$ or $\\Delta$ & " + " & ".join(cell(r, scale) for r in cols) + " \\\\",
        "$\\log_2 q_{\\mathrm{del}}$ & " + " & ".join(cell(r, lambda r: f"{r['log2_q_del']:.2f}" if r.get("q_del") else "--") for r in cols) + " \\\\",
        "Worst-case noise $\\log_2 B$ & " + " & ".join(cell(r, lambda r: f"{r['log2_B']:.2f}") for r in cols) + " \\\\",
        "$\\sigma_{\\mathrm{fl}}$ (required) & " + " & ".join(cell(r, lambda r: f"{r['sigma_fl']} ({r['sigma_required']})") for r in cols) + " \\\\",
        "Decoding term / $\\tau$ & " + " & ".join(cell(r, lambda r: f"{r['decode_term']:.3f}" if r["scheme"] == "BFV" else pow2(r["log2_tau"], 2)) for r in cols) + " \\\\",
        "Deliverable & " + " & ".join(cell(r, deliverable) for r in cols) + " \\\\",
        "Largest error (inputs) & " + " & ".join(accuracy(s) for s in SETS) + " \\\\",
        "Pre-flood noise / bound & " + " & ".join(noise(s) for s in SETS) + " \\\\",
        ("Security (bits, core-SVP; full)" if any("full_min" in e for e in sec.values()) else "Security (bits, core-SVP)")
        + " & " + " & ".join(security(s, r) for s, r in zip(SETS, cols)) + " \\\\",
        "\\bottomrule",
        "\\end{tabular}",
    ]
    if not sec:
        lines.append("% a: Table 2 of the paper (estimated at q = 2^logQ); the estimator was not run on the actual chains.")
    else:
        lines.append(f"% Security: lattice estimator {next(iter(sec.values())).get('estimator', '')}, LWE.estimate.rough (core-SVP,"
                     " min over attacks) on the actual Q, equal to Table 2 at q = 2^logQ to 0.1 bit; in parentheses"
                     " LWE.estimate with all attacks.")
    write("tab_v8_params.tex", "\n".join(lines) + "\n")


STAGES = [
    ("Seller registration (slot, $\\pi_{\\text{key}}$, $\\pi_{\\text{enc}}$)", ["seller.prepare_slots"]),
    ("Buyer key and $\\pi_{\\text{key}}$", ["buyer.keygen_and_pi_key"]),
    ("Buyer's check of the offer", ["buyer.check_offer"]),
    ("Order: encrypt or evaluate, and prove", ["buyer.prepare_order"]),
    ("Seller's check of the order", ["seller.check_order"]),
    ("Claim: HE (and blob) or partial decryption", ["seller.he_and_blob", "seller.partial_decrypt"]),
    ("Claim proof", ["seller.prove"]),
    ("Buyer's decoding", ["buyer.decode"]),
]

BYTES = [
    ("Key material (DA)", ["buyer_key", "slot_key"]),
    ("Data ciphertext $c_1$ (DA)", ["slot_c1"]),
    ("Order input (DA)", ["order_ciphertext", "order_c21"]),
    ("Off-chain proofs (DA)", ["pi_key", "pi_enc", "pi_member", "pi_eval"]),
    ("Deliverable (claim)", ["deliverable"]),
    ("Claim proof", ["claim_proof"]),
]

LEDGER = [
    ("Ledger: registration calldata", ["registerOffer", "registerKey"]),
    ("Ledger: order and claim calldata", ["order", "claimBlob", "claimDec"]),
]


def table_costs():
    happy = e2e_latest("happy")
    reps = {s: len(rs) for s, rs in happy.items()}
    lines = [
        "% Generated by scripts/gen_v8_tables.py from results/v8/e2e.jsonl (cmd/e2e -scale full);",
        "% times are medians of the happy runs (" + ", ".join(f"{s}: {n}" for s, n in reps.items()) + ").",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        " & " + " & ".join(LABEL[s] for s in SETS) + " \\\\",
        "\\midrule",
    ]

    def med(s, f):
        vals = [v for v in (f(r) for r in happy.get(s, [])) if v is not None]
        return statistics.median(vals) if vals else None

    for label, keys in STAGES:
        cells = []
        for s in SETS:
            v = med(s, lambda r: sum(r["stages_s"][k] for k in keys if k in r["stages_s"]) if any(k in r["stages_s"] for k in keys) else None)
            cells.append(fmt_s_fine(v))
        lines.append(f"{label} & " + " & ".join(cells) + " \\\\")
    lines.append("\\midrule")
    for label, keys in BYTES:
        cells = [fmt_bytes(med(s, lambda r: sum(r["bytes"][k] for k in keys if k in r["bytes"]) if any(k in r.get("bytes", {}) for k in keys) else None)) for s in SETS]
        lines.append(f"{label} & " + " & ".join(cells) + " \\\\")
    for label, keys in LEDGER:
        cells = [fmt_bytes(med(s, lambda r: sum(r["calldata_bytes"][k] for k in keys if k in r.get("calldata_bytes", {})) or None)) for s in SETS]
        lines.append(f"{label} & " + " & ".join(cells) + " \\\\")
    lines.append("Blobs of the claim & " + " & ".join(fmt_int(med(s, lambda r: r.get("blobs", 0))) for s in SETS) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    write("tab_v8_costs.tex", "\n".join(lines) + "\n")


GAS = [
    ("registerOffer", "registerOffer"),
    ("registerKey (Case 1)", "registerKey"),
    ("order", "order"),
    ("claim (proof verified)", "claimBlob|claimDec"),
    ("refund", "refund"),
    ("reject", "reject"),
    ("retire", "retire"),
]

# Each function from the scenario where it succeeds: the claim and the
# registrations from happy runs, refund from refund runs, reject from reject
# runs, retire from late runs (whose claim reverts).
SOURCE = {"registerOffer": "happy", "registerKey": "happy", "order": "happy", "claimBlob": "happy",
          "claimDec": "happy", "refund": "refund", "reject": "reject", "retire": "late"}


def table_gas():
    by = {scn: e2e_latest(scn) for scn in set(SOURCE.values())}
    lines = [
        "% Generated by scripts/gen_v8_tables.py from results/v8/e2e.jsonl (medians over the runs of the latest commit).",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        "Function & " + " & ".join(LABEL[s] for s in SETS) + " \\\\",
        "\\midrule",
    ]

    def gas(s, fn):
        vals = [r["gas"][fn] for r in by[SOURCE[fn]].get(s, []) if fn in r["gas"]]
        return int(statistics.median(vals)) if vals else None

    for label, keys in GAS:
        cells = []
        for s in SETS:
            v = None
            for k in keys.split("|"):
                v = gas(s, k) if gas(s, k) is not None else v
            cells.append(fmt_int(v))
        lines.append(f"\\texttt{{{label}}} & " + " & ".join(cells) + " \\\\")
    blob = [fmt_int(int(statistics.median([r["blob_gas"] for r in by["happy"].get(s, []) if r.get("blob_gas")])) if any(r.get("blob_gas") for r in by["happy"].get(s, [])) else None) for s in SETS]
    lines.append("Blob gas of the claim & " + " & ".join(blob) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    write("tab_v8_gas.tex", "\n".join(lines) + "\n")


CIRCUITS = [("pi_key", "$\\pi_{\\text{key}}$"), ("pi_member", "$\\pi_{\\text{member}}$"), ("pi_enc", "$\\pi_{\\text{enc}}$"),
            ("pi_eval_c2", "$\\pi_{\\text{eval}}$ (Case 2)"), ("pi_dec", "$\\pi_{\\text{dec}}$"), ("pi_eval_c1", "$\\pi_{\\text{eval}}$ (Case 1)")]


def table_zk():
    zk = rows("zk.jsonl")
    measured = latest(zk, lambda r: (r["circuit"], r["params"]), lambda r: r.get("prove_s", 0) > 0 and r["params"] in SETS)
    compiled = latest(zk, lambda r: (r["circuit"], r["params"]), lambda r: r["params"] in SETS)
    reps = sorted({r.get("reps", 1) for r in measured.values()})
    lines = [
        "% Generated by scripts/gen_v8_tables.py from results/v8/zk.jsonl; prove and verify are medians of "
        + "/".join(str(n) for n in reps) + " run(s).",
        "\\begin{tabular}{llrrrrrrr}",
        "\\toprule",
        "Proof & Setting & Constraints & Public & Setup & Prove & Verify & Proof & Peak \\\\",
        "\\midrule",
    ]
    for c, label in CIRCUITS:
        for s in SETS:
            r = measured.get((c, s)) or compiled.get((c, s))
            if r is None:
                continue
            m = bool(r.get("prove_s"))
            lines.append(" & ".join([label, LABEL[s], fmt_int(r["constraints"]), fmt_int(r["public_inputs"]),
                                     fmt_s(r.get("setup_s")) if m else "--",
                                     fmt_s(r.get("prove_s")) if m else "--",
                                     fmt_s(r.get("verify_s")) if m else "--",
                                     f"{r['proof_bytes']}\\,B" if m and r.get("proof_bytes") else "--",
                                     f"{r['peak_commit_gib']:.1f}\\,GiB" if m else "--"]) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    write("tab_v8_zk.tex", "\n".join(lines) + "\n")


# Option O2: the witness that each proof would encrypt for straight-line
# extraction, as (proof, setting, label, bits per entry, entries). Field
# capacity: 254 bits on BLS12-381 (Case 1), 253 on BN254 (Case 2).
SE_TARGETS = [
    ("pi_key", "case1_bfv", "secret $s$", 2, 8192), ("pi_key", "case2_bfv", "secret $s$", 2, 8192),
    ("pi_member", "case1_bfv", "weights $w$", 9, 31), ("pi_member", "case1_ckks", "weights $w$", 16, 31),
    ("pi_eval_c2", "case2_bfv", "weights $w$", 9, 31), ("pi_eval_c2", "case2_ckks", "weights $w$", 16, 31),
    ("pi_enc", "case2_bfv", "data $S$", 26, 528), ("pi_enc", "case2_ckks", "data $S$", 21, 528),
    ("pi_eval_c1", "case1_bfv", "data $S$", 26, 528), ("pi_eval_c1", "case1_ckks", "data $S$", 21, 528),
    ("pi_dec", "case2_bfv", "secret $s$", 2, 8192), ("pi_dec", "case2_ckks", "secret $s$", 2, 8192),
]
CIRCUIT_LABEL = dict(CIRCUITS)


def se_model():
    """Fixed and per-element constraints of the encryption gadget (least squares)."""
    rs = [r for r in rows("se.jsonl") if r.get("field") == "bls12_381"]
    pts = sorted({(r["elements"], r["constraints"]) for r in rs})
    if len(pts) < 2:
        return None
    n = len(pts)
    mx = sum(x for x, _ in pts) / n
    my = sum(y for _, y in pts) / n
    slope = sum((x - mx) * (y - my) for x, y in pts) / sum((x - mx) ** 2 for x, _ in pts)
    return my - slope * mx, slope


def table_se():
    zk = rows("zk.jsonl")
    measured = latest(zk, lambda r: (r["circuit"], r["params"]), lambda r: r.get("prove_s", 0) > 0)
    compiled = latest(zk, lambda r: (r["circuit"], r["params"]))
    model = se_model()
    lines = [
        "% Generated by scripts/gen_v8_tables.py from results/v8/zk.jsonl and se.jsonl (option O2).",
        "\\begin{tabular}{llrrrrr}",
        "\\toprule",
        "Proof & Setting & Extracted & Elements & Constraints & Added & Overhead \\\\",
        "\\midrule",
    ]
    for c, setting, label, bits, entries in SE_TARGETS:
        cap = 254 if setting.startswith("case1") else 253
        elems = -(-entries // (cap // bits))
        base = (measured.get((c, setting)) or compiled.get((c, setting)) or {}).get("constraints")
        se = (measured.get((c + "_se", setting)) or compiled.get((c + "_se", setting)) or {}).get("constraints")
        if se is not None and base is not None:
            added, mark = se - base, ""
        elif model is not None:
            added, mark = round(model[0] + model[1] * elems), "\\textsuperscript{e}"
        else:
            continue
        over = f"{100 * added / base:.1f}\\,\\%" if base else "--"
        lines.append(" & ".join([CIRCUIT_LABEL[c], LABEL[setting], label, str(elems), fmt_int(base),
                                 fmt_int(added) + mark, over]) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    if model is not None:
        lines.append(f"% e: estimated as {model[0]:.0f} + {model[1]:.0f} constraints per encrypted element (two scalar"
                     " multiplications on the embedded curve, one keystream hash per element).")
    for setting in ["case1_bfv", "case1_ckks"]:
        b, e = measured.get(("pi_member", setting)), measured.get(("pi_member_se", setting))
        if b and e:
            lines.append(f"% {setting}: pi_member prove {b['prove_s']:.2f} s -> {e['prove_s']:.2f} s, verify"
                         f" {1000 * b['verify_s']:.1f} -> {1000 * e['verify_s']:.1f} ms, peak {b['peak_commit_gib']:.2f}"
                         f" -> {e['peak_commit_gib']:.2f} GiB (medians of {e.get('reps', 1)} runs).")
    write("tab_v8_se.tex", "\n".join(lines) + "\n")


# Option O1: (circuit, setting, label, main circuit). pi_seal of Case 2 seals
# the one element p and is the same circuit for BFV and CKKS.
O1_ROWS = [
    ("pi_seal", "case1_bfv", "$\\pi_{\\text{seal}}$", None),
    ("pi_seal", "case1_ckks", "$\\pi_{\\text{seal}}$", None),
    ("pi_seal", "case2_bfv", "$\\pi_{\\text{seal}}$", None),
    ("pi_eval_c1_sealed", "case1_bfv", "$\\pi_{\\text{eval}}$ (Case 1), sealed", "pi_eval_c1"),
    ("pi_eval_c1_sealed", "case1_ckks", "$\\pi_{\\text{eval}}$ (Case 1), sealed", "pi_eval_c1"),
    ("pi_dec_sealed", "case2_bfv", "$\\pi_{\\text{dec}}$, sealed", "pi_dec"),
    ("pi_dec_sealed", "case2_ckks", "$\\pi_{\\text{dec}}$, sealed", "pi_dec"),
]


def table_o1():
    zk = rows("zk.jsonl")
    measured = latest(zk, lambda r: (r["circuit"], r["params"]), lambda r: r.get("prove_s", 0) > 0)
    blob = {s: r.get("blob_elements") for s, r in latest(rows("params.jsonl"), lambda r: r["params"]).items()}
    lines = [
        "% Generated by scripts/gen_v8_tables.py from results/v8/zk.jsonl (option O1); prove and verify are medians.",
        "\\begin{tabular}{llrrrrrrr}",
        "\\toprule",
        "Proof & Setting & Elements & Constraints & vs.\\ main & Setup & Prove & Verify & Peak \\\\",
        "\\midrule",
    ]
    for c, setting, label, main in O1_ROWS:
        r = measured.get((c, setting))
        if r is None:
            continue
        elems = blob.get(setting) or 1
        vs = "--"
        if main and measured.get((main, setting)):
            base = measured[(main, setting)]["constraints"]
            d = r["constraints"] - base
            vs = f"{'+' if d >= 0 else '$-$'}{fmt_int(abs(d))} ({'+' if d >= 0 else '$-$'}{abs(100 * d / base):.2f}\\,\\%)"
        where = "Case 2" if c == "pi_seal" and setting.startswith("case2") else LABEL[setting]
        # A measured row without verify_s read 0: below the clock's resolution.
        lines.append(" & ".join([label, where, fmt_int(elems), fmt_int(r["constraints"]), vs, fmt_s(r.get("setup_s")),
                                 fmt_s(r.get("prove_s")), fmt_s(r.get("verify_s", 0.0)),
                                 f"{r['peak_commit_gib']:.1f}\\,GiB"]) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}",
              "% Elements: field elements of the deliverable that pi_seal seals and h_D covers. The sealed proofs"
              " keep the deliverable behind the salted h_D; the main proofs are those of tab_v8_zk.tex.",
              "% Verify: single verifications take about a millisecond, the resolution of the Go clock on"
              " Windows; a median of 0 is shown as <1 ms."]
    write("tab_v8_o1.tex", "\n".join(lines) + "\n")


# Option O6: the postings of one exchange, as (label, message keys of the
# bytes map); the payload is the value with its proof.
O6_POSTS = [("Key material", ["key", "slot_key"]), ("Data ciphertext $c_1$", ["slot_c1"]), ("Order input", ["order"])]
O6_STAGES = ["seller.post_slots", "buyer.post_key", "buyer.post_order"]
CALLDATA_FLOOR = 40  # EIP-7623: 10 gas per token, 4 tokens per nonzero byte
TX_BASE = 21000


def table_o6():
    blob = e2e_latest("happy", board="blob")
    if not blob:
        return
    reps = {s: len(rs) for s, rs in blob.items()}

    def med(s, f):
        vals = [v for v in (f(r) for r in blob.get(s, [])) if v is not None]
        return statistics.median(vals) if vals else None

    lines = [
        "% Generated by scripts/gen_v8_tables.py from results/v8/e2e.jsonl (cmd/e2e -scale full -board blob);",
        "% medians of the happy runs (" + ", ".join(f"{s}: {n}" for s, n in reps.items()) + ").",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        " & " + " & ".join(LABEL[s] for s in SETS) + " \\\\",
        "\\midrule",
    ]
    for label, msgs in O6_POSTS:
        cells = []
        for s in SETS:
            pl = med(s, lambda r: next((r["bytes"][f"post_{m}_payload"] for m in msgs if f"post_{m}_payload" in r.get("bytes", {})), None))
            nb = med(s, lambda r: next((r["bytes"][f"post_{m}_blobs"] for m in msgs if f"post_{m}_blobs" in r.get("bytes", {})), None))
            cells.append("--" if pl is None else f"{fmt_bytes(pl)} ({int(nb)})")
        lines.append(f"{label} (payload, blobs) & " + " & ".join(cells) + " \\\\")
    lines.append("Blobs per exchange (postings and claim) & " + " & ".join(fmt_int(med(s, lambda r: r.get("blobs", 0))) for s in SETS) + " \\\\")
    post_gas = {s: med(s, lambda r: sum(v for k, v in r["gas"].items() if k.startswith("post_")) or None) for s in SETS}
    lines.append("Gas of the posting transactions & " + " & ".join(fmt_int(None if v is None else int(v)) for v in post_gas.values()) + " \\\\")
    lines.append("Blob gas per exchange & " + " & ".join(fmt_int(med(s, lambda r: r.get("blob_gas"))) for s in SETS) + " \\\\")
    lines.append("Posting time & " + " & ".join(fmt_s(med(s, lambda r: sum(r["stages_s"].get(k, 0) for k in O6_STAGES))) for s in SETS) + " \\\\")

    def calldata(r):
        pls = [v for k, v in r.get("bytes", {}).items() if k.startswith("post_") and k.endswith("_payload")]
        txs = sum(1 for k in r["gas"] if k.startswith("post_"))  # one posting transaction of each kind here
        return TX_BASE * txs + CALLDATA_FLOOR * sum(pls) if pls else None

    lines.append("Same payloads as calldata (gas, floor) & " + " & ".join(fmt_int(None if med(s, calldata) is None else int(med(s, calldata))) for s in SETS) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}",
              "% Payloads: the value (compact encoding) with its proof and an 8-byte header, 254 bits per blob element"
              " (130,048 bytes per blob). Calldata: the same posting transactions (21,000 each) at the EIP-7623"
              " floor of 40 gas per nonzero byte, for comparison only."]
    write("tab_v8_o6.tex", "\n".join(lines) + "\n")


def table_o7():
    cost = rows("archive.jsonl")
    if not cost:
        return
    c = cost[-1]
    arch = e2e_latest("archive")
    runs = [r for rs in arch.values() for r in rs]
    lines = [
        "% Generated by scripts/gen_v8_tables.py from results/v8/archive.jsonl (TestO7ArchiveCost, means of "
        + str(c["reps"]) + " runs) and e2e.jsonl (scenario archive, W cut to 128 blocks).",
        "\\begin{tabular}{lr}",
        "\\toprule",
        "Archive of the claim blobs (option O7) & Per claim \\\\",
        "\\midrule",
        f"Stored: the blob (its commitment is recomputed on reading) & {fmt_bytes(c['blob_bytes'])} \\\\",
        f"Store: fetch from the network, check against the versioned hash, write & {c['store_ms']:.1f}\\,ms \\\\",
        f"Read back and check against the versioned hash & {c['read_ms']:.1f}\\,ms \\\\",
        f"\\quad of which the check (KZG commitment and versioned hash) & {c['check_ms']:.1f}\\,ms \\\\",
    ]
    if runs:
        sets = " and ".join(LABEL[s] for s in SETS if s in arch)
        lines.append(f"Exchanges decoded from the archive after $W$ ({sets}) & {sum(r['correct'] for r in runs)} of {len(runs)} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    write("tab_v8_o7.tex", "\n".join(lines) + "\n")


if __name__ == "__main__":
    table_params()
    table_costs()
    table_gas()
    table_zk()
    table_se()
    table_o1()
    table_o6()
    table_o7()
