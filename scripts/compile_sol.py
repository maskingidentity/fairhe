"""Compile one Solidity source to an ABI+bytecode JSON artifact.

Used for every contract of the settlement: gnark-exported verifiers (BN254 for pi_dec, BLS12-381 with the
EIP-2537 precompiles for the Case 1 pi_eval) and the market contract. solc
0.8.24 via py-solc-x, optimizer runs=200, and evmVersion "cancun" by default:
0.8.24 defaults to "shanghai", which lacks the blobhash opcode and the mcopy
that gnark's verifier template emits on its commitment branch.

The source is passed as standard-JSON content (read by Python), so solc never
opens the non-ASCII repository path. The artifact records sha256 of the
source so that a Go test can detect a stale artifact after a fresh Groth16
setup.

Usage: python scripts/compile_sol.py SRC.sol OUT.json CONTRACT [--evm cancun]
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import solcx

SOLC_VERSION = "0.8.24"
OPTIMIZER_RUNS = 200


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out")
    ap.add_argument("contract")
    ap.add_argument("--evm", default="cancun")
    args = ap.parse_args()

    src = Path(args.src)
    raw = src.read_bytes()
    solcx.install_solc(SOLC_VERSION)
    standard_input = {
        "language": "Solidity",
        "sources": {src.name: {"content": raw.decode("utf-8")}},
        "settings": {
            "evmVersion": args.evm,
            "optimizer": {"enabled": True, "runs": OPTIMIZER_RUNS},
            "outputSelection": {
                "*": {"*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"]}
            },
        },
    }
    result = solcx.compile_standard(standard_input, solc_version=SOLC_VERSION)
    for msg in result.get("errors", []):
        print(f"[{msg['severity']}] {msg.get('formattedMessage', msg['message'])}", file=sys.stderr)
        if msg["severity"] == "error":
            return 1
    try:
        artifact = result["contracts"][src.name][args.contract]
    except KeyError:
        print(f"contract {args.contract} not found in solc output", file=sys.stderr)
        return 1
    out = {
        "contractName": args.contract,
        "source": src.name,
        "solcVersion": SOLC_VERSION,
        "optimizerRuns": OPTIMIZER_RUNS,
        "evmVersion": args.evm,
        "sourceSha256": hashlib.sha256(raw).hexdigest(),
        "abi": artifact["abi"],
        "bin": artifact["evm"]["bytecode"]["object"],
        "binRuntime": artifact["evm"]["deployedBytecode"]["object"],
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=1), encoding="utf-8")
    runtime = len(out["binRuntime"]) // 2
    print(f"wrote {out_path} (creation {len(out['bin']) // 2} bytes, runtime {runtime} bytes)")
    if runtime > 24576:
        print("runtime bytecode exceeds the EIP-170 limit", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
