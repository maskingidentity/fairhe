// Command keys sets up the verification keys of the proofs and writes the
// deployment manifest:
//
//	go run ./cmd/keys -scale small -out keys/small
//	go run ./cmd/keys -scale full -out keys/full [-only pi_dec_case2_bfv,...]
//
// Each entry gets <name>.pk, <name>.vk and a manifest record with its VK ID
// (keccak256 of the verifying key), constraint count and circuit constants;
// on-chain proofs (pi_dec, Case 1 pi_eval) also get their Solidity verifier
// under contracts/v8 and contracts/out. The setup is local, a stand-in for
// the ceremony of the paper's Setup (i).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"fairhe/pkg/zk/keys"
	"fairhe/pkg/zk/registry"
)

func main() {
	scale := flag.String("scale", "small", "small or full")
	out := flag.String("out", "", "output directory (default keys/<scale>)")
	only := flag.String("only", "", "comma-separated entry names (default all)")
	flag.Parse()
	sc := registry.Scale(*scale)
	if sc != registry.Small && sc != registry.Full {
		log.Fatalf("unknown scale %q", *scale)
	}
	dir := *out
	if dir == "" {
		dir = "keys/" + *scale
	}
	entries, err := registry.All(sc)
	if err != nil {
		log.Fatal(err)
	}
	want := map[string]bool{}
	for _, n := range strings.Split(*only, ",") {
		if n != "" {
			want[n] = true
		}
	}
	m := &keys.Manifest{Scale: *scale, Created: time.Now().UTC().Format(time.RFC3339),
		Note: "local Groth16 setup (not a ceremony); VK ID = keccak256 of the raw verifying key"}
	if old, err := keys.ReadManifest(dir, sc); err == nil && len(want) > 0 {
		m.Records = old.Records // keep the records of entries not redone
	}
	for _, e := range entries {
		if len(want) > 0 && !want[e.Name()] {
			continue
		}
		start := time.Now()
		rec, _, _, _, err := keys.Setup(e, dir, sc)
		if err != nil {
			log.Fatal(err)
		}
		m.Records = replace(m.Records, *rec)
		fmt.Printf("%-24s %-6s %9d constraints %6d public  setup %6.1fs  total %6.1fs  vk %s\n",
			rec.Name, rec.Curve, rec.Constraints, rec.PublicInputs, rec.SetupSeconds, time.Since(start).Seconds(), rec.VKID[:18])
		if err := keys.WriteManifest(dir, m); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Fprintf(os.Stderr, "manifest: %s/manifest_%s.json (%d records)\n", dir, *scale, len(m.Records))
}

func replace(rs []keys.Record, r keys.Record) []keys.Record {
	for i := range rs {
		if rs[i].Name == r.Name {
			rs[i] = r
			return rs
		}
	}
	return append(rs, r)
}
