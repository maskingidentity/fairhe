// Command params writes the parameter table of the implementation (Table 3
// of the paper) to results/v8/params.jsonl: for each of the four
// settings the explicit prime chain, log2 Q, q_del, the flood width and the
// one the class requires, the worst-case noise, the decoding term or the
// CKKS tolerance, the deliverable size, and the security figure of Table 2
// (estimated separately by scripts/security_v8.py).
//
//	go run ./cmd/params
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/zkmeasure"
)

// Row is one parameter set.
type Row struct {
	Time          string   `json:"time"`
	Params        string   `json:"params"`
	Scheme        string   `json:"scheme"`
	Case          int      `json:"case"`
	ChainBits     []int    `json:"chain_bits"`
	Chain         []uint64 `json:"chain"`
	LogQ          float64  `json:"log2_Q"`
	QDel          string   `json:"q_del,omitempty"`
	LogQDel       float64  `json:"log2_q_del,omitempty"`
	SigmaFl       int      `json:"sigma_fl"`
	SigmaRequired int      `json:"sigma_required"`
	LogB          float64  `json:"log2_B"`
	DecodeTerm    float64  `json:"decode_term,omitempty"`
	LogTau        float64  `json:"log2_tau,omitempty"`
	N             int      `json:"n"`
	BErr          int      `json:"b_err"`
	LambdaS       int      `json:"lambda_s"`
	LogT          int      `json:"log2_t,omitempty"`         // BFV plaintext modulus t = 2^LogT
	LogScaleEnc   int      `json:"log2_scale_enc,omitempty"` // CKKS scale of the encrypted operand
	LogScalePt    int      `json:"log2_scale_pt,omitempty"`  // CKKS scale of the plaintext operand
	FracBits      int      `json:"frac_bits,omitempty"`      // CKKS fixed-point unit 2^-FracBits
	DeliverBits   int      `json:"deliverable_bits"`
	DeliverKiB    float64  `json:"deliverable_kib"`
	BlobElements  int      `json:"blob_elements,omitempty"`
	SecurityBits  int      `json:"security_bits_table2"`
	MarginsOK     bool     `json:"margins_ok"`
	GitCommit     string   `json:"git_commit"`
}

// Security figures of Table 2 (lattice estimator, core-SVP, at q = 2^logQ).
var security = map[string]int{"case1_bfv": 187, "case1_ckks": 264, "case2_bfv": 205, "case2_ckks": 239}

func main() {
	out := filepath.Join("results", "v8", "params.jsonl")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		log.Fatal(err)
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, lit := range rlwe.Flagship() {
		p := rlwe.MustParams(lit)
		rep := p.CheckMargins(bounds(p))
		row := Row{
			Time: time.Now().UTC().Format(time.RFC3339), Params: lit.Name, Scheme: p.Scheme().String(), Case: int(p.Case()),
			Chain: lit.Q, LogQ: rep.LogQ, SigmaFl: rep.SigmaFl, SigmaRequired: rep.SigmaRequired, LogB: rep.LogB,
			DecodeTerm: rep.DecodeTerm, LogTau: rep.LogTau, SecurityBits: security[lit.Name], MarginsOK: rep.OK(),
			N: p.N(), BErr: lit.BErr, LambdaS: lit.LambdaS, GitCommit: zkmeasure.GitCommit(),
		}
		if p.Scheme() == rlwe.BFV {
			row.LogT = lit.LogT
		} else {
			row.LogScaleEnc, row.LogScalePt, row.FracBits = lit.LogScaleEnc, lit.LogScalePt, lit.FracBits
		}
		for _, q := range lit.Q {
			row.ChainBits = append(row.ChainBits, new(big.Int).SetUint64(q).BitLen())
		}
		if q := p.QDel(); q != nil {
			row.QDel, row.LogQDel = q.String(), rep.LogQDel
			bits := new(big.Int).Sub(q, big.NewInt(1)).BitLen()
			row.DeliverBits = (p.N() + 1) * bits
			per := 254 / bits
			row.BlobElements = (p.N() + 1 + per - 1) / per
		} else {
			row.DeliverBits = new(big.Int).Sub(p.Q(), big.NewInt(1)).BitLen()
		}
		row.DeliverKiB = float64(row.DeliverBits) / 8 / 1024
		if err := enc.Encode(row); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%-10s chain %v log2Q %.8f sigma %d/%d log2B %.3f decode %.4f log2tau %.4f deliver %.1f KiB ok=%v\n",
			row.Params, row.ChainBits, row.LogQ, row.SigmaFl, row.SigmaRequired, row.LogB, row.DecodeTerm, row.LogTau, row.DeliverKiB, row.MarginsOK)
	}
}

func bounds(p *rlwe.Params) rlwe.ClassBounds {
	switch {
	case p.Case() == rlwe.Case1 && p.Scheme() == rlwe.BFV:
		return rlwe.ClassBounds{PtNormL1: valuation.SNormL1MaxInt(), FMax: new(big.Rat).SetInt(valuation.FMaxInt())}
	case p.Case() == rlwe.Case1:
		return rlwe.ClassBounds{PtNormL1: valuation.SNormL1MaxFixed(), FMax: valuation.FMaxFixed()}
	case p.Scheme() == rlwe.BFV:
		return rlwe.ClassBounds{PtNormL1: valuation.WHatNormL1MaxInt(), FMax: new(big.Rat).SetInt(valuation.FMaxInt())}
	}
	return rlwe.ClassBounds{PtNormL1: valuation.WHatNormL1MaxFixed(), FMax: valuation.FMaxFixed()}
}
