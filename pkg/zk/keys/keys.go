// Package keys sets up and manages the verification keys of the proofs: for
// each registry entry it compiles the circuit, runs a local Groth16 setup (a
// stand-in for the market-wide ceremony of Setup (i) in the paper, recorded
// as a limitation), writes the proving and verifying keys, derives the VK ID
// (keccak256 of the serialised verifying key), exports and compiles the
// Solidity verifier of on-chain proofs, and records everything in a manifest
// that the settlement deployment reads.
package keys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"fairhe/pkg/onchain"
	"fairhe/pkg/zk/registry"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/ethereum/go-ethereum/crypto"
)

// Record describes one verification key.
type Record struct {
	Name             string            `json:"name"`
	Circuit          string            `json:"circuit"`
	Params           string            `json:"params"`
	Curve            string            `json:"curve"`
	OnChain          bool              `json:"on_chain"`
	VKID             string            `json:"vk_id"`
	Constraints      int               `json:"constraints"`
	PublicInputs     int               `json:"public_inputs"`
	Commitments      int               `json:"commitments"`
	PKFile           string            `json:"pk_file"`
	VKFile           string            `json:"vk_file"`
	Verifier         string            `json:"verifier,omitempty"`
	VerifierArtifact string            `json:"verifier_artifact,omitempty"`
	Constants        map[string]string `json:"constants"`
	SetupSeconds     float64           `json:"setup_s"`
	GitCommit        string            `json:"git_commit"`
}

// Manifest is the deployment input: every verification key of a scale.
type Manifest struct {
	Scale   string   `json:"scale"`
	Created string   `json:"created"`
	Note    string   `json:"note"`
	Records []Record `json:"records"`
}

// VKID returns keccak256 of the raw serialisation of a verifying key.
func VKID(vk groth16.VerifyingKey) (string, error) {
	var buf bytes.Buffer
	if _, err := vk.WriteRawTo(&buf); err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(crypto.Keccak256(buf.Bytes())), nil
}

// Setup compiles an entry, sets it up, writes its keys under dir and, for
// an on-chain proof, its Solidity verifier; it returns the record and the
// in-memory keys.
func Setup(e registry.Entry, dir string, scale registry.Scale) (*Record, constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	cs, res, err := zkmeasure.Compile(e.Curve, e.New(), e.Circuit, e.Params)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	start := time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("keys: setup %s: %w", e.Name(), err)
	}
	rec := &Record{
		Name: e.Name(), Circuit: e.Circuit, Params: e.Params, Curve: res.Curve, OnChain: e.OnChain,
		Constraints: res.Constraints, PublicInputs: res.Public, Commitments: res.Commitments,
		Constants: e.Constants, SetupSeconds: time.Since(start).Seconds(), GitCommit: res.GitCommit,
		PKFile: e.Name() + ".pk", VKFile: e.Name() + ".vk",
	}
	if rec.VKID, err = VKID(vk); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := writeTo(filepath.Join(dir, rec.PKFile), pk); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := writeTo(filepath.Join(dir, rec.VKFile), vk); err != nil {
		return nil, nil, nil, nil, err
	}
	if e.OnChain {
		if err := EnsureVerifier(rec, vk, scale); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	return rec, cs, pk, vk, nil
}

func writeTo(path string, v interface {
	WriteRawTo(w io.Writer) (int64, error)
}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = v.WriteRawTo(f)
	return err
}

// LoadKeys reads the keys of a record from dir.
func LoadKeys(rec Record, dir string, e registry.Entry) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk := groth16.NewProvingKey(e.Curve)
	vk := groth16.NewVerifyingKey(e.Curve)
	for _, x := range []struct {
		path string
		v    io.ReaderFrom
	}{{filepath.Join(dir, rec.PKFile), pk}, {filepath.Join(dir, rec.VKFile), vk}} {
		f, err := os.Open(x.path)
		if err != nil {
			return nil, nil, err
		}
		_, err = x.v.ReadFrom(f)
		f.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("keys: read %s: %w", x.path, err)
		}
	}
	if id, err := VKID(vk); err != nil || id != rec.VKID {
		return nil, nil, fmt.Errorf("keys: %s: verifying key does not match the manifest", rec.Name)
	}
	return pk, vk, nil
}

// WriteManifest writes the manifest of a scale to dir/manifest_<scale>.json.
func WriteManifest(dir string, m *Manifest) error {
	raw, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest_"+m.Scale+".json"), raw, 0o644)
}

// ReadManifest reads dir/manifest_<scale>.json.
func ReadManifest(dir string, scale registry.Scale) (*Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest_"+string(scale)+".json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	return &m, json.Unmarshal(raw, &m)
}

// EnsureVerifier (re)generates the Solidity verifier of an on-chain proof
// from its verifying key. The name carries the VK ID, so verifiers of
// different setups never overwrite each other's artifacts.
func EnsureVerifier(rec *Record, vk groth16.VerifyingKey, scale registry.Scale) error {
	name := "Verifier_" + rec.Name + "_" + rec.VKID[2:10]
	if scale == registry.Small {
		name += "_Small"
	}
	if _, err := onchain.CompileVerifier(vk, name); err != nil {
		return err
	}
	rec.Verifier = name
	rec.VerifierArtifact = filepath.ToSlash(filepath.Join("contracts", "out", name+".json"))
	return nil
}
