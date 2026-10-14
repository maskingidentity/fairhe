package keys

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// Prove proves an assignment and returns the serialised proof (gnark's
// binary encoding; on-chain proofs pass the Solidity prover option).
func Prove(curve ecc.ID, cs constraint.ConstraintSystem, pk groth16.ProvingKey, assignment frontend.Circuit, opts ...backend.ProverOption) ([]byte, groth16.Proof, error) {
	w, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	proof, err := groth16.Prove(cs, pk, w, opts...)
	if err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), proof, nil
}

// VerifyOffchain verifies a serialised proof against the public part of a
// statement (an assignment whose public fields are set).
func VerifyOffchain(curve ecc.ID, vk groth16.VerifyingKey, public frontend.Circuit, proofBytes []byte) error {
	proof := groth16.NewProof(curve)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("keys: read proof: %w", err)
	}
	pw, err := frontend.NewWitness(public, curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	return groth16.Verify(proof, vk, pw)
}
