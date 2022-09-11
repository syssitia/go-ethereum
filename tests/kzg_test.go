package tests

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"

	"github.com/ethereum/go-ethereum/crypto/kzg"

	gokzg "github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)
// Test the go-kzg library for correctness
// Do the trusted setup, generate a polynomial, commit to it, make proof, verify proof.
func TestGoKzg(t *testing.T) {
	// Generate roots of unity
	// Create a CRS with `n` elements for `s`
	s := "1927409816240961209460912649124"
	kzgSetupG1, kzgSetupG2 := gokzg.GenerateTestingSetup(s, params.FieldElementsPerBlob)

	// Wrap it all up in KZG settings
	kzgSettings := gokzg.NewKZGSettings(kzg.FFTSettings, kzgSetupG1, kzgSetupG2)

	kzgSetupLagrange, err := kzg.FFTSettings.FFTG1(kzgSettings.SecretG1[:params.FieldElementsPerBlob], true)
	if err != nil {
		t.Fatal(err)
	}

	// Create testing polynomial (in coefficient form)
	polynomial := make([]bls.Fr, params.FieldElementsPerBlob)
	for i := uint64(0); i < params.FieldElementsPerBlob; i++ {
		bls.CopyFr(&polynomial[i], bls.RandomFr())
	}

	// Get polynomial in evaluation form
	evalPoly, err := kzg.FFTSettings.FFT(polynomial, false)
	if err != nil {
		t.Fatal(err)
	}

	// Get commitments to polynomial
	commitmentByCoeffs := kzgSettings.CommitToPoly(polynomial)
	commitmentByEval := gokzg.CommitToEvalPoly(kzgSetupLagrange, evalPoly)
	if !bls.EqualG1(commitmentByEval, commitmentByCoeffs) {
		t.Fatalf("expected commitments to be equal, but got:\nby eval: %s\nby coeffs: %s",
			commitmentByEval, commitmentByCoeffs)
	}

	// Create proof for testing
	xFr := bls.RandomFr()
	proof := kzg.ComputeProof(polynomial, xFr, kzg.KzgSetupG1)

	// Get actual evaluation at x
	var value bls.Fr
	bls.EvalPolyAt(&value, polynomial, xFr)

	// Check proof against evaluation
	if !kzgSettings.CheckProofSingle(commitmentByEval, proof, xFr, &value) {
		t.Fatal("could not verify proof")
	}
}

// Test the geth KZG module (use our trusted setup instead of creating a new one)
func TestKzg(t *testing.T) {
	// Create testing polynomial (in coefficient form)
	polynomial := make([]bls.Fr, params.FieldElementsPerBlob)
	for i := uint64(0); i < params.FieldElementsPerBlob; i++ {
		bls.CopyFr(&polynomial[i], bls.RandomFr())
	}

	// Get polynomial in evaluation form
	evalPoly, err := kzg.FFTSettings.FFT(polynomial, false)
	if err != nil {
		t.Fatal(err)
	}

	// Now let's start testing the kzg module
	// Create a commitment
	commitment := kzg.BlobToKzg(evalPoly)

	// Create proof for testing
	xFr := bls.RandomFr()
	proof := kzg.ComputeProof(polynomial, xFr, kzg.KzgSetupG1)

	// Get actual evaluation at x
	var value bls.Fr
	bls.EvalPolyAt(&value, polynomial, xFr)
	t.Log("value\n", bls.FrStr(&value))

	// Verify kzg proof
	if kzg.VerifyKzgProof(commitment, xFr, &value, proof) != true {
		t.Fatal("failed proof verification")
	}
}

type JSONTestdataBlobs struct {
	KzgBlob1 string
	KzgBlob2 string
}

// Helper: Create test vector for the PointEvaluation precompile
func TestPointEvaluationTestVector(t *testing.T) {
	// Create testing polynomial
	polynomial := make([]bls.Fr, params.FieldElementsPerBlob)
	for i := uint64(0); i < params.FieldElementsPerBlob; i++ {
		bls.CopyFr(&polynomial[i], bls.RandomFr())
	}

	// Get polynomial in evaluation form
	evalPoly, err := kzg.FFTSettings.FFT(polynomial, false)
	if err != nil {
		t.Fatal(err)
	}

	// Create a commitment
	commitment := kzg.BlobToKzg(evalPoly)

	// Create proof for testing
	xFr := bls.RandomFr()
	proof := kzg.ComputeProof(polynomial, xFr, kzg.KzgSetupG1)

	// Get actual evaluation at x
	var y bls.Fr
	bls.EvalPolyAt(&y, polynomial, xFr)

	// Verify kzg proof
	if kzg.VerifyKzgProof(commitment, xFr, &y, proof) != true {
		panic("failed proof verification")
	}

	var commitmentBytes types.KZGCommitment
	copy(commitmentBytes[:], bls.ToCompressedG1(commitment))

	versionedHash := commitmentBytes.ComputeVersionedHash()

	proofBytes := bls.ToCompressedG1(proof)

	xBytes := bls.FrTo32(xFr)
	yBytes := bls.FrTo32(&y)

	calldata := append(versionedHash[:], xBytes[:]...)
	calldata = append(calldata, yBytes[:]...)
	calldata = append(calldata, commitmentBytes[:]...)
	calldata = append(calldata, proofBytes...)

	t.Logf("test-vector: %x", calldata)

	precompile := vm.PrecompiledContractsRollux[common.BytesToAddress([]byte{0x14})]
	if _, err := precompile.Run(calldata, nil); err != nil {
		t.Fatalf("expected point verification to succeed")
	}
	// change a byte of the proof
	calldata[144+7] ^= 42
	if _, err := precompile.Run(calldata, nil); err == nil {
		t.Fatalf("expected point verification to fail")
	}
}
