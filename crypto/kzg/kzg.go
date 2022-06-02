package kzg

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/params"
	"github.com/protolambda/go-kzg/bls"
)

// KZG CRS for G2
var KzgSetupG2 []bls.G2Point

// KZG CRS for commitment computation
var KzgSetupLagrange []bls.G1Point

// KZG CRS for G1 (only used in tests (for proof creation))
var KzgSetupG1 []bls.G1Point

// Convert polynomial in evaluation form to KZG commitment
func BlobToKzg(eval []bls.Fr) *bls.G1Point {
	return bls.LinCombG1(KzgSetupLagrange, eval)
}

// Verify a KZG proof
func VerifyKzgProof(commitment *bls.G1Point, x *bls.Fr, y *bls.Fr, proof *bls.G1Point) bool {
	// Verify the pairing equation
	var xG2 bls.G2Point
	bls.MulG2(&xG2, &bls.GenG2, x)
	var sMinuxX bls.G2Point
	bls.SubG2(&sMinuxX, &KzgSetupG2[1], &xG2)
	var yG1 bls.G1Point
	bls.MulG1(&yG1, &bls.GenG1, y)
	var commitmentMinusY bls.G1Point
	bls.SubG1(&commitmentMinusY, commitment, &yG1)

	return bls.PairingsVerify(&commitmentMinusY, &bls.GenG2, proof, &sMinuxX)
}

type BlobsBatch struct {
	sync.Mutex
	init                bool
	aggregateCommitment bls.G1Point
	aggregateBlob       [params.FieldElementsPerBlob]bls.Fr
}

func (batch *BlobsBatch) Join(commitments []*bls.G1Point, blobs [][]bls.Fr) error {
	batch.Lock()
	defer batch.Unlock()
	if len(commitments) != len(blobs) {
		return fmt.Errorf("expected commitments len %d to equal blobs len %d", len(commitments), len(blobs))
	}
	if !batch.init && len(commitments) > 0 {
		batch.init = true
		bls.CopyG1(&batch.aggregateCommitment, commitments[0])
		copy(batch.aggregateBlob[:], blobs[0])
		commitments = commitments[1:]
		blobs = blobs[1:]
	}
	for i, commit := range commitments {
		batch.join(commit, blobs[i])
	}
	return nil
}

func (batch *BlobsBatch) join(commitment *bls.G1Point, blob []bls.Fr) {
	// we multiply the input we are joining with a random scalar, so we can add it to the aggregate safely
	randomScalar := bls.RandomFr()

	// TODO: instead of computing the lin-comb of the commitments on the go, we could buffer
	// the random scalar and commitment, and run a LinCombG1 over all of them during Verify()
	var tmpG1 bls.G1Point
	bls.MulG1(&tmpG1, commitment, randomScalar)
	bls.AddG1(&batch.aggregateCommitment, &batch.aggregateCommitment, &tmpG1)

	var tmpFr bls.Fr
	for i := 0; i < params.FieldElementsPerBlob; i++ {
		bls.MulModFr(&tmpFr, &blob[i], randomScalar)
		bls.AddModFr(&batch.aggregateBlob[i], &batch.aggregateBlob[i], &tmpFr)
	}
}

func (batch *BlobsBatch) Verify() error {
	batch.Lock()
	defer batch.Unlock()
	if !batch.init {
		return nil // empty batch
	}
	// Compute both MSMs and check equality
	lResult := bls.LinCombG1(KzgSetupLagrange, batch.aggregateBlob[:])
	if !bls.EqualG1(lResult, &batch.aggregateCommitment) {
		return errors.New("BlobsBatch failed to Verify")
	}
	return nil
}

type JSONTrustedSetup struct {
	SetupG1       []bls.G1Point
	SetupG2       []bls.G2Point
	SetupLagrange []bls.G1Point
}

// Initialize KZG subsystem (load the trusted setup data)
func SetupKZG() {
	var parsedSetup = JSONTrustedSetup{}
	// TODO: This is dirty. KZG setup should be loaded using an actual config file directive
	err := json.Unmarshal([]byte(KZGSetupStr), &parsedSetup)
	if err != nil {
		panic(err)
	}
	KzgSetupG2 = parsedSetup.SetupG2
	KzgSetupLagrange = parsedSetup.SetupLagrange
	KzgSetupG1 = parsedSetup.SetupG1
}
/*func init() {
	var parsedSetup = JSONTrustedSetup{}
	// TODO: This is dirty. KZG setup should be loaded using an actual config file directive
	err := json.Unmarshal([]byte(KZGSetupStr), &parsedSetup)
	if err != nil {
		panic(err)
	}
	KzgSetupG2 = parsedSetup.SetupG2
	KzgSetupLagrange = parsedSetup.SetupLagrange
	KzgSetupG1 = parsedSetup.SetupG1
}*/