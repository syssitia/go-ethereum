package tests

import (
	"testing"
	"runtime"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg"
	"github.com/ethereum/go-ethereum/params"
	"github.com/protolambda/go-kzg/bls"
)

func randomBlob() []bls.Fr {
	blob := make([]bls.Fr, params.FieldElementsPerBlob)
	for i := 0; i < len(blob); i++ {
		blob[i] = *bls.RandomFr()
	}
	return blob
}

func BenchmarkBlobToKzg(b *testing.B) {
	blob := randomBlob()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kzg.BlobToKzg(blob)
	}
}

// the strategy is to use single verification because its massively parallelizable each kzg check can be in its own thread without locking
// so we would calculate KZG commitment in evaluation form using FFT, use fiat shamir strategy on X, compute proof at X, evaluate to get Y
// prover can publically store commitment to polynomial (in evaluation form), Y evaluated point, and the proof of point X on the polynomial
// the verifier will recompute X using FS (sha256 of blob + commitment) and verify against commitment/proof/X/Y 
func BenchmarkVerifyKzgProof(b *testing.B) {
	runtime.GOMAXPROCS(0)
	// First let's do some go-kzg preparations to be able to convert polynomial between coefficient and evaluation form
	var blobs []types.Blob
	var commitments []types.KZGCommitment
	var proofs []types.KZGProof
	var yFrs []types.BLSFieldElement
	var versionhashes []common.Hash
	for i := 0; i < params.MaxBlobsPerBlock; i++ {
		var blob types.Blob = make([]types.BLSFieldElement, params.FieldElementsPerBlob)
		polynomial := randomBlob()
		for j := range polynomial {
			blob[j] = bls.FrTo32(&polynomial[j])
		}
		// Get polynomial in evaluation form
		evalPoly, err := kzg.FFTSettings.FFT(polynomial, false)
		if err != nil {
			b.Fatal(err)
		}
		blobs = append(blobs, blob)
		// Create a commitment
		commitment := kzg.BlobToKzg(evalPoly)
		// create challenges
		var blobKzg types.KZGCommitment
		copy(blobKzg[:], bls.ToCompressedG1(commitment))
		commitments = append(commitments, blobKzg)
		sum, err := types.SszHash(&types.BlobAndCommitment{Blob: &blob, BlobKzg: &blobKzg})
		if err != nil {
			b.Fatal(err)
		}
		var xFr bls.Fr
		var yFr bls.Fr
		types.HashToFr(&xFr, sum)
		var proof types.KZGProof
		copy(proof[:], bls.ToCompressedG1(kzg.ComputeProof(polynomial, &xFr, kzg.KzgSetupG1)))
		proofs = append(proofs, proof)
		bls.EvalPolyAt(&yFr, polynomial, &xFr)
		yFrs = append(yFrs, bls.FrTo32(&yFr))
		versionhashes = append(versionhashes, blobKzg.ComputeVersionedHash())
	}

	// Get actual evaluation at x
	result := true
	var wg sync.WaitGroup
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for i := 0; i < params.MaxBlobsPerBlock; i++ {
			wg.Add(1)
			go types.VerifyKZG(&versionhashes[i], &blobs[i], &commitments[i], &yFrs[i], &proofs[i], &wg, &result)
		}
		wg.Wait()
		if result != true {
			b.Fatal("failed proof verification")
		}
	}
}
