package tests

import (
	"math"
	"fmt"
	"testing"
	"runtime"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg"
	"github.com/ethereum/go-ethereum/params"
	gokzg "github.com/protolambda/go-kzg"
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

func BenchmarkVerifyBlobsWithoutKZGProof(b *testing.B) {
	var blobs [][]bls.Fr
	var commitments []*bls.G1Point
	for i := 0; i < 32; i++ {
		blob := randomBlob()
		blobs = append(blobs, blob)
		commitments = append(commitments, kzg.BlobToKzg(blob))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kzg.VerifyBlobsLegacy(commitments, blobs)
	}
}
func BenchmarkVerifyBlobs(b *testing.B) {
	blobs := make([]types.Blob, params.MaxBlobsPerBlock)
	var commitments []types.KZGCommitment
	var hashes []common.Hash
	for i := 0; i < len(blobs); i++ {
		tmp := randomBlob()
		blobs[i] = make(types.Blob, params.FieldElementsPerBlob)
		for j := range tmp {
			blobs[i][j] = bls.FrTo32(&tmp[j])
		}
		c, _, ok := blobs[i].ComputeCommitment()
		if !ok {
			b.Fatal("Could not compute commitment")
		}
		commitments = append(commitments, c)
		hashes = append(hashes, c.ComputeVersionedHash())
	}
	_, _, aggregatedProof, err := types.Blobs(blobs).ComputeCommitmentsAndAggregatedProof()
	if err != nil {
		b.Fatal(err)
	}
	wrapData := &types.BlobTxWrapper{
		BlobKzgs:           commitments,
		Blobs:              blobs,
		KzgAggregatedProof: aggregatedProof,
		BlobVersionedHashes: hashes,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := wrapData.Verify(); err != nil {
			b.Fatal(err)
		}
	}
}
func verifykzgworker(b *testing.B, blob types.Blob, commitment bls.G1Point, yFr bls.Fr, proof bls.G1Point, wg *sync.WaitGroup, result *bool) {
	defer wg.Done()
	// create challenges
	var blobKzg types.KZGCommitment
	copy(blobKzg[:], bls.ToCompressedG1(&commitment))
	sum, err := types.SszHash(&types.BlobAndCommitment{Blob: blob, BlobKzg: blobKzg})
	if err != nil {
		*result = false
		return
	}
	var xFr bls.Fr
	types.HashToFr(&xFr, sum)
	resultKzg := kzg.VerifyKzgProof(&commitment, &xFr, &yFr, &proof)
	if resultKzg != true {
		*result = false
	}
}

func BenchmarkVerifyKzgProofOld(b *testing.B) {
	// First let's do some go-kzg preparations to be able to convert polynomial between coefficient and evaluation form
	fs := gokzg.NewFFTSettings(uint8(math.Log2(params.FieldElementsPerBlob)))

	// Create testing polynomial (in coefficient form)
	polynomial := make([]bls.Fr, params.FieldElementsPerBlob)
	for i := uint64(0); i < params.FieldElementsPerBlob; i++ {
		bls.CopyFr(&polynomial[i], bls.RandomFr())
	}

	// Get polynomial in evaluation form
	evalPoly, err := fs.FFT(polynomial, false)
	if err != nil {
		b.Fatal(err)
	}

	// Now let's start testing the kzg module
	// Create a commitment
	commitment := kzg.BlobToKzg(evalPoly)

	// Create proof for testing
	xFr := bls.RandomFr()
	proof := ComputeProof(polynomial, xFr, kzg.KzgSetupG1)

	// Get actual evaluation at x
	var value bls.Fr
	bls.EvalPolyAt(&value, polynomial, xFr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Verify kzg proof
		if kzg.VerifyKzgProof(commitment, xFr, &value, proof) != true {
			b.Fatal("failed proof verification")
		}
	}
}
// the strategy is to use single verification because its massively parallelizable each kzg check can be in its own thread without locking
// so we would calculate KZG commitment in evaluation form using FFT, use fiat shamir strategy on X, compute proof at X, evaluate to get Y
// prover can publically store commitment to polynomial (in evaluation form), Y evaluated point, and the proof of point X on the polynomial
// the verifier will recompute X using FS (sha256 of blob + commitment) and verify against commitment/proof/X/Y 
func BenchmarkVerifyKzgProof(b *testing.B) {
	runtime.GOMAXPROCS(0)
	// First let's do some go-kzg preparations to be able to convert polynomial between coefficient and evaluation form
	fs := gokzg.NewFFTSettings(uint8(math.Log2(params.FieldElementsPerBlob)))
	var blobs []types.Blob
	var commitments []bls.G1Point
	var proofs []bls.G1Point
	var yFrs []bls.Fr
	for i := 0; i < params.MaxBlobsPerBlock; i++ {
		var blob types.Blob = make([]types.BLSFieldElement, params.FieldElementsPerBlob)
		polynomial := randomBlob()
		for j := range polynomial {
			blob[j] = bls.FrTo32(&polynomial[j])
		}
		// Get polynomial in evaluation form
		evalPoly, err := fs.FFT(polynomial, false)
		if err != nil {
			b.Fatal(err)
		}
		blobs = append(blobs, blob)
		// Create a commitment
		commitment := kzg.BlobToKzg(evalPoly)
		commitments = append(commitments, *commitment)
		// create challenges
		var blobKzg types.KZGCommitment
		copy(blobKzg[:], bls.ToCompressedG1(commitment))
		sum, err := types.SszHash(&types.BlobAndCommitment{Blob: blob, BlobKzg: blobKzg})
		if err != nil {
			b.Fatal(err)
		}
		var xFr bls.Fr
		var yFr bls.Fr
		types.HashToFr(&xFr, sum)
		proofs = append(proofs, *ComputeProof(polynomial, &xFr, kzg.KzgSetupG1))
		bls.EvalPolyAt(&yFr, polynomial, &xFr)
		yFrs = append(yFrs, yFr)
	}

	// Get actual evaluation at x
	result := true
	var wg sync.WaitGroup
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for i := 0; i < params.MaxBlobsPerBlock; i++ {
			wg.Add(1)
			go verifykzgworker(b, blobs[i], commitments[i], yFrs[i], proofs[i], &wg, &result)
		}
		wg.Wait()
		if result != true {
			b.Fatal("failed proof verification")
		}
	}
}

func BenchmarkVerifyMultiple(b *testing.B) {
	runBenchmark := func(siz int) {
		b.Run(fmt.Sprintf("%d", siz), func(b *testing.B) {
			var blobsSet [][]types.Blob
			var commitmentsSet [][]types.KZGCommitment
			var hashesSet [][]common.Hash
			for i := 0; i < siz; i++ {
				var blobs []types.Blob
				var commitments []types.KZGCommitment
				var hashes []common.Hash
				for i := 0; i < params.MaxBlobsPerBlock; i++ {
					var blobElements types.Blob = make([]types.BLSFieldElement, params.FieldElementsPerBlob)
					blob := randomBlob()
					for j := range blob {
						blobElements[j] = bls.FrTo32(&blob[j])
					}
					blobs = append(blobs, blobElements)
					c, _, ok := blobElements.ComputeCommitment()
					if !ok {
						b.Fatal("Could not compute commitment")
					}
					commitments = append(commitments, c)
					hashes = append(hashes, c.ComputeVersionedHash())
				}
				blobsSet = append(blobsSet, blobs)
				commitmentsSet = append(commitmentsSet, commitments)
				hashesSet = append(hashesSet, hashes)
			}

			var txs []*types.BlobTxWrapper
			for i := range blobsSet {
				blobs := blobsSet[i]
				commitments := commitmentsSet[i]
				hashes := hashesSet[i]

		
				_, _, aggregatedProof, err := types.Blobs(blobs).ComputeCommitmentsAndAggregatedProof()
				if err != nil {
					b.Fatal(err)
				}
				wrapData := &types.BlobTxWrapper{
					BlobKzgs:           commitments,
					Blobs:              blobs,
					KzgAggregatedProof: aggregatedProof,
					BlobVersionedHashes: hashes,
				}
				txs = append(txs, wrapData)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, tx := range txs {
					if err := tx.Verify(); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}

	runBenchmark(2)
	//runBenchmark(4)
	//runBenchmark(8)
	//runBenchmark(16)
	//runBenchmark(32)
}

func BenchmarkBatchVerifyWithoutKZGProofs(b *testing.B) {
	runBenchmark := func(siz int) {
		b.Run(fmt.Sprintf("%d", siz), func(b *testing.B) {
			var blobsSet [][][]bls.Fr
			var commitmentsSet [][]*bls.G1Point
			for i := 0; i < siz; i++ {
				var blobs [][]bls.Fr
				var commitments []*bls.G1Point
				for i := 0; i < params.MaxBlobsPerBlock; i++ {
					blob := randomBlob()
					blobs = append(blobs, blob)
					commitments = append(commitments, kzg.BlobToKzg(blob))
				}
				blobsSet = append(blobsSet, blobs)
				commitmentsSet = append(commitmentsSet, commitments)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var batchVerify kzg.BlobsBatch
				for i := range blobsSet {
					if err := batchVerify.Join(commitmentsSet[i], blobsSet[i]); err != nil {
						b.Fatalf("unable to join: %v", err)
					}
				}
				if err := batchVerify.Verify(); err != nil {
					b.Fatalf("batch verify failed: %v", err)
				}
			}
		})
	}

	runBenchmark(1)
	//runBenchmark(4)
	//runBenchmark(8)
	//runBenchmark(16)
	//runBenchmark(32)
}


func BenchmarkVerifyBlob(b *testing.B) {
	blobs := make([]types.Blob, 1)
	var commitments []types.KZGCommitment
	var hashes []common.Hash
	for i := 0; i < len(blobs); i++ {
		tmp := randomBlob()
		blobs[i] = make(types.Blob, params.FieldElementsPerBlob)
		for j := range tmp {
			blobs[i][j] = bls.FrTo32(&tmp[j])
		}
		c, _, ok := blobs[i].ComputeCommitment()
		if !ok {
			b.Fatal("Could not compute commitment")
		}
		commitments = append(commitments, c)
		hashes = append(hashes, c.ComputeVersionedHash())
	}
	wrapData := &types.BlobTxWrapperSingle{
		BlobKzg:           commitments[0],
		Blob:              blobs[0],
		BlobVersionedHash: hashes[0],
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := wrapData.Verify(); err != nil {
			b.Fatal(err)
		}
	}
}