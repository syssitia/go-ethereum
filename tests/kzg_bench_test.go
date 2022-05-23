package tests

import (
	"github.com/ethereum/go-ethereum/crypto/kzg"
	"github.com/ethereum/go-ethereum/params"
	gokzg "github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
	"math"
	"sync"
	"testing"
	"runtime"
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
func BenchmarkVerifyBlobs(b *testing.B) {
	var blobs [][]bls.Fr
	var commitments []*bls.G1Point
	for i := 0; i < 32; i++ {
		blob := randomBlob()
		blobs = append(blobs, blob)
		commitments = append(commitments, kzg.BlobToKzg(blob))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := kzg.VerifyBlobs(commitments, blobs)
		if err != nil {
			b.Fatal(err)
		}
	}
}
func verifykzg(commitment bls.G1Point, xFr bls.Fr, value bls.Fr, proof bls.G1Point, wg *sync.WaitGroup, result *bool) {
	defer wg.Done()
	resultKzg := kzg.VerifyKzgProof(&commitment, &xFr, &value, &proof)
	if resultKzg != true {
		*result = false
	}
}
func BenchmarkVerifyKzgProof(b *testing.B) {
	runtime.GOMAXPROCS(0)
	// First let's do some go-kzg preparations to be able to convert polynomial between coefficient and evaluation form
	fs := gokzg.NewFFTSettings(uint8(math.Log2(params.FieldElementsPerBlob)))

	// Create testing polynomial (in coefficient form)
	polynomial := make([]bls.Fr, params.FieldElementsPerBlob, params.FieldElementsPerBlob)
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
	
	xFr := bls.RandomFr()
	proof := ComputeProof(polynomial, xFr, kzg.KzgSetupG1)

	// Get actual evaluation at x
	var value bls.Fr
	bls.EvalPolyAt(&value, polynomial, xFr)
	commitment := kzg.BlobToKzg(evalPoly)
	// Create proof for testing
	result := true
	var wg sync.WaitGroup
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 23; j++ {
			wg.Add(1)
			go verifykzg(*commitment, *xFr, value, *proof, &wg, &result)
		}
		if result != true {
			b.Fatal("failed proof verification")
		}
		wg.Wait()
	}
}