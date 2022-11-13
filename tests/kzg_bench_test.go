package tests

import (
	"testing"

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
		kzg.VerifyBlobs(commitments, &blobs)
	}
}
