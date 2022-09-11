package kzg

import (
	"math/big"

	"github.com/ethereum/go-ethereum/params"
	"github.com/protolambda/go-kzg/bls"
)

var (
	BLSModulus *big.Int
	Domain     [params.FieldElementsPerBlob]*big.Int
	DomainFr   [params.FieldElementsPerBlob]bls.Fr
)

func initDomain() {
	BLSModulus = new(big.Int)
	BLSModulus.SetString("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 0)

	// ROOT_OF_UNITY = pow(PRIMITIVE_ROOT, (MODULUS - 1) // WIDTH, MODULUS)
	primitiveRoot := big.NewInt(7)
	width := big.NewInt(int64(params.FieldElementsPerBlob))
	exp := new(big.Int).Div(new(big.Int).Sub(BLSModulus, big.NewInt(1)), width)
	rootOfUnity := new(big.Int).Exp(primitiveRoot, exp, BLSModulus)
	for i := 0; i < params.FieldElementsPerBlob; i++ {
		Domain[i] = new(big.Int).Exp(rootOfUnity, big.NewInt(int64(i)), BLSModulus)
		_ = BigToFr(&DomainFr[i], Domain[i])
	}
}

func BigToFr(out *bls.Fr, in *big.Int) bool {
	var b [32]byte
	inb := in.Bytes()
	copy(b[32-len(inb):], inb)
	// again, we have to double convert as go-kzg only accepts little-endian
	for i := 0; i < 16; i++ {
		b[31-i], b[i] = b[i], b[31-i]
	}
	return bls.FrFrom32(out, b)
}


// Helper: invert the divisor, then multiply
func polyFactorDiv(dst *bls.Fr, a *bls.Fr, b *bls.Fr) {
	// TODO: use divmod instead.
	var tmp bls.Fr
	bls.InvModFr(&tmp, b)
	bls.MulModFr(dst, &tmp, a)
}

// Helper: Long polynomial division for two polynomials in coefficient form
func polyLongDiv(dividend []bls.Fr, divisor []bls.Fr) []bls.Fr {
	a := make([]bls.Fr, len(dividend))
	for i := 0; i < len(a); i++ {
		bls.CopyFr(&a[i], &dividend[i])
	}
	aPos := len(a) - 1
	bPos := len(divisor) - 1
	diff := aPos - bPos
	out := make([]bls.Fr, diff+1)
	for diff >= 0 {
		quot := &out[diff]
		polyFactorDiv(quot, &a[aPos], &divisor[bPos])
		var tmp, tmp2 bls.Fr
		for i := bPos; i >= 0; i-- {
			// In steps: a[diff + i] -= b[i] * quot
			// tmp =  b[i] * quot
			bls.MulModFr(&tmp, quot, &divisor[i])
			// tmp2 = a[diff + i] - tmp
			bls.SubModFr(&tmp2, &a[diff+i], &tmp)
			// a[diff + i] = tmp2
			bls.CopyFr(&a[diff+i], &tmp2)
		}
		aPos -= 1
		diff -= 1
	}
	return out
}

// Helper: Compute proof for polynomial
func ComputeProof(poly []bls.Fr, xFr* bls.Fr, crsG1 []bls.G1Point) *bls.G1Point {
	// divisor = [-x, 1]
	divisor := [2]bls.Fr{}
	bls.SubModFr(&divisor[0], &bls.ZERO, xFr)
	bls.CopyFr(&divisor[1], &bls.ONE)
	// quot = poly / divisor
	quotientPolynomial := polyLongDiv(poly, divisor[:])
	// evaluate quotient poly at shared secret, in G1
	return bls.LinCombG1(crsG1[:len(quotientPolynomial)], quotientPolynomial)
}
