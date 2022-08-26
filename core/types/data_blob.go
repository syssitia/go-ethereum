package types

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/protolambda/go-kzg/bls"
	"github.com/syscoin/btcd/wire"
)

// Compressed BLS12-381 G1 element
type KZGCommitment [48]byte

type NEVMBlob struct {
	VersionHash common.Hash
	Commitment  *bls.G1Point
	Blob        []bls.Fr
}
type NEVMBlobs struct {
	Blobs []*NEVMBlob
}

// Verify that the list of `commitments` maps to the list of `blobs`
//
// This is an optimization over the naive approach (found in the EIP) of iteratively checking each blob against each
// commitment.  The naive approach requires n*l scalar multiplications where `n` is the number of blobs and `l` is
// FIELD_ELEMENTS_PER_BLOB to compute the commitments for all blobs.
//
// A more efficient approach is to build a linear combination of all blobs and commitments and check all of them in a
// single multi-scalar multiplication.
//
// The MSM would look like this (for three blobs with two field elements each):
//     r_0(b0_0*L_0 + b0_1*L_1) + r_1(b1_0*L_0 + b1_1*L_1) + r_2(b2_0*L_0 + b2_1*L_1)
// which we would need to check against the linear combination of commitments: r_0*C_0 + r_1*C_1 + r_2*C_2
// In the above, `r` are the random scalars of the linear combination, `b0` is the zero blob, `L` are the elements
// of the KZG_SETUP_LAGRANGE and `C` are the commitments provided.
//
// By regrouping the above equation around the `L` points we can reduce the length of the MSM further
// (down to just `n` scalar multiplications) by making it look like this:
//     (r_0*b0_0 + r_1*b1_0 + r_2*b2_0) * L_0 + (r_0*b0_1 + r_1*b1_1 + r_2*b2_1) * L_1
func (n *NEVMBlobs) Verify() error {
	lenBlobs := len(n.Blobs)
	// Prepare objects to hold our two MSMs
	lPoints := make([]bls.G1Point, params.FieldElementsPerBlob)
	lScalars := make([]bls.Fr, params.FieldElementsPerBlob)
	rPoints := make([]bls.G1Point, lenBlobs)
	rScalars := make([]bls.Fr, lenBlobs)

	// Generate list of random scalars for lincomb
	rList := make([]bls.Fr, lenBlobs)
	for i := 0; i < lenBlobs; i++ {
		bls.CopyFr(&rList[i], bls.RandomFr())
	}

	// Build left-side MSM:
	//   (r_0*b0_0 + r_1*b1_0 + r_2*b2_0) * L_0 + (r_0*b0_1 + r_1*b1_1 + r_2*b2_1) * L_1
	for c := 0; c < params.FieldElementsPerBlob; c++ {
		var sum bls.Fr
		for i := 0; i < lenBlobs; i++ {
			var tmp bls.Fr

			r := rList[i]
			blob := n.Blobs[i]

			bls.MulModFr(&tmp, &r, &blob.Blob[c])
			bls.AddModFr(&sum, &sum, &tmp)
		}
		lScalars[c] = sum
		lPoints[c] = kzg.KzgSetupLagrange[c]
	}

	// Build right-side MSM: r_0 * C_0 + r_1 * C_1 + r_2 * C_2 + ...
	for i, blob := range n.Blobs {
		rScalars[i] = rList[i]
		rPoints[i] = *blob.Commitment
	}

	// Compute both MSMs and check equality
	lResult := bls.LinCombG1(lPoints, lScalars)
	rResult := bls.LinCombG1(rPoints, rScalars)
	if !bls.EqualG1(lResult, rResult) {
		return errors.New("VerifyBlobs failed")
	}

	// TODO: Potential improvement is to unify both MSMs into a single MSM, but you would need to batch-invert the `r`s
	// of the right-side MSM to effectively pull them to the left side.

	return nil
}
func (n *NEVMBlob) FromWire(NEVMBlobWire *wire.NEVMBlob) error {
	var err error
	n.VersionHash = common.BytesToHash(NEVMBlobWire.VersionHash)
	if n.VersionHash[0] != params.BlobCommitmentVersionKZG {
		return errors.New("invalid versioned hash")
	}
	var commitment KZGCommitment
	lenCommitment := commitment.FixedLength()
	copy(commitment[:], NEVMBlobWire.Blob[0:lenCommitment])
	NEVMBlobWire.Blob = NEVMBlobWire.Blob[lenCommitment:]
	if commitment.ComputeVersionedHash() != n.VersionHash {
		return errors.New("mismatched versioned hash")
	}
	n.Commitment, err = commitment.Point()
	if err != nil {
		return errors.New("invalid proof")
	}
	lenBlob := len(NEVMBlobWire.Blob)
	if lenBlob < 1024 {
		return errors.New("Blob too small")
	}
	if lenBlob%32 != 0 {
		return errors.New("Blob should be a factor of 32")
	}
	n.Blob = make([]bls.Fr, params.FieldElementsPerBlob)
	numElements := lenBlob / 32
	if numElements > params.FieldElementsPerBlob {
		return errors.New("Blob too big")
	}
	var inputPoint [32]byte
	for i := 0; i < numElements; i++ {
		copy(inputPoint[:32], NEVMBlobWire.Blob[i*32:(i+1)*32])
		ok := bls.FrFrom32(&n.Blob[i], inputPoint)
		if !ok {
			return fmt.Errorf("FromWire: invalid chunk (element %d inputPoint %v)", i, inputPoint)
		}
	}
	return nil
}
func (n *NEVMBlob) FromBytes(blob []byte) error {
	lenBlob := len(blob)
	if lenBlob == 0 {
		return errors.New("empty blob")
	}
	if lenBlob < 1024 {
		return errors.New("Blob too small")
	}
	if lenBlob%32 != 0 {
		return errors.New("Blob should be a factor of 32")
	}
	n.Blob = make([]bls.Fr, params.FieldElementsPerBlob)
	numElements := lenBlob / 32
	if numElements > params.FieldElementsPerBlob {
		return errors.New("Blob too big")
	}
	var inputPoint [32]byte
	for i := 0; i < numElements; i++ {
		copy(inputPoint[:32], blob[i*32:(i+1)*32])
		ok := bls.FrFrom32(&n.Blob[i], inputPoint)
		if !ok {
			return fmt.Errorf("FromBytes: invalid chunk (element %d inputPoint %v)", i, inputPoint)
		}
	}

	// Get versioned hash out of input points
	n.Commitment = kzg.BlobToKzg(n.Blob)
	// need the full field elements array above to properly calculate and validate blob to kzg,
	// can splice it after for network purposes and later when deserializing will again create full elements array to input spliced data from network
	n.Blob = n.Blob[0:numElements]
	var compressedCommitment KZGCommitment
	copy(compressedCommitment[:], bls.ToCompressedG1(n.Commitment))
	n.VersionHash = compressedCommitment.ComputeVersionedHash()
	return nil
}
func (n *NEVMBlob) Deserialize(bytesIn []byte) error {
	var NEVMBlobWire wire.NEVMBlob
	r := bytes.NewReader(bytesIn)
	err := NEVMBlobWire.Deserialize(r)
	if err != nil {
		log.Error("NEVMBlockConnect: could not deserialize", "err", err)
		return err
	}
	err = n.FromWire(&NEVMBlobWire)
	if err != nil {
		return err
	}
	return nil
}
func (n *NEVMBlob) Serialize() ([]byte, error) {
	var NEVMBlobWire wire.NEVMBlob
	var err error
	NEVMBlobWire.VersionHash = n.VersionHash.Bytes()
	var tmpCommit KZGCommitment
	lenBlobData := len(n.Blob) * 32
	NEVMBlobWire.Blob = make([]byte, 0, lenBlobData+int(tmpCommit.FixedLength()))
	NEVMBlobWire.Blob = append(NEVMBlobWire.Blob, bls.ToCompressedG1(n.Commitment)...)
	for i := range n.Blob {
		bBytes := bls.FrTo32(&n.Blob[i])
		NEVMBlobWire.Blob = append(NEVMBlobWire.Blob, bBytes[:]...)
	}
	var buffer bytes.Buffer
	err = NEVMBlobWire.Serialize(&buffer)
	if err != nil {
		log.Error("NEVMBlockConnect: could not serialize", "err", err)
		return nil, err
	}
	return buffer.Bytes(), nil
}
func (n *NEVMBlobs) Deserialize(bytesIn []byte) error {
	var NEVMBlobsWire wire.NEVMBlobs
	r := bytes.NewReader(bytesIn)
	err := NEVMBlobsWire.Deserialize(r)
	if err != nil {
		log.Error("NEVMBlobs: could not deserialize", "err", err)
		return err
	}
	numBlobs := len(NEVMBlobsWire.Blobs)
	n.Blobs = make([]*NEVMBlob, numBlobs)
	for i := 0; i < numBlobs; i++ {
		var blob NEVMBlob
		err = blob.FromWire(NEVMBlobsWire.Blobs[i])
		if err != nil {
			return err
		}
		n.Blobs[i] = &blob
	}
	return nil
}
func (KZGCommitment) ByteLength() uint64 {
	return 48
}

func (KZGCommitment) FixedLength() uint64 {
	return 48
}

func (p KZGCommitment) MarshalText() ([]byte, error) {
	return []byte("0x" + hex.EncodeToString(p[:])), nil
}

func (p KZGCommitment) String() string {
	return "0x" + hex.EncodeToString(p[:])
}

func (p *KZGCommitment) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("KZGCommitment", text, p[:])
}

func (p *KZGCommitment) Point() (*bls.G1Point, error) {
	return bls.FromCompressedG1(p[:])
}

func (kzg KZGCommitment) ComputeVersionedHash() common.Hash {
	h := crypto.Keccak256Hash(kzg[:])
	h[0] = params.BlobCommitmentVersionKZG
	return h
}

type BLSFieldElement [32]byte

func (p BLSFieldElement) MarshalText() ([]byte, error) {
	return []byte("0x" + hex.EncodeToString(p[:])), nil
}

func (p BLSFieldElement) String() string {
	return "0x" + hex.EncodeToString(p[:])
}

func (p *BLSFieldElement) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("BLSFieldElement", text, p[:])
}

// Blob data
type Blob [params.FieldElementsPerBlob]BLSFieldElement

func (blob *Blob) ByteLength() (out uint64) {
	return params.FieldElementsPerBlob * 32
}

func (blob *Blob) FixedLength() uint64 {
	return params.FieldElementsPerBlob * 32
}

func (blob *Blob) ComputeCommitment() (commitment KZGCommitment, ok bool) {
	frs := make([]bls.Fr, len(blob))
	for i, elem := range blob {
		if !bls.FrFrom32(&frs[i], elem) {
			return KZGCommitment{}, false
		}
	}
	// data is presented in eval form
	commitmentG1 := kzg.BlobToKzg(frs)
	var out KZGCommitment
	copy(out[:], bls.ToCompressedG1(commitmentG1))
	return out, true
}

func (blob *Blob) MarshalText() ([]byte, error) {
	out := make([]byte, 2+params.FieldElementsPerBlob*32*2)
	copy(out[:2], "0x")
	j := 2
	for _, elem := range blob {
		hex.Encode(out[j:j+64], elem[:])
		j += 64
	}
	return out, nil
}

func (blob *Blob) String() string {
	v, err := blob.MarshalText()
	if err != nil {
		return "<invalid-blob>"
	}
	return string(v)
}

func (blob *Blob) UnmarshalText(text []byte) error {
	if blob == nil {
		return errors.New("cannot decode text into nil Blob")
	}
	l := 2 + params.FieldElementsPerBlob*32*2
	if len(text) != l {
		return fmt.Errorf("expected %d characters but got %d", l, len(text))
	}
	if !(text[0] == '0' && text[1] == 'x') {
		return fmt.Errorf("expected '0x' prefix in Blob string")
	}
	j := 0
	for i := 2; i < l; i += 64 {
		if _, err := hex.Decode(blob[j][:], text[i:i+64]); err != nil {
			return fmt.Errorf("blob item %d is not formatted correctly: %v", j, err)
		}
		j += 1
	}
	return nil
}

// Parse blob into Fr elements array
func (blob *Blob) Parse() (out []bls.Fr, err error) {
	out = make([]bls.Fr, params.FieldElementsPerBlob)
	for i, chunk := range blob {
		ok := bls.FrFrom32(&out[i], chunk)
		if !ok {
			return nil, errors.New("internal error commitments")
		}
	}
	return out, nil
}

type BlobKzgs []KZGCommitment

// Extract the crypto material underlying these commitments
func (li BlobKzgs) Parse() ([]*bls.G1Point, error) {
	out := make([]*bls.G1Point, len(li))
	for i, c := range li {
		p, err := c.Point()
		if err != nil {
			return nil, fmt.Errorf("failed to parse commitment %d: %v", i, err)
		}
		out[i] = p
	}
	return out, nil
}

func (li BlobKzgs) ByteLength() uint64 {
	return uint64(len(li)) * 48
}

func (li *BlobKzgs) FixedLength() uint64 {
	return 0
}

func (li BlobKzgs) copy() BlobKzgs {
	cpy := make(BlobKzgs, len(li))
	copy(cpy, li)
	return cpy
}

type Blobs []Blob

// Extract the crypto material underlying these blobs
func (blobs Blobs) Parse() ([][]bls.Fr, error) {
	out := make([][]bls.Fr, len(blobs))
	for i, b := range blobs {
		blob, err := b.Parse()
		if err != nil {
			return nil, fmt.Errorf("failed to parse blob %d: %v", i, err)
		}
		out[i] = blob
	}
	return out, nil
}

func (a Blobs) ByteLength() (out uint64) {
	return uint64(len(a)) * params.FieldElementsPerBlob * 32
}

func (a *Blobs) FixedLength() uint64 {
	return 0 // it's a list, no fixed length
}

func (blobs Blobs) copy() Blobs {
	cpy := make(Blobs, len(blobs))
	copy(cpy, blobs) // each blob element is an array and gets deep-copied
	return cpy
}

// Return KZG commitments and versioned hashes that correspond to these blobs
func (blobs Blobs) ComputeCommitments() (commitments []KZGCommitment, versionedHashes []common.Hash, ok bool) {
	commitments = make([]KZGCommitment, len(blobs))
	versionedHashes = make([]common.Hash, len(blobs))
	for i, blob := range blobs {
		commitments[i], ok = blob.ComputeCommitment()
		if !ok {
			return nil, nil, false
		}
		versionedHashes[i] = commitments[i].ComputeVersionedHash()
	}
	return commitments, versionedHashes, true
}