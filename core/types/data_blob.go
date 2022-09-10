package types

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/protolambda/go-kzg/bls"
	"github.com/syscoin/btcd/wire"
	"github.com/protolambda/ztyp/codec"
)

// Compressed BLS12-381 G1 element
type KZGCommitment [48]byte

func (n *BlobTxWrapperSingle) FromWire(NEVMBlobWire *wire.NEVMBlob) error {
	n.BlobVersionedHash = common.BytesToHash(NEVMBlobWire.VersionHash)
	if n.BlobVersionedHash[0] != params.BlobCommitmentVersionKZG {
		return errors.New("invalid versioned hash")
	}
	lenCommitment := n.BlobKzg.FixedLength()
	copy(n.BlobKzg[:], NEVMBlobWire.Blob[0:lenCommitment])
	NEVMBlobWire.Blob = NEVMBlobWire.Blob[lenCommitment:]
	lenBlob := len(NEVMBlobWire.Blob)
	if lenBlob < 1024 {
		return errors.New("Blob too small")
	}
	if lenBlob%32 != 0 {
		return errors.New("Blob should be a factor of 32")
	}
	numElements := lenBlob / 32
	if numElements > params.FieldElementsPerBlob {
		return errors.New("Blob too big")
	}
	n.Blob = make([]BLSFieldElement, params.FieldElementsPerBlob)
	for i := 0; i < numElements; i++ {
		copy(n.Blob[i][:32], NEVMBlobWire.Blob[i*32:(i+1)*32])
	}
	return nil
}
func (n *BlobTxWrapperSingle) FromBytes(blobIn []byte) error {
	lenBlob := len(blobIn)
	if lenBlob == 0 {
		return errors.New("empty blob")
	}
	if lenBlob < 1024 {
		return errors.New("Blob too small")
	}
	if lenBlob%32 != 0 {
		return errors.New("Blob should be a factor of 32")
	}
	numElements := lenBlob / 32
	if numElements > params.FieldElementsPerBlob {
		return errors.New("Blob too big")
	}
	n.Blob = make([]BLSFieldElement, params.FieldElementsPerBlob)
	for i := 0; i < numElements; i++ {
		copy(n.Blob[i][:32], blobIn[i*32:(i+1)*32])
	}
	polynomial, err := n.Blob.Parse()
	if err != nil {
		return err
	}
	// Get versioned hash out of input points
	copy(n.BlobKzg[:], bls.ToCompressedG1(kzg.BlobToKzg(polynomial)))
	// need the full field elements array above to properly calculate and validate blob to kzg,
	// can splice it after for network purposes and later when deserializing will again create full elements array to input spliced data from network
	n.Blob = n.Blob[0:numElements]
	n.BlobVersionedHash = n.BlobKzg.ComputeVersionedHash()
	return nil
}
func (n *BlobTxWrapperSingle) Deserialize(bytesIn []byte) error {
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
func (n *BlobTxWrapperSingle) Serialize() ([]byte, error) {
	var NEVMBlobWire wire.NEVMBlob
	var err error
	NEVMBlobWire.VersionHash = n.BlobVersionedHash.Bytes()
	lenBlobData := len(n.Blob) * 32
	NEVMBlobWire.Blob = make([]byte, 0, lenBlobData+int(n.BlobKzg.FixedLength()))
	NEVMBlobWire.Blob = append(NEVMBlobWire.Blob, n.BlobKzg[:]...)
	for i := range n.Blob {
		NEVMBlobWire.Blob = append(NEVMBlobWire.Blob, n.Blob[i][:]...)
	}
	var buffer bytes.Buffer
	err = NEVMBlobWire.Serialize(&buffer)
	if err != nil {
		log.Error("NEVMBlockConnect: could not serialize", "err", err)
		return nil, err
	}
	return buffer.Bytes(), nil
}
func (n *BlobTxWrapper) FromWire(NEVMBlobWire *wire.NEVMBlob, i int) error {
	n.BlobVersionedHashes[i] = common.BytesToHash(NEVMBlobWire.VersionHash)
	if n.BlobVersionedHashes[i][0] != params.BlobCommitmentVersionKZG {
		return errors.New("invalid versioned hash")
	}
	lenCommitment := n.BlobKzgs[i].FixedLength()
	copy(n.BlobKzgs[i][:], NEVMBlobWire.Blob[0:lenCommitment])
	NEVMBlobWire.Blob = NEVMBlobWire.Blob[lenCommitment:]
	lenBlob := len(NEVMBlobWire.Blob)
	if lenBlob < 1024 {
		return errors.New("Blob too small")
	}
	if lenBlob%32 != 0 {
		return errors.New("Blob should be a factor of 32")
	}
	numElements := lenBlob / 32
	if numElements > params.FieldElementsPerBlob {
		return errors.New("Blob too big")
	}
	n.Blobs = make([]Blob, numElements)
	for j := 0; j < numElements; i++ {
		copy(n.Blobs[i][j][:32], NEVMBlobWire.Blob[j*32:(j+1)*32])
	}
	return nil
}
func (n *BlobTxWrapper) Deserialize(bytesIn []byte) error {
	var NEVMBlobsWire wire.NEVMBlobs
	r := bytes.NewReader(bytesIn)
	err := NEVMBlobsWire.Deserialize(r)
	if err != nil {
		log.Error("NEVMBlobs: could not deserialize", "err", err)
		return err
	}
	numBlobs := len(NEVMBlobsWire.Blobs)
	n.BlobVersionedHashes = make([]common.Hash, numBlobs)
	n.BlobKzgs = make([]KZGCommitment, numBlobs)
	n.Blobs = make([]Blob, numBlobs)
	for i := 0; i < numBlobs; i++ {
		err = n.FromWire(NEVMBlobsWire.Blobs[i], i)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *KZGCommitment) Deserialize(dr *codec.DecodingReader) error {
	if p == nil {
		return errors.New("nil pubkey")
	}
	_, err := dr.Read(p[:])
	return err
}

func (p *KZGCommitment) Serialize(w *codec.EncodingWriter) error {
	return w.Write(p[:])
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

// Compressed BLS12-381 G1 element
type KZGProof [48]byte

func (p *KZGProof) Deserialize(dr *codec.DecodingReader) error {
	if p == nil {
		return errors.New("nil pubkey")
	}
	_, err := dr.Read(p[:])
	return err
}

func (p *KZGProof) Serialize(w *codec.EncodingWriter) error {
	return w.Write(p[:])
}

func (KZGProof) ByteLength() uint64 {
	return 48
}

func (KZGProof) FixedLength() uint64 {
	return 48
}

func (p KZGProof) MarshalText() ([]byte, error) {
	return []byte("0x" + hex.EncodeToString(p[:])), nil
}

func (p KZGProof) String() string {
	return "0x" + hex.EncodeToString(p[:])
}

func (p *KZGProof) UnmarshalText(text []byte) error {
	return hexutil.UnmarshalFixedText("KZGProof", text, p[:])
}

func (p *KZGProof) Point() (*bls.G1Point, error) {
	return bls.FromCompressedG1(p[:])
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
type Blob []BLSFieldElement

func (blob *Blob) Deserialize(dr *codec.DecodingReader) error {
	if blob == nil {
		return errors.New("cannot decode ssz into nil Blob")
	}
	for i := int(0); i < len(*blob); i++ {
		// TODO: do we want to check if each field element is within range?
		if _, err := dr.Read((*blob)[i][:]); err != nil {
			return err
		}
	}
	return nil
}

func (blob *Blob) Serialize(w *codec.EncodingWriter) error {
	for i := int(0); i < len(*blob); i++ {
		if err := w.Write((*blob)[i][:]); err != nil {
			return err
		}
	}
	return nil
}

func (blob *Blob) ByteLength() (out uint64) {
	return params.FieldElementsPerBlob * 32
}

func (blob *Blob) FixedLength() uint64 {
	return params.FieldElementsPerBlob * 32
}

func (blob *Blob) ComputeCommitment() (kzgcommitment KZGCommitment, commitment bls.G1Point, ok bool) {
	frs := make([]bls.Fr, len(*blob))
	for i := int(0); i < len(*blob); i++ {
		if !bls.FrFrom32(&frs[i], (*blob)[i]) {
			return KZGCommitment{}, bls.G1Point{}, false
		}
	}
	// data is presented in eval form
	commitmentG1 := kzg.BlobToKzg(frs)
	var out KZGCommitment
	copy(out[:], bls.ToCompressedG1(commitmentG1))
	return out, *commitmentG1, true
}

// Parse blob into Fr elements array
func (blob *Blob) Parse() (out []bls.Fr, err error) {
	out = make([]bls.Fr, params.FieldElementsPerBlob)
	for i := int(0); i < len(*blob); i++ {
		ok := bls.FrFrom32(&out[i], (*blob)[i])
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

func (li *BlobKzgs) Deserialize(dr *codec.DecodingReader) error {
	return dr.List(func() codec.Deserializable {
		i := len(*li)
		*li = append(*li, KZGCommitment{})
		return &(*li)[i]
	}, 48, params.MaxBlobsPerBlock)
}

func (li BlobKzgs) Serialize(w *codec.EncodingWriter) error {
	return w.List(func(i uint64) codec.Serializable {
		return &li[i]
	}, 48, uint64(len(li)))
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

func (a *Blobs) Deserialize(dr *codec.DecodingReader) error {
	return dr.List(func() codec.Deserializable {
		i := len(*a)
		*a = append(*a, Blob{})
		return &(*a)[i]
	}, params.FieldElementsPerBlob*32, params.FieldElementsPerBlob)
}

func (a Blobs) Serialize(w *codec.EncodingWriter) error {
	return w.List(func(i uint64) codec.Serializable {
		return &a[i]
	}, params.FieldElementsPerBlob*32, uint64(len(a)))
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
// Return KZG commitments, versioned hashes and the aggregated KZG proof that correspond to these blobs
func (blobs Blobs) ComputeCommitmentsAndAggregatedProof() (commitments []KZGCommitment, versionedHashes []common.Hash, aggregatedProof KZGProof, err error) {
	commitments = make([]KZGCommitment, len(blobs))
	versionedHashes = make([]common.Hash, len(blobs))
	for i, blob := range blobs {
		var ok bool
		commitments[i], _, ok = blob.ComputeCommitment()
		if !ok {
			return nil, nil, KZGProof{}, errors.New("invalid blob for commitment")
		}
		versionedHashes[i] = commitments[i].ComputeVersionedHash()
	}

	var kzgProof KZGProof
	if len(blobs) != 0 {
		aggregatePoly, aggregateCommitmentG1, err := computeAggregateKzgCommitment(blobs, commitments)
		if err != nil {
			return nil, nil, KZGProof{}, err
		}

		var aggregateCommitment KZGCommitment
		copy(aggregateCommitment[:], bls.ToCompressedG1(aggregateCommitmentG1))

		var aggregateBlob Blob = make([]BLSFieldElement, params.FieldElementsPerBlob)
		for i := range aggregatePoly {
			aggregateBlob[i] = bls.FrTo32(&aggregatePoly[i])
		}
		sum, err := SszHash(&PolynomialAndCommitment{aggregateBlob, aggregateCommitment})
		if err != nil {
			return nil, nil, KZGProof{}, err
		}
		var z bls.Fr
		HashToFr(&z, sum)

		var y bls.Fr
		kzg.EvaluatePolyInEvaluationForm(&y, aggregatePoly[:], &z)

		aggProofG1, err := kzg.ComputeProof(aggregatePoly, &z)
		if err != nil {
			return nil, nil, KZGProof{}, err
		}
		copy(kzgProof[:], bls.ToCompressedG1(aggProofG1))
	}

	return commitments, versionedHashes, kzgProof, nil
}

// Return KZG commitments, versioned hashes and the aggregated KZG proof that correspond to these blobs
func (b *BlobTxWrapper) ComputeAggregatedProof() (aggregatedProof KZGProof, err error) {
	var kzgProof KZGProof
	if len(b.Blobs) != 0 {
		aggregatePoly, aggregateCommitmentG1, err := computeAggregateKzgCommitment(b.Blobs, b.BlobKzgs)
		if err != nil {
			return KZGProof{}, err
		}

		var aggregateCommitment KZGCommitment
		copy(aggregateCommitment[:], bls.ToCompressedG1(aggregateCommitmentG1))

		var aggregateBlob Blob = make([]BLSFieldElement, params.FieldElementsPerBlob)
		for i := range aggregatePoly {
			aggregateBlob[i] = bls.FrTo32(&aggregatePoly[i])
		}
		sum, err := SszHash(&PolynomialAndCommitment{aggregateBlob, aggregateCommitment})
		if err != nil {
			return KZGProof{}, err
		}
		var z bls.Fr
		HashToFr(&z, sum)

		var y bls.Fr
		kzg.EvaluatePolyInEvaluationForm(&y, aggregatePoly[:], &z)

		aggProofG1, err := kzg.ComputeProof(aggregatePoly, &z)
		if err != nil {
			return KZGProof{}, err
		}
		copy(kzgProof[:], bls.ToCompressedG1(aggProofG1))
	}

	return kzgProof, nil
}

type BlobsAndCommitments struct {
	Blobs    Blobs
	BlobKzgs BlobKzgs
}


func (b *BlobsAndCommitments) Serialize(w *codec.EncodingWriter) error {
	return w.Container(&b.Blobs, &b.BlobKzgs)
}

func (b *BlobsAndCommitments) ByteLength() uint64 {
	return codec.ContainerLength(&b.Blobs, &b.BlobKzgs)
}

func (b *BlobsAndCommitments) FixedLength() uint64 {
	return 0
}


type BlobAndCommitment struct {
	Blob    Blob
	BlobKzg KZGCommitment
}


func (b *BlobAndCommitment) Serialize(w *codec.EncodingWriter) error {
	return w.Container(&b.Blob, &b.BlobKzg)
}

func (b *BlobAndCommitment) ByteLength() uint64 {
	return codec.ContainerLength(&b.Blob, &b.BlobKzg)
}

func (b *BlobAndCommitment) FixedLength() uint64 {
	return 0
}


type PolynomialAndCommitment struct {
	b Blob
	c KZGCommitment
}


func (p *PolynomialAndCommitment) Serialize(w *codec.EncodingWriter) error {
	return w.Container(&p.b, &p.c)
}

func (p *PolynomialAndCommitment) ByteLength() uint64 {
	return codec.ContainerLength(&p.b, &p.c)
}

func (p *PolynomialAndCommitment) FixedLength() uint64 {
	return 0
}


type BlobTxWrapperSingle struct {
	BlobVersionedHash    common.Hash
	BlobKzg           KZGCommitment
	Blob              Blob
}

func (b *BlobTxWrapperSingle) verifyVersionedHash() error {
	if computed := b.BlobKzg.ComputeVersionedHash(); computed != b.BlobVersionedHash {
		return fmt.Errorf("versioned hash %d does not match computed %s", b.BlobVersionedHash, computed)
	}
	return nil
}
// Blob verification using KZG proofs
func (b *BlobTxWrapperSingle) Verify() error {
	if err := b.verifyVersionedHash(); err != nil {
		return err
	}
	// Create a commitment
	parsedCommitment, err := b.BlobKzg.Point()
	if err != nil {
		return err
	}
	polynomial, err := b.Blob.Parse()
	if err != nil {
		return err
	}
	// Create proof for testing
	x := uint64(17)
	var xFr bls.Fr
	bls.AsFr(&xFr, x)
	proof, err := kzg.ComputeProof(polynomial, &xFr)
	if err != nil {
		return err
	}
	// Get actual evaluation at x
	var value bls.Fr
	bls.EvalPolyAt(&value, polynomial, &xFr)

	// Verify kzg proof
	if kzg.VerifyKzgProof(parsedCommitment, &xFr, &value, proof) != true {
		return errors.New("failed to verify kzg")
	}
	return nil
}

type BlobTxWrapper struct {
	BlobVersionedHashes      []common.Hash
	BlobKzgs           BlobKzgs
	Blobs              Blobs
	KzgAggregatedProof KZGProof
}
func (b *BlobTxWrapper) verifyVersionedHashes() error {
	if a, b := len(b.BlobVersionedHashes), params.MaxBlobsPerBlock; a > b {
		return fmt.Errorf("too many blobs in blob tx, got %d, expected no more than %d", a, b)
	}
	if a, b := len(b.BlobKzgs), len(b.Blobs); a != b {
		return fmt.Errorf("expected equal amount but got %d kzgs and %d blobs", a, b)
	}
	if a, b := len(b.BlobKzgs), len(b.BlobVersionedHashes); a != b {
		return fmt.Errorf("expected equal amount but got %d kzgs and %d versioned hashes", a, b)
	}
	for i, h := range b.BlobVersionedHashes {
		if computed := b.BlobKzgs[i].ComputeVersionedHash(); computed != h {
			return fmt.Errorf("versioned hash %d supposedly %s but does not match computed %s", i, h, computed)
		}
	}
	return nil
}
func (txw *BlobTxWrapper) ByteLength() uint64 {
	return codec.ContainerLength(&txw.BlobKzgs, &txw.Blobs, &txw.KzgAggregatedProof)
}

func (txw *BlobTxWrapper) FixedLength() uint64 {
	return 0
}

// Blob verification using KZG proofs
func (b *BlobTxWrapper) Verify() error {
	if err := b.verifyVersionedHashes(); err != nil {
		return err
	}
	aggregatePoly, aggregateCommitmentG1, err := computeAggregateKzgCommitment(b.Blobs, b.BlobKzgs)
	if err != nil {
		return fmt.Errorf("failed to compute aggregate commitment: %v", err)
	}
	var aggregateBlob Blob = make([]BLSFieldElement, params.FieldElementsPerBlob)
	for i := range aggregatePoly {
		aggregateBlob[i] = bls.FrTo32(&aggregatePoly[i])
	}
	var aggregateCommitment KZGCommitment
	copy(aggregateCommitment[:], bls.ToCompressedG1(aggregateCommitmentG1))
	sum, err := SszHash(&PolynomialAndCommitment{aggregateBlob, aggregateCommitment})
	if err != nil {
		return err
	}
	var z bls.Fr
	HashToFr(&z, sum)

	var y bls.Fr
	kzg.EvaluatePolyInEvaluationForm(&y, aggregatePoly[:], &z)

	aggregateProofG1, err := b.KzgAggregatedProof.Point()
	if err != nil {
		return fmt.Errorf("aggregate proof parse error: %v", err)
	}
	if !kzg.VerifyKzgProof(aggregateCommitmentG1, &z, &y, aggregateProofG1) {
		return errors.New("failed to verify kzg")
	}
	return nil
}

func computeAggregateKzgCommitment(blobs Blobs, commitments []KZGCommitment) ([]bls.Fr, *bls.G1Point, error) {
	// create challenges
	sum, err := SszHash(&BlobsAndCommitments{blobs, commitments})
	if err != nil {
		return nil, nil, err
	}
	var r bls.Fr
	HashToFr(&r, sum)

	powers := computePowers(&r, len(blobs))

	commitmentsG1 := make([]bls.G1Point, len(commitments))
	for i := 0; i < len(commitmentsG1); i++ {
		p, _ := commitments[i].Point()
		bls.CopyG1(&commitmentsG1[i], p)
	}
	aggregateCommitmentG1 := bls.LinCombG1(commitmentsG1, powers)
	var aggregateCommitment KZGCommitment
	copy(aggregateCommitment[:], bls.ToCompressedG1(aggregateCommitmentG1))

	polys, err := blobs.Parse()
	if err != nil {
		return nil, nil, err
	}
	aggregatePoly := kzg.MatrixLinComb(polys, powers)
	return aggregatePoly, aggregateCommitmentG1, nil
}

func computePowers(r *bls.Fr, n int) []bls.Fr {
	var currentPower bls.Fr
	bls.AsFr(&currentPower, 1)
	powers := make([]bls.Fr, n)
	for i := range powers {
		powers[i] = currentPower
		bls.MulModFr(&currentPower, &currentPower, r)
	}
	return powers
}

func HashToFr(out *bls.Fr, h [32]byte) {
	// re-interpret as little-endian
	var b [32]byte = h
	for i := 0; i < 16; i++ {
		b[31-i], b[i] = b[i], b[31-i]
	}
	zB := new(big.Int).Mod(new(big.Int).SetBytes(b[:]), kzg.BLSModulus)
	_ = kzg.BigToFr(out, zB)
}
