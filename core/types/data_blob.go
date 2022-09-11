package types

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
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

func (p *KZGCommitment) Serialize(w *codec.EncodingWriter) error {
	return w.Write(p[:])
}

func (KZGCommitment) ByteLength() uint64 {
	return 48
}

func (KZGCommitment) FixedLength() uint64 {
	return 48
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

func (KZGProof) ByteLength() uint64 {
	return 48
}

func (KZGProof) FixedLength() uint64 {
	return 48
}

func (p *KZGProof) Point() (*bls.G1Point, error) {
	return bls.FromCompressedG1(p[:])
}

type BLSFieldElement [32]byte

// Blob data
type Blob []BLSFieldElement

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

type Blobs []Blob

type BlobAndCommitment struct {
	Blob    *Blob
	BlobKzg *KZGCommitment
}

func (b *BlobAndCommitment) Serialize(w *codec.EncodingWriter) error {
	return w.Container(b.Blob, b.BlobKzg)
}

func (b *BlobAndCommitment) ByteLength() uint64 {
	return codec.ContainerLength(b.Blob, b.BlobKzg)
}

func (b *BlobAndCommitment) FixedLength() uint64 {
	return 0
}

type BlobTxWrapperSingle struct {
	BlobVersionedHash    common.Hash
	BlobKzg           KZGCommitment
	Blob              Blob
	KZGProof		  KZGProof
	yFr				  BLSFieldElement
}

type BlobTxWrapper struct {
	BlobVersionedHashes      []common.Hash
	BlobKzgs           BlobKzgs
	Blobs              Blobs
	KZGProofs 	   	   []KZGProof
	yFrs			   []BLSFieldElement
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
	n.Blob = make(Blob, numElements)
	for i := 0; i < numElements; i++ {
		copy(n.Blob[i][:32], blobIn[i*32:(i+1)*32])
	}
	polynomial, err := n.Blob.Parse()
	if err != nil {
		return err
	}
	// Get polynomial in evaluation form
	evalPoly, err := kzg.FFTSettings.FFT(polynomial, false)
	if err != nil {
		return err
	}
	// Get versioned hash out of input points
	copy(n.BlobKzg[:], bls.ToCompressedG1(kzg.BlobToKzg(evalPoly)))
	n.BlobVersionedHash = n.BlobKzg.ComputeVersionedHash()

	// create challenges
	sum, err := SszHash(&BlobAndCommitment{Blob: &n.Blob, BlobKzg: &n.BlobKzg})
	if err != nil {
		return err
	}
	var xFr bls.Fr
	HashToFr(&xFr, sum)
	copy(n.KZGProof[:], bls.ToCompressedG1(kzg.ComputeProof(polynomial, &xFr, kzg.KzgSetupG1)))
	var yFr bls.Fr
	bls.EvalPolyAt(&yFr, polynomial, &xFr)
	n.yFr = bls.FrTo32(&yFr)
	return nil
}

func (n *BlobTxWrapperSingle) Serialize() ([]byte, error) {
	var NEVMBlobWire wire.NEVMBlob
	var err error
	NEVMBlobWire.VersionHash = n.BlobVersionedHash.Bytes()
	lenBlobData := len(n.Blob) * 32
	NEVMBlobWire.Blob = make([]byte, 0, lenBlobData+int(n.BlobKzg.FixedLength())+int(n.KZGProof.FixedLength())+32)
	NEVMBlobWire.Blob = append(NEVMBlobWire.Blob, n.BlobKzg[:]...)
	NEVMBlobWire.Blob = append(NEVMBlobWire.Blob, n.KZGProof[:]...)
	NEVMBlobWire.Blob = append(NEVMBlobWire.Blob, n.yFr[:]...)
	for i := range n.Blob {
		NEVMBlobWire.Blob = append(NEVMBlobWire.Blob, n.Blob[i][:]...)
	}
	lenCommitment := n.BlobKzg.FixedLength()
	lenProof := n.KZGProof.FixedLength()
	lenYFr := uint64(32)
	if uint64(len(NEVMBlobWire.Blob)) < (1024+lenCommitment+lenProof+lenYFr) {
		return nil, errors.New("Blob too small")
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
	lenBlob := len(NEVMBlobWire.Blob)

	lenCommitment := n.BlobKzgs[i].FixedLength()
	lenProof := n.KZGProofs[i].FixedLength()
	lenYFr := uint64(32)
	if uint64(lenBlob) < (1024+lenCommitment+lenProof+lenYFr) {
		return errors.New("Blob too small")
	}
	copy(n.BlobKzgs[i][:], NEVMBlobWire.Blob[0:lenCommitment])
	totalLen := lenCommitment
	copy(n.KZGProofs[i][:], NEVMBlobWire.Blob[totalLen:totalLen + lenProof])
	totalLen += lenProof
	copy(n.yFrs[i][:], NEVMBlobWire.Blob[totalLen:totalLen + lenYFr])
	totalLen += lenYFr
	NEVMBlobWire.Blob = NEVMBlobWire.Blob[totalLen:]
	lenBlob = len(NEVMBlobWire.Blob)
	if lenBlob%32 != 0 {
		return errors.New("Blob should be a factor of 32")
	}
	numElements := lenBlob / 32
	if numElements > params.FieldElementsPerBlob {
		return errors.New("Blob too big")
	}
	n.Blobs[i] = make(Blob, numElements)
	for j := 0; j < numElements; j++ {
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
	n.BlobKzgs = make(BlobKzgs, numBlobs)
	n.Blobs = make(Blobs, numBlobs)
	n.KZGProofs = make([]KZGProof, numBlobs)
	n.yFrs = make([]BLSFieldElement, numBlobs)
	for i := 0; i < numBlobs; i++ {
		err = n.FromWire(NEVMBlobsWire.Blobs[i], i)
		if err != nil {
			return err
		}
	}
	return nil
}

// Blob verification using KZG proofs
func (b *BlobTxWrapper) Verify() error {
	if a, b := len(b.BlobVersionedHashes), params.MaxBlobsPerBlock; a > b {
		return fmt.Errorf("too many blobs in blob tx, got %d, expected no more than %d", a, b)
	}
	if a, b := len(b.BlobKzgs), len(b.Blobs); a != b {
		return fmt.Errorf("expected equal amount but got %d kzgs and %d blobs", a, b)
	}
	if a, b := len(b.BlobKzgs), len(b.BlobVersionedHashes); a != b {
		return fmt.Errorf("expected equal amount but got %d kzgs and %d versioned hashes", a, b)
	}
	if a, b := len(b.yFrs), len(b.BlobVersionedHashes); a != b {
		return fmt.Errorf("expected equal amount but got %d yFrs and %d versioned hashes", a, b)
	}
	if a, b := len(b.KZGProofs), len(b.BlobVersionedHashes); a != b {
		return fmt.Errorf("expected equal amount but got %d kzg proofs and %d versioned hashes", a, b)
	}
	result := true
	var wg sync.WaitGroup
	for i := 0; i < len(b.BlobVersionedHashes); i++ {
		wg.Add(1)
		go VerifyKZG(&b.BlobVersionedHashes[i], &b.Blobs[i], &b.BlobKzgs[i], &b.yFrs[i], &b.KZGProofs[i], &wg, &result)
	}
	wg.Wait()
	if result != true {
		return errors.New("failed proof verification")
	}
	
	return nil
}

func VerifyKZG(blobVersionedHash *common.Hash, blob *Blob, blobKzg *KZGCommitment, yFr *BLSFieldElement, proof *KZGProof, wg *sync.WaitGroup, result *bool) {
	defer wg.Done()
	if computed := blobKzg.ComputeVersionedHash(); computed != *blobVersionedHash {
		*result = false
		return
	}
	// create challenges
	// Create a commitment
	parsedCommitment, err := blobKzg.Point()
	if err != nil {
		*result = false
		return
	}
	parsedProof, err := proof.Point()
	if err != nil {
		*result = false
		return
	}
	sum, err := SszHash(&BlobAndCommitment{Blob: blob, BlobKzg: blobKzg})
	if err != nil {
		*result = false
		return
	}
	var y bls.Fr
	ok := bls.FrFrom32(&y, *yFr)
	if !ok {
		*result = false
		return	
	}
	var xFr bls.Fr
	HashToFr(&xFr, sum)
	resultKzg := kzg.VerifyKzgProof(parsedCommitment, &xFr, &y, parsedProof)
	if resultKzg != true {
		*result = false
	}
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
