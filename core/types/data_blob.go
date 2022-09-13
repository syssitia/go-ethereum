package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/protolambda/go-kzg/bls"
	"github.com/syscoin/btcd/wire"
)

// Compressed BLS12-381 G1 element
type KZGCommitment [48]byte


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

type Blobs []Blob

type BlobTxWrapperSingle struct {
	BlobKzg           KZGCommitment
	Blob              []bls.Fr
}

type BlobTxWrapper struct {
	BlobKzgs           BlobKzgs
	Blobs              [][]bls.Fr
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
	n.Blob = make([]bls.Fr, params.FieldElementsPerBlob)
	var inputPoint [32]byte
	for j := 0; j < numElements; j++ {
		copy(inputPoint[:32], blobIn[j*32:(j+1)*32])
		ok := bls.FrFrom32(&n.Blob[j], inputPoint)
		if !ok {
			return fmt.Errorf("FromWire: invalid chunk (element %d inputPoint %v)", j, inputPoint)
		}
	}
	// Get versioned hash out of input points
	copy(n.BlobKzg[:], bls.ToCompressedG1(kzg.BlobToKzg(n.Blob)))
	return nil
}

func (n *BlobTxWrapperSingle) Serialize() ([]byte, error) {
	var NEVMBlobWire wire.NEVMBlob
	var err error
	NEVMBlobWire.VersionHash = n.BlobKzg.ComputeVersionedHash().Bytes()
	lenBlobData := len(n.Blob) * 32
	NEVMBlobWire.Blob = make([]byte, 0, lenBlobData+int(n.BlobKzg.FixedLength()))
	NEVMBlobWire.Blob = append(NEVMBlobWire.Blob, n.BlobKzg[:]...)
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
	NEVMBlobWire.Blob = nil
	return buffer.Bytes(), nil
}

func (n *BlobTxWrapper) FromWire(NEVMBlobWire *wire.NEVMBlob, i int) error {
	VH := common.BytesToHash(NEVMBlobWire.VersionHash)
	if VH[0] != params.BlobCommitmentVersionKZG {
		return errors.New("invalid versioned hash")
	}
	lenBlob := len(NEVMBlobWire.Blob)
	lenCommitment := n.BlobKzgs[i].FixedLength()
	if uint64(lenBlob) < (1024+lenCommitment) {
		return errors.New("Blob too small")
	}
	copy(n.BlobKzgs[i][:], NEVMBlobWire.Blob[0:lenCommitment])
	if(n.BlobKzgs[i].ComputeVersionedHash() != VH) {
		return errors.New("mismatched versioned hash")
	} 
	totalLen := lenCommitment
	NEVMBlobWire.Blob = NEVMBlobWire.Blob[totalLen:]
	lenBlob = len(NEVMBlobWire.Blob)
	if lenBlob%32 != 0 {
		return errors.New("Blob should be a factor of 32")
	}
	numElements := lenBlob / 32
	if numElements > params.FieldElementsPerBlob {
		return errors.New("Blob too big")
	}
	n.Blobs[i] = make([]bls.Fr, params.FieldElementsPerBlob)
	var inputPoint [32]byte
	for j := 0; j < numElements; j++ {
		copy(inputPoint[:32], NEVMBlobWire.Blob[i*32:(i+1)*32])
		ok := bls.FrFrom32(&n.Blobs[i][j], inputPoint)
		if !ok {
			return fmt.Errorf("FromWire: invalid chunk (element %d inputPoint %v)", i, inputPoint)
		}
	}
	NEVMBlobWire.Blob = nil
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
	n.BlobKzgs = make(BlobKzgs, numBlobs)
	n.Blobs = make([][]bls.Fr, numBlobs)
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
	if a, b := len(b.Blobs), params.MaxBlobsPerBlock; a > b {
		return fmt.Errorf("too many blobs in blob tx, got %d, expected no more than %d", a, b)
	}
	if a, b := len(b.BlobKzgs), len(b.Blobs); a != b {
		return fmt.Errorf("expected equal amount but got %d kzgs and %d blobs", a, b)
	}

	commitments, err := b.BlobKzgs.Parse()
	if err != nil {
		return err
	}
	err = kzg.VerifyBlobs(commitments, b.Blobs)
	if err != nil {
		return err
	}
	for i := 0; i < len(b.Blobs); i++ {
		b.BlobKzgs = nil
		for j := 0; j < len(b.Blobs); j++ {
			b.Blobs[j] = nil
		}
		b.Blobs = nil
		commitments = nil
	}
	return nil
}