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


func (n *KZGCommitment) BlobToKzg(blobIn []byte) error {
	blob := make([]bls.Fr, params.FieldElementsPerBlob)
	err := FromBytes(blobIn, &blob)
	if err != nil {
		return err
	}
	// Get versioned hash out of input points
	copy(n[:], bls.ToCompressedG1(kzg.BlobToKzg(blob)))
	blob = nil
	return nil
}
func FromBytes(blobIn []byte, blobOut *[]bls.Fr) error {
	lenBlob := len(blobIn)
	if lenBlob == 0 {
		return errors.New("empty blob")
	}
	if lenBlob < 31 {
		return errors.New("Blob too small")
	}
	if lenBlob > params.FieldElementsPerBlob*31 {
		return errors.New("Blob too big")
	}
	numElements := lenBlob / 31
	var inputPoint [32]byte
	for j := 0; j < numElements; j++ {
		copy(inputPoint[:31], blobIn[j*31:(j+1)*31])
		ok := bls.FrFrom32(&(*blobOut)[j], inputPoint)
		if !ok {
			return fmt.Errorf("FromWire: invalid chunk (element %d inputPoint %v)", j, inputPoint)
		}
	}
	// if not on boundry of 31 bytes add the rest of the data
	if (lenBlob % 31) != 0 {
		inputPoint = [32]byte{}
		copy(inputPoint[:31], blobIn[numElements*31:])
		ok := bls.FrFrom32(&(*blobOut)[numElements], inputPoint)
		if !ok {
			return fmt.Errorf("FromWire: invalid chunk (element %d inputPoint %v)", numElements, inputPoint)
		}
	}
	return nil
}

func (n *KZGCommitment) Serialize() ([]byte, error) {
	var NEVMBlobWire wire.NEVMBlob
	var err error
	NEVMBlobWire.VersionHash = n.ComputeVersionedHash().Bytes()
	NEVMBlobWire.Blob = make([]byte, 0, int(n.FixedLength()))
	NEVMBlobWire.Blob = append(NEVMBlobWire.Blob, n[:]...)
	var buffer bytes.Buffer
	err = NEVMBlobWire.Serialize(&buffer)
	if err != nil {
		log.Error("NEVMBlockConnect: could not serialize", "err", err)
		return nil, err
	}
	NEVMBlobWire.Blob = nil
	return buffer.Bytes(), nil
}

func FromWire(NEVMBlobWire *wire.NEVMBlob, blobOut *[]bls.Fr, blobKzg *KZGCommitment) error {
	VH := common.BytesToHash(NEVMBlobWire.VersionHash)
	if VH[0] != params.BlobCommitmentVersionKZG {
		return errors.New("invalid versioned hash")
	}
	lenBlob := len(NEVMBlobWire.Blob)
	lenCommitment := blobKzg.FixedLength()
	if uint64(lenBlob) < (31+lenCommitment) {
		return errors.New("Blob too small")
	}
	copy(blobKzg[:], NEVMBlobWire.Blob[0:lenCommitment])
	if(blobKzg.ComputeVersionedHash() != VH) {
		return errors.New("mismatched versioned hash")
	} 
	NEVMBlobWire.Blob = NEVMBlobWire.Blob[lenCommitment:]
	err := FromBytes(NEVMBlobWire.Blob, blobOut)
	if err != nil {
		return err
	}
	NEVMBlobWire.Blob = nil
	return nil
}

// Blob verification using KZG proofs
func Verify(blobs *[][]bls.Fr, blobKzgs *BlobKzgs) error {
	if a, b := len(*blobs), params.MaxBlobsPerBlock; a > b {
		return fmt.Errorf("too many blobs in blob tx, got %d, expected no more than %d", a, b)
	}
	if a, b := len(*blobKzgs), len(*blobs); a != b {
		return fmt.Errorf("expected equal amount but got %d kzgs and %d blobs", a, b)
	}

	commitments, err := blobKzgs.Parse()
	if err != nil {
		return err
	}
	err = kzg.VerifyBlobs(commitments, blobs)
	if err != nil {
		return err
	}
	commitments = nil
	return nil
}

func DeserializeAndVerify(bytesIn []byte) error {
	var NEVMBlobsWire wire.NEVMBlobs
	r := bytes.NewReader(bytesIn)
	err := NEVMBlobsWire.Deserialize(r)
	if err != nil {
		log.Error("NEVMBlobs: DeserializeAndVerify could not deserialize", "err", err)
		return err
	}
	numBlobs := len(NEVMBlobsWire.Blobs)
	blobKzgs := make(BlobKzgs, numBlobs)
	blobs := make([][]bls.Fr, numBlobs)
	for i := 0; i < numBlobs; i++ {
		blobs[i] = make([]bls.Fr, params.FieldElementsPerBlob)
		err = FromWire(NEVMBlobsWire.Blobs[i], &blobs[i], &blobKzgs[i])
		if err != nil {
			return err
		}
	}
	err = Verify(&blobs, &blobKzgs)
	if err != nil {
		log.Error("NEVMBlobs: DeserializeAndVerify could not verify", "err", err)
		return err
	}
	for i := 0; i < len(blobs); i++ {
		blobKzgs = nil
		for j := 0; j < len(blobs); j++ {
			blobs[j] = nil
		}
		blobs = nil
	}
	return nil
}