package pkcs5

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkix"
	"golang.org/x/crypto/scrypt"
)

func (c HmacOID) Equal(d HmacOID) bool {
	return asn1.ObjectIdentifier(c).Equal(asn1.ObjectIdentifier(d))
}
func (c HmacOID) ToAsn1() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier(c)
}

func makeSalt(size int, current *[]byte) (salt []byte, err error) {
	if size > 0 {
		salt = make([]byte, size)
		_, err = rand.Read(salt)
		if current != nil {
			*current = salt
		}
		return
	}
	if current != nil && len(*current) == 0 {
		err = fmt.Errorf("pkcs5: Salt is empty")
	} else {
		salt = *current
	}
	return
}

type scryptBase struct {
	Salt                     []byte
	CostParameter            int
	BlockSize                int
	ParallelizationParameter int
}

func (p *scryptBase) MakeSalt(saltSize int) error {
	_, err := makeSalt(saltSize, &p.Salt)
	return err
}

func (p *scryptBase) DeriveKey(password []byte, size int) (key []byte, err error) {
	return scrypt.Key([]byte(password), p.Salt, p.CostParameter, p.BlockSize,
		p.ParallelizationParameter, size)
}

func (p *scryptBase) Param() any {
	return *p
}

func (p *scryptBase) OID() asn1.ObjectIdentifier {
	return OidScrypt
}

func (p *scryptBase) HmacOID() HmacOID {
	return nil
}

func (p *scryptBase) SetSalt(salt []byte) {
	p.Salt = salt
}

func (p *scryptBase) GetSalt() []byte {
	return p.Salt
}

func (p *scryptBase) SetKeyLength(_ int) {
}

func (p *scryptBase) GetKeyLength() int {
	return 0
}

func (p *scryptBase) SetIterations(iter int) {
}

func (p *scryptBase) GetIterations() int {
	return 0
}

func NewScryptParams(CostParameter int, BlockSize int, ParallelizationParameter int) *scryptBase {
	return &scryptBase{
		CostParameter:            CostParameter,
		BlockSize:                BlockSize,
		ParallelizationParameter: ParallelizationParameter,
	}
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

func (p *pbkdf2Params) MakeSalt(saltSize int) error {
	_, err := makeSalt(saltSize, &p.Salt)
	return err
}

func (p *pbkdf2Params) DeriveKey(password []byte, size int) (key []byte, err error) {
	switch {
	case len(p.PRF.Algorithm) == 0 || p.PRF.Algorithm.Equal(OidHMACWithSHA1.ToAsn1()):
		return pbkdf2.Key(sha1.New, string(password), p.Salt, p.IterationCount, size)
	case p.PRF.Algorithm.Equal(OidHMACWithSHA224.ToAsn1()):
		return pbkdf2.Key(sha256.New224, string(password), p.Salt, p.IterationCount, size)
	case p.PRF.Algorithm.Equal(OidHMACWithSHA256.ToAsn1()):
		return pbkdf2.Key(sha256.New, string(password), p.Salt, p.IterationCount, size)
	case p.PRF.Algorithm.Equal(OidHMACWithSHA384.ToAsn1()):
		return pbkdf2.Key(sha512.New384, string(password), p.Salt, p.IterationCount, size)
	case p.PRF.Algorithm.Equal(OidHMACWithSHA512.ToAsn1()):
		return pbkdf2.Key(sha512.New, string(password), p.Salt, p.IterationCount, size)
	case p.PRF.Algorithm.Equal(OidHMACWithSHA512_224.ToAsn1()):
		return pbkdf2.Key(sha512.New512_224, string(password), p.Salt, p.IterationCount, size)
	case p.PRF.Algorithm.Equal(OidHMACWithSHA512_256.ToAsn1()):
		return pbkdf2.Key(sha512.New512_256, string(password), p.Salt, p.IterationCount, size)
	}
	return nil, fmt.Errorf("pkcs8: unsupported hash function")
}

func (p *pbkdf2Params) Param() any {
	return *p
}

func (p *pbkdf2Params) OID() asn1.ObjectIdentifier {
	return OidPKCS5PBKDF2
}

func (p *pbkdf2Params) HmacOID() HmacOID {
	return HmacOID(p.PRF.Algorithm)
}

func (p *pbkdf2Params) SetSalt(salt []byte) {
	p.Salt = salt
}

func (p *pbkdf2Params) GetSalt() []byte {
	return p.Salt
}

func (p *pbkdf2Params) SetKeyLength(size int) {
	p.KeyLength = size
}

func (p *pbkdf2Params) GetKeyLength() int {
	return p.KeyLength
}

func (p *pbkdf2Params) SetIterations(iter int) {
	p.IterationCount = iter
}

func (p *pbkdf2Params) GetIterations() int {
	return p.IterationCount
}

func NewPbkdf2Params(IterationCount int, Algorithm HmacOID) *pbkdf2Params {
	return &pbkdf2Params{
		IterationCount: IterationCount,
		PRF: pkix.AlgorithmIdentifier{
			Algorithm:  Algorithm.ToAsn1(),
			Parameters: asn1.RawValue{},
		},
	}
}

// KDFParams contains options for a key derivation function.
// An implementation of this interface must be specified when encrypting a PKCS#8 key.
type KDFParams interface {
	MakeSalt(saltSize int) error
	// DeriveKey derives a key of size bytes from the given password and salt.
	// It returns the key and the ASN.1-encodable parameters used.
	DeriveKey(password []byte, size int) (key []byte, err error)
	// GetSaltSize returns the salt size specified.
	// GetSaltSize() int
	// OID returns the OID of the KDF specified.
	OID() asn1.ObjectIdentifier
	HmacOID() HmacOID
	// return the KDFParams itself to allow marshal
	Param() any
	// SetSalt
	SetSalt(salt []byte)
	GetSalt() []byte
	// KeyLength
	SetKeyLength(size int)
	GetKeyLength() int
	// Iterations
	SetIterations(iter int)
	GetIterations() int
}

func NewKDFParams(oid asn1.ObjectIdentifier, hmac ...HmacOID) (KDFParams, error) {
	usedhmac := HmacOID{}
	if len(hmac) > 0 {
		usedhmac = hmac[0]
	}
	switch {
	case oid.Equal(OidPKCS5PBKDF2):
		return NewPbkdf2Params(0, usedhmac), nil
	case oid.Equal(OidScrypt):
		return NewScryptParams(0, 0, 0), nil
	}
	return nil, fmt.Errorf("pkcs5: unsupported KDF (OID: %s)", oid.String())
}

func NewDefaultKDF() KDFParams { return NewPbkdf2Params(10000, OidHMACWithSHA256) }
