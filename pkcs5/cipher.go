package pkcs5

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/internal/intcrypto"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

// ErrDecryption represents a failure to decrypt the input.
var ErrDecryption = fmt.Errorf("pkcs12: decryption error, incorrect padding")

type cipherWithBlock struct {
	oid     asn1.ObjectIdentifier
	ivSize  int
	keySize int
}

func (c cipherWithBlock) IVSize() int {
	return c.ivSize
}

func (c cipherWithBlock) KeySize() int {
	return c.keySize
}

func (c cipherWithBlock) OID() asn1.ObjectIdentifier {
	return c.oid
}

func (c cipherWithBlock) Encrypt(key, iv, plaintext []byte) ([]byte, pkerr.Kerror) {
	return cbcEncrypt(key, iv, plaintext)
}

func (c cipherWithBlock) Decrypt(key, iv, ciphertext []byte) ([]byte, pkerr.Kerror) {
	return cbcDecrypt(key, iv, ciphertext)
}

func cbcEncrypt(key, iv, plaintext []byte) ([]byte, pkerr.Kerror) {
	block, nativeError := aes.NewCipher(key)
	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext, nativeError := intcrypto.Pad(plaintext, aes.BlockSize)
	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext, nil
}

func cbcDecrypt(key, iv, ciphertext []byte) ([]byte, pkerr.Kerror) {
	block, nativeError := aes.NewCipher(key)
	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return intcrypto.Unpad(plaintext, aes.BlockSize)
}

// Cipher represents a cipher for encrypting the key material.
type Cipher interface {
	// IVSize returns the IV size of the cipher, in bytes.
	IVSize() int
	// KeySize returns the key size of the cipher, in bytes.
	KeySize() int
	// Encrypt encrypts the key material.
	Encrypt(key, iv, plaintext []byte) ([]byte, pkerr.Kerror)
	// Decrypt decrypts the key material.
	Decrypt(key, iv, ciphertext []byte) ([]byte, pkerr.Kerror)
	// OID returns the OID of the cipher specified.
	OID() asn1.ObjectIdentifier
}

func NewCipher(oid pkix.CipherOID) (Cipher, pkerr.Kerror) {
	a1oid := oid.ToAsn1()
	switch {
	// AES128CBC is the 128-bit key AES cipher in CBC mode.
	case oid.Equal(pkix.OidAES128CBC):
		return &cipherWithBlock{
			ivSize:  aes.BlockSize,
			keySize: 16,
			oid:     a1oid,
		}, nil
	// AES192CBC is the 192-bit key AES cipher in CBC mode.
	case oid.Equal(pkix.OidAES192CBC):
		return &cipherWithBlock{
			ivSize:  aes.BlockSize,
			keySize: 24,
			oid:     a1oid,
		}, nil
	// AES256CBC is the 256-bit key AES cipher in CBC mode.
	case oid.Equal(pkix.OidAES256CBC):
		return &cipherWithBlock{
			ivSize:  aes.BlockSize,
			keySize: 32,
			oid:     a1oid,
		}, nil
	}
	return nil, pkerr.NewErrUnsupportedEncryptionAlgorithm(a1oid.String())
}

func NewDefaultCipher() *cipherWithBlock {
	return &cipherWithBlock{
		ivSize:  aes.BlockSize,
		keySize: 32,
		oid:     pkix.OidAES256CBC.ToAsn1(),
	}
}

func NewDefaultPBMAC1Cipher() *cipherWithBlock {
	return &cipherWithBlock{
		oid: pkix.OidHMACWithSHA256.ToAsn1(),
	}
}
