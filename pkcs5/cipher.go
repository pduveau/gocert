package pkcs5

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/oids"
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

func (c cipherWithBlock) Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	return cbcEncrypt(key, iv, plaintext)
}

func (c cipherWithBlock) Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	return cbcDecrypt(key, iv, ciphertext)
}

func cbcEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	paddingLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	ciphertext := make([]byte, len(plaintext)+paddingLen)
	copy(ciphertext, plaintext)
	copy(ciphertext[len(plaintext):], bytes.Repeat([]byte{byte(paddingLen)}, paddingLen))
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext, nil
}

func cbcDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	psLen := int(plaintext[len(plaintext)-1])

	if len(plaintext) < psLen {
		return nil, ErrDecryption
	}

	ps := plaintext[len(plaintext)-psLen:]
	plaintext = plaintext[:len(plaintext)-psLen]
	if !bytes.Equal(ps, bytes.Repeat([]byte{byte(psLen)}, psLen)) {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

// Cipher represents a cipher for encrypting the key material.
type Cipher interface {
	// IVSize returns the IV size of the cipher, in bytes.
	IVSize() int
	// KeySize returns the key size of the cipher, in bytes.
	KeySize() int
	// Encrypt encrypts the key material.
	Encrypt(key, iv, plaintext []byte) ([]byte, error)
	// Decrypt decrypts the key material.
	Decrypt(key, iv, ciphertext []byte) ([]byte, error)
	// OID returns the OID of the cipher specified.
	OID() asn1.ObjectIdentifier
}

func NewCipher(oid oids.CipherOID) (Cipher, error) {
	a1oid := oid.ToAsn1()
	switch {
	// AES128CBC is the 128-bit key AES cipher in CBC mode.
	case oid.Equal(oids.OidAES128CBC):
		return &cipherWithBlock{
			ivSize:  aes.BlockSize,
			keySize: 16,
			oid:     a1oid,
		}, nil
	// AES192CBC is the 192-bit key AES cipher in CBC mode.
	case oid.Equal(oids.OidAES192CBC):
		return &cipherWithBlock{
			ivSize:  aes.BlockSize,
			keySize: 24,
			oid:     a1oid,
		}, nil
	// AES256CBC is the 256-bit key AES cipher in CBC mode.
	case oid.Equal(oids.OidAES256CBC):
		return &cipherWithBlock{
			ivSize:  aes.BlockSize,
			keySize: 32,
			oid:     a1oid,
		}, nil
	}
	return nil, fmt.Errorf("pksc5: unsupported Encryption algorithm (%s)", a1oid.String())
}

func NewDefaultCipher() *cipherWithBlock {
	return &cipherWithBlock{
		ivSize:  aes.BlockSize,
		keySize: 32,
		oid:     oids.OidAES256CBC.ToAsn1(),
	}
}

func NewDefaultPBMAC1Cipher() *cipherWithBlock {
	return &cipherWithBlock{
		oid: oids.OidHMACWithSHA256.ToAsn1(),
	}
}
