package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/internal/intcrypto"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
	"github.com/pduveau/gocert/x509"
)

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, pkerr.Kerror) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, pkerr.NewErrDecryptableDataType()
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, pkerr.NewErrNoEnvelopForCertificate()
	}
	switch k := pkey.(type) {
	case *rsa.PrivateKey:
		var contentKey []byte
		contentKey, err := rsa.DecryptPKCS1v15(rand.Reader, k, recipient.EncryptedKey)
		if err != nil {
			return nil, pkerr.NewErrNative(err)
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	}
	return nil, pkerr.NewErrCannotDecryptData()
}

// DecryptUsingPSK decrypts encrypted data using caller provided
// pre-shared secret
func (p7 *PKCS7) DecryptUsingPSK(key []byte) ([]byte, pkerr.Kerror) {
	data, ok := p7.raw.(encryptedData)
	if !ok {
		return nil, pkerr.NewErrDecryptableDataType()
	}
	return data.EncryptedContentInfo.decrypt(key)
}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, pkerr.Kerror) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	if !alg.Equal(oidDecryptionAlgorithmDESCBC) &&
		!alg.Equal(oidDecryptionAlgorithmDESEDE3CBC) &&
		!alg.Equal(pkix.OIDEncryptionAlgorithmAES256CBC) &&
		!alg.Equal(pkix.OIDEncryptionAlgorithmAES128CBC) &&
		!alg.Equal(pkix.OIDEncryptionAlgorithmAES128GCM) &&
		!alg.Equal(pkix.OIDEncryptionAlgorithmAES256GCM) {
		return nil, pkerr.NewErrUnsupportedEncryptionAlgorithm(alg.String())
	}

	// EncryptedContent can either be constructed of multple OCTET STRINGs
	// or _be_ a tagged OCTET STRING
	var cyphertext []byte
	if eci.EncryptedContent.IsCompound {
		// Complex case to concat all of the children OCTET STRINGs
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
		}
		cyphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the cyphertext
		cyphertext = eci.EncryptedContent.Bytes
	}

	var block cipher.Block
	var errNative error

	switch {
	case alg.Equal(oidDecryptionAlgorithmDESCBC):
		block, errNative = des.NewCipher(key)
	case alg.Equal(oidDecryptionAlgorithmDESEDE3CBC):
		block, errNative = des.NewTripleDESCipher(key)
	default:
		block, errNative = aes.NewCipher(key)
	}

	if errNative != nil {
		return nil, pkerr.NewErrNative(errNative)
	}

	if alg.Equal(pkix.OIDEncryptionAlgorithmAES128GCM) || alg.Equal(pkix.OIDEncryptionAlgorithmAES256GCM) {
		params := aesGCMParameters{}
		paramBytes := eci.ContentEncryptionAlgorithm.Parameters.Bytes

		_, err := asn1.Unmarshal(paramBytes, &params)
		if err != nil {
			return nil, err
		}

		gcm, errNative := cipher.NewGCM(block)
		if errNative != nil {
			return nil, pkerr.NewErrNative(errNative)
		}

		if len(params.Nonce) != gcm.NonceSize() {
			return nil, pkerr.NewErrInvalidAlgorithmParams()
		}
		if params.ICVLen != gcm.Overhead() {
			return nil, pkerr.NewErrInvalidAlgorithmParams()
		}

		plaintext, errNative := gcm.Open(nil, params.Nonce, cyphertext, nil)
		return plaintext, pkerr.NewErrNative(errNative)
	}

	iv := eci.ContentEncryptionAlgorithm.Parameters.Bytes
	if len(iv) != block.BlockSize() {
		return nil, pkerr.NewErrInvalidAlgorithmParams()
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(cyphertext))
	mode.CryptBlocks(plaintext, cyphertext)

	var err pkerr.Kerror
	if plaintext, err = intcrypto.Unpad(plaintext, mode.BlockSize()); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func selectRecipientForCertificate(recipients []recipientInfo, cert *x509.Certificate) recipientInfo {
	for _, recp := range recipients {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return recp
		}
	}
	return recipientInfo{}
}
