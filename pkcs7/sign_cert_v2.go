package pkcs7

import (
	"github.com/pduveau/gocert/pkix"
)

type essCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"` // default sha256
	CertHash      []byte
	IssuerSerial  issuerAndSerial `asn1:"optional"`
}

type signingCertificateV2 struct {
	Certs []essCertIDv2
}
