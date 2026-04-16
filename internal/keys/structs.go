package keys

import (
	"math/big"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkix"
)

type PublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// EcPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//
//	RFC 5915
//	SEC1 - http://www.secg.org/sec1-v2.pdf
//
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type EcPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type Pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// pkcs1PrivateKey is a structure which mirrors the PKCS #1 ASN.1 for an RSA private key.
type Pkcs1PrivateKey struct {
	Version int
	N       *big.Int
	E       int
	D       *big.Int
	P       *big.Int
	Q       *big.Int
	Dp      *big.Int `asn1:"optional"`
	Dq      *big.Int `asn1:"optional"`
	Qinv    *big.Int `asn1:"optional"`

	AdditionalPrimes []Pkcs1AdditionalRSAPrime `asn1:"optional,omitempty"`
}

type Pkcs1AdditionalRSAPrime struct {
	Prime *big.Int

	// We ignore these values because rsa will calculate them.
	Exp   *big.Int
	Coeff *big.Int
}

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS #1 public key.
type Pkcs1PublicKey struct {
	N *big.Int
	E int
}
