package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/internal/pkixstring"
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

type PublicKeyInfo struct {
	//	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func (p *PublicKeyInfo) Public() crypto.PublicKey {
	pub, _ := p.ParsePublicKey()
	return pub
}

func (keyData *PublicKeyInfo) ParsePublicKey() (any, pkerr.Kerror) {
	oid := keyData.Algorithm.Algorithm
	params := keyData.Algorithm.Parameters
	data := keyData.PublicKey.RightAlign()
	switch {
	case oid.Equal(pkix.OidPublicKeyRSA):
		// RSA public keys must have a NULL in the parameters.
		// See RFC 3279, Section 2.3.1.
		if !bytes.Equal(params.FullBytes, asn1.NullBytes) {
			return nil, pkerr.NewErrRSAMissingParams()
		}

		der := pkixstring.String(data)
		p := &Pkcs1PublicKey{N: new(big.Int)}
		if !der.ReadASN1(&der, pkixstring.SEQUENCE) {
			return nil, pkerr.NewErrRSAMissingParams()
		}
		if !der.ReadASN1Integer(p.N) {
			return nil, pkerr.NewErrRSAInvalidModulus()
		}
		if !der.ReadASN1Integer(&p.E) {
			return nil, pkerr.NewErrRSAInvalidPublicExponent()
		}

		if p.N.Sign() <= 0 {
			return nil, pkerr.NewErrRSAInvalidModulus()
		}
		if p.E <= 0 {
			return nil, pkerr.NewErrRSAInvalidPublicExponent()
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	case oid.Equal(pkix.OidPublicKeyECDSA):
		paramsDer := pkixstring.String(params.FullBytes)
		namedCurveOID := new(asn1.ObjectIdentifier)
		if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
			return nil, pkerr.NewErrInvalidECDSAParams()
		}
		namedCurve := pkix.NamedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, pkerr.NewErrUnsupportedEC()
		}
		key, nativeError := ecdsa.ParseUncompressedPublicKey(namedCurve, data)
		if nativeError != nil {
			return nil, pkerr.NewErrNative(nativeError)
		}
		return key, nil
	case oid.Equal(pkix.OidPublicKeyEd25519):
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(params.FullBytes) != 0 {
			return nil, pkerr.NewErrInvalidEd25519Params()
		}
		if len(data) != ed25519.PublicKeySize {
			return nil, pkerr.NewErrEd25519Keylen()
		}
		return ed25519.PublicKey(data), nil
	case oid.Equal(pkix.OidPublicKeyX25519):
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(params.FullBytes) != 0 {
			return nil, pkerr.NewErrIllegalX25519Params()
		}
		key, nativeError := ecdh.X25519().NewPublicKey(data)
		if nativeError != nil {
			return nil, pkerr.NewErrNative(nativeError)
		}
		return key, nil
	case oid.Equal(pkix.OidPublicKeyDSA):
		return nil, pkerr.NewErrDeprecatedAlgorithm()
	default:
		return nil, pkerr.NewErrUnknownPubKeyAlgorithm()
	}
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
type Pkcs8PrivateKey struct {
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

const ecPrivKeyVersion = 1

// marshalECPrivateKeyWithOID marshals an EC private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func MarshalECPrivateKeyWithOID(key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier) ([]byte, pkerr.Kerror) {
	privateKey, nativeError := key.Bytes()
	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}
	publicKey, nativeError := key.PublicKey.Bytes()
	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}
	return asn1.Marshal(EcPrivateKey{
		Version:       1,
		PrivateKey:    privateKey,
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: publicKey},
	})
}

// marshalECDHPrivateKey marshals an EC private key into ASN.1, DER format
// suitable for NIST curves.
func MarshalECDHPrivateKey(key *ecdh.PrivateKey) ([]byte, pkerr.Kerror) {
	return asn1.Marshal(EcPrivateKey{
		Version:    1,
		PrivateKey: key.Bytes(),
		PublicKey:  asn1.BitString{Bytes: key.PublicKey().Bytes()},
	})
}

// parseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func ParseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *ecdsa.PrivateKey, err pkerr.Kerror) {
	var privKey EcPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &Pkcs8PrivateKey{}); err == nil {
			return nil, pkerr.NewErrFailToParsePrivateKeyGotoPKCS8()
		}
		if _, err := asn1.Unmarshal(der, &Pkcs1PrivateKey{}); err == nil {
			return nil, pkerr.NewErrFailToParsePrivateKeyGotoPKCS1()
		}
		return nil, pkerr.NewErrFailToParseECPrivateKey(err)
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, pkerr.NewErrUnknownPrivateKeyVersion(privKey.Version)
	}

	var curve elliptic.Curve
	if namedCurveOID != nil {
		curve = pkix.NamedCurveFromOID(*namedCurveOID)
	} else {
		curve = pkix.NamedCurveFromOID(privKey.NamedCurveOID)
	}
	if curve == nil {
		return nil, pkerr.NewErrUnknownEC()
	}

	size := (curve.Params().N.BitLen() + 7) / 8
	privateKey := make([]byte, size)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, pkerr.NewErrInvalidKeylen()
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)

	key, nativeError := ecdsa.ParseRawPrivateKey(curve, privateKey)
	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}
	return key, nil
}

func MarshalPublicKey(pub any) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err pkerr.Kerror) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(Pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Algorithm = pkix.OidPublicKeyRSA
		// This is a NULL parameters value which is required by
		// RFC 3279, Section 2.3.1.
		publicKeyAlgorithm.Parameters = asn1.NullRawValue
	case *ecdsa.PublicKey:
		oid, ok := pkix.OidFromNamedCurve(pub.Curve)
		if !ok {
			err = pkerr.NewErrUnsupportedEC()
			return
		}
		var nativeError error
		publicKeyBytes, nativeError = pub.Bytes()
		err = pkerr.NewErrNative(nativeError)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Algorithm = pkix.OidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case ed25519.PublicKey:
		publicKeyBytes = pub
		publicKeyAlgorithm.Algorithm = pkix.OidPublicKeyEd25519
	case *ecdh.PublicKey:
		publicKeyBytes = pub.Bytes()
		if pub.Curve() == ecdh.X25519() {
			publicKeyAlgorithm.Algorithm = pkix.OidPublicKeyX25519
		} else {
			oid, ok := pkix.OidFromECDHCurve(pub.Curve())
			if !ok {
				return nil, pkix.AlgorithmIdentifier{}, pkerr.NewErrUnsupportedEC()
			}
			publicKeyAlgorithm.Algorithm = pkix.OidPublicKeyECDSA
			var paramBytes []byte
			paramBytes, err = asn1.Marshal(oid)
			if err != nil {
				return
			}
			publicKeyAlgorithm.Parameters.FullBytes = paramBytes
		}
	default:
		return nil, pkix.AlgorithmIdentifier{}, pkerr.NewErrUnsupportedPublicKeyType(pub)
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}
