package keys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/oids"
)

const ecPrivKeyVersion = 1

// marshalECPrivateKeyWithOID marshals an EC private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func MarshalECPrivateKeyWithOID(key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
	privateKey, err := key.Bytes()
	if err != nil {
		return nil, err
	}
	publicKey, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, err
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
func MarshalECDHPrivateKey(key *ecdh.PrivateKey) ([]byte, error) {
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
func ParseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *ecdsa.PrivateKey, err error) {
	var privKey EcPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &Pkcs8{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &Pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	var curve elliptic.Curve
	if namedCurveOID != nil {
		curve = oids.NamedCurveFromOID(*namedCurveOID)
	} else {
		curve = oids.NamedCurveFromOID(privKey.NamedCurveOID)
	}
	if curve == nil {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	size := (curve.Params().N.BitLen() + 7) / 8
	privateKey := make([]byte, size)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)

	return ecdsa.ParseRawPrivateKey(curve, privateKey)
}
