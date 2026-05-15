package pkix

import (
	"crypto"
	"crypto/ecdh"
	"crypto/elliptic"
	"strconv"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkerr"
)

type HmacOID asn1.ObjectIdentifier
type CipherOID asn1.ObjectIdentifier

var (
	OidScrypt      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	OidPKCS5PBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	OidPBES2       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	OidPBMAC1      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

	// Digest Algorithms for compatibility while parsing
	oidDigestAlgorithmSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	// Digest Algorithms
	OIDDigestAlgorithmSHA256      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDDigestAlgorithmECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDDigestAlgorithmECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDDigestAlgorithmECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// Signature Algorithms
	OIDEncryptionAlgorithmRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDSignatureAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSignatureAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSignatureAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	OIDSignatureAlgorithmECDSAP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDSignatureAlgorithmECDSAP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OIDSignatureAlgorithmECDSAP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	// Encryption Algorithms
	OIDEncryptionAlgorithmAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OIDEncryptionAlgorithmAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	OIDEncryptionAlgorithmAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	OIDEncryptionAlgorithmAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}

	// Hmac Algorithms
	OidHMACWithSHA1       = HmacOID{1, 2, 840, 113549, 2, 7}
	OidHMACWithSHA224     = HmacOID{1, 2, 840, 113549, 2, 8}
	OidHMACWithSHA256     = HmacOID{1, 2, 840, 113549, 2, 9}
	OidHMACWithSHA384     = HmacOID{1, 2, 840, 113549, 2, 10}
	OidHMACWithSHA512     = HmacOID{1, 2, 840, 113549, 2, 11}
	OidHMACWithSHA512_224 = HmacOID{1, 2, 840, 113549, 2, 12}
	OidHMACWithSHA512_256 = HmacOID{1, 2, 840, 113549, 2, 13}

	// Encryption Algorithms
	OidAES128CBC = CipherOID{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OidAES192CBC = CipherOID{2, 16, 840, 1, 101, 3, 4, 1, 22}
	OidAES256CBC = CipherOID{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

func (c HmacOID) Equal(d HmacOID) bool {
	return asn1.ObjectIdentifier(c).Equal(asn1.ObjectIdentifier(d))
}
func (c HmacOID) ToAsn1() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier(c)
}

func (c CipherOID) Equal(d CipherOID) bool {
	return c.ToAsn1().Equal(d.ToAsn1())
}

func (c CipherOID) ToAsn1() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier(c)
}

type PublicKeyAlgorithm int

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA // Only supported for parsing.
	ECDSA
	Ed25519
)

var publicKeyAlgoName = [...]string{
	RSA:     "RSA",
	DSA:     "DSA",
	ECDSA:   "ECDSA",
	Ed25519: "Ed25519",
}

func (algo PublicKeyAlgorithm) String() string {
	if 0 < algo && int(algo) < len(publicKeyAlgoName) {
		return publicKeyAlgoName[algo]
	}
	return strconv.Itoa(int(algo))
}

// getPublicKeyAlgorithmFromOID returns the exposed PublicKeyAlgorithm
// identifier for public key types supported in certificates and CSRs. Marshal
// and Parse functions may support a different set of public key types.
func GetPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
	switch {
	case oid.Equal(OidPublicKeyRSA):
		return RSA
	case oid.Equal(OidPublicKeyDSA):
		return DSA
	case oid.Equal(OidPublicKeyECDSA):
		return ECDSA
	case oid.Equal(OidPublicKeyEd25519):
		return Ed25519
	}
	return UnknownPublicKeyAlgorithm
}

// OIDs for signature algorithms
//
//	pkcs-1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
//
// RFC 3279 2.2.1 RSA Signature Algorithms
//
//	md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }
//
//	sha-1WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 5 }
//
//	dsaWithSha1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
//
// RFC 3279 2.2.3 ECDSA Signature Algorithm
//
//	ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) ansi-x962(10045)
//		signatures(4) ecdsa-with-SHA1(1)}
//
// RFC 4055 5 PKCS #1 Version 1.5
//
//	sha256WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 11 }
//
//	sha384WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 12 }
//
//	sha512WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 13 }
//
// RFC 5758 3.1 DSA Signature Algorithms
//
//	dsaWithSha256 OBJECT IDENTIFIER ::= {
//		joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
//		csor(3) algorithms(4) id-dsa-with-sha2(3) 2}
//
// RFC 5758 3.2 ECDSA Signature Algorithm
//
//	ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
//
//	ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
//
//	ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
//
// RFC 8410 3 Curve25519 and Curve448 Algorithm Identifiers
//
//	id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
var (
	OidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	OidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	OidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	OidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OidSignatureEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	OidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	OidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// OidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	OidISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)

var emptyRawValue = asn1.RawValue{}

// DER encoded RSA PSS parameters for the
// SHA256, SHA384, and SHA512 hashes as defined in RFC 3447, Appendix A.2.3.
// The parameters contain the following values:
//   - hashAlgorithm contains the associated hash identifier with NULL parameters
//   - maskGenAlgorithm always contains the default mgf1SHA1 identifier
//   - saltLength contains the length of the associated hash
//   - trailerField always contains the default trailerFieldBC value
var (
	pssParametersSHA256 = asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 162, 3, 2, 1, 32}}
	pssParametersSHA384 = asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 162, 3, 2, 1, 48}}
	pssParametersSHA512 = asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 162, 3, 2, 1, 64}}
)

type SignatureAlgorithm int

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota

	RSAWithMD5  // Only supported for signing, not verification.
	RSAWithSHA1 // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
	RSAWithSHA256
	RSAWithSHA384
	RSAWithSHA512
	RSAPSSWithSHA256
	RSAPSSWithSHA384
	RSAPSSWithSHA512
	DSAWithSHA1   // Unsupported.
	DSAWithSHA256 // Unsupported.
	ECDSAWithSHA1 // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	PureEd25519
	maxSignatureAlgorithm
)

type signatureAlgorithmDetails_t struct {
	Algo       SignatureAlgorithm
	Name       string
	Oid        asn1.ObjectIdentifier
	Params     asn1.RawValue
	PubKeyAlgo PublicKeyAlgorithm
	Hash       crypto.Hash
	IsRSAPSS   bool
}

var signatureAlgorithmDetails = []signatureAlgorithmDetails_t{
	{},
	{RSAWithMD5, "MD5-RSA", OidSignatureMD5WithRSA, asn1.NullRawValue, RSA, crypto.MD5, false},
	{RSAWithSHA1, "SHA1-RSA", OidSignatureSHA1WithRSA, asn1.NullRawValue, RSA, crypto.SHA1, false},
	{RSAWithSHA256, "SHA256-RSA", OidSignatureSHA256WithRSA, asn1.NullRawValue, RSA, crypto.SHA256, false},
	{RSAWithSHA384, "SHA384-RSA", OidSignatureSHA384WithRSA, asn1.NullRawValue, RSA, crypto.SHA384, false},
	{RSAWithSHA512, "SHA512-RSA", OidSignatureSHA512WithRSA, asn1.NullRawValue, RSA, crypto.SHA512, false},
	{RSAPSSWithSHA256, "SHA256-RSAPSS", OidSignatureRSAPSS, pssParametersSHA256, RSA, crypto.SHA256, true},
	{RSAPSSWithSHA384, "SHA384-RSAPSS", OidSignatureRSAPSS, pssParametersSHA384, RSA, crypto.SHA384, true},
	{RSAPSSWithSHA512, "SHA512-RSAPSS", OidSignatureRSAPSS, pssParametersSHA512, RSA, crypto.SHA512, true},
	{DSAWithSHA1, "DSA-SHA1", OidSignatureDSAWithSHA1, emptyRawValue, DSA, crypto.SHA1, false},
	{DSAWithSHA256, "DSA-SHA256", OidSignatureDSAWithSHA256, emptyRawValue, DSA, crypto.SHA256, false},
	{ECDSAWithSHA1, "ECDSA-SHA1", OidSignatureECDSAWithSHA1, emptyRawValue, ECDSA, crypto.SHA1, false},
	{ECDSAWithSHA256, "ECDSA-SHA256", OidSignatureECDSAWithSHA256, emptyRawValue, ECDSA, crypto.SHA256, false},
	{ECDSAWithSHA384, "ECDSA-SHA384", OidSignatureECDSAWithSHA384, emptyRawValue, ECDSA, crypto.SHA384, false},
	{ECDSAWithSHA512, "ECDSA-SHA512", OidSignatureECDSAWithSHA512, emptyRawValue, ECDSA, crypto.SHA512, false},
	{PureEd25519, "Ed25519", OidSignatureEd25519, emptyRawValue, Ed25519, crypto.Hash(0) /* no pre-hashing */, false},
}

var signatureAlgorithmDetailsMS = signatureAlgorithmDetails_t{RSAWithSHA1, "SHA1-RSA", OidISOSignatureSHA1WithRSA, asn1.NullRawValue, RSA, crypto.SHA1, false}

func (algo SignatureAlgorithm) IsRSAPSS() bool {
	if algo > 0 && algo < maxSignatureAlgorithm {
		return signatureAlgorithmDetails[algo].IsRSAPSS
	}
	return false
}

func (algo SignatureAlgorithm) HashFunc() crypto.Hash {
	if algo > 0 && algo < maxSignatureAlgorithm {
		return signatureAlgorithmDetails[algo].Hash
	}
	return crypto.Hash(0)
}

func (algo SignatureAlgorithm) String() string {
	if algo > 0 && algo < maxSignatureAlgorithm {
		return signatureAlgorithmDetails[algo].Name
	}
	return strconv.Itoa(int(algo))
}

// DigestOID returns the corresponding OID digest algorithm
func (digestAlg SignatureAlgorithm) DigestOID() (asn1.ObjectIdentifier, pkerr.Kerror) {
	switch digestAlg {
	case RSAWithSHA256, ECDSAWithSHA256:
		return OIDDigestAlgorithmSHA256, nil
	case RSAWithSHA384, ECDSAWithSHA384:
		return OIDDigestAlgorithmSHA384, nil
	case RSAWithSHA512, ECDSAWithSHA512:
		return OIDDigestAlgorithmSHA512, nil
	}
	return nil, pkerr.NewErrOIDConvertToAlgorithm()
}

func GetSignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) SignatureAlgorithm {
	if oid.Equal(signatureAlgorithmDetailsMS.Oid) {
		return signatureAlgorithmDetailsMS.Algo
	}
	for _, details := range signatureAlgorithmDetails {
		if oid.Equal(details.Oid) {
			return details.Algo
		}
	}
	return UnknownSignatureAlgorithm
}

func GetSignatureAlgorithmDetailsFromAlgo(algo SignatureAlgorithm) *signatureAlgorithmDetails_t {
	if algo > 0 && algo < maxSignatureAlgorithm {
		return &signatureAlgorithmDetails[algo]
	}
	return nil
}

func GetSignatureAlgorithmDetailsFromAlgoAndPubKeyType(algo SignatureAlgorithm, pubType PublicKeyAlgorithm) (*signatureAlgorithmDetails_t, pkerr.Kerror) {
	if algo > 0 && algo < maxSignatureAlgorithm {
		details := signatureAlgorithmDetails[algo]
		if details.PubKeyAlgo != pubType {
			return nil, pkerr.NewErrSignaturePublicKeyAlgoMismatch(details.PubKeyAlgo.String(), pubType)
		}
		if details.Hash == crypto.MD5 {
			return nil, pkerr.NewErrUnknownSignatureAlgorithm()
		}
		return &details, nil
	}
	return nil, nil
}

var (
	// RFC 3279, 2.3 Public Key Algorithms
	//
	//	pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
	//		rsadsi(113549) pkcs(1) 1 }
	//
	// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
	//
	//	id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
	//		x9-57(10040) x9cm(4) 1 }
	OidPublicKeyRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OidPublicKeyDSA = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	// RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
	//
	//	id-ecPublicKey OBJECT IDENTIFIER ::= {
	//		iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
	OidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	// RFC 8410, Section 3
	//
	//	id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }
	//	id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
	OidPublicKeyX25519  = asn1.ObjectIdentifier{1, 3, 101, 110}
	OidPublicKeyEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// RFC 5480, 2.1.1.1. Named Curve
//
//	secp224r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
//	secp256r1 OBJECT IDENTIFIER ::= {
//	  iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//	  prime(1) 7 }
//
//	secp384r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
//	secp521r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
// NB: secp256r1 is equivalent to prime256v1
var (
	OidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	OidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func NamedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(OidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(OidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(OidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(OidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

func OidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return OidNamedCurveP224, true
	case elliptic.P256():
		return OidNamedCurveP256, true
	case elliptic.P384():
		return OidNamedCurveP384, true
	case elliptic.P521():
		return OidNamedCurveP521, true
	}

	return nil, false
}

func OidFromECDHCurve(curve ecdh.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case ecdh.X25519():
		return OidPublicKeyX25519, true
	case ecdh.P256():
		return OidNamedCurveP256, true
	case ecdh.P384():
		return OidNamedCurveP384, true
	case ecdh.P521():
		return OidNamedCurveP521, true
	}

	return nil, false
}
