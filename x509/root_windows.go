// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

func loadSystemRoots() (*CertPool, pkerr.Kerror) {
	return &CertPool{systemPool: true}, nil
}

// Creates a new *syscall.CertContext representing the leaf certificate in an in-memory
// certificate store containing itself and all of the intermediate certificates specified
// in the opts.Intermediates CertPool.
//
// A pointer to the in-memory store is available in the returned CertContext's Store field.
// The store is automatically freed when the CertContext is freed using
// syscall.CertFreeCertificateContext.
func createStoreContext(leaf *Certificate, opts *VerifyOptions) (*syscall.CertContext, pkerr.Kerror) {
	var storeCtx *syscall.CertContext

	leafCtx, nativeError := syscall.CertCreateCertificateContext(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING, &leaf.Raw[0], uint32(len(leaf.Raw)))
	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}
	defer syscall.CertFreeCertificateContext(leafCtx)

	handle, nativeError := syscall.CertOpenStore(syscall.CERT_STORE_PROV_MEMORY, 0, 0, syscall.CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, 0)
	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}
	defer syscall.CertCloseStore(handle, 0)

	nativeError = syscall.CertAddCertificateContextToStore(handle, leafCtx, syscall.CERT_STORE_ADD_ALWAYS, &storeCtx)
	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}

	if opts.Intermediates != nil {
		for i := 0; i < opts.Intermediates.len(); i++ {
			intermediate, _, err := opts.Intermediates.cert(i)
			if err != nil {
				return nil, err
			}
			ctx, nativeError := syscall.CertCreateCertificateContext(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING, &intermediate.Raw[0], uint32(len(intermediate.Raw)))
			if nativeError != nil {
				return nil, pkerr.NewErrNative(nativeError)
			}

			nativeError = syscall.CertAddCertificateContextToStore(handle, ctx, syscall.CERT_STORE_ADD_ALWAYS, nil)
			syscall.CertFreeCertificateContext(ctx)
			if nativeError != nil {
				return nil, pkerr.NewErrNative(nativeError)
			}
		}
	}

	return storeCtx, nil
}

// extractSimpleChain extracts the final certificate chain from a CertSimpleChain.
func extractSimpleChain(simpleChain **syscall.CertSimpleChain, count int) (chain []*Certificate, err pkerr.Kerror) {
	if simpleChain == nil || count == 0 {
		return nil, pkerr.NewErrInvalidSimpleChain()
	}

	simpleChains := unsafe.Slice(simpleChain, count)
	lastChain := simpleChains[count-1]
	elements := unsafe.Slice(lastChain.Elements, lastChain.NumElements)
	for i := 0; i < int(lastChain.NumElements); i++ {
		// Copy the buf, since ParseCertificate does not create its own copy.
		cert := elements[i].CertContext
		encodedCert := unsafe.Slice(cert.EncodedCert, cert.Length)
		buf := bytes.Clone(encodedCert)
		parsedCert, err := ParseCertificate(buf)
		if err != nil {
			return nil, err
		}
		chain = append(chain, parsedCert)
	}

	return chain, nil
}

// checkChainTrustStatus checks the trust status of the certificate chain, translating
// any errors it finds into Go errors in the process.
func checkChainTrustStatus(chainCtx *syscall.CertChainContext) pkerr.Kerror {
	if chainCtx.TrustStatus.ErrorStatus != syscall.CERT_TRUST_NO_ERROR {
		status := chainCtx.TrustStatus.ErrorStatus
		switch status {
		case syscall.CERT_TRUST_IS_NOT_TIME_VALID:
			return pkerr.NewErrCertificateInvalid(pkerr.NunErrExpired)
		case syscall.CERT_TRUST_IS_NOT_VALID_FOR_USAGE:
			return pkerr.NewErrCertificateInvalid(pkerr.NunErrIncompatibleUsage)
		// TODO(filippo): surface more error statuses.
		default:
			return UnknownAuthorityError(nil, nil)
		}
	}
	return nil
}

// checkChainSSLServerPolicy checks that the certificate chain in chainCtx is valid for
// use as a certificate chain for a SSL/TLS server.
func checkChainSSLServerPolicy(c *Certificate, chainCtx *syscall.CertChainContext, opts *VerifyOptions) pkerr.Kerror {
	servernamep, nativeError := syscall.UTF16PtrFromString(strings.TrimSuffix(opts.DNSName, "."))
	if nativeError != nil {
		return pkerr.NewErrNative(nativeError)
	}
	sslPara := &syscall.SSLExtraCertChainPolicyPara{
		AuthType:   syscall.AUTHTYPE_SERVER,
		ServerName: servernamep,
	}
	sslPara.Size = uint32(unsafe.Sizeof(*sslPara))

	para := &syscall.CertChainPolicyPara{
		ExtraPolicyPara: (syscall.Pointer)(unsafe.Pointer(sslPara)),
	}
	para.Size = uint32(unsafe.Sizeof(*para))

	status := syscall.CertChainPolicyStatus{}
	nativeError = syscall.CertVerifyCertificateChainPolicy(syscall.CERT_CHAIN_POLICY_SSL, chainCtx, para, &status)
	if nativeError != nil {
		return pkerr.NewErrNative(nativeError)
	}

	// TODO(mkrautz): use the lChainIndex and lElementIndex fields
	// of the CertChainPolicyStatus to provide proper context, instead
	// using c.
	if status.Error != 0 {
		switch status.Error {
		case syscall.CERT_E_EXPIRED:
			return pkerr.NewErrCertificateInvalid(pkerr.NunErrExpired)
		case syscall.CERT_E_CN_NO_MATCH:
			return HostnameError(opts.DNSName, c)
		case syscall.CERT_E_UNTRUSTEDROOT:
			return UnknownAuthorityError(nil, nil)
		default:
			return UnknownAuthorityError(nil, nil)
		}
	}

	return nil
}

// windowsExtKeyUsageOIDs are the C NUL-terminated string representations of the
// OIDs for use with the Windows API.
var windowsExtKeyUsageOIDs = make(map[ExtKeyUsage][]byte, len(extKeyUsageOIDs))

func init() {
	for _, eku := range extKeyUsageOIDs {
		windowsExtKeyUsageOIDs[eku.extKeyUsage] = []byte(eku.oid.String() + "\x00")
	}
}

func verifyChain(c *Certificate, chainCtx *syscall.CertChainContext, opts *VerifyOptions) (chain []*Certificate, err pkerr.Kerror) {
	err = checkChainTrustStatus(chainCtx)
	if err != nil {
		return nil, err
	}

	if opts != nil && len(opts.DNSName) > 0 {
		err = checkChainSSLServerPolicy(c, chainCtx, opts)
		if err != nil {
			return nil, err
		}
	}

	chain, err = extractSimpleChain(chainCtx.Chains, int(chainCtx.ChainCount))
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, pkerr.NewErrEmptyChain()
	}

	// Mitigate CVE-2020-0601, where the Windows system verifier might be
	// tricked into using custom curve parameters for a trusted root, by
	// double-checking all ECDSA signatures. If the system was tricked into
	// using spoofed parameters, the signature will be invalid for the correct
	// ones we parsed. (We don't support custom curves ourselves.)
	for i, parent := range chain[1:] {
		if parent.PublicKeyAlgorithm != pkix.ECDSA {
			continue
		}
		if err := parent.CheckSignature(chain[i].SignatureAlgorithm,
			chain[i].RawTBSCertificate, chain[i].Signature); err != nil {
			return nil, err
		}
	}
	return chain, nil
}

// systemVerify is like Verify, except that it uses CryptoAPI calls
// to build certificate chains and verify them.
func (c *Certificate) systemVerify(opts *VerifyOptions) (chains [][]*Certificate, err pkerr.Kerror) {
	storeCtx, err := createStoreContext(c, opts)
	if err != nil {
		return nil, err
	}
	defer syscall.CertFreeCertificateContext(storeCtx)

	para := new(syscall.CertChainPara)
	para.Size = uint32(unsafe.Sizeof(*para))

	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []ExtKeyUsage{ExtKeyUsageServerAuth}
	}
	oids := make([]*byte, 0, len(keyUsages))
	for _, eku := range keyUsages {
		if eku == ExtKeyUsageAny {
			oids = nil
			break
		}
		if oid, ok := windowsExtKeyUsageOIDs[eku]; ok {
			oids = append(oids, &oid[0])
		}
	}
	if oids != nil {
		para.RequestedUsage.Type = syscall.USAGE_MATCH_TYPE_OR
		para.RequestedUsage.Usage.Length = uint32(len(oids))
		para.RequestedUsage.Usage.UsageIdentifiers = &oids[0]
	} else {
		para.RequestedUsage.Type = syscall.USAGE_MATCH_TYPE_AND
		para.RequestedUsage.Usage.Length = 0
		para.RequestedUsage.Usage.UsageIdentifiers = nil
	}

	var verifyTime *syscall.Filetime
	if opts != nil && !opts.CurrentTime.IsZero() {
		ft := syscall.NsecToFiletime(opts.CurrentTime.UnixNano())
		verifyTime = &ft
	}

	// The default is to return only the highest quality chain,
	// setting this flag will add additional lower quality contexts.
	// These are returned in the LowerQualityChains field.
	const CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS = 0x00000080

	// CertGetCertificateChain will traverse Windows's root stores in an attempt to build a verified certificate chain
	var topCtx *syscall.CertChainContext
	nativeError := syscall.CertGetCertificateChain(syscall.Handle(0), storeCtx, verifyTime, storeCtx.Store, para, CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS, 0, &topCtx)
	if nativeError != nil {
		return nil, pkerr.NewErrNative(nativeError)
	}
	defer syscall.CertFreeCertificateChain(topCtx)

	chain, topErr := verifyChain(c, topCtx, opts)
	if topErr == nil {
		chains = append(chains, chain)
	}

	if lqCtxCount := topCtx.LowerQualityChainCount; lqCtxCount > 0 {
		lqCtxs := unsafe.Slice(topCtx.LowerQualityChains, lqCtxCount)
		for _, ctx := range lqCtxs {
			chain, err := verifyChain(c, ctx, opts)
			if err == nil {
				chains = append(chains, chain)
			}
		}
	}

	if len(chains) == 0 {
		// Return the error from the highest quality context.
		return nil, topErr
	}

	return chains, nil
}
