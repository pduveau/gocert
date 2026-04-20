package pkixstring

import (
	"github.com/pduveau/gocert/pkerr"
	"github.com/pduveau/gocert/pkix"
)

func ParseAuthorityKeyIdentifier(e pkix.Extension) ([]byte, pkerr.Kerror) {
	// RFC 5280, Section 4.2.1.1
	if e.Critical {
		// Conforming CAs MUST mark this extension as non-critical
		return nil, pkerr.NewErrAKICritical()
	}
	val := String(e.Value)
	var akid String
	if !val.ReadASN1(&akid, SEQUENCE) {
		return nil, pkerr.NewErrInvalidAKI()
	}
	if akid.PeekASN1Tag(Tag(0).ContextSpecific()) {
		if !akid.ReadASN1(&akid, Tag(0).ContextSpecific()) {
			return nil, pkerr.NewErrInvalidAKI()
		}
		return akid, nil
	}
	return nil, nil
}
