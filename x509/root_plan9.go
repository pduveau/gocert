// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build plan9

package x509

import (
	"os"

	"github.com/pduveau/gocert/pkerr"
)

// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/sys/lib/tls/ca.pem",
}

func (c *Certificate) systemVerify(_ *VerifyOptions) (chains [][]*Certificate, err pkerr.Kerror) {
	return nil, nil
}

func loadSystemRoots() (*CertPool, pkerr.Kerror) {
	roots := NewCertPool()
	var bestErr pkerr.Kerror
	for _, file := range certFiles {
		data, nativeError := os.ReadFile(file)
		if nativeError == nil {
			roots.AppendCertsFromPEM(data)
			return roots, nil
		}
		if bestErr == nil || (os.IsNotExist(bestErr) && !os.IsNotExist(nativeError)) {
			bestErr = pkerr.NewErrNative(nativeError)
		}
	}
	if bestErr == nil {
		return roots, nil
	}
	return nil, bestErr
}
