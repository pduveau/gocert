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

func (c *Certificate) systemVerify(opts *VerifyOptions) (chains [][]*Certificate, err pkerr.Pkerror) {
	return nil, nil
}

func loadSystemRoots() (*CertPool, pkerr.Pkerror) {
	roots := NewCertPool()
	var bestErr pkerr.Pkerror
	for _, file := range certFiles {
		data, err := os.ReadFile(file)
		if err == nil {
			roots.AppendCertsFromPEM(data)
			return roots, nil
		}
		if bestErr == nil || (os.IsNotExist(bestErr) && !os.IsNotExist(err)) {
			bestErr = pkerr.NewBaseErrorFromNativeError(err)
		}
	}
	if bestErr == nil {
		return roots, nil
	}
	return nil, bestErr
}
