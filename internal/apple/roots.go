// Package apple supplies the Apple trust anchors shared by authentication and
// signed Private Relay configuration verification.
package apple

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"sync"
)

//go:embed roots.pem
var rootsPEM []byte

var cachedRoots = sync.OnceValues(func() (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootsPEM) {
		return nil, errors.New("load Apple Root CA bundle")
	}
	return roots, nil
})

var cachedSystemRoots = sync.OnceValues(func() (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(rootsPEM) {
		return nil, errors.New("load Apple Root CA bundle")
	}
	return roots, nil
})

// Roots returns the cached Apple-only trust anchors. Treat the pool as read-only.
func Roots() (*x509.CertPool, error) { return cachedRoots() }

// SystemRoots returns system roots plus Apple anchors. Treat the pool as read-only.
func SystemRoots() (*x509.CertPool, error) { return cachedSystemRoots() }
