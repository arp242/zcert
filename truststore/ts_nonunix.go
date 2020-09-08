// +build !aix
// +build !dragonfly
// +build !freebsd
// +build !linux
// +build !netbsd
// +build !openbsd
// +build !solaris

package truststore

import (
	"crypto/x509"
	"errors"
)

type Unix struct{}

func (Unix) Name() string                              { return "Unix" }
func (Unix) Verbose(v bool)                            {}
func (Unix) OnSystem() bool                            { return false }
func (Unix) HasCert(*x509.Certificate) bool            { return false }
func (Unix) Install(string, *x509.Certificate) error   { return errors.New("dummy") }
func (Unix) Uninstall(string, *x509.Certificate) error { return errors.New("dummy") }
