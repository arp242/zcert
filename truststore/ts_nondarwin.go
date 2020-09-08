// +build !darwin

package truststore

import (
	"crypto/x509"
	"errors"
)

type Darwin struct{}

func (Darwin) Name() string                              { return "Darwin" }
func (Darwin) Verbose(v bool)                            {}
func (Darwin) OnSystem() bool                            { return false }
func (Darwin) HasCert(*x509.Certificate) bool            { return false }
func (Darwin) Install(string, *x509.Certificate) error   { return errors.New("dummy") }
func (Darwin) Uninstall(string, *x509.Certificate) error { return errors.New("dummy") }
