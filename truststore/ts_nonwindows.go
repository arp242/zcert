// +build !windows

package truststore

import (
	"crypto/x509"
	"errors"
)

type Windows struct{}

func (Windows) Name() string                              { return "Windows" }
func (Windows) Verbose(v bool)                            {}
func (Windows) OnSystem() bool                            { return false }
func (Windows) HasCert(*x509.Certificate) bool            { return false }
func (Windows) Install(string, *x509.Certificate) error   { return errors.New("dummy") }
func (Windows) Uninstall(string, *x509.Certificate) error { return errors.New("dummy") }
