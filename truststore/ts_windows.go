// +build windows

package truststore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	firefoxProfile      = os.Getenv("USERPROFILE") + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
	certutilInstallHelp = "" // certutil unsupported on Windows
	nssBrowsers         = "Firefox"
)

type Windows struct{ verbose bool }

func (Windows) Name() string      { return "Windows" }
func (t *Windows) Verbose(v bool) { t.verbose = v }
func (Windows) OnSystem() bool    { return runtime.GOOS == "windows" }

func (t Windows) HasCert(caCert *x509.Certificate) bool {
	// TODO
	return false
}

func (t Windows) Install(rootCert string, caCert *x509.Certificate) error {
	cert, err := ioutil.ReadFile(rootCert)
	if err != nil {
		return fmt.Errorf("truststore.Windows: %w", err)
	}

	certBlock, _ := pem.Decode(cert)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("truststore.Windows: invalid PEM data")
	}

	cert = certBlock.Bytes
	store, err := openWindowsRootStore()
	if err != nil {
		return fmt.Errorf("truststore.Windows: open root store: %w", err)
	}

	defer store.close()

	// Add cert
	err = store.addCert(cert)
	if err != nil {
		return fmt.Errorf("truststore.Windows: add cert to root: %w", err)
	}

	return nil
}

func (t Windows) Uninstall(rootCert string, caCert *x509.Certificate) error {
	// We'll just remove all certs with the same serial number
	store, err := openWindowsRootStore()
	if err != nil {
		return fmt.Errorf("truststore.Windows: open root store: %w", err)
	}
	defer store.close()

	deletedAny, err := store.deleteCertsWithSerial(caCert.SerialNumber)
	if err != nil {
		return fmt.Errorf("truststore.Windows: delete cert: %w", err)
	}
	if !deletedAny {
		err = fmt.Errorf("truststore.Windows: no certs found")
	}
	return nil
}

type windowsRootStore uintptr

var (
	modcrypt32                           = syscall.NewLazyDLL("crypt32.dll")
	procCertAddEncodedCertificateToStore = modcrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertCloseStore                   = modcrypt32.NewProc("CertCloseStore")
	procCertDeleteCertificateFromStore   = modcrypt32.NewProc("CertDeleteCertificateFromStore")
	procCertDuplicateCertificateContext  = modcrypt32.NewProc("CertDuplicateCertificateContext")
	procCertEnumCertificatesInStore      = modcrypt32.NewProc("CertEnumCertificatesInStore")
	procCertOpenSystemStoreW             = modcrypt32.NewProc("CertOpenSystemStoreW")
)

func openWindowsRootStore() (windowsRootStore, error) {
	store, _, err := procCertOpenSystemStoreW.Call(0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("ROOT"))))
	if store != 0 {
		return windowsRootStore(store), nil
	}
	return 0, fmt.Errorf("Failed to open windows root store: %v", err)
}

func (w windowsRootStore) close() error {
	ret, _, err := procCertCloseStore.Call(uintptr(w), 0)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("close windows root store: %w", err)
}

func (w windowsRootStore) addCert(cert []byte) error {
	// TODO: ok to always overwrite?
	ret, _, err := procCertAddEncodedCertificateToStore.Call(
		uintptr(w), // HCERTSTORE hCertStore
		uintptr(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING), // DWORD dwCertEncodingType
		uintptr(unsafe.Pointer(&cert[0])),                              // const BYTE *pbCertEncoded
		uintptr(len(cert)),                                             // DWORD cbCertEncoded
		3,                                                              // DWORD dwAddDisposition (CERT_STORE_ADD_REPLACE_EXISTING is 3)
		0,                                                              // PCCERT_CONTEXT *ppCertContext
	)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("adding cert: %v", err)
}

func (w windowsRootStore) deleteCertsWithSerial(serial *big.Int) (bool, error) {
	// Go over each, deleting the ones we find
	var cert *syscall.CertContext
	deletedAny := false
	for {
		// Next enum
		certPtr, _, err := procCertEnumCertificatesInStore.Call(uintptr(w), uintptr(unsafe.Pointer(cert)))
		if cert = (*syscall.CertContext)(unsafe.Pointer(certPtr)); cert == nil {
			if errno, ok := err.(syscall.Errno); ok && errno == 0x80092004 {
				break
			}
			return deletedAny, fmt.Errorf("enumerating certs: %v", err)
		}

		// Parse cert
		certBytes := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:cert.Length]
		parsedCert, err := x509.ParseCertificate(certBytes)

		// We'll just ignore parse failures for now
		if err == nil && parsedCert.SerialNumber != nil && parsedCert.SerialNumber.Cmp(serial) == 0 {
			// Duplicate the context so it doesn't stop the enum when we delete it
			dupCertPtr, _, err := procCertDuplicateCertificateContext.Call(uintptr(unsafe.Pointer(cert)))
			if dupCertPtr == 0 {
				return deletedAny, fmt.Errorf("duplicating context: %v", err)
			}
			if ret, _, err := procCertDeleteCertificateFromStore.Call(dupCertPtr); ret == 0 {
				return deletedAny, fmt.Errorf("deleting certificate: %v", err)
			}
			deletedAny = true
		}
	}
	return deletedAny, nil
}
