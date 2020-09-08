package zcert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"zgo.at/zcert/truststore"
)

// CARoot is a root certificate that's used to sign certificates with.
type CARoot struct {
	Verbose bool // Print verbose output to stderr.

	cert *x509.Certificate
	key  crypto.PrivateKey
}

// New creates a new instance of CARoot. It will load an existing root
// certificate if it exists, or creates a new one if it doesn't.
func New() (ca CARoot, created bool, err error) {
	if !ca.Exists() {
		err = ca.Create()
		created = true
	} else {
		err = ca.Load()
	}
	return ca, created, err
}

// Certificate gets the loaded root certificate; may return nil if Load() isn't
// called yet.
func (ca CARoot) Certificate() *x509.Certificate {
	return ca.cert
}

// Create a new root certificate; this will return an error if a root CA already
// exist.
func (ca *CARoot) Create() error {
	rootCert, rootKey := ca.StorePath()
	if rootCert == "" {
		return errors.New("zcert.Create: can't find a location to store the root certificate; set CAROOT")
	}

	if ca.Exists() {
		return fmt.Errorf("zcert.Create: CA root already exists at %q", rootCert)
	}

	err := os.MkdirAll(filepath.Dir(rootCert), 0755)
	if err != nil {
		return fmt.Errorf("zcert.Create: %w", err)
	}

	privKey, err := generateKey()
	if err != nil {
		return fmt.Errorf("zcert.Create: generating private key: %w", err)
	}
	pubKey := privKey.(crypto.Signer).Public()

	spkiASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("zcert.Create: encode public key: %w", err)
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		return fmt.Errorf("zcert.Create: decode public key: %w", err)
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return fmt.Errorf("zcert.Create: generating serial number: %w", err)
	}

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{"zcert development CA"},
			OrganizationalUnit: []string{userAndHostname()},

			// The CommonName is required by iOS to show the certificate in the
			// "Certificate Trust Settings" menu.
			// https://github.com/FiloSottile/mkcert/issues/47
			CommonName: "zcert " + userAndHostname(),
		},
		SubjectKeyId: skid[:],

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now(),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pubKey, privKey)
	if err != nil {
		return fmt.Errorf("zcert.Create: generate CA certificate: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("zcert.Create: encode CA key: %w", err)
	}

	err = ioutil.WriteFile(rootKey, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	if err != nil {
		return fmt.Errorf("zcert.Create: save CA key: %w", err)
	}

	err = ioutil.WriteFile(rootCert, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	if err != nil {
		return fmt.Errorf("zcert.Create: save CA certificate: %w", err)
	}

	ca.cert = tpl
	ca.key = privKey
	return nil
}

// Exists reports if the root certificate exits.
func (ca CARoot) Exists() bool {
	rootCert, _ := ca.StorePath()
	return pathExists(rootCert)
}

// Load the root certificate from disk.
func (ca *CARoot) Load() error {
	if !ca.Exists() {
		return errors.New("zcert.Load: CA certificate doesn't exist")
	}

	rootCert, rootKey := ca.StorePath()
	cert, err := tls.LoadX509KeyPair(rootCert, rootKey)
	if err != nil {
		return fmt.Errorf("zcert.Load: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return errors.New("zcert.Load: no certificates in rootCA")
	}

	pc, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("zcert.Load: %w", err)
	}

	ca.cert = pc
	ca.key = cert.PrivateKey
	return nil
}

// Delete the root certificate.
func (ca CARoot) Delete() error {
	if !ca.Exists() {
		return nil
	}

	rootCert, rootKey := ca.StorePath()
	err := os.Remove(rootCert)
	if err != nil {
		return fmt.Errorf("zcert.Delete: %w", err)
	}

	err = os.Remove(rootKey)
	if err != nil {
		return fmt.Errorf("zcert.Delete: %w", err)
	}

	err = os.Remove(filepath.Dir(rootCert))
	if err != nil {
		return fmt.Errorf("zcert.Delete: %w", err)
	}

	return nil
}

// Install the root certificate to all truststores we can find.
func (ca CARoot) Install() error {
	if ca.cert == nil {
		err := ca.Load()
		if err != nil {
			return err
		}
	}

	stores := truststore.Find(ca.Verbose)
	if len(stores) == 0 {
		return errors.New("no compatible truststores found")
	}

	rootCert, _ := ca.StorePath()
	errs := NewGroup(0)
	for _, s := range stores {
		fmt.Printf("Installing for %s...\n", s.Name())
		errs.Append(s.Install(rootCert, ca.cert))
		fmt.Println("  done")
	}
	return errs.ErrorOrNil()
}

// Uninstall the root certificate from all truststores we can find.
func (ca CARoot) Uninstall() error {
	if ca.cert == nil {
		err := ca.Load()
		if err != nil {
			return err
		}
	}

	stores := truststore.Find(ca.Verbose)
	if len(stores) == 0 {
		return errors.New("no compatible truststores found")
	}

	rootCert, _ := ca.StorePath()
	errs := NewGroup(0)
	for _, s := range stores {
		fmt.Printf("Uninstalling for %s\n", s.Name())
		errs.Append(s.Uninstall(rootCert, ca.cert))
	}
	return errs.ErrorOrNil()
}

// MakeCert creates a new certificate signed with the root certificate and
// writes the PEM-encoded data to out.
func (ca CARoot) MakeCert(out io.Writer, clientCert bool, hosts ...string) error {
	if ca.cert == nil || ca.key == nil {
		err := ca.Load()
		if err != nil {
			return fmt.Errorf("zcert.MakeCert: %w", err)
		}
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return fmt.Errorf("zcert.MakeCert: generating serial number: %w", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{"zcert development certificate"},
			OrganizationalUnit: []string{userAndHostname()},
		},

		NotAfter:  time.Now().AddDate(1, 0, 0),
		NotBefore: time.Now(),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			tpl.EmailAddresses = append(tpl.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			tpl.URIs = append(tpl.URIs, uriName)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}

	if clientCert {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		tpl.Subject.CommonName = hosts[0]
	} else if len(tpl.IPAddresses) > 0 || len(tpl.DNSNames) > 0 {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if len(tpl.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection)
	}

	privKey, err := generateKey()
	if err != nil {
		return fmt.Errorf("zcert.MakeCert: generating private key: %w", err)
	}
	pubKey := privKey.(crypto.Signer).Public()

	cert, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pubKey, ca.key)
	if err != nil {
		return fmt.Errorf("zcert.MakeCert: generating certificate: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("zcert.MakeCert: failed to encode certificate key: %w", err)
	}

	_, err = out.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	if err != nil {
		return fmt.Errorf("zcert.MakeCert: write private key: %w", err)
	}
	_, err = out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
	if err != nil {
		return fmt.Errorf("zcert.MakeCert: write certificate key: %w", err)
	}

	return nil
}

// TLSConfig returns a new tls.Config which creates certificates for any
// hostname.
func (ca CARoot) TLSConfig() *tls.Config {
	certs := make(map[string]*tls.Certificate)
	tlsc := new(tls.Config)
	tlsc.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, ok := certs[hello.ServerName]
		if !ok {
			var err error
			c, err = ca.MakeTLSCert(false, hello.ServerName)
			if err != nil {
				return nil, err
			}
			certs[hello.ServerName] = c
		}
		return c, nil
	}
	return tlsc
}

// MakeTLS creates a new TLS certificate signed with the root certificate.
func (ca CARoot) MakeTLSCert(clientCert bool, hosts ...string) (*tls.Certificate, error) {
	out := new(bytes.Buffer)
	err := ca.MakeCert(out, clientCert, hosts...)
	if err != nil {
		return nil, err
	}

	t, err := tls.X509KeyPair(out.Bytes(), out.Bytes())
	if err != nil {
		return nil, fmt.Errorf("zcert.MakeTLSCert: %w", err)
	}
	return &t, nil
}

// StorePaths gets the full path name to the root certificate. Returns
// certificate and key.
func (CARoot) StorePath() (string, string) {
	var dir string
	switch {
	case os.Getenv("CAROOT") != "":
		dir = os.Getenv("CAROOT")

	case runtime.GOOS == "windows":
		dir = os.Getenv("LocalAppData")

	case os.Getenv("XDG_DATA_HOME") != "":
		dir = os.Getenv("XDG_DATA_HOME")

	case runtime.GOOS == "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return "", ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")

	default: // Unix
		dir = os.Getenv("HOME")
		if dir == "" {
			return "", ""
		}
		dir = filepath.Join(dir, ".local", "share")
	}
	if dir == "" {
		return "", ""
	}

	// TODO: store in single file?
	dir = filepath.Join(dir, "zcert")
	return filepath.Join(dir, "rootCA.pem"), filepath.Join(dir, "rootCA-key.pem")
}

var (
	getUser  sync.Once
	userInfo string
)

func userAndHostname() string {
	getUser.Do(func() {
		var ret string
		u, err := user.Current()
		if err == nil {
			ret = u.Username + "@"
		}
		if h, err := os.Hostname(); err == nil {
			ret += h
		}
		if err == nil && u.Name != "" && u.Name != u.Username {
			ret += " (" + u.Name + ")"
		}
		userInfo = ret
	})
	return userInfo
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func randomSerialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func generateKey() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
