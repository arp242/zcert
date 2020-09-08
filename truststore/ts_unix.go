// +build aix dragonfly freebsd linux,!appengine netbsd openbsd solaris

package truststore

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

var (
	firefoxProfile = os.Getenv("HOME") + "/.mozilla/firefox/*"
	nssBrowsers    = "Firefox and Chrome/Chromium"

	trustFile, trustCmd = func() (string, []string) {
		switch {
		case pathExists("/etc/pki/ca-trust/source/anchors/"):
			return "/etc/pki/ca-trust/source/anchors/%s.pem",
				[]string{"update-ca-trust", "extract"}

		case pathExists("/usr/local/share/ca-certificates/"):
			return "/usr/local/share/ca-certificates/%s.crt",
				[]string{"update-ca-certificates"}

		case pathExists("/etc/ca-certificates/trust-source/anchors/"):
			return "/etc/ca-certificates/trust-source/anchors/%s.crt",
				[]string{"trust", "extract-compat"}

		case pathExists("/usr/share/pki/trust/anchors"):
			return "/usr/share/pki/trust/anchors/%s.pem",
				[]string{"update-ca-certificates"}

		case pathExists("/usr/share/ca-certificates/mozilla"):
			return "/usr/share/ca-certificates/mozilla/%s.crt",
				[]string{"update-ca-certificates"}
		}
		return "", nil
	}()

	certutilInstallHelp = func() string {
		switch {
		case binaryExists("apt"):
			return "apt install libnss3-tools"
		case binaryExists("yum"):
			return "yum install nss-tools"
		case binaryExists("zypper"):
			return "zypper install mozilla-nss-tools"
		case binaryExists("xbps-install"):
			return "xbps-install nss"
		}
		return ""
	}()
)

type Unix struct{ verbose bool }

func (Unix) Name() string      { return "Unix" }
func (t *Unix) Verbose(v bool) { t.verbose = v }

// TODO
func (Unix) OnSystem() bool {
	return true
}

func (t Unix) HasCert(caCert *x509.Certificate) bool {
	// TODO
	return false
}

func (t Unix) Install(rootCert string, caCert *x509.Certificate) error {
	if trustCmd == nil {
		return fmt.Errorf("truststore.Unix: not yet supported on this Unix, but %s will still work", nssBrowsers)
	}

	cert, err := ioutil.ReadFile(rootCert)
	if err != nil {
		return fmt.Errorf("truststore.Unix: read root certificate: %w", err)
	}

	cmd := privCmd("tee", t.systemTrust(caCert))
	cmd.Stdin = bytes.NewReader(cert)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		return fmt.Errorf("truststore.Unix: %w", err)
	}

	cmd = privCmd(trustCmd...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		return fmt.Errorf("truststore.Unix: %w", err)
	}

	return nil
}

func (t Unix) Uninstall(rootCert string, caCert *x509.Certificate) error {
	if trustCmd == nil {
		return nil
	}

	cmd := privCmd("rm", "-f", t.systemTrust(caCert))
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("truststore.Unix: %w", err)
	}

	cmd = privCmd(trustCmd...)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("truststore.Unix: %w", err)
	}
	return nil
}

func (Unix) systemTrust(caCert *x509.Certificate) string {
	return fmt.Sprintf(trustFile, strings.ReplaceAll(caName(caCert), " ", "_"))
}
