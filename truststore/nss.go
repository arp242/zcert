package truststore

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

var (
	nssDBs = []string{
		filepath.Join(os.Getenv("HOME"), ".pki/nssdb"),
		filepath.Join(os.Getenv("HOME"), "snap/chromium/current/.pki/nssdb"), // Snapcraft
		"/etc/pki/nssdb", // CentOS 7
	}

	firefoxPaths = []string{
		"/usr/bin/firefox",
		"/usr/bin/firefox-nightly",
		"/usr/bin/firefox-developer-edition",
		"/Applications/Firefox.app",
		"/Applications/FirefoxDeveloperEdition.app",
		"/Applications/Firefox Developer Edition.app",
		"/Applications/Firefox Nightly.app",
		"C:\\Program Files\\Mozilla Firefox",
	}
)

type NSS struct{ verbose bool }

func (NSS) Name() string      { return "NSS" }
func (t *NSS) Verbose(v bool) { t.verbose = v }

func (NSS) OnSystem() bool {
	for _, p := range append(nssDBs, firefoxPaths...) {
		if pathExists(p) {
			return true
		}
	}
	return false
}

func (t NSS) HasCert(caCert *x509.Certificate) bool {
	p, err := t.forEachProfile(func(profile string) error {
		return exec.Command("certutil", "-V", "-d", profile, "-u", "L", "-n", caName(caCert)).Run()
	})
	return err == nil && p > 0
}

func (t NSS) Install(rootCert string, caCert *x509.Certificate) error {
	p, err := t.forEachProfile(func(profile string) error {
		out, err := t.execCertutil(exec.Command("certutil",
			"-A", "-d", profile, "-t", "C,,", "-n",
			caName(caCert), "-i", rootCert))
		if err != nil {
			return fmt.Errorf("certutil -A -d %s: %s", profile, out)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if p == 0 {
		return errors.New("truststore.NSS: no security database found")
	}

	if !t.HasCert(caCert) {
		return fmt.Errorf("truststore.NSS: installing to %q failed", "TODO")
	}
	return nil
}

func (t NSS) Uninstall(rootCert string, caCert *x509.Certificate) error {
	_, err := t.forEachProfile(func(profile string) error {
		err := exec.Command("certutil", "-V", "-d", profile, "-u", "L", "-n", caName(caCert)).Run()
		if err != nil {
			return nil
		}

		out, err := t.execCertutil(exec.Command("certutil", "-D", "-d", profile, "-n", caName(caCert)))
		if err != nil {
			return fmt.Errorf("certutil -D -d %s: %s", profile, out)
		}
		return nil
	})
	return err
}

func (NSS) forEachProfile(f func(profile string) error) (int, error) {
	profiles, _ := filepath.Glob(firefoxProfile)
	profiles = append(profiles, nssDBs...)

	var found int
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}

		var err error
		if pathExists(filepath.Join(profile, "cert9.db")) {
			err = f("sql:" + profile)
			found++
		} else if pathExists(filepath.Join(profile, "cert8.db")) {
			err = f("dbm:" + profile)
			found++
		}
		if err != nil {
			return 0, err
		}
	}
	return found, nil
}

// execCertutil will execute a "certutil" command and if needed re-execute
// the command with privCmd to work around file permissions.
func (NSS) execCertutil(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()

	if err != nil && bytes.Contains(out, []byte("SEC_ERROR_READ_ONLY")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd = privCmd(cmd.Path)
		cmd.Args = append(cmd.Args, origArgs...)
		out, err = cmd.CombinedOutput()
	}

	return out, err
}
