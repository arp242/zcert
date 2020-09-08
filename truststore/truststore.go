package truststore

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"sync"
)

type Store interface {
	Name() string                                              // Name for this truststore.
	OnSystem() bool                                            // Is this trust store on the system?
	Verbose(bool)                                              // Print extra information to stderr.
	HasCert(cacert *x509.Certificate) bool                     // Check if the key is in the store.
	Install(rootCert string, cacert *x509.Certificate) error   // Install a new certificate.
	Uninstall(rootCert string, cacert *x509.Certificate) error // Uninstall existing certificate.
}

// Find all stores enabled on this system.
//
// If verbose is given the Verbose() will be set on the returned stores.
func Find(verbose bool) []Store {
	var storeEnabled map[string]bool
	// TODO: use flag for this.
	// if ts := os.Getenv("TRUST_STORES"); ts != "" {
	// 	storeEnabled = make(map[string]bool)
	// 	for _, store := range strings.Split(ts, ",") {
	// 		storeEnabled[strings.TrimSpace(store)] = true
	// 	}
	// }

	var stores []Store
	for _, t := range []Store{&NSS{}, &Java{}, &Unix{}, &Darwin{}, &Windows{}} {
		if t.OnSystem() && (storeEnabled == nil || storeEnabled[t.Name()]) {
			t.Verbose(verbose)
			stores = append(stores, t)
		}
	}
	return stores
}

func caName(caCert *x509.Certificate) string {
	return "zcert development CA " + caCert.SerialNumber.String()
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

var privWarning sync.Once

func privCmd(cmd ...string) *exec.Cmd {
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	if binaryExists("sudo") {
		return exec.Command("sudo", append([]string{"--prompt=Sudo password:", "--"}, cmd...)...)
	}
	if binaryExists("doas") {
		return exec.Command("doas", append([]string{"--"}, cmd...)...)
	}

	privWarning.Do(func() {
		fmt.Fprintf(os.Stderr,
			"zcert: sudo or doas not available and not running as root; the (un)install might fail")
	})
	return exec.Command(cmd[0], cmd[1:]...)
}
