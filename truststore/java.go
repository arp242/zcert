package truststore

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	javaHome = os.Getenv("JAVA_HOME")
	hasJava  = javaHome != ""

	keytoolPath = func() string {
		p := filepath.Join("bin", "keytool")
		if runtime.GOOS == "windows" {
			p += ".exe"
		}
		return filepath.Join(javaHome, p)
	}()
	hasKeytool = pathExists(keytoolPath)

	cacertsPath = func() string {
		p := filepath.Join(javaHome, "lib", "security", "cacerts")
		if pathExists(p) {
			return p
		}

		p = filepath.Join(javaHome, "jre", "lib", "security", "cacerts")
		if pathExists(p) {
			return p
		}

		return ""
	}()

	storePass = "changeit"
)

type Java struct{ verbose bool }

func (Java) Name() string      { return "Java" }
func (t *Java) Verbose(v bool) { t.verbose = v }
func (Java) OnSystem() bool    { return hasKeytool }

func (t Java) HasCert(caCert *x509.Certificate) bool {
	if !hasKeytool {
		return false
	}

	// exists returns true if the given x509.Certificate's fingerprint
	// is in the keytool -list output
	exists := func(c *x509.Certificate, h hash.Hash, keytoolOutput []byte) bool {
		h.Write(c.Raw)
		fp := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		return bytes.Contains(keytoolOutput, []byte(fp))
	}

	keytoolOutput, err := exec.Command(keytoolPath, "-list", "-keystore",
		cacertsPath, "-storepass", storePass).CombinedOutput()
	if err != nil {
		// fatalIfCmdErr(err, "keytool -list", keytoolOutput)
		return false
	}

	// keytool outputs SHA1 and SHA256 (Java 9+) certificates in uppercase hex
	// with each octet pair delimitated by ":". Drop them from the keytool output
	keytoolOutput = bytes.Replace(keytoolOutput, []byte(":"), nil, -1)

	// pre-Java 9 uses SHA1 fingerprints
	s1, s256 := sha1.New(), sha256.New()
	return exists(caCert, s1, keytoolOutput) || exists(caCert, s256, keytoolOutput)
}

func (t Java) Install(rootCert string, caCert *x509.Certificate) error {
	_, err := t.execKeytool(exec.Command(keytoolPath,
		"-importcert", "-noprompt",
		"-keystore", cacertsPath,
		"-storepass", storePass,
		"-file", rootCert,
		"-alias", caName(caCert)))
	if err != nil {
		return err
	}
	return nil
}

func (t Java) Uninstall(rootCert string, caCert *x509.Certificate) error {
	out, err := t.execKeytool(exec.Command(keytoolPath,
		"-delete",
		"-alias", caName(caCert),
		"-keystore", cacertsPath,
		"-storepass", storePass))
	if bytes.Contains(out, []byte("does not exist")) {
		return nil
	}
	if err != nil {
		return err
	}
	return nil
}

// execKeytool will execute a "keytool" command and if needed re-execute
// the command with privCmd to work around file permissions.
func (t Java) execKeytool(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("java.io.FileNotFoundException")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd = privCmd(cmd.Path)
		cmd.Args = append(cmd.Args, origArgs...)
		cmd.Env = []string{"JAVA_HOME=" + javaHome}
		out, err = cmd.CombinedOutput()
	}

	if err != nil {
		return out, fmt.Errorf("truststore.Java: %w", err)
	}

	return out, nil
}
