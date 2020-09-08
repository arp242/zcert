// +build darwin

package truststore

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"

	"howett.net/plist"
)

var (
	firefoxProfile = os.Getenv("HOME") + "/Library/Application Support/Firefox/Profiles/*"
	nssBrowsers    = "Firefox"

	CertutilInstallHelp = "brew install nss"
)

// https://github.com/golang/go/issues/24652#issuecomment-399826583
var trustSettings []interface{}
var _, _ = plist.Unmarshal(trustSettingsData, &trustSettings)
var trustSettingsData = []byte(`
<array>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAED
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>sslServer</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAEC
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>basicX509</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
</array>
`)

type Darwin struct{ verbose bool }

func (Darwin) Name() string      { return "Darwin" }
func (t *Darwin) Verbose(v bool) { t.verbose = v }
func (Darwin) OnSystem() bool    { return runtime.GOOS == "darwin" }

func (t Darwin) HasCert(caCert *x509.Certificate) bool {
	// TODO
	return false
}

func (t Darwin) Install(rootCert string, caCert *x509.Certificate) error {
	cmd := privCmd("security", "add-trusted-cert", "-d", "-k",
		"/Library/Keychains/System.keychain", rootCert)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	} // security add-trusted-cert

	// Make trustSettings explicit, as older Go does not know the defaults.
	// https://github.com/golang/go/issues/24652
	plistFile, err := ioutil.TempFile("", "trust-settings")
	if err != nil {
		return err
	} // (err, "failed to create temp file")
	defer os.Remove(plistFile.Name())

	cmd = privCmd("security", "trust-settings-export", "-d", plistFile.Name())
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	} // "security trust-settings-export"

	plistData, err := ioutil.ReadFile(plistFile.Name())
	if err != nil {
		return fmt.Errorf("read trust settings: %w", err)
	}

	var plistRoot map[string]interface{}
	_, err = plist.Unmarshal(plistData, &plistRoot)
	if err != nil {
		fmt.Errorf("parse trust settings: %w", err)
	}

	rootSubjectASN1, _ := asn1.Marshal(caCert.Subject.ToRDNSequence())

	if plistRoot["trustVersion"].(uint64) != 1 {
		log.Fatalln("ERROR: unsupported trust settings version:", plistRoot["trustVersion"])
	}
	trustList := plistRoot["trustList"].(map[string]interface{})
	for key := range trustList {
		entry := trustList[key].(map[string]interface{})
		if _, ok := entry["issuerName"]; !ok {
			continue
		}
		issuerName := entry["issuerName"].([]byte)
		if !bytes.Equal(rootSubjectASN1, issuerName) {
			continue
		}
		entry["trustSettings"] = trustSettings
		break
	}

	plistData, err = plist.MarshalIndent(plistRoot, plist.XMLFormat, "\t")
	if err != nil {
		return err // fatalIfErr(err, "failed to serialize trust settings")
	}

	err = ioutil.WriteFile(plistFile.Name(), plistData, 0600)
	if err != nil {
		return err
	} //fatalIfErr(err, "failed to write trust settings")

	cmd = privCmd("security", "trust-settings-import", "-d", plistFile.Name())
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	} // fatalIfCmdErr(err, "security trust-settings-import", out)

	return nil
}

func (t Darwin) Uninstall(rootCert string, caCert *x509.Certificate) error {
	// TODO
	// cmd := privCmd("security", "remove-trusted-cert", "-d", filepath.Join(m.CAROOT, rootName))
	// out, err := cmd.CombinedOutput()
	// if err != nil {
	// 	return err
	// } // fatalIfCmdErr(err, "security remove-trusted-cert", out)
	return nil
}
