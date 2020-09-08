package zcert

import (
	"crypto/tls"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestCARoot(t *testing.T) {
	tmp := fmt.Sprintf("%s/zcert-%d", os.TempDir(), time.Now().UnixNano())
	err := os.MkdirAll(tmp, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { os.RemoveAll(tmp) }()

	os.Setenv("CAROOT", tmp)

	var root CARoot
	if root.Exists() {
		t.Errorf("exists reports true")
	}

	err = root.Create()
	if err != nil {
		t.Fatal(err)
	}
	if !root.Exists() {
		t.Errorf("exists reports false")
	}
	if root.cert == nil {
		t.Errorf("root.cert == nil")
	}
	if root.key == nil {
		t.Errorf("root.key == nil")
	}

	out, err := os.Create(tmp + "/out.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = root.MakeCert(out, false, "example.localhost")
	if err != nil {
		t.Fatal(err)
	}
	err = out.Close()
	if err != nil {
		t.Fatal(err)
	}

	config := new(tls.Config)
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(out.Name(), out.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Load from disk.
	{
		var root CARoot
		out, err := os.Create(tmp + "/out2.pem")
		if err != nil {
			t.Fatal(err)
		}

		err = root.MakeCert(out, false, "example2.localhost")
		if err != nil {
			t.Fatal(err)
		}
		err = out.Close()
		if err != nil {
			t.Fatal(err)
		}

		config := new(tls.Config)
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(out.Name(), out.Name())
		if err != nil {
			t.Fatal(err)
		}
	}

	// TODO: test with HTTP server?
}
