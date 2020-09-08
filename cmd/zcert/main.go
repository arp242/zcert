package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"zgo.at/zcert"
	"zgo.at/zli"
)

const usage = `Usage: zcert [flags] command

Commands:
  help   Show slightly more detailed help.

  info   Print information about a certificate.

  make   Create a new certificate signed with the root certificate.

            -out filename    Set output file; use - for stdout, default is to use host
            -client          Create client certificate.
            name [name ..]   Domains, IPs, or emails to create certificate for.

  root   Manage root certificate.

           info             Show info.
           install          Install a root certificate to all supported trust
                            stores; create a new one if it doesn't exist yet.
           uninstall        Uninstall root certificate from trust stores.
           create           Create a new certificate. Use -force of -f to
                            override any existing root certificate.
           remove           Remove the root certificate

Global flags:
  -v -verbose   Print verbose information to stderr.

Environment:
    CAROOT    Directory to store the root certificate. If this isn't set it's
              stored in the local user's profile directory.
`

const usageDetail = `
Example:
  Create a root certificate and add it to the system's trust store; this ensures
  that browsers and other programs will recognize certificates created will be
  recognizes as valid. You only need to do this once, and is optional (use "root
  create" if you want to manually trust certificates):

    $ zcert root install

  Create a new certificate:

    $ zcert make example.com

  Or for two domains (with wildcard):

    $ zcert make '*.example.com' example.com

  Print some basic info for the created certificates:

    $ zcert info example.com.pem '*.example.com.pem'
`

func main() {
	f := zli.NewFlags(os.Args)
	var (
		verbose = f.Bool(false, "verbose", "v")
		client  = f.Bool(false, "client", "c")
		out     = f.String("", "out", "o")
		force   = f.Bool(false, "force", "f")
	)
	f.Parse()

	var (
		cmd  = f.Shift()
		root = zcert.CARoot{Verbose: verbose.Set()}
	)
	switch cmd {
	default:
		zli.Fatalf("unknown command: %q", cmd)
	case "":
		fmt.Print(zli.Usage(zli.UsageHeaders, usage))
	case "help":
		fmt.Print(zli.Usage(zli.UsageHeaders, usage+usageDetail))

	case "root":
		cmdRoot(f, root, verbose.Set(), force.Set())

	case "info":
		if len(f.Args) < 1 {
			zli.Fatalf("must give at least one filename")
		}
		_ = root.Load() // Not a fatal error, can print info non-zcert certs.
		for i, file := range f.Args {
			printInfo(root, file)
			if i < len(f.Args)-1 {
				fmt.Println("")
			}
		}

	case "make":
		names := f.Args
		if len(names) < 1 {
			zli.Fatalf("must give at least one host")
		}

		var (
			fp       io.WriteCloser
			filename = out.String()
		)
		switch filename {
		case "-":
			fp = NopCloser(os.Stdout)
		case "":
			filename = safePath(names[0]) + ".pem"
			fallthrough
		default:
			if Exists(filename) && !force.Set() {
				zli.Fatalf("%q already exists; use -f to overwrite", filename)
			}

			var err error
			fp, err = os.Create(filename)
			zli.F(err)
		}

		zli.F(root.MakeCert(fp, client.Set(), names...))
	}
}

func cmdRoot(f zli.Flags, root zcert.CARoot, verbose, force bool) {
	f = zli.NewFlags(append([]string{""}, f.Args...))
	f.Parse()

	cmd := f.Shift()
	switch cmd {
	default:
		zli.Fatalf("unknown root command: %q", cmd)

	case "", "info":
		rootCert, rootKey := root.StorePath()
		fmt.Printf("Root storage location:\n\t%s\n\t%s\n\n", rootCert, rootKey)

		caroot, ok := os.LookupEnv("CAROOT")
		if !ok {
			caroot = "(not set)"
		}
		ts, ok := os.LookupEnv("TRUST_STORES")
		if !ok {
			ts = "(not set)"
		}

		fmt.Printf("Environment:\n\tCAROOT=%s\n\tTRUST_STORES=%s\n\n", caroot, ts)

		if !root.Exists() {
			fmt.Println("No root certificate exists")
			return
		}

		zli.F(root.Load())
		c := root.Certificate()
		fmt.Println("Root certificate:")
		fmt.Printf("\tSubject:    %s\n", c.Subject)
		fmt.Printf("\tValid:      %s to %s\n", c.NotBefore.Format("2006-01-02 15:04:05"), c.NotAfter.Format("2006-01-02 15:04:05"))
		fmt.Printf("\tSerial:     %s\n", c.SerialNumber)
		fmt.Printf("\tAlgorithm:  %s\n", c.SignatureAlgorithm)

	case "create":
		if force {
			zli.F(root.Delete())
		}
		zli.F(root.Create())

	case "remove":
		zli.F(root.Delete())

	case "install":
		if !root.Exists() {
			zli.F(root.Create())
		}
		zli.F(root.Install())

	case "uninstall":
		if !root.Exists() {
			zli.Fatalf("root certificate doesn't exist")
		}
		zli.F(root.Uninstall())
	}
}

func printInfo(root zcert.CARoot, file string) {
	cert, err := tls.LoadX509KeyPair(file, file)
	zli.F(err)

	if len(cert.Certificate) == 0 {
		zli.Fatalf("no certificates in %q", file)
	}

	c, err := x509.ParseCertificate(cert.Certificate[0])
	zli.F(err)

	fmt.Println(file)
	fmt.Printf("\tSubject:    %s\n", c.Subject)
	fmt.Printf("\tValid:      %s to %s\n", c.NotBefore.Format("2006-01-02 15:04:05"), c.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("\tSerial:     %s\n", c.SerialNumber)
	fmt.Printf("\tAlgorithm:  %s\n", c.SignatureAlgorithm)
	fmt.Printf("\tDNSNames:   %s\n", c.DNSNames)
	fmt.Printf("\tIPs:        %s\n", c.IPAddresses)
	fmt.Printf("\tEmails:     %s\n", c.EmailAddresses)
	fmt.Printf("\tURIs:       %s\n", c.URIs)
	if len(c.ExtKeyUsage) > 0 {
		for _, e := range c.ExtKeyUsage {
			if e == x509.ExtKeyUsageClientAuth {
				fmt.Println("\tClientCert: true")
				break
			}
		}
	}

	chains, err := verifyRoot(root, c)
	if err != nil {
		// Won't fall back to the system store automatically.
		pool := x509.NewCertPool()
		if len(cert.Certificate) > 1 {
			for _, x := range cert.Certificate[1:] {
				c, err := x509.ParseCertificate(x)
				zli.F(err)
				pool.AddCert(c)
			}
		}
		chains, err = c.Verify(x509.VerifyOptions{Intermediates: pool})
	}
	if err != nil {
		fmt.Printf("\tVerify:     %s\n", err)
	}
	fmt.Print("\tVerify:     ")
	for i, chain := range chains {
		pad := ""
		if i > 0 {
			pad = "\t            "
		}
		fmt.Printf("%sSerial:  %s\n", pad, chain[1].SerialNumber)
		pad = "\t            "
		fmt.Printf("%sSubject: %s\n", pad, chain[1].Subject)
	}
}

func verifyRoot(root zcert.CARoot, c *x509.Certificate) ([][]*x509.Certificate, error) {
	if root.Certificate() == nil {
		return nil, errors.New("no root")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.Certificate())
	return c.Verify(x509.VerifyOptions{Roots: pool})
}

var tr = strings.NewReplacer(
	"..", "",
	"/", "",
	`\`, "",
	"\x00", "",
)

// safePath converts any string to a safe pathname, preventing directory
// traversal attacks and the like.
func safePath(s string) string {
	return tr.Replace(s)
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// NopCloser returns a WriteCloser with a no-op Close method.
func NopCloser(r io.Writer) io.WriteCloser { return nopCloser{r} }

// Exists reports if a path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
