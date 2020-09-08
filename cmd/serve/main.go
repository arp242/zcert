package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"zgo.at/zcert"
)

func main() {
	// Flags; normally you'd get this from the CLI or env or whatnot.
	var (
		listen   = "localhost:9000"
		certFile = ""
	)

	// Use certificate from file if one was explicitly given.
	if len(os.Args) > 1 {
		certFile = os.Args[1]

		// Install certificate; not done automatically as this may ask for the
		// user password.
		if certFile == "install-cert" {
			ca, _, err := zcert.New()
			if err != nil {
				log.Fatal(err)
			}
			err = ca.Install()
			if err != nil {
				log.Fatal(err)
			}

			return
		}
	}

	serve := http.Server{Addr: listen}
	http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Well, hello there!")
	}))

	// Create new root certificate if it doesn't exist yet, and use it to sign
	// any host.
	if certFile == "" {
		ca, created, err := zcert.New()
		if err != nil {
			log.Fatal(err)
		}
		serve.TLSConfig = ca.TLSConfig()
		if created {
			p, _ := ca.StorePath()
			fmt.Println(strings.Repeat("=", 40))
			fmt.Printf("Created new root certificate in %q\n", p)
			fmt.Printf("Use '%s install-cert' to install it in the system trust store\n", os.Args[0])
			fmt.Println(strings.Repeat("=", 40))
		}
	}

	log.Printf("listening on %q with certificate from %q", listen, certFile)
	err := serve.ListenAndServeTLS(certFile, certFile)
	if err != nil {
		log.Fatal(err)
	}
}
