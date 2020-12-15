zcert is a library and commandline tool to manage development certificates.

It's a refactor from [mkcert], with a slightly nicer CLI (IMHO anyway) and can
be used as a Go library.

<!--
See the [releases] page for binaries for most platforms, or install from source
with `go get zgo.at/zcert/cmd/zcert`. The Go API is documented at
https://pkg.godoc.org/zgo.at/zcert
-->

Install from source with `go get zgo.at/zcert/cmd/zcert`. The Go API is
documented at https://pkg.godoc.org/zgo.at/zcert

[releases]: github.com/zgoat/zcert/releases
[mkcert]: https://github.com/FiloSottile/mkcert/


Concepts
--------

1. zcert creates a new root signing certificate; all certificates creates are
   signed with this certificate.

2. You can install the root certificate in your system's truststore (either
   manually or automatically), so browsers and tools recognize it.


CLI usage
---------

The root cerificate can be managed with:

    zcert root create          Create a new root certificate
    zcert root install         Install it in the trust store.
    zcert root uninstall       Remove it from the trust store.
    zcert root remove          Remove the root certificate.
    zcert root info            Show information about the root certificate.

Usually, just `zcert root install` is enough; this will create a root
certificate if it exists and installs it to the truststores it can find.

Use `zcert mame host` to create new certificates for your application:

    zcert make new.example.com

Can add multiple hostnames, wildcards, etc:

    zcert make example.com '*.example.com'

See `zcert` for an overview of the help, and `zcert help` for more detailed
help.


Library usage
-------------

zcert can function as a Go library; this is pretty useful to automatically
generate development certificates with minimal user intervention. The main
reason for this (and also the main reason I worked on this in the first place)
is to always serve your local dev server over https without too much mucking
about:

```go
ca, _, err := zcert.New()
if err != nil {
    log.Fatal(err)
}

serve := http.Server{Addr: listen, TLSconfig: ca.TLSConfig()}
serve.ListenAndServeTLS("", "")
```

See [`cmd/serve`](cmd/serve) for an example of this.

The `truststore` subpackage can be used to install your own keys in the trust
store, if you want.
