package oauthserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	knet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/util/cert"
)

// newStaticRoundTripper returns an http.RoundTripper with fixed TLS configuration.
func newStaticRoundTripper(ca, certFile, keyFile string) (http.RoundTripper, error) {
	if len(ca) == 0 && len(certFile) == 0 && len(keyFile) == 0 {
		return http.DefaultTransport, nil
	}

	if (len(certFile) == 0) != (len(keyFile) == 0) {
		return nil, errors.New("certFile and keyFile must be specified together")
	}

	transport := knet.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{},
	})

	if len(ca) != 0 {
		roots, err := cert.NewPool(ca)
		if err != nil {
			return nil, fmt.Errorf("error loading cert pool from CA file %q: %w", ca, err)
		}
		transport.TLSClientConfig.RootCAs = roots
	}

	if len(certFile) != 0 {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("error loading x509 keypair from cert file %q and key file %q: %w", certFile, keyFile, err)
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	return transport, nil
}
