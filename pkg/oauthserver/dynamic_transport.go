package oauthserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	knet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"
)

// dynamicCARoundTripper is an http.RoundTripper that rebuilds the underlying
// http.Transport when the proxy CA rotates. It implements
// dynamiccertificates.Listener and registers on a shared
// DynamicFileCAContent provided at construction time. The transport's RootCAs
// combines a static IdP CA (from provider config) with the dynamic proxy CA.
// Static TLS material (IdP CA certs and client certificate) is loaded once at
// construction time; only the proxy CA is reloaded dynamically.
type dynamicCARoundTripper struct {
	proxyCAContent *dynamiccertificates.DynamicFileCAContent
	idpCACerts     []*x509.Certificate
	clientCert     *tls.Certificate
	transport      atomic.Pointer[http.Transport]
}

var _ http.RoundTripper = &dynamicCARoundTripper{}
var _ dynamiccertificates.Listener = &dynamicCARoundTripper{}

func newDynamicCARoundTripper(proxyCAContent *dynamiccertificates.DynamicFileCAContent, idpCAFile, certFile, keyFile string) (*dynamicCARoundTripper, error) {
	if (len(certFile) == 0) != (len(keyFile) == 0) {
		return nil, errors.New("certFile and keyFile must be specified together")
	}

	rt := &dynamicCARoundTripper{
		proxyCAContent: proxyCAContent,
	}

	if len(idpCAFile) != 0 {
		var err error
		rt.idpCACerts, err = cert.CertsFromFile(idpCAFile)
		if err != nil {
			return nil, fmt.Errorf("error loading IdP CA from %q: %w", idpCAFile, err)
		}
	}

	if len(certFile) != 0 {
		clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("error loading x509 keypair from cert file %q and key file %q: %w", certFile, keyFile, err)
		}
		rt.clientCert = &clientCert
	}

	t, err := rt.buildTransport()
	if err != nil {
		return nil, err
	}
	rt.transport.Store(t)

	proxyCAContent.AddListener(rt)
	return rt, nil
}

func (rt *dynamicCARoundTripper) buildTransport() (*http.Transport, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system cert pool: %w", err)
	}

	for _, c := range rt.idpCACerts {
		roots.AddCert(c)
	}

	proxyCABundle := rt.proxyCAContent.CurrentCABundleContent()
	if !roots.AppendCertsFromPEM(proxyCABundle) {
		return nil, fmt.Errorf("failed to parse proxy CA bundle")
	}

	t := knet.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
	})
	if rt.clientCert != nil {
		t.TLSClientConfig.Certificates = []tls.Certificate{*rt.clientCert}
	}
	return t, nil
}

func (rt *dynamicCARoundTripper) Enqueue() {
	newTransport, err := rt.buildTransport()
	if err != nil {
		klog.Warningf("Failed to rebuild transport after proxy CA change: %v", err)
		return
	}

	old := rt.transport.Swap(newTransport)
	if old != nil {
		old.CloseIdleConnections()
	}
	klog.V(2).Infof("Rebuilt outbound transport with updated proxy CA bundle")
}

func (rt *dynamicCARoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.transport.Load().RoundTrip(req)
}
