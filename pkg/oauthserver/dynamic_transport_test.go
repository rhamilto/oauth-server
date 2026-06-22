package oauthserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

// TestDynamicCARoundTripper_CombinedCAs verifies that a transport with both
// IdP CA and proxy CA can connect to servers signed by either CA.
func TestDynamicCARoundTripper_CombinedCAs(t *testing.T) {
	// IdP CA and its server
	idpCAPEM, idpCACert, idpCAKey := generateCA(t)
	idpServerCert := generateServerCert(t, idpCACert, idpCAKey)
	idpServer := startTLSServer(t, idpServerCert)

	// Proxy CA and its server
	proxyCAPEM, proxyCACert, proxyCAKey := generateCA(t)
	proxyServerCert := generateServerCert(t, proxyCACert, proxyCAKey)
	proxyServer := startTLSServer(t, proxyServerCert)

	dir := t.TempDir()
	idpCAFile := filepath.Join(dir, "idp-ca.pem")
	proxyCAFile := filepath.Join(dir, "proxy-ca.pem")
	writeFile(t, idpCAFile, idpCAPEM)
	writeFile(t, proxyCAFile, proxyCAPEM)

	rt, err := newDynamicCARoundTripper(proxyCAFile, idpCAFile, "", "")
	if err != nil {
		t.Fatalf("newDynamicCARoundTripper: %v", err)
	}

	mustGet(t, rt, idpServer.URL, "IdP server")
	mustGet(t, rt, proxyServer.URL, "proxy server")
}

// TestTransportForInner_WithProxyCA verifies the full proxy CA wiring:
// transportForInner returns a *dynamicCARoundTripper, registers it in
// dynamicTransports, and starting the watchers enables live CA reload.
func TestTransportForInner_WithProxyCA(t *testing.T) {
	proxyCA1PEM, proxyCA1Cert, proxyCA1Key := generateCA(t)
	server1Cert := generateServerCert(t, proxyCA1Cert, proxyCA1Key)
	server1 := startTLSServer(t, server1Cert)

	proxyCA2PEM, proxyCA2Cert, proxyCA2Key := generateCA(t)
	server2Cert := generateServerCert(t, proxyCA2Cert, proxyCA2Key)
	server2 := startTLSServer(t, server2Cert)

	dir := t.TempDir()
	proxyCAFile := filepath.Join(dir, "proxy-ca.pem")
	writeFile(t, proxyCAFile, proxyCA1PEM)

	c := &OAuthServerConfig{}
	c.ExtraOAuthConfig.Options.ProxyTrustedCA = proxyCAFile

	rt, err := c.transportForInner("", "", "")
	if err != nil {
		t.Fatalf("transportForInner: %v", err)
	}

	if _, ok := rt.(*dynamicCARoundTripper); !ok {
		t.Fatalf("expected *dynamicCARoundTripper, got %T", rt)
	}

	if len(c.ExtraOAuthConfig.dynamicTransports) != 1 {
		t.Fatalf("expected 1 registered dynamic transport, got %d", len(c.ExtraOAuthConfig.dynamicTransports))
	}

	// Start watchers the same way the post-start hook does.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c.ExtraOAuthConfig.startDynamicCAWatchers(ctx)

	// server1 should be reachable via proxyCA1
	mustGet(t, rt, server1.URL, "server signed by initial proxy CA")

	// server2 should fail before rotation
	resp, err := doRequest(t, rt, server2.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected RoundTrip to server2 to fail before CA rotation")
	}

	// Rotate the proxy CA and verify the watcher picks it up
	writeFile(t, proxyCAFile, proxyCA2PEM)

	err = wait.PollUntilContextTimeout(t.Context(), 50*time.Millisecond, 10*time.Second, false, func(ctx context.Context) (bool, error) {
		resp, err := doRequest(t, rt, server2.URL)
		if err != nil {
			return false, nil
		}
		_ = resp.Body.Close()
		return true, nil
	})
	if err != nil {
		t.Fatal("timed out waiting for proxy CA reload through transportForInner wiring")
	}
}

// TestTransportForInner_WithoutProxyCA verifies that when proxyTrustedCA is
// empty, transportForInner returns a static transport and registers nothing.
func TestTransportForInner_WithoutProxyCA(t *testing.T) {
	idpCAPEM, _, _ := generateCA(t)
	idpCAFile := filepath.Join(t.TempDir(), "idp-ca.pem")
	writeFile(t, idpCAFile, idpCAPEM)

	c := &OAuthServerConfig{
		ExtraOAuthConfig: ExtraOAuthConfig{},
	}

	rt, err := c.transportForInner(idpCAFile, "", "")
	if err != nil {
		t.Fatalf("transportForInner: %v", err)
	}

	if _, ok := rt.(*dynamicCARoundTripper); ok {
		t.Fatal("expected static transport, got *dynamicCARoundTripper")
	}

	if len(c.ExtraOAuthConfig.dynamicTransports) != 0 {
		t.Fatalf("expected no registered dynamic transports, got %d", len(c.ExtraOAuthConfig.dynamicTransports))
	}
}

// TestDynamicCARoundTripper_ErrorResilience verifies that corrupting the proxy
// CA file does not break existing connections — the old transport is preserved.
func TestDynamicCARoundTripper_ErrorResilience(t *testing.T) {
	proxyCAPEM, proxyCACert, proxyCAKey := generateCA(t)
	serverCert := generateServerCert(t, proxyCACert, proxyCAKey)
	server := startTLSServer(t, serverCert)

	proxyCAFile := filepath.Join(t.TempDir(), "proxy-ca.pem")
	writeFile(t, proxyCAFile, proxyCAPEM)

	rt, err := newDynamicCARoundTripper(proxyCAFile, "", "", "")
	if err != nil {
		t.Fatalf("newDynamicCARoundTripper: %v", err)
	}

	// Corrupt the proxy CA file
	writeFile(t, proxyCAFile, []byte("not-a-certificate"))
	if err := rt.proxyCAContent.RunOnce(t.Context()); err == nil {
		t.Fatal("expected RunOnce to fail with corrupt CA")
	}

	// Old transport should still work
	mustGet(t, rt, server.URL, "old transport after corrupt CA reload")
}

// TestDynamicCARoundTripper_InvalidProxyCAFile verifies that constructing
// a dynamicCARoundTripper with a nonexistent proxy CA file fails.
func TestDynamicCARoundTripper_InvalidProxyCAFile(t *testing.T) {
	_, err := newDynamicCARoundTripper("/nonexistent/proxy-ca.pem", "", "", "")
	if err == nil {
		t.Fatal("expected error for nonexistent proxy CA file")
	}
}

// TestTransportForInner_DefaultTransport verifies that when no CA and no proxy
// are configured, transportForInner returns http.DefaultTransport.
func TestTransportForInner_DefaultTransport(t *testing.T) {
	c := &OAuthServerConfig{
		ExtraOAuthConfig: ExtraOAuthConfig{},
	}

	rt, err := c.transportForInner("", "", "")
	if err != nil {
		t.Fatalf("transportForInner: %v", err)
	}

	if rt != http.DefaultTransport {
		t.Fatalf("expected http.DefaultTransport, got %T", rt)
	}
}

func generateCA(t *testing.T) (certPEM []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return certPEM, cert, key
}

func generateServerCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  serverKey,
	}
}

func startTLSServer(t *testing.T, serverCert tls.Certificate) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func doRequest(t *testing.T, rt http.RoundTripper, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), "GET", url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return rt.RoundTrip(req)
}

func mustGet(t *testing.T, rt http.RoundTripper, url, msg string) {
	t.Helper()
	resp, err := doRequest(t, rt, url)
	if err != nil {
		t.Fatalf("%s: GET %s: %v", msg, url, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: GET %s: expected 200, got %d", msg, url, resp.StatusCode)
	}
}
