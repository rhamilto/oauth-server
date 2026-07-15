package oauthserver

import (
	"path/filepath"
	"testing"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
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

	proxyCAContent, err := dynamiccertificates.NewDynamicCAContentFromFile("proxy-ca", proxyCAFile)
	if err != nil {
		t.Fatalf("NewDynamicCAContentFromFile: %v", err)
	}
	rt, err := newDynamicCARoundTripper(proxyCAContent, idpCAFile, "", "")
	if err != nil {
		t.Fatalf("newDynamicCARoundTripper: %v", err)
	}

	mustGet(t, rt, idpServer.URL, "IdP server")
	mustGet(t, rt, proxyServer.URL, "proxy server")
}

func TestNewDynamicCARoundTripper_CertWithoutKey(t *testing.T) {
	_, err := newDynamicCARoundTripper(nil, "", "cert.pem", "")
	if err == nil {
		t.Fatal("expected error when certFile is specified without keyFile")
	}
	const want = "certFile and keyFile must be specified together"
	if err.Error() != want {
		t.Fatalf("expected %q, got %q", want, err.Error())
	}
}

func TestNewDynamicCARoundTripper_KeyWithoutCert(t *testing.T) {
	_, err := newDynamicCARoundTripper(nil, "", "", "key.pem")
	if err == nil {
		t.Fatal("expected error when keyFile is specified without certFile")
	}
	const want = "certFile and keyFile must be specified together"
	if err.Error() != want {
		t.Fatalf("expected %q, got %q", want, err.Error())
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

	proxyCAContent, err := dynamiccertificates.NewDynamicCAContentFromFile("proxy-ca", proxyCAFile)
	if err != nil {
		t.Fatalf("NewDynamicCAContentFromFile: %v", err)
	}
	rt, err := newDynamicCARoundTripper(proxyCAContent, "", "", "")
	if err != nil {
		t.Fatalf("newDynamicCARoundTripper: %v", err)
	}

	// Corrupt the proxy CA file
	writeFile(t, proxyCAFile, []byte("not-a-certificate"))
	if err := proxyCAContent.RunOnce(t.Context()); err == nil {
		t.Fatal("expected RunOnce to fail with corrupt CA")
	}

	// Old transport should still work
	mustGet(t, rt, server.URL, "old transport after corrupt CA reload")
}
