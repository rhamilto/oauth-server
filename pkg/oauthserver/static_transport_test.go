package oauthserver

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewStaticRoundTripper_DefaultTransport(t *testing.T) {
	rt, err := newStaticRoundTripper("", "", "")
	if err != nil {
		t.Fatalf("newStaticRoundTripper: %v", err)
	}

	if rt != http.DefaultTransport {
		t.Fatalf("expected http.DefaultTransport, got %T", rt)
	}
}

func TestNewStaticRoundTripper_CertWithoutKey(t *testing.T) {
	_, err := newStaticRoundTripper("", "cert.pem", "")
	if err == nil {
		t.Fatal("expected error when certFile is specified without keyFile")
	}
	const want = "certFile and keyFile must be specified together"
	if err.Error() != want {
		t.Fatalf("expected %q, got %q", want, err.Error())
	}
}

func TestNewStaticRoundTripper_KeyWithoutCert(t *testing.T) {
	_, err := newStaticRoundTripper("", "", "key.pem")
	if err == nil {
		t.Fatal("expected error when keyFile is specified without certFile")
	}
	const want = "certFile and keyFile must be specified together"
	if err.Error() != want {
		t.Fatalf("expected %q, got %q", want, err.Error())
	}
}

func TestNewStaticRoundTripper_WithCAAndClientCert(t *testing.T) {
	caPEM, _, _ := generateCA(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writeFile(t, caFile, caPEM)

	certFile, keyFile := generateClientCertFiles(t)

	rt, err := newStaticRoundTripper(caFile, certFile, keyFile)
	if err != nil {
		t.Fatalf("newStaticRoundTripper: %v", err)
	}

	transport, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", rt)
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected RootCAs to be set")
	}
	if len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("expected 1 client certificate, got %d", len(transport.TLSClientConfig.Certificates))
	}
}

func TestNewStaticRoundTripper_InvalidCA(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writeFile(t, caFile, []byte("not-a-certificate"))

	_, err := newStaticRoundTripper(caFile, "", "")
	if err == nil {
		t.Fatal("expected error for invalid CA file")
	}
	if !strings.Contains(err.Error(), "error loading cert pool from CA file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewStaticRoundTripper_InvalidClientCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	writeFile(t, certFile, []byte("not-a-cert"))
	writeFile(t, keyFile, []byte("not-a-key"))

	_, err := newStaticRoundTripper("", certFile, keyFile)
	if err == nil {
		t.Fatal("expected error for invalid client cert/key pair")
	}
	if !strings.Contains(err.Error(), "error loading x509 keypair from cert file") {
		t.Fatalf("unexpected error: %v", err)
	}
}
