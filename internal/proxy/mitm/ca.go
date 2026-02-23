package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"

	"time"
	"velar/internal/config"
)

const (
	maxLeafLifetime = 24 * time.Hour
)

type CAStore struct {
	certPath string
	keyPath  string

	mu       sync.Mutex
	caCert   *x509.Certificate
	caKey    *rsa.PrivateKey
	certPool map[string]*tls.Certificate
}

func NewCAStore(baseDir string) *CAStore {
	return &CAStore{
		certPath: filepath.Join(baseDir, "cert.pem"),
		keyPath:  filepath.Join(baseDir, "key.pem"),
		certPool: make(map[string]*tls.Certificate),
	}
}

func DefaultCAPath() (string, error) {
	appDir, err := config.AppDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(appDir, "ca"), nil
}

func (c *CAStore) EnsureRootCA() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensureRootCALocked()
}

func (c *CAStore) GetLeafCert(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureRootCALocked(); err != nil {
		return nil, err
	}
	if cert, ok := c.certPool[host]; ok {
		return cert, nil
	}
	cert, err := c.generateLeafCertLocked(host)
	if err != nil {
		return nil, err
	}
	c.certPool[host] = cert
	return cert, nil
}

func (c *CAStore) ensureRootCALocked() error {
	if c.caCert != nil && c.caKey != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.certPath), 0o700); err != nil {
		return fmt.Errorf("create ca dir: %w", err)
	}

	certPEM, certErr := os.ReadFile(c.certPath)
	keyPEM, keyErr := os.ReadFile(c.keyPath)
	if certErr == nil && keyErr == nil {
		cert, key, err := parseCAPair(certPEM, keyPEM)
		if err != nil {
			return err
		}
		c.caCert = cert
		c.caKey = key
		return nil
	}

	certPEM, keyPEM, cert, key, err := generateRootCA()
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write ca cert: %w", err)
	}
	if err := os.WriteFile(c.keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write ca key: %w", err)
	}
	c.caCert = cert
	c.caKey = key
	return nil
}

func parseCAPair(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("invalid ca cert pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid ca key pem")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %w", err)
	}
	return cert, key, nil
}

func generateRootCA() ([]byte, []byte, *x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate root key: %w", err)
	}

	notBefore := time.Now().Add(-time.Hour)
	tpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "Velar Root CA", Organization: []string{"Velar"}},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create root cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse root cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM, cert, priv, nil
}

func (c *CAStore) generateLeafCertLocked(host string) (*tls.Certificate, error) {
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	notBefore := time.Now().Add(-time.Hour)
	tpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: host, Organization: []string{"Velar MITM"}},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(maxLeafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Check if host is an IP address or hostname
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, c.caCert, &leafKey.PublicKey, c.caKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	pair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("build leaf pair: %w", err)
	}
	return &pair, nil
}

func randomSerial() *big.Int {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if serial == nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}
