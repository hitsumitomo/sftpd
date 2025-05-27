package https

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha3"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"math/rand/v2"
	"time"
)

// GenerateECDSACert generates deterministic ECDSA certificate using the given common name.
func GenerateECDSACert(commonName string) (*tls.Certificate, error) {
	seed := sha3.Sum256([]byte(commonName))
	prng := rand.NewChaCha8(seed)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), prng)
	if err != nil {
		return nil, err
	}

	serialNumber := new(big.Int).SetBytes(seed[:])

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          seed[:],
		DNSNames: []string{commonName, "localhost"},
	}

	derBytes, err := x509.CreateCertificate(prng, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{ derBytes },
		PrivateKey:  priv,
	}
	return &tlsCert, nil
}