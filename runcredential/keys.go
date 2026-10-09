package runcredential

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/qoryai/forager/accesskey"
)

// PublicKey reads the key's public_key_file with read and parses it as the key type its
// alg needs:
//
//   - the file is one PEM block of type PUBLIC KEY, a PKIX SubjectPublicKeyInfo, with
//     no PEM headers and nothing but white space around it; a private key, a
//     certificate and a PKCS #1 RSA PUBLIC KEY are refused;
//   - RS256: an RSA key of at least [MinRSABits] bits with an odd public exponent of at
//     least 3, an *rsa.PublicKey;
//   - ES256: an ECDSA key on P-256, an *ecdsa.PublicKey;
//   - EdDSA: an Ed25519 key, an ed25519.PublicKey, that passes the checks the contract
//     requires of an Ed25519 public key ([accesskey.PublicKey.Check]); Ed448 and X25519
//     are refused.
//
// The error names the file and why, never what it holds.
func (k Key) PublicKey(read ReadFile) (crypto.PublicKey, error) {
	if k.PublicKeyFile == "" {
		return nil, fmt.Errorf("no public_key_file")
	}
	if read == nil {
		return nil, fmt.Errorf("the public key %s: no way to read it", k.PublicKeyFile)
	}
	b, err := read(k.PublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("the public key %s: %w", k.PublicKeyFile, err)
	}
	pub, err := parsePublicKey(k.Alg, b)
	if err != nil {
		return nil, fmt.Errorf("the public key %s: %w", k.PublicKeyFile, err)
	}
	return pub, nil
}

// parsePublicKey parses the bytes of a public key file as the key type alg needs.
func parsePublicKey(alg string, b []byte) (crypto.PublicKey, error) {
	block, rest := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("it holds no PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("its PEM block is of type %q; want PUBLIC KEY", shownType(block.Type))
	}
	if len(block.Headers) > 0 {
		return nil, fmt.Errorf("its PEM block has headers")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("it holds more than one PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("it is not a public key Go reads: %w", err)
	}
	switch alg {
	case RS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("it is not an RSA key, which RS256 needs")
		}
		if k.N.BitLen() < MinRSABits {
			return nil, fmt.Errorf("its RSA modulus has %d bits; RS256 needs at least %d", k.N.BitLen(), MinRSABits)
		}
		if k.E < 3 || k.E%2 == 0 {
			return nil, fmt.Errorf("its RSA public exponent is not an odd number of at least 3")
		}
		return k, nil
	case ES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("it is not an ECDSA key on P-256, which ES256 needs")
		}
		return k, nil
	case EdDSA:
		k, ok := pub.(ed25519.PublicKey)
		if !ok || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("it is not an Ed25519 key, which EdDSA needs")
		}
		if err := accesskey.PublicKey(k).Check(); err != nil {
			return nil, err
		}
		return k, nil
	}
	return nil, fmt.Errorf("the alg %q is not RS256, ES256 or EdDSA", alg)
}

// shownType is a PEM block's type as an error shows it: at most 32 bytes, so a file that
// is not a key is not echoed.
func shownType(t string) string {
	if len(t) > 32 || !plain(t) {
		return "unreadable"
	}
	return t
}
