package machineenrollment

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
)

const p256CoordinateBytes = 32

// signJWT returns a compact JWS of claims, signed by signer. The alg header is chosen from the
// signer's public key: RS256 for RSA keys (what the machine identity service accepts) and ES256 for P-256 keys. extraHeader adds members to
// the protected header.
func signJWT(signer crypto.Signer, extraHeader, claims map[string]any) (string, error) {
	alg, err := algorithmFor(signer.Public())
	if err != nil {
		return "", err
	}

	header := map[string]any{"alg": alg, "typ": "JWT"}
	maps.Copy(header, extraHeader)
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed encoding jwt header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed encoding jwt claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed signing jwt: %w", err)
	}
	if alg == "ES256" {
		// crypto.Signer returns an ASN.1 ECDSA signature; JWS wants the fixed-size R || S.
		if sig, err = ecdsaSignatureToJWS(sig); err != nil {
			return "", err
		}
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func algorithmFor(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", errors.New("only P-256 ECDSA keys are supported")
		}
		return "ES256", nil
	case *rsa.PublicKey:
		return "RS256", nil
	default:
		return "", fmt.Errorf("unsupported signing key type %T", pub)
	}
}

func ecdsaSignatureToJWS(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) > 0 {
		return nil, errors.New("malformed ECDSA signature")
	}
	out := make([]byte, 2*p256CoordinateBytes)
	sig.R.FillBytes(out[:p256CoordinateBytes])
	sig.S.FillBytes(out[p256CoordinateBytes:])
	return out, nil
}

// publicJWK returns the RFC 7517 JWK of a public key with only its required members: kty, n and e
// for an RSA key, and kty, crv, x and y for a P-256 key.
func publicJWK(pub crypto.PublicKey) (map[string]string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return map[string]string{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		b, err := k.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed encoding public key: %w", err)
		}
		// Bytes returns the uncompressed point: 0x04 || X || Y.
		return map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(b[1 : 1+p256CoordinateBytes]),
			"y":   base64.RawURLEncoding.EncodeToString(b[1+p256CoordinateBytes:]),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

// thumbprint returns the RFC 7638 JWK thumbprint of a public key, which is also its kid.
func thumbprint(pub crypto.PublicKey) (string, error) {
	jwk, err := publicJWK(pub)
	if err != nil {
		return "", err
	}
	// The required members in lexicographic order, with no whitespace.
	var canonical string
	if jwk["kty"] == "RSA" {
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, jwk["e"], jwk["n"])
	} else {
		canonical = fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, jwk["x"], jwk["y"])
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
