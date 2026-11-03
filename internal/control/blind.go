package control

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// BlindState is one token awaiting the issuer's raw RSA response.
type BlindState struct {
	KeyID, Content, Blinded []byte
	client                  blindrsa.Client
	state                   blindrsa.State
}

// NewBlind matches CryptoKitPrivate's RSABSSATokenBlinder: SHA384 PSS with
// 48-byte salt, no Prepare prefix, and random 32-byte content when content is nil.
func NewBlind(keyDER, content []byte) (*BlindState, error) {
	publicKey, err := blindPublicKey(keyDER)
	if err != nil {
		return nil, err
	}
	client, err := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, publicKey)
	if err != nil {
		return nil, err
	}
	message := bytes.Clone(content)
	if content == nil {
		message = make([]byte, 32)
		if _, err := rand.Read(message); err != nil {
			return nil, fmt.Errorf("generate token content: %w", err)
		}
	}
	blinded, state, err := client.Blind(rand.Reader, message)
	if err != nil {
		return nil, fmt.Errorf("blind token: %w", err)
	}
	keyID := sha256.Sum256(keyDER)
	return &BlindState{KeyID: keyID[:], Content: message, Blinded: blinded, client: client, state: state}, nil
}

// Finalize unblinds the issuer response and verifies the resulting RSA signature.
func (s *BlindState) Finalize(signature []byte) ([]byte, error) {
	result, err := s.client.Finalize(s.state, signature)
	if err != nil {
		return nil, fmt.Errorf("finalize token signature: %w", err)
	}
	return result, nil
}

// Go's x509.ParsePKIXPublicKey does not accept id-RSASSA-PSS SPKIs. Read the
// algorithm parameters and the inner PKCS1 key separately, hashing the original
// SPKI bytes for KeyID rather than re-encoding them as rsaEncryption.
func blindPublicKey(keyDER []byte) (*rsa.PublicKey, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(keyDER, &spki); err != nil || len(rest) != 0 {
		return nil, errors.New("token key is not a DER SubjectPublicKeyInfo")
	}
	pssOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	sha384OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	mgf1OID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	if !spki.Algorithm.Algorithm.Equal(pssOID) {
		return nil, errors.New("token key does not use RSASSA-PSS")
	}
	var params struct {
		HashAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
		MaskAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
		SaltLength    int                      `asn1:"explicit,tag:2"`
		TrailerField  int                      `asn1:"optional,explicit,tag:3,default:1"`
	}
	if rest, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &params); err != nil || len(rest) != 0 {
		return nil, errors.New("token key has invalid RSASSA-PSS parameters")
	}
	var maskHash pkix.AlgorithmIdentifier
	if rest, err := asn1.Unmarshal(params.MaskAlgorithm.Parameters.FullBytes, &maskHash); err != nil || len(rest) != 0 {
		return nil, errors.New("token key has invalid MGF1 parameters")
	}
	if !params.HashAlgorithm.Algorithm.Equal(sha384OID) ||
		!params.MaskAlgorithm.Algorithm.Equal(mgf1OID) ||
		!maskHash.Algorithm.Equal(sha384OID) || params.SaltLength != 48 || params.TrailerField != 1 {
		return nil, errors.New("token key requires unsupported PSS parameters")
	}
	key, err := x509.ParsePKCS1PublicKey(spki.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse token RSA key: %w", err)
	}
	return key, nil
}
