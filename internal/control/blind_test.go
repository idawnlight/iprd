package control

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

func TestBlindRSAPSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := testPSSPublicKey(t, &key.PublicKey, 48)
	parsed, err := blindPublicKey(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.E != key.E || parsed.N.Cmp(key.N) != 0 {
		t.Fatal("PSS SPKI changed the RSA public key")
	}
	keyID := sha256.Sum256(keyDER)
	for _, test := range []struct {
		name    string
		content []byte
	}{
		{"random legacy content", nil},
		{"explicit content", bytes.Repeat([]byte{0x42}, 98)},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, err := NewBlind(keyDER, test.content)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(state.KeyID, keyID[:]) {
				t.Fatal("KeyID is not SHA256 of the original PSS SPKI")
			}
			if test.content == nil {
				if len(state.Content) != 32 {
					t.Fatalf("random content length = %d, want 32", len(state.Content))
				}
			} else if !bytes.Equal(state.Content, test.content) {
				t.Fatal("explicit content gained a preparation prefix")
			}
			issuer := blindrsa.NewSigner(key)
			response, err := issuer.BlindSign(state.Blinded)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := state.Finalize(response)
			if err != nil {
				t.Fatal(err)
			}
			// Use the standard library, independently of CIRCL's verifier, to
			// check the unblinded signature and its exact hash/salt parameters.
			digest := sha512.Sum384(state.Content)
			if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA384, digest[:], signature, &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}); err != nil {
				t.Fatalf("independent RSA-PSS verification: %v", err)
			}
			response[len(response)-1] ^= 1
			if _, err := state.Finalize(response); err == nil {
				t.Fatal("accepted a changed issuer response")
			}
		})
	}
	t.Run("unsupported PSS parameters", func(t *testing.T) {
		if _, err := blindPublicKey(testPSSPublicKey(t, &key.PublicKey, 32)); err == nil {
			t.Fatal("accepted SHA384-PSS with a 32-byte salt")
		}
	})
	t.Run("rsaEncryption SPKI", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := blindPublicKey(der); err == nil {
			t.Fatal("accepted rsaEncryption in place of id-RSASSA-PSS")
		}
	})
}

func testPSSPublicKey(t *testing.T, key *rsa.PublicKey, saltLength int) []byte {
	t.Helper()
	hash := pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2},
		Parameters: asn1.RawValue{Tag: asn1.TagNull},
	}
	hashDER, err := asn1.Marshal(hash)
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := asn1.Marshal(struct {
		HashAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
		MaskAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
		SaltLength    int                      `asn1:"explicit,tag:2"`
		TrailerField  int                      `asn1:"optional,explicit,tag:3,default:1"`
	}{
		HashAlgorithm: hash,
		MaskAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}, Parameters: asn1.RawValue{FullBytes: hashDER}},
		SaltLength:    saltLength,
		TrailerField:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := x509.MarshalPKCS1PublicKey(key)
	spki, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, Parameters: asn1.RawValue{FullBytes: parameters}},
		PublicKey: asn1.BitString{Bytes: publicKey, BitLength: len(publicKey) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return spki
}
