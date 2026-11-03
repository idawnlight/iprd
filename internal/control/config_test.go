package control

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestSignedConfiguration(t *testing.T) {
	// This public configuration contains proxy metadata and Apple's signing
	// certificates, without account credentials or issued access tokens.
	data, err := os.ReadFile("testdata/signed-config.pb")
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := ParseSignedConfiguration(data)
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.SignatureVerified || len(configuration.Paths) == 0 || configuration.SelectedPath.Weight == 0 {
		t.Fatal("signed configuration did not produce a verified, positive-weight path")
	}
	if !bytes.Equal(configuration.Raw, data) {
		t.Fatal("signed envelope bytes changed during parsing")
	}

	envelope, err := readProto(data)
	if err != nil {
		t.Fatal(err)
	}
	raw, signature, certificates := protoByte(envelope, 1), protoByte(envelope, 2), protoBytes(envelope, 3)
	if len(certificates) < 2 {
		t.Fatal("fixture has no leaf and intermediate certificates")
	}
	for i, marker := range []asn1.ObjectIdentifier{
		{1, 2, 840, 113635, 100, 12, 22},
		{1, 2, 840, 113635, 100, 6, 2, 17},
	} {
		certificate, err := x509.ParseCertificate(certificates[i])
		if err != nil {
			t.Fatal(err)
		}
		if !certificateHasMarker(certificate, marker) {
			t.Fatalf("certificate %d lacks Apple policy marker %s", i, marker)
		}
		if certificateHasMarker(certificate, asn1.ObjectIdentifier{1, 2, 3, 4}) {
			t.Fatalf("certificate %d matched an absent policy marker", i)
		}
	}

	changedRaw, changedSignature := bytes.Clone(raw), bytes.Clone(signature)
	changedRaw[len(changedRaw)-1] ^= 1
	changedSignature[len(changedSignature)-1] ^= 1
	for _, test := range []struct {
		name         string
		raw, sig     []byte
		certificates [][]byte
		algorithm    uint64
		wantError    string
	}{
		{"changed configuration", changedRaw, signature, certificates, 1, "signature mismatch"},
		{"changed signature", raw, changedSignature, certificates, 1, "signature mismatch"},
		{"missing intermediate", raw, signature, certificates[:1], 1, "certificate chain"},
		{"wrong Apple policy", raw, signature, certificates[1:], 1, "networkserviceproxy policy"},
		{"unsupported algorithm", raw, signature, certificates, 2, "unsupported configuration signature algorithm"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := verifyConfigurationSignature(test.raw, test.sig, test.certificates, test.algorithm)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("verification error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestConfigurationPreferences(t *testing.T) {
	apple := Proxy{Name: "Apple", Server: "apple.invalid:443", ServerName: "apple.invalid"}
	akamai := Proxy{Name: "Akamai", Server: "akamai.invalid:443", ServerName: "akamai.invalid"}
	fastlyA := Proxy{Name: "Fastly_A", Server: "fastly-a.invalid:443", ServerName: "fastly-a.invalid"}
	cloudflare := Proxy{Name: "Cloudflare", Server: "cloudflare.invalid:443", ServerName: "cloudflare.invalid"}
	fastlyB := Proxy{Name: "Fastly_B", Server: "fastly-b.invalid:443", ServerName: "fastly-b.invalid"}
	paths := []Path{
		{Indexes: []int{0, 2}, Weight: 80, Ingress: apple, Egress: fastlyA},
		{Indexes: []int{0, 3}, Weight: 50, Ingress: apple, Egress: cloudflare},
		{Indexes: []int{1, 3}, Weight: 100, Ingress: akamai, Egress: cloudflare},
		{Indexes: []int{1, 2}, Weight: 0, Ingress: akamai, Egress: fastlyA},
		{Indexes: []int{0, 4}, Weight: 80, Ingress: apple, Egress: fastlyB},
	}
	for _, test := range []struct {
		name        string
		preferences Preferences
		order       []int
		fallback    bool
	}{
		{"weight and stable ties", Preferences{}, []int{2, 0, 4, 1, 3}, false},
		{"complete match", Preferences{Ingress: []string{"Apple"}, Egress: []string{"Cloudflare"}}, []int{1, 0, 4, 2, 3}, false},
		{"partial fallback", Preferences{Ingress: []string{"Apple"}, Egress: []string{"unavailable"}}, []int{0, 4, 1, 2, 3}, true},
		{"ordered preferences", Preferences{Ingress: []string{"unknown, Akamai", "Apple"}}, []int{2, 0, 4, 1, 3}, false},
		{"endpoint preference", Preferences{Ingress: []string{"apple.invalid:443"}, Egress: []string{"fastly-b.invalid"}}, []int{4, 0, 1, 2, 3}, false},
		{"zero weight cannot win", Preferences{Ingress: []string{"Akamai"}, Egress: []string{"Fastly_A"}}, []int{2, 0, 4, 1, 3}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := Configuration{Paths: slices.Clone(paths)}
			if err := configuration.SelectPath(test.preferences); err != nil {
				t.Fatal(err)
			}
			if len(configuration.Paths) != len(paths) {
				t.Fatalf("path count = %d, want %d including zero-weight discovery paths", len(configuration.Paths), len(paths))
			}
			for i, index := range test.order {
				if !slices.Equal(configuration.Paths[i].Indexes, paths[index].Indexes) {
					t.Fatalf("path %d = %v, want %v", i, configuration.Paths[i].Indexes, paths[index].Indexes)
				}
			}
			if !slices.Equal(configuration.SelectedPath.Indexes, paths[test.order[0]].Indexes) || configuration.SelectedPath.Weight == 0 {
				t.Fatalf("selected path = %v, want %v", configuration.SelectedPath.Indexes, paths[test.order[0]].Indexes)
			}
			if configuration.PreferenceFallback != test.fallback {
				t.Fatalf("PreferenceFallback = %v, want %v", configuration.PreferenceFallback, test.fallback)
			}
		})
	}
	t.Run("all zero weights", func(t *testing.T) {
		configuration := Configuration{Paths: []Path{paths[3]}}
		if err := configuration.SelectPath(Preferences{}); err == nil {
			t.Fatal("selected a zero-weight path")
		}
	})
}
