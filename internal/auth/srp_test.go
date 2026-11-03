package auth

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// These fictional vectors were calculated independently with Python hashlib,
// hmac and server-side SRP: B=(k*v+g^b) mod N, S=(A*v^u)^b mod N.
// SPD ciphertexts were produced separately using AES-CBC, not this Go code.
const testSRPSecret = "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393"

const testSRPS2KPremaster = `
9cc8724f6eb69d973f9bd29f6595a39fe30917e4c681524fa4a5c1e03db070ad
0c6e810b311745c5292fc489e63ffa853f5d13854626683a71c54af0169058796
947953ebf8fbc9d2de7c80c82e27b1e7e171d2bbcff98608537183e6600a0bde
0e8bda2ba5d55b57d4a4598825fd3642b7de857b67c63694831c83c0500e74a7
513c2a385b250c375e780adb5e09ffb661702c2ae5f6b8b4b193bff2ab6ce352
af3854b9d805f7e413e3f799e8fa963687f85ee80df614976383114c943969351
3915455264284b61dc272a168e450c33a16116afea2d509f2bf06bc293767460e
6e420ca75a26229d0cba7e12e81b4c7d2d3011fcd6acbcd6651a79586c824
`

const testSRPS2KM2 = "93f81ad85330144be4612ece6e8d11569bb0aa80fb1165babbe8f8ff0199ff89"

func TestLoginSRPVectors(t *testing.T) {
	for _, test := range []struct {
		protocol, serverPublic, premaster, m1, m2 string
	}{
		{
			protocol: "s2k",
			serverPublic: `
665a4a053231d6cb6fe4a03466ac357d314cbfbad60d8b3209e5cd33ed8f30a36
88cf72dac2c15d748427eb98b16eab467d32c95882c21d665aa2516f974304316
7011fa497ec9f66a89f244f5966d92faf96ac130c4fe69c33817cde71eb87c3b1
4a8eda6b8005bf5a155a30f8e388f42072f70d991462f631fb361c2d229095ba
db8f499d4b19d01411b6a6c60e2abc74da28bde4742f3fa4edf2da5c002a034a
95684c92082c713abf9f162ecfac1b19afd3bbdb9918dcefae4a8a7fda7a17ca
8949687e31b5d07e2eaa364e579d20b55ed14f2da4dc1205b8334ecb8dcd53e9
2eb7149b586f9c7673f86c3b058a96d93b05c76765307151e668dcc52b3a8`,
			premaster: testSRPS2KPremaster,
			m1:        "ba4e2149b77ad8bdd94f0c0d1c410000c0c6eed34f11f0f9f442434991ce6477",
			m2:        testSRPS2KM2,
		},
		{
			protocol: "s2k_fo",
			serverPublic: `
675edf057b1c67078e2c492e60f367adab6011d8b95bfcf33e8c6f67e8606c47
e877ea44b2104c596c5f1b6564030753b38fabd6090ef9198032e9af7cc44ee4f
9d35bd428ea7ed5d3b6c7286a1641afe246a75458029bf5fe506df3fa29b3b4a
6709d1f1ac52e17ac52b944901ff6dfaadbca6d37721ad441576cab9cb5d4970
42c059271e24a8cc675d2c2bb7282ae207f8ae51a40a667801d316046d1927a2
7d7c2974922262a4e2c5ec39f9146321728e7a7d66412e7a99d36f64ee71ebc
165a10499565ab72d91b5c57b10f481c5a6c5eeaa4315a62feea92f1c55e1ae3
9ec010b8bb5ccd136782c0ce564b694f907487954e107c15cd86d57f7783975e`,
			premaster: `
7863edf467528336e303de183942b771c88944085e5b08516a81783e1aadac280
94e59810bf335349623619931cc20269edc11d3454a071c7e3668361efc3789511
1c5d7fd87fd5517bcc614aad8ef8171a5a81017a52e4f6bda2c3c8271260989b
e2d04edf3ecd519d56bf4a864d0c8766f8284ae4d825e3569e1f4d56583360b9
3bef644e0d2dc513c72d6bf6fcce5aefa039bfa4fc0774a16df106201bbc5577a
d8d407b7bcbf8e49b31b87c0edf041cb7538d2d6dace73e490057abbc4b06b7
a8a7ce686d5513771ae163955f8b37e1a9079ccdac13cf3e41f4456b706ee999a
15b5438a42882cf45d30bf7b018affbde57dfd90d4f71186c116179d1a6e`,
			m1: "29b146c3ff5e99440349a2ab915c5a077aeb1d12ff859798297fc06306c90ba4",
			m2: "f0c3c32a51bb5221b06f6c1f6ea9ad7b1f62e21ca3309f9540c14e943d20fb55",
		},
	} {
		t.Run(test.protocol, func(t *testing.T) {
			n, ok := new(big.Int).SetString(loginSRPModulus, 16)
			if !ok {
				t.Fatal("invalid SRP group")
			}
			a := new(big.Int).SetBytes(testSRPHex(t, testSRPSecret))
			client := &loginSRP{n: n, a: a, public: new(big.Int).Exp(big.NewInt(2), a, n)}
			proof, err := client.process("offline@example.invalid", []byte("not-an-account-password"), testSRPHex(t, "beb25379d1a8581eb5a727673a2441ee"), testSRPHex(t, test.serverPublic), 4096, test.protocol)
			if err != nil {
				t.Fatal(err)
			}
			for _, result := range []struct {
				name string
				got  []byte
				want string
			}{
				{"premaster", proof.premaster, test.premaster},
				{"M1", proof.m1, test.m1},
				{"M2", proof.m2, test.m2},
			} {
				if !bytes.Equal(result.got, testSRPHex(t, result.want)) {
					t.Errorf("%s = %x, want %s", result.name, result.got, strings.Join(strings.Fields(result.want), ""))
				}
			}
		})
	}
}

func TestLoginSPDDecrypt(t *testing.T) {
	proof := &loginSRPProof{m2: testSRPHex(t, testSRPS2KM2), premaster: testSRPHex(t, testSRPS2KPremaster)}
	for _, test := range []struct {
		name, ciphertext, plaintext string
		wrongProof, wantError       bool
	}{
		{
			name: "plist",
			ciphertext: `0795a24d61dc1111de1f96197e2a9265b36062b872f9be9d3fbd741943b888665
83ebbbfc31fe430941cb098457d8ea929b9684b9578dd6193c93b8ce1fabcc376
6968503879b9047ae3e0214eb508e6`,
			plaintext: `<?xml version="1.0"?><plist><dict><key>offline</key><true/></dict></plist>`,
		},
		{name: "full block padding", ciphertext: "a98df8cad3fa30b5d2bd7e11dc01123d"},
		{name: "zero padding", ciphertext: "244a9cb42d329dd0bf6088e2c9c021ff", wantError: true},
		{name: "inconsistent padding", ciphertext: "c9b383855d6421d016b332645d6919d8", wantError: true},
		{name: "empty ciphertext", wantError: true},
		{name: "non-block ciphertext", ciphertext: "00", wantError: true},
		{name: "wrong server proof", ciphertext: "a98df8cad3fa30b5d2bd7e11dc01123d", wrongProof: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverProof := bytes.Clone(proof.m2)
			if test.wrongProof {
				serverProof[0] ^= 1
			}
			plaintext, err := proof.decrypt(serverProof, testSRPHex(t, test.ciphertext))
			if test.wantError {
				if err == nil {
					t.Fatal("accepted invalid SPD")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(plaintext) != test.plaintext {
				t.Fatalf("plaintext = %q, want %q", plaintext, test.plaintext)
			}
		})
	}
}

func testSRPHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.Join(strings.Fields(value), ""))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
