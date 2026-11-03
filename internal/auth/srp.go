package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

// Match apple-crates' srp 0.7 G2048/SHA256 client, including its Apple
// username_in_x=false option and RFC5054 proof padding.
const loginSRPModulus = "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a" +
	"37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e" +
	"8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f" +
	"97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97" +
	"b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f877485445" +
	"23b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874" +
	"e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c" +
	"803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73"

type loginSRP struct {
	n, a, public *big.Int
}

type loginSRPProof struct {
	m1, m2, premaster []byte
}

func newLoginSRP() (*loginSRP, error) {
	n, ok := new(big.Int).SetString(loginSRPModulus, 16)
	if !ok {
		return nil, errors.New("invalid SRP group")
	}
	secret := make([]byte, 256)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("SRP random secret: %w", err)
	}
	a := new(big.Int).SetBytes(secret)
	return &loginSRP{n: n, a: a, public: new(big.Int).Exp(big.NewInt(2), a, n)}, nil
}

func loginHash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	return h.Sum(nil)
}

func (s *loginSRP) process(username string, password, salt, serverPublic []byte, iterations int, protocol string) (*loginSRPProof, error) {
	if iterations <= 0 {
		return nil, errors.New("GrandSlam returned an invalid PBKDF2 iteration count")
	}
	if len(serverPublic) == 0 || len(serverPublic) > 256 {
		return nil, errors.New("GrandSlam returned an invalid SRP public value")
	}
	b := new(big.Int).SetBytes(serverPublic)
	if new(big.Int).Mod(new(big.Int).Set(b), s.n).Sign() == 0 {
		return nil, errors.New("GrandSlam returned SRP B mod N = 0")
	}
	passwordHash := loginHash(password)
	switch protocol {
	case "s2k":
	case "s2k_fo":
		passwordHash = []byte(hex.EncodeToString(passwordHash))
	default:
		return nil, fmt.Errorf("GrandSlam selected unsupported SRP protocol %q", protocol)
	}
	processed := pbkdf2.Key(passwordHash, salt, iterations, 32, sha256.New)
	// Omitting the username in x retains the colon. The username is still in M1.
	x := new(big.Int).SetBytes(loginHash(salt, loginHash([]byte(":"), processed)))
	pad := func(v *big.Int) []byte { return v.FillBytes(make([]byte, 256)) }
	g := big.NewInt(2)
	padG := pad(g)
	k := new(big.Int).SetBytes(loginHash(s.n.Bytes(), padG))
	u := new(big.Int).SetBytes(loginHash(pad(s.public), pad(b)))
	if u.Sign() == 0 {
		return nil, errors.New("GrandSlam returned SRP u = 0")
	}
	base := new(big.Int).Mul(k, new(big.Int).Exp(g, x, s.n))
	base.Sub(b, base).Mod(base, s.n)
	exponent := new(big.Int).Mul(u, x)
	exponent.Add(exponent, s.a)
	premaster := new(big.Int).Exp(base, exponent, s.n).Bytes()
	key := loginHash(premaster)
	xor := loginHash(s.n.Bytes())
	hashG := loginHash(padG)
	for i := range xor {
		xor[i] ^= hashG[i]
	}
	// A is trimmed, and B is used as received in the proofs; only u pads them.
	public := s.public.Bytes()
	m1 := loginHash(xor, loginHash([]byte(username)), salt, public, serverPublic, key)
	return &loginSRPProof{m1: m1, m2: loginHash(public, m1, key), premaster: premaster}, nil
}

func (p *loginSRPProof) decrypt(serverProof, encrypted []byte) ([]byte, error) {
	if !hmac.Equal(p.m2, serverProof) {
		return nil, errors.New("GrandSlam SRP server proof mismatch")
	}
	// apple-crates uses verifier.key() here: un-hashed S, while M1/M2 use H(S).
	derive := func(label string) []byte {
		h := hmac.New(sha256.New, p.premaster)
		_, _ = h.Write([]byte(label))
		return h.Sum(nil)
	}
	block, err := aes.NewCipher(derive("extra data key:"))
	if err != nil {
		return nil, err
	}
	if len(encrypted) == 0 || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("GrandSlam SPD has an invalid ciphertext length")
	}
	decoded := make([]byte, len(encrypted))
	iv := derive("extra data iv:")
	cipher.NewCBCDecrypter(block, iv[:aes.BlockSize]).CryptBlocks(decoded, encrypted)
	padding := int(decoded[len(decoded)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(decoded) {
		return nil, errors.New("GrandSlam SPD has invalid PKCS7 padding")
	}
	for _, value := range decoded[len(decoded)-padding:] {
		if int(value) != padding {
			return nil, errors.New("GrandSlam SPD has invalid PKCS7 padding")
		}
	}
	return decoded[:len(decoded)-padding], nil
}
