package src

// Cryptography fixtures: weak hashes, weak ciphers, static IVs, weak keys,
// insecure randomness, TLS misconfiguration, timing-unsafe comparison.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // VULN: blocklisted import — gosec G502
	"crypto/md5" // VULN: blocklisted import — gosec G501
	"crypto/rand"
	"crypto/rc4" // VULN: blocklisted import — gosec G503
	"crypto/rsa"
	"crypto/sha1" // VULN: blocklisted import — gosec G505
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	mrand "math/rand"
	"net/http"
)

// VULN: MD5 used for password hashing — CWE-327, CWE-916 — gosec G401
func HashPasswordMD5(password string) string {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

// VULN: SHA-1 for integrity — CWE-328 — gosec G401
func HashSHA1(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

// VULN: unsalted fast hash for password storage — CWE-916
func HashPasswordUnsalted(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

// VULN: DES (56-bit) — CWE-327 — gosec G405
func EncryptDES(key, plaintext []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plaintext)%block.BlockSize() != 0 {
		return nil, errors.New("plaintext not block aligned")
	}
	out := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += block.BlockSize() {
		block.Encrypt(out[i:], plaintext[i:]) // ECB mode
	}
	return out, nil
}

// VULN: RC4 stream cipher — CWE-327 — gosec G405
func EncryptRC4(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

// VULN: hard-coded / static IV with AES-CBC — CWE-329
var staticIV = []byte("0123456789abcdef")

func EncryptAESCBCStaticIV(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext not block aligned")
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, staticIV).CryptBlocks(out, plaintext)
	return out, nil
}

// VULN: hard-coded AES key — CWE-321
var hardcodedAESKey = []byte("ThisIsA32ByteLongHardcodedKey!!!")

func EncryptWithHardcodedKey(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(hardcodedAESKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize()) // VULN: all-zero nonce reuse — CWE-323
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// VULN: RSA key below 2048 bits — CWE-326 — gosec G403
func GenerateWeakRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}

// VULN: math/rand used for a security token — CWE-338 — gosec G404
func InsecureSessionToken() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(mrand.Intn(256))
	}
	return hex.EncodeToString(b)
}

// SAFE: crypto/rand token. Must NOT be flagged.
func SecureSessionToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// VULN: TLS certificate verification disabled — CWE-295 — gosec G402
func InsecureHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// VULN: weak minimum TLS version and weak cipher suite — CWE-326 — gosec G402
func WeakTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	}
}

// VULN: timing-unsafe comparison of secret — CWE-208
func CompareTokenUnsafe(provided, expected string) bool {
	return provided == expected
}

// SAFE: constant-time comparison. Must NOT be flagged.
func CompareTokenSafe(provided, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}
