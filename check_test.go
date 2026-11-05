// Copyright 2022 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
)

const testPassword = "s3cret"

type testKeys struct {
	rsaA *rsa.PrivateKey
	rsaB *rsa.PrivateKey
	ecA  *ecdsa.PrivateKey
	ecB  *ecdsa.PrivateKey
	edA  ed25519.PrivateKey
	edB  ed25519.PrivateKey
}

func generateTestKeys(t *testing.T) testKeys {
	t.Helper()
	rsaA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKeys{rsaA, rsaB, ecA, ecB, edA, edB}
}

// selfSignedCert returns a self-signed certificate DER for the given key.
func selfSignedCert(t *testing.T, signer crypto.Signer) []byte {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mkcert check test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pkcs8KeyPEM(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func pkcs8KeyDER(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func rsaPKCS1PEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func ecSEC1PEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestCheckPair(t *testing.T) {
	keys := generateTestKeys(t)
	rsaCertADER := selfSignedCert(t, keys.rsaA)
	rsaCertA := certPEM(rsaCertADER)
	rsaCertB := certPEM(selfSignedCert(t, keys.rsaB))
	ecCertA := certPEM(selfSignedCert(t, keys.ecA))
	ecCertB := certPEM(selfSignedCert(t, keys.ecB))
	edCertA := certPEM(selfSignedCert(t, keys.edA))

	encryptedPKCS8 := encryptPKCS8PEM(t, pkcs8KeyDER(t, keys.rsaA), testPassword,
		oidPBKDF2, oidHMACWithSHA256, oidAES256CBC, 1000)
	encryptedPKCS8SHA1 := encryptPKCS8PEM(t, pkcs8KeyDER(t, keys.rsaA), testPassword,
		oidPBKDF2, nil, oidAES128CBC, 1000)
	encryptedPKCS8Scrypt := encryptPKCS8PEM(t, pkcs8KeyDER(t, keys.rsaA), testPassword,
		oidScrypt, nil, oidAES256CBC, 0)
	encryptedPKCS8GCM := encryptPKCS8PEM(t, pkcs8KeyDER(t, keys.rsaA), testPassword,
		oidPBKDF2, oidHMACWithSHA256, oidAES256GCM, 1000)
	encryptedLegacyRSA := encryptLegacyPEM(t, "RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(keys.rsaA), testPassword)
	encryptedLegacyEC := encryptLegacyPEM(t, "EC PRIVATE KEY",
		marshalECPrivateKey(t, keys.ecA), testPassword)

	dsaBlock := pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("not a key")})

	tests := []struct {
		name      string
		certPEM   []byte
		keyPEM    []byte
		password  []byte
		want      checkStatus
		wantNotes []string // substrings expected in the output
	}{
		{
			name:      "RSA PKCS8 match",
			certPEM:   rsaCertA,
			keyPEM:    pkcs8KeyPEM(t, keys.rsaA),
			want:      statusMatch,
			wantNotes: []string{"match", "RSA"},
		},
		{
			name:    "RSA PKCS1 match",
			certPEM: rsaCertA,
			keyPEM:  rsaPKCS1PEM(keys.rsaA),
			want:    statusMatch,
		},
		{
			name:    "ECDSA PKCS8 match",
			certPEM: ecCertA,
			keyPEM:  pkcs8KeyPEM(t, keys.ecA),
			want:    statusMatch,
		},
		{
			name:    "ECDSA SEC1 match",
			certPEM: ecCertA,
			keyPEM:  ecSEC1PEM(t, keys.ecA),
			want:    statusMatch,
		},
		{
			name:      "Ed25519 match",
			certPEM:   edCertA,
			keyPEM:    pkcs8KeyPEM(t, keys.edA),
			want:      statusMatch,
			wantNotes: []string{"Ed25519"},
		},
		{
			name:      "RSA mismatch",
			certPEM:   rsaCertA,
			keyPEM:    pkcs8KeyPEM(t, keys.rsaB),
			want:      statusMismatch,
			wantNotes: []string{"do not match"},
		},
		{
			name:      "ECDSA mismatch",
			certPEM:   ecCertA,
			keyPEM:    pkcs8KeyPEM(t, keys.ecB),
			want:      statusMismatch,
			wantNotes: []string{"do not match"},
		},
		{
			name:      "Ed25519 mismatch",
			certPEM:   edCertA,
			keyPEM:    pkcs8KeyPEM(t, keys.edB),
			want:      statusMismatch,
			wantNotes: []string{"do not match"},
		},
		{
			name:      "different key types mismatch",
			certPEM:   rsaCertA,
			keyPEM:    pkcs8KeyPEM(t, keys.ecA),
			want:      statusMismatch,
			wantNotes: []string{"RSA", "ECDSA"},
		},

		{
			name:    "combined PEM match",
			certPEM: append(append([]byte{}, rsaCertA...), pkcs8KeyPEM(t, keys.rsaA)...),
			keyPEM:  append(append([]byte{}, rsaCertA...), pkcs8KeyPEM(t, keys.rsaA)...),
			want:    statusMatch,
		},
		{
			name:      "combined PEM mismatch",
			certPEM:   append(append([]byte{}, rsaCertA...), pkcs8KeyPEM(t, keys.rsaB)...),
			keyPEM:    append(append([]byte{}, rsaCertA...), pkcs8KeyPEM(t, keys.rsaB)...),
			want:      statusMismatch,
			wantNotes: []string{"do not match"},
		},
		{
			name:      "multiple certificates, matching one first",
			certPEM:   append(append([]byte{}, rsaCertA...), ecCertB...),
			keyPEM:    pkcs8KeyPEM(t, keys.rsaA),
			want:      statusMatch,
			wantNotes: []string{"2 certificates"},
		},
		{
			name:      "multiple certificates, mismatching one first",
			certPEM:   append(append([]byte{}, ecCertB...), rsaCertA...),
			keyPEM:    pkcs8KeyPEM(t, keys.rsaA),
			want:      statusMismatch,
			wantNotes: []string{"2 certificates", "do not match"},
		},
		{
			name: "certificate chain plus key in one file",
			certPEM: bytes.Join([][]byte{
				ecCertA, rsaCertB, ecCertB, pkcs8KeyPEM(t, keys.ecA),
			}, []byte("\n")),
			keyPEM: bytes.Join([][]byte{
				ecCertA, rsaCertB, ecCertB, pkcs8KeyPEM(t, keys.ecA),
			}, []byte("\n")),
			want:      statusMatch,
			wantNotes: []string{"3 certificates"},
		},
		{
			name:      "multiple private keys uses the first",
			certPEM:   rsaCertA,
			keyPEM:    append(append([]byte{}, pkcs8KeyPEM(t, keys.rsaA)...), pkcs8KeyPEM(t, keys.rsaB)...),
			want:      statusMatch,
			wantNotes: []string{"2 private keys"},
		},

		{
			name:      "encrypted PKCS8 PBKDF2-SHA256 match",
			certPEM:   rsaCertA,
			keyPEM:    encryptedPKCS8,
			password:  []byte(testPassword),
			want:      statusMatch,
			wantNotes: []string{"RSA"},
		},
		{
			name:      "encrypted PKCS8 PBKDF2-SHA256 wrong password",
			certPEM:   rsaCertA,
			keyPEM:    encryptedPKCS8,
			password:  []byte("wrong"),
			want:      statusInvalid,
			wantNotes: []string{"decrypt"},
		},
		{
			name:      "encrypted PKCS8 without password",
			certPEM:   rsaCertA,
			keyPEM:    encryptedPKCS8,
			password:  nil,
			want:      statusInvalid,
			wantNotes: []string{"encrypted", "password"},
		},
		{
			name:     "encrypted PKCS8 PBKDF2-SHA1 default PRF match",
			certPEM:  rsaCertA,
			keyPEM:   encryptedPKCS8SHA1,
			password: []byte(testPassword),
			want:     statusMatch,
		},
		{
			name:     "encrypted PKCS8 PBKDF2-SHA1 wrong password",
			certPEM:  rsaCertA,
			keyPEM:   encryptedPKCS8SHA1,
			password: []byte("nope"),
			want:     statusInvalid,
		},
		{
			name:     "encrypted PKCS8 scrypt match",
			certPEM:  rsaCertA,
			keyPEM:   encryptedPKCS8Scrypt,
			password: []byte(testPassword),
			want:     statusMatch,
		},
		{
			name:     "encrypted PKCS8 scrypt wrong password",
			certPEM:  rsaCertA,
			keyPEM:   encryptedPKCS8Scrypt,
			password: []byte("bad"),
			want:     statusInvalid,
		},
		{
			name:     "encrypted PKCS8 AES-GCM match",
			certPEM:  rsaCertA,
			keyPEM:   encryptedPKCS8GCM,
			password: []byte(testPassword),
			want:     statusMatch,
		},
		{
			name:     "encrypted PKCS8 AES-GCM wrong password",
			certPEM:  rsaCertA,
			keyPEM:   encryptedPKCS8GCM,
			password: []byte("bad"),
			want:     statusInvalid,
		},
		{
			name:     "legacy encrypted RSA PEM match",
			certPEM:  rsaCertA,
			keyPEM:   encryptedLegacyRSA,
			password: []byte(testPassword),
			want:     statusMatch,
		},
		{
			name:      "legacy encrypted RSA PEM wrong password",
			certPEM:   rsaCertA,
			keyPEM:    encryptedLegacyRSA,
			password:  []byte("bad"),
			want:      statusInvalid,
			wantNotes: []string{"password"},
		},
		{
			name:      "legacy encrypted RSA PEM without password",
			certPEM:   rsaCertA,
			keyPEM:    encryptedLegacyRSA,
			password:  nil,
			want:      statusInvalid,
			wantNotes: []string{"password"},
		},
		{
			name:     "legacy encrypted EC PEM match",
			certPEM:  ecCertA,
			keyPEM:   encryptedLegacyEC,
			password: []byte(testPassword),
			want:     statusMatch,
		},

		{
			name:      "empty file",
			certPEM:   []byte(""),
			keyPEM:    pkcs8KeyPEM(t, keys.rsaA),
			want:      statusInvalid,
			wantNotes: []string{"no PEM blocks"},
		},
		{
			name:      "garbage file",
			certPEM:   []byte("this is definitely not a PEM file\n"),
			keyPEM:    pkcs8KeyPEM(t, keys.rsaA),
			want:      statusInvalid,
			wantNotes: []string{"no PEM blocks"},
		},
		{
			name: "trailing non-PEM data",
			certPEM: append(append([]byte{}, rsaCertA...),
				[]byte("----- this is garbage -----\n")...),
			keyPEM:    pkcs8KeyPEM(t, keys.rsaA),
			want:      statusInvalid,
			wantNotes: []string{"not part of any PEM block"},
		},
		{
			name:      "truncated certificate DER",
			certPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCertADER[:80]}),
			keyPEM:    pkcs8KeyPEM(t, keys.rsaA),
			want:      statusInvalid,
			wantNotes: []string{"failed to parse the certificate"},
		},
		{
			name:      "truncated private key DER",
			certPEM:   rsaCertA,
			keyPEM:    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: make([]byte, 16)}),
			want:      statusInvalid,
			wantNotes: []string{"failed to parse"},
		},
		{
			name:      "no certificate block",
			certPEM:   []byte("-----BEGIN PUBLIC KEY-----\nBM9x\n-----END PUBLIC KEY-----\n"),
			keyPEM:    pkcs8KeyPEM(t, keys.rsaA),
			want:      statusInvalid,
			wantNotes: []string{"no CERTIFICATE PEM block"},
		},
		{
			name:      "no private key block",
			certPEM:   rsaCertA,
			keyPEM:    rsaCertA,
			want:      statusInvalid,
			wantNotes: []string{"no private key PEM block"},
		},
		{
			name:      "unsupported DSA private key",
			certPEM:   rsaCertA,
			keyPEM:    dsaBlock,
			want:      statusUnsupported,
			wantNotes: []string{"unsupported private key type", "DSA"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, lines := checkPair(tt.certPEM, tt.keyPEM, tt.password)
			if got != tt.want {
				t.Errorf("checkPair() status = %v, want %v; output:\n%s", got, tt.want, strings.Join(lines, "\n"))
			}
			output := strings.Join(lines, "\n")
			for _, note := range tt.wantNotes {
				if !strings.Contains(output, note) {
					t.Errorf("expected output to contain %q, got:\n%s", note, output)
				}
			}
			// The private key itself must never show up in the output.
			if bytes.Contains([]byte(output), tt.keyPEM) {
				t.Errorf("output contains the private key PEM:\n%s", output)
			}
		})
	}
}

func TestCheckPairNeverLeaksKey(t *testing.T) {
	keys := generateTestKeys(t)
	der := selfSignedCert(t, keys.rsaA)
	keyPEMData := pkcs8KeyPEM(t, keys.rsaA)

	// Any distinctive chunk of the base64-encoded key body would indicate a leak.
	block, _ := pem.Decode(keyPEMData)
	fingerprint := hex.EncodeToString(block.Bytes[50:90])

	_, lines := checkPair(certPEM(der), keyPEMData, nil)
	for _, line := range lines {
		if strings.Contains(line, fingerprint) || strings.Contains(line, "PRIVATE KEY-----") {
			t.Fatalf("private key material leaked into output: %q", line)
		}
	}
}

func TestResolveCheckPaths(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		certFlag string
		keyFlag  string
		cert     string
		key      string
		wantErr  bool
	}{
		{"two files", []string{"cert.pem", "key.pem"}, "", "", "cert.pem", "key.pem", false},
		{"combined file", []string{"bundle.pem"}, "", "", "bundle.pem", "bundle.pem", false},
		{"flags", nil, "cert.pem", "key.pem", "cert.pem", "key.pem", false},
		{"no input", nil, "", "", "", "", true},
		{"only cert flag", nil, "cert.pem", "", "", "", true},
		{"only key flag", nil, "", "key.pem", "", "", true},
		{"mixed args and flags", []string{"bundle.pem"}, "cert.pem", "", "", "", true},
		{"too many args", []string{"a", "b", "c"}, "", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, err := resolveCheckPaths(tt.args, tt.certFlag, tt.keyFlag)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && (cert != tt.cert || key != tt.key) {
				t.Errorf("got (%q, %q), want (%q, %q)", cert, key, tt.cert, tt.key)
			}
		})
	}
}

func TestRunCheckFromFiles(t *testing.T) {
	keys := generateTestKeys(t)
	dir := t.TempDir()

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	bundlePath := filepath.Join(dir, "bundle.pem")
	mismatchKeyPath := filepath.Join(dir, "mismatch-key.pem")
	corruptPath := filepath.Join(dir, "corrupt.pem")
	encryptedKeyPath := filepath.Join(dir, "encrypted-key.pem")
	passwordPath := filepath.Join(dir, "password.txt")
	wrongPasswordPath := filepath.Join(dir, "wrong-password.txt")

	mustWrite(t, certPath, certPEM(selfSignedCert(t, keys.rsaA)))
	mustWrite(t, keyPath, pkcs8KeyPEM(t, keys.rsaA))
	mustWrite(t, bundlePath, append(append([]byte{}, mustRead(t, certPath)...), mustRead(t, keyPath)...))
	mustWrite(t, mismatchKeyPath, pkcs8KeyPEM(t, keys.rsaB))
	mustWrite(t, corruptPath, []byte("not PEM at all\n"))
	mustWrite(t, encryptedKeyPath, encryptPKCS8PEM(t, pkcs8KeyDER(t, keys.rsaA), "s3cret",
		oidPBKDF2, oidHMACWithSHA256, oidAES256CBC, 1000))
	mustWrite(t, passwordPath, []byte("s3cret\n")) // trailing newline must be trimmed
	mustWrite(t, wrongPasswordPath, []byte("wrong"))

	tests := []struct {
		name         string
		cert, key    string
		passwordFile string
		wantCode     int
		wantOutput   []string
	}{
		{"match", certPath, keyPath, "", checkExitMatch, []string{"match"}},
		{"combined", bundlePath, bundlePath, "", checkExitMatch, []string{"combined"}},
		{"mismatch", certPath, mismatchKeyPath, "", checkExitMismatch, []string{"do not match"}},
		{"corrupt cert", corruptPath, keyPath, "", checkExitInvalid, []string{"no PEM blocks"}},
		{"missing file", filepath.Join(dir, "nope.pem"), keyPath, "", checkExitInvalid, []string{"failed to read"}},
		{"encrypted right password", certPath, encryptedKeyPath, passwordPath, checkExitMatch, []string{"match"}},
		{"encrypted wrong password", certPath, encryptedKeyPath, wrongPasswordPath, checkExitInvalid, []string{"decrypt"}},
		{"encrypted no password", certPath, encryptedKeyPath, "", checkExitInvalid, []string{"encrypted", "password"}},
		{"missing password file", certPath, encryptedKeyPath, filepath.Join(dir, "nopass.txt"),
			checkExitInvalid, []string{"failed to read the password"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				code := runCheck(tt.cert, tt.key, tt.passwordFile)
				if code != tt.wantCode {
					t.Errorf("exit code = %d, want %d", code, tt.wantCode)
				}
			})
			for _, want := range tt.wantOutput {
				if !strings.Contains(out, want) {
					t.Errorf("output %q does not contain %q", out, want)
				}
			}
			// Never print PEM bodies or headers.
			if strings.Contains(out, "-----BEGIN") {
				t.Errorf("output contains PEM data:\n%s", out)
			}
		})
	}
}

func TestReadCheckPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pass")
	mustWrite(t, path, []byte("s3cret\n"))
	pw, err := readCheckPassword(path)
	if err != nil || string(pw) != "s3cret" {
		t.Fatalf("got %q, %v; want s3cret", pw, err)
	}
	mustWrite(t, path, []byte("line1\r\n"))
	pw, err = readCheckPassword(path)
	if err != nil || string(pw) != "line1" {
		t.Fatalf("got %q, %v; want line1", pw, err)
	}
	mustWrite(t, path, []byte(""))
	pw, err = readCheckPassword(path)
	if err != nil || len(pw) != 0 {
		t.Fatalf("got %q, %v; want empty password", pw, err)
	}
	pw, err = readCheckPassword("")
	if err != nil || pw != nil {
		t.Fatalf("got %q, %v; want nil", pw, err)
	}
	mustWrite(t, path, []byte("\xEF\xBB\xBFs3cret\r\n"))
	pw, err = readCheckPassword(path)
	if err != nil || string(pw) != "s3cret" {
		t.Fatalf("got %q, %v; want BOM-stripped s3cret", pw, err)
	}
}

// Test helpers and fixture encryption builders follow.

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	f()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func marshalECPrivateKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// encryptLegacyPEM builds a legacy PEM-encrypted block ("Proc-Type:
// 4,ENCRYPTED", AES-256-CBC with the EVP_BytesToKey/MD5 key derivation),
// as produced by "openssl rsa -aes256 -traditional".
func encryptLegacyPEM(t *testing.T, blockType string, der []byte, password string) []byte {
	t.Helper()
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	key := evpBytesToKey(md5.New, []byte(password), iv[:8], 32)
	padded := pkcs7Pad(der, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: ciphertext,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AES-256-CBC," + hex.EncodeToString(iv),
		},
	})
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// encryptPKCS8PEM builds an ENCRYPTED PRIVATE KEY block using PBES2 with
// PBKDF2 (or scrypt) and AES-CBC (or AES-GCM).
func encryptPKCS8PEM(t *testing.T, der []byte, password string,
	kdfOID, prfOID, schemeOID asn1.ObjectIdentifier, iterations int) []byte {
	t.Helper()
	passwordBytes := []byte(password)

	keySize, _ := aesKeySize(schemeOID)
	useGCM := schemeOID.Equal(oidAES128GCM) || schemeOID.Equal(oidAES192GCM) || schemeOID.Equal(oidAES256GCM)

	salt := make([]byte, 16)
	rand.Read(salt)

	var kdfAI algorithmIdentifier
	switch {
	case kdfOID.Equal(oidPBKDF2):
		params := pbkdf2Params{Salt: salt, IterationCount: iterations}
		if prfOID != nil {
			params.PRF = algorithmIdentifier{OID: prfOID}
		}
		paramsDER, err := asn1.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		kdfAI = algorithmIdentifier{OID: oidPBKDF2, Parameters: rawValue(t, paramsDER)}
	case kdfOID.Equal(oidScrypt):
		params := scryptParams{
			Salt: salt, CostParameter: 1 << 15, BlockSize: 8, Parallelization: 1,
		}
		paramsDER, err := asn1.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		kdfAI = algorithmIdentifier{OID: oidScrypt, Parameters: rawValue(t, paramsDER)}
	default:
		t.Fatalf("unsupported test KDF %s", kdfOID)
	}

	var kdfKey []byte
	var err error
	if kdfOID.Equal(oidScrypt) {
		kdfKey, err = scrypt.Key(passwordBytes, salt, 1<<15, 8, 1, keySize)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		newHash := sha1.New
		if prfOID != nil && prfOID.Equal(oidHMACWithSHA256) {
			newHash = sha256.New
		}
		kdfKey = pbkdf2DerivedKey(passwordBytes, salt, iterations, keySize, newHash)
	}

	var schemeAI algorithmIdentifier
	var encryptedData []byte
	block, err := aes.NewCipher(kdfKey)
	if err != nil {
		t.Fatal(err)
	}
	if useGCM {
		nonce := make([]byte, 12)
		rand.Read(nonce)
		// RFC 5084: aes-ICVlen DEFAULT 12.
		gcm, err := cipher.NewGCMWithTagSize(block, 12)
		if err != nil {
			t.Fatal(err)
		}
		encryptedData = gcm.Seal(nil, nonce, der, nil)
		gcmDER, err := asn1.Marshal(gcmParameters{Nonce: nonce, ICVLen: 12})
		if err != nil {
			t.Fatal(err)
		}
		schemeAI = algorithmIdentifier{OID: schemeOID, Parameters: rawValue(t, gcmDER)}
	} else {
		iv := make([]byte, 16)
		rand.Read(iv)
		padded := pkcs7Pad(der, block.BlockSize())
		encryptedData = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(encryptedData, padded)
		ivDER, err := asn1.Marshal(iv)
		if err != nil {
			t.Fatal(err)
		}
		schemeAI = algorithmIdentifier{OID: schemeOID, Parameters: rawValue(t, ivDER)}
	}

	pbes2DER, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: kdfAI,
		EncryptionScheme:  schemeAI,
	})
	if err != nil {
		t.Fatal(err)
	}
	epkiDER, err := asn1.Marshal(encryptedPrivateKeyInfo{
		EncryptionAlgorithm: algorithmIdentifier{OID: oidPBES2, Parameters: rawValue(t, pbes2DER)},
		EncryptedData:       encryptedData,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: epkiDER})
}

func rawValue(t *testing.T, der []byte) asn1.RawValue {
	t.Helper()
	var rv asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &rv); err != nil {
		t.Fatal(err)
	} else if len(rest) != 0 {
		t.Fatal("trailing data in test ASN.1")
	}
	return rv
}
