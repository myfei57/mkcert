// Copyright 2022 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Exit codes returned by "mkcert -check". They are kept distinct on purpose
// so that scripts can tell a mismatch apart from an unusable input.
const (
	checkExitMatch       = 0 // the certificate and the private key match
	checkExitMismatch    = 1 // both parsed fine, but the public keys differ
	checkExitInvalid     = 2 // the input can't be read or parsed (incl. wrong password)
	checkExitUnsupported = 3 // the key type is recognized but not supported
)

type checkStatus int

const (
	statusMatch checkStatus = iota
	statusMismatch
	statusInvalid
	statusUnsupported
)

func (s checkStatus) exitCode() int {
	switch s {
	case statusMatch:
		return checkExitMatch
	case statusMismatch:
		return checkExitMismatch
	case statusUnsupported:
		return checkExitUnsupported
	default:
		return checkExitInvalid
	}
}

// runCheck implements "mkcert -check". It is strictly read-only: it reads the
// two files, compares the public keys derived from them and never writes
// anything, never loads the CA and never prints the private key.
func runCheck(certPath, keyPath, passwordFile string) int {
	password, err := readCheckPassword(passwordFile)
	if err != nil {
		fmtErr("failed to read the password: %s", err)
		return checkExitInvalid
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		fmtErr("failed to read the certificate %q: %s", certPath, err)
		return checkExitInvalid
	}
	var keyPEM []byte
	if keyPath == certPath {
		keyPEM = certPEM // combined certificate and private key file
	} else {
		keyPEM, err = os.ReadFile(keyPath)
		if err != nil {
			fmtErr("failed to read the private key %q: %s", keyPath, err)
			return checkExitInvalid
		}
	}

	if keyPath == certPath {
		fmtNote("Reading the combined certificate and private key file %q", certPath)
	} else {
		fmtNote("Reading certificate %q and private key %q", certPath, keyPath)
	}

	status, lines := checkPair(certPEM, keyPEM, password)
	for _, line := range lines {
		fmt.Println(line)
	}
	return status.exitCode()
}

func fmtErr(format string, args ...interface{}) {
	fmt.Printf("ERROR: "+format+"\n", args...)
}

func fmtNote(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

// checkPair derives the public key from the first certificate and the first
// private key found in the given PEM data, marshals both to the standard
// PKIX/SPKI encoding and compares them. It returns machine-readable status
// plus human-readable result lines, which never contain key material.
func checkPair(certPEMData, keyPEMData, password []byte) (checkStatus, []string) {
	var notes []string

	certBlocks, err := decodePEMBlocks(certPEMData)
	if err != nil {
		return statusInvalid, []string{fmtErrf("failed to parse the certificate PEM: %s", err)}
	}
	cert, certCount, err := selectCertificate(certBlocks)
	if err != nil {
		return statusInvalid, []string{fmtErrf("%s", err)}
	}
	if certCount > 1 {
		notes = append(notes, fmt.Sprintf("Found %d certificates; using the first one and ignoring the rest.", certCount))
	}

	keyBlocks, err := decodePEMBlocks(keyPEMData)
	if err != nil {
		return statusInvalid, []string{fmtErrf("failed to parse the private key PEM: %s", err)}
	}
	key, keyCount, err := selectPrivateKey(keyBlocks, password)
	if err != nil {
		var u unsupportedKeyError
		if errors.As(err, &u) {
			return statusUnsupported, []string{fmtErrf("unsupported private key type: %s", u)}
		}
		return statusInvalid, []string{fmtErrf("%s", err)}
	}
	if keyCount > 1 {
		notes = append(notes, fmt.Sprintf("Found %d private keys; using the first one and ignoring the rest.", keyCount))
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return statusUnsupported, append(notes, fmtErrf("unsupported private key type: %T", key))
	}
	certPub := cert.PublicKey
	keyPub := signer.Public()

	certType := publicKeyName(certPub)
	keyType := publicKeyName(keyPub)
	if certType == "" {
		return statusUnsupported, append(notes, fmtErrf("the certificate uses an unsupported key type: %T", certPub))
	}
	if keyType == "" {
		return statusUnsupported, append(notes, fmtErrf("the private key uses an unsupported key type: %T", keyPub))
	}

	certSPKI, err := x509.MarshalPKIXPublicKey(certPub)
	if err != nil {
		return statusUnsupported, append(notes, fmtErrf("failed to encode the certificate public key: %s", err))
	}
	keySPKI, err := x509.MarshalPKIXPublicKey(keyPub)
	if err != nil {
		return statusUnsupported, append(notes, fmtErrf("failed to encode the private key public key: %s", err))
	}

	if !bytes.Equal(certSPKI, keySPKI) {
		return statusMismatch, append(notes,
			fmtErrf("the certificate and the private key do not match ❌ (certificate key: %s, private key: %s)", certType, keyType))
	}

	return statusMatch, append(notes,
		fmt.Sprintf("The certificate and the private key match ✅ (%s)", certType))
}

func fmtErrf(format string, args ...interface{}) string {
	return "ERROR: " + fmt.Sprintf(format, args...)
}

// resolveCheckPaths turns the -check arguments into certificate and key
// paths. A single argument denotes a combined PEM file holding both the
// certificate and the private key; two arguments denote the two files.
func resolveCheckPaths(args []string, certFileFlag, keyFileFlag string) (string, string, error) {
	if len(args) > 2 {
		return "", "", errors.New("-check takes at most two arguments: CERT [KEY]")
	}
	flagsSet := certFileFlag != "" || keyFileFlag != ""
	if len(args) > 0 && flagsSet {
		return "", "", errors.New("can't combine file arguments with -cert-file/-key-file")
	}
	switch len(args) {
	case 2:
		return args[0], args[1], nil
	case 1:
		return args[0], args[0], nil
	default:
		if certFileFlag == "" || keyFileFlag == "" {
			return "", "", errors.New("missing CERT and KEY files: use \"mkcert -check CERT [KEY]\" or -cert-file and -key-file")
		}
		return certFileFlag, keyFileFlag, nil
	}
}

// readCheckPassword reads the key password from passwordFile. An empty path
// means no password was provided, "-" means standard input.
func readCheckPassword(passwordFile string) ([]byte, error) {
	if passwordFile == "" {
		return nil, nil
	}
	var data []byte
	var err error
	if passwordFile == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(passwordFile)
	}
	if err != nil {
		return nil, err
	}
	// Tolerate a UTF-8 BOM, which Notepad and some shells prepend.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	// Strip at most one trailing line ending, so "echo password > file" and
	// interactive input both work while an empty file yields an empty password.
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	return data, nil
}

// decodePEMBlocks decodes every PEM block in data and rejects trailing
// non-PEM content so that truncated or corrupted files don't pass silently.
func decodePEMBlocks(data []byte) ([]*pem.Block, error) {
	var blocks []*pem.Block
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		return nil, errors.New("no PEM blocks found (file is empty, corrupted or not in PEM format)")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("found data that is not part of any PEM block (file is corrupted or concatenated incorrectly)")
	}
	return blocks, nil
}

func selectCertificate(blocks []*pem.Block) (*x509.Certificate, int, error) {
	var certDER []byte
	count := 0
	for _, block := range blocks {
		if block.Type != "CERTIFICATE" {
			continue
		}
		if count == 0 {
			certDER = block.Bytes
		}
		count++
	}
	if count == 0 {
		return nil, 0, errors.New("no CERTIFICATE PEM block found")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse the certificate: %w", err)
	}
	return cert, count, nil
}

type unsupportedKeyError string

func (e unsupportedKeyError) Error() string { return string(e) }

// selectPrivateKey finds and parses the first private key PEM block. It
// supports PKCS #8 ("PRIVATE KEY", including the "ENCRYPTED PRIVATE KEY"
// variant), PKCS #1 ("RSA PRIVATE KEY") and SEC 1 ("EC PRIVATE KEY",
// including the legacy PEM-level encryption).
func selectPrivateKey(blocks []*pem.Block, password []byte) (crypto.PrivateKey, int, error) {
	var keyBlock *pem.Block
	count := 0
	for _, block := range blocks {
		switch block.Type {
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			if count == 0 {
				keyBlock = block
			}
			count++
		case "DSA PRIVATE KEY":
			return nil, 0, unsupportedKeyError("DSA (\"DSA PRIVATE KEY\")")
		}
	}
	if count == 0 {
		return nil, 0, errors.New("no private key PEM block found (expected PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY or ENCRYPTED PRIVATE KEY)")
	}

	var key crypto.PrivateKey
	var err error
	switch keyBlock.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse the PKCS #8 private key: %w", err)
		}
	case "RSA PRIVATE KEY":
		der, err := decryptLegacyPEMKey(keyBlock, password)
		if err != nil {
			return nil, 0, err
		}
		key, err = x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse the RSA private key: %w", err)
		}
	case "EC PRIVATE KEY":
		der, err := decryptLegacyPEMKey(keyBlock, password)
		if err != nil {
			return nil, 0, err
		}
		key, err = x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse the EC private key: %w", err)
		}
	case "ENCRYPTED PRIVATE KEY":
		if password == nil {
			return nil, 0, errors.New("the private key is encrypted, provide the password with -password-file (\"-\" reads it from standard input)")
		}
		der, err := decryptPKCS8PrivateKey(keyBlock.Bytes, password)
		if err != nil {
			return nil, 0, err
		}
		key, err = x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, 0, errors.New("failed to decrypt the private key (wrong password or unsupported encryption)")
		}
	}
	return key, count, nil
}

// isLegacyEncrypted reports whether a PKCS #1/SEC 1 block uses the legacy
// PEM-level encryption ("Proc-Type: 4,ENCRYPTED").
func isLegacyEncrypted(block *pem.Block) bool {
	return block.Headers["Proc-Type"] == "4,ENCRYPTED" || block.Headers["DEK-Info"] != ""
}

func decryptLegacyPEMKey(block *pem.Block, password []byte) ([]byte, error) {
	if !isLegacyEncrypted(block) {
		return block.Bytes, nil
	}
	if password == nil {
		return nil, errors.New("the private key is encrypted, provide the password with -password-file (\"-\" reads it from standard input)")
	}
	dek := block.Headers["DEK-Info"]
	if block.Headers["Proc-Type"] != "4,ENCRYPTED" || dek == "" {
		return nil, errors.New("malformed encrypted PEM block: missing Proc-Type/DEK-Info headers")
	}
	parts := strings.SplitN(dek, ",", 2)
	if len(parts) != 2 {
		return nil, errors.New("malformed DEK-Info header")
	}
	alg := strings.ToUpper(strings.TrimSpace(parts[0]))
	iv, err := hex.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("malformed DEK-Info initialization vector: %w", err)
	}
	spec, ok := legacyCipherSpecs[alg]
	if !ok {
		return nil, fmt.Errorf("unsupported legacy PEM encryption algorithm %q", alg)
	}
	if len(iv) < 8 {
		return nil, errors.New("malformed DEK-Info initialization vector: too short")
	}
	salt := iv[:8]

	// The digest used by EVP_BytesToKey is not recorded in the file. MD5 is
	// the historical default; SHA-256/SHA-1 are tried as a fallback.
	var lastErr error
	for _, newHash := range spec.hashes {
		key := evpBytesToKey(newHash, password, salt, spec.keySize)
		plaintext, err := cbcOpen(spec.newCipher, key, block.Bytes, iv)
		if err != nil {
			lastErr = err
			continue
		}
		return plaintext, nil
	}
	return nil, fmt.Errorf("failed to decrypt the private key (wrong password?): %w", lastErr)
}

type legacyCipherSpec struct {
	keySize   int
	newCipher func(key []byte) (cipher.Block, error)
	hashes    []func() hash.Hash
}

var legacyCipherSpecs = map[string]legacyCipherSpec{
	"AES-128-CBC":  {16, aes.NewCipher, []func() hash.Hash{md5.New, sha256.New, sha1.New}},
	"AES-192-CBC":  {24, aes.NewCipher, []func() hash.Hash{md5.New, sha256.New, sha1.New}},
	"AES-256-CBC":  {32, aes.NewCipher, []func() hash.Hash{md5.New, sha256.New, sha1.New}},
	"DES-CBC":      {8, des.NewCipher, []func() hash.Hash{md5.New, sha256.New, sha1.New}},
	"DES-EDE3-CBC": {24, des.NewTripleDESCipher, []func() hash.Hash{md5.New, sha256.New, sha1.New}},
}

// evpBytesToKey implements OpenSSL's EVP_BytesToKey (RFC 5246-style
// concatenated hashing), used by the legacy PEM encryption.
func evpBytesToKey(newHash func() hash.Hash, password, salt []byte, keySize int) []byte {
	var key, prev []byte
	for len(key) < keySize {
		h := newHash()
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	return key[:keySize]
}

func cbcOpen(newCipher func(key []byte) (cipher.Block, error), key, ciphertext, iv []byte) ([]byte, error) {
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(iv) != bs || len(ciphertext)%bs != 0 || len(ciphertext) == 0 {
		return nil, errors.New("invalid encrypted data length")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext, bs)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data)%blockSize != 0 || len(data) == 0 {
		return nil, errors.New("invalid padded data length")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, errors.New("invalid padding (wrong password?)")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("invalid padding (wrong password?)")
		}
	}
	return data[:len(data)-pad], nil
}

// PKCS #8 encrypted key structures (RFC 5208, RFC 2898 and RFC 8410).
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidAES192GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
	oidAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

// algorithmIdentifier is a local copy of pkix.AlgorithmIdentifier, whose
// OID field name differs across Go releases (OID before Go 1.25,
// Algorithm afterwards).
type algorithmIdentifier struct {
	OID        asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm algorithmIdentifier
	EncryptedData       []byte
}

type pbes2Params struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                 `asn1:"optional"`
	PRF            algorithmIdentifier `asn1:"optional"`
}

type scryptParams struct {
	Salt            []byte
	CostParameter   int
	BlockSize       int
	Parallelization int
	KeyLength       int `asn1:"optional"`
}

type gcmParameters struct {
	Nonce  []byte
	ICVLen int `asn1:"default:12"`
}

func decryptPKCS8PrivateKey(der, password []byte) ([]byte, error) {
	var epki encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &epki); err != nil {
		return nil, fmt.Errorf("malformed ENCRYPTED PRIVATE KEY: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("malformed ENCRYPTED PRIVATE KEY: trailing data")
	}
	if !epki.EncryptionAlgorithm.OID.Equal(oidPBES2) {
		return nil, fmt.Errorf("unsupported private key encryption algorithm %s (only PBES2 is supported)", epki.EncryptionAlgorithm.OID)
	}

	var params pbes2Params
	if rest, err := asn1.Unmarshal(epki.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("malformed PBES2 parameters: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("malformed PBES2 parameters: trailing data")
	}

	keySize, ok := aesKeySize(params.EncryptionScheme.OID)
	if !ok {
		return nil, fmt.Errorf("unsupported PBES2 encryption algorithm %s", params.EncryptionScheme.OID)
	}

	var kdfKey []byte
	switch {
	case params.KeyDerivationFunc.OID.Equal(oidPBKDF2):
		var kdf pbkdf2Params
		if rest, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil {
			return nil, fmt.Errorf("malformed PBKDF2 parameters: %w", err)
		} else if len(rest) != 0 {
			return nil, errors.New("malformed PBKDF2 parameters: trailing data")
		}
		newHash, err := pbkdf2Hash(oidHMACWithSHA1, kdf.PRF.OID)
		if err != nil {
			return nil, err
		}
		if kdf.IterationCount <= 0 {
			return nil, errors.New("invalid PBKDF2 iteration count")
		}
		kdfKey = pbkdf2DerivedKey(password, kdf.Salt, kdf.IterationCount, keySize, newHash)
	case params.KeyDerivationFunc.OID.Equal(oidScrypt):
		var kdf scryptParams
		if rest, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil {
			return nil, fmt.Errorf("malformed scrypt parameters: %w", err)
		} else if len(rest) != 0 {
			return nil, errors.New("malformed scrypt parameters: trailing data")
		}
		var err error
		kdfKey, err = scrypt.Key(password, kdf.Salt, kdf.CostParameter, kdf.BlockSize, kdf.Parallelization, keySize)
		if err != nil {
			return nil, fmt.Errorf("invalid scrypt parameters: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported PBES2 key derivation function %s", params.KeyDerivationFunc.OID)
	}

	oid := params.EncryptionScheme.OID
	switch {
	case oid.Equal(oidAES128CBC), oid.Equal(oidAES192CBC), oid.Equal(oidAES256CBC):
		var iv []byte
		if rest, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
			return nil, fmt.Errorf("malformed AES-CBC parameters: %w", err)
		} else if len(rest) != 0 {
			return nil, errors.New("malformed AES-CBC parameters: trailing data")
		}
		plaintext, err := cbcOpen(aes.NewCipher, kdfKey, epki.EncryptedData, iv)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt the private key (wrong password?): %w", err)
		}
		return plaintext, nil
	case oid.Equal(oidAES128GCM), oid.Equal(oidAES192GCM), oid.Equal(oidAES256GCM):
		var gp gcmParameters
		if rest, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &gp); err != nil {
			return nil, fmt.Errorf("malformed AES-GCM parameters: %w", err)
		} else if len(rest) != 0 {
			return nil, errors.New("malformed AES-GCM parameters: trailing data")
		}
		if gp.ICVLen == 0 {
			gp.ICVLen = 12
		}
		block, err := aes.NewCipher(kdfKey)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCMWithTagSize(block, gp.ICVLen)
		if err != nil {
			return nil, err
		}
		plaintext, err := gcm.Open(nil, gp.Nonce, epki.EncryptedData, nil)
		if err != nil {
			return nil, errors.New("failed to decrypt the private key (wrong password?)")
		}
		return plaintext, nil
	default:
		return nil, fmt.Errorf("unsupported PBES2 encryption algorithm %s", oid)
	}
}

func aesKeySize(oid asn1.ObjectIdentifier) (int, bool) {
	switch {
	case oid.Equal(oidAES128CBC), oid.Equal(oidAES128GCM):
		return 16, true
	case oid.Equal(oidAES192CBC), oid.Equal(oidAES192GCM):
		return 24, true
	case oid.Equal(oidAES256CBC), oid.Equal(oidAES256GCM):
		return 32, true
	default:
		return 0, false
	}
}

func pbkdf2Hash(defaultOID, prfOID asn1.ObjectIdentifier) (func() hash.Hash, error) {
	if len(prfOID) == 0 || prfOID.Equal(defaultOID) {
		return sha1.New, nil
	}
	switch {
	case prfOID.Equal(oidHMACWithSHA1):
		return sha1.New, nil
	case prfOID.Equal(oidHMACWithSHA224):
		return sha256.New224, nil
	case prfOID.Equal(oidHMACWithSHA256):
		return sha256.New, nil
	case prfOID.Equal(oidHMACWithSHA384):
		return sha512.New384, nil
	case prfOID.Equal(oidHMACWithSHA512):
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported PBKDF2 pseudorandom function %s", prfOID)
	}
}

// pbkdf2DerivedKey implements PBKDF2 (RFC 8018) with HMAC as PRF.
func pbkdf2DerivedKey(password, salt []byte, iterations, keySize int, newHash func() hash.Hash) []byte {
	prf := hmac.New(newHash, password)
	hashLen := prf.Size()
	numBlocks := (keySize + hashLen - 1) / hashLen

	var dk []byte
	var blockIndex [4]byte
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(blockIndex[:], uint32(block))
		prf.Write(blockIndex[:])
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for n := 1; n < iterations; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keySize]
}

func publicKeyName(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", k.N.BitLen())
	case *ecdsa.PublicKey:
		if k.Curve == nil {
			return "ECDSA"
		}
		if name := k.Params().Name; name != "" {
			return "ECDSA " + name
		}
		return "ECDSA (unknown curve)"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return ""
	}
}
