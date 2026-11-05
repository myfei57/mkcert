// Copyright 2022 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// auditTestHosts exercises every SAN type.
var auditTestHosts = []string{
	"example.com",
	"*.example.org",
	"127.0.0.1",
	"::1",
	"user@example.com",
	"https://example.net/path",
}

func auditTestCert(t *testing.T, serial int64, hosts []string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "audit test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(2, 3, 0),
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			tpl.EmailAddresses = append(tpl.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			tpl.URIs = append(tpl.URIs, uriName)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}
	return c
}

func TestNewAuditRecord(t *testing.T) {
	c := auditTestCert(t, 42, auditTestHosts)
	rec := newAuditRecord(c)

	if rec.SerialNumber != "2a" {
		t.Errorf("serial number = %q, want %q", rec.SerialNumber, "2a")
	}
	if !rec.NotBefore.Equal(c.NotBefore.UTC()) {
		t.Errorf("not_before = %v, want %v", rec.NotBefore, c.NotBefore.UTC())
	}
	if !rec.NotAfter.Equal(c.NotAfter.UTC()) {
		t.Errorf("not_after = %v, want %v", rec.NotAfter, c.NotAfter.UTC())
	}
	if got, want := rec.SANs.DNS, []string{"example.com", "*.example.org"}; !equalStrings(got, want) {
		t.Errorf("dns SANs = %v, want %v", got, want)
	}
	if got, want := rec.SANs.IP, []string{"127.0.0.1", "::1"}; !equalStrings(got, want) {
		t.Errorf("ip SANs = %v, want %v", got, want)
	}
	if got, want := rec.SANs.Email, []string{"user@example.com"}; !equalStrings(got, want) {
		t.Errorf("email SANs = %v, want %v", got, want)
	}
	if got, want := rec.SANs.URI, []string{"https://example.net/path"}; !equalStrings(got, want) {
		t.Errorf("uri SANs = %v, want %v", got, want)
	}

	sum := sha256.Sum256(c.Raw)
	if want := colonHex(sum[:]); rec.SHA256 != want {
		t.Errorf("fingerprint = %q, want %q", rec.SHA256, want)
	}
	if !strings.Contains(rec.SHA256, ":") || strings.ToUpper(rec.SHA256) != rec.SHA256 {
		t.Errorf("fingerprint %q is not uppercase colon-separated hex", rec.SHA256)
	}

	// The serialized record must use a fixed, non-sensitive field set and
	// never carry key, CSR or password material.
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("failed to marshal record: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		t.Fatalf("record is not valid JSON: %v", err)
	}
	wantFields := map[string]bool{
		"serial_number": true, "not_before": true, "not_after": true,
		"sans": true, "sha256_fingerprint": true,
	}
	if len(fields) != len(wantFields) {
		t.Errorf("record has %d fields, want %d: %s", len(fields), len(wantFields), line)
	}
	for name := range fields {
		if !wantFields[name] {
			t.Errorf("unexpected audit field %q", name)
		}
	}
	for _, secret := range []string{"PRIVATE KEY", "CERTIFICATE REQUEST", "changeit"} {
		if bytes.Contains(line, []byte(secret)) {
			t.Errorf("audit record must not contain %q: %s", secret, line)
		}
	}
	if bytes.Count(line, []byte("\n")) != 0 {
		t.Errorf("a marshaled record must fit on a single line: %s", line)
	}
}

func TestAuditRecordEmptySANs(t *testing.T) {
	// Every SAN slice must render as [], not null.
	c := auditTestCert(t, 7, nil)
	line, err := json.Marshal(newAuditRecord(c))
	if err != nil {
		t.Fatalf("failed to marshal record: %v", err)
	}
	var rec auditRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		t.Fatalf("record is not valid JSON: %v", err)
	}
	for name, sans := range map[string][]string{
		"dns": rec.SANs.DNS, "ip": rec.SANs.IP,
		"email": rec.SANs.Email, "uri": rec.SANs.URI,
	} {
		if sans == nil || len(sans) != 0 {
			t.Errorf("%s SANs = %v, want non-nil empty slice", name, sans)
		}
	}
}

func TestAuditDisabledIsNoop(t *testing.T) {
	// With no log path configured nothing must happen, even with a nil
	// certificate: this is the "output unchanged" guarantee.
	(&mkcert{}).auditCertificate(nil)
}

func readAuditLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(data) == 0 {
		return nil
	}
	if data[len(data)-1] != '\n' {
		t.Fatalf("audit log does not end with a newline (torn record?)")
	}
	lines := bytes.Split(data, []byte("\n"))
	return lines[:len(lines)-1] // trailing empty element after the final newline
}

func TestAuditLogAppendAndDuplicateIssuance(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	l := newAuditLogger(logPath)

	// "Re-issuing" the same names produces a fresh serial each time; both
	// complete records must end up in the log, one per line.
	first := auditTestCert(t, 100, auditTestHosts)
	second := auditTestCert(t, 101, auditTestHosts)
	if err := l.logCertificate(first); err != nil {
		t.Fatalf("first append failed: %v", err)
	}
	if err := l.logCertificate(second); err != nil {
		t.Fatalf("second (duplicate) append failed: %v", err)
	}

	lines := readAuditLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("audit log has %d lines, want 2", len(lines))
	}

	var records [2]auditRecord
	serials := map[string]bool{}
	fingerprints := map[string]bool{}
	for i, line := range lines {
		if err := json.Unmarshal(line, &records[i]); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if serials[records[i].SerialNumber] {
			t.Errorf("serial %q recorded twice", records[i].SerialNumber)
		}
		serials[records[i].SerialNumber] = true
		fingerprints[records[i].SHA256] = true
	}
	if records[0].SerialNumber != "64" || records[1].SerialNumber != "65" {
		t.Errorf("serials = %q, %q; want 64, 65", records[0].SerialNumber, records[1].SerialNumber)
	}
	if len(serials) != 2 || len(fingerprints) != 2 {
		t.Errorf("expected two distinct serials and fingerprints, got %v / %v", serials, fingerprints)
	}
	if records[0].SHA256 != colonHex(sha256Sum(first.Raw)) {
		t.Errorf("first fingerprint mismatch")
	}
	if records[1].SHA256 != colonHex(sha256Sum(second.Raw)) {
		t.Errorf("second fingerprint mismatch")
	}

	// The lock must not be left behind.
	if _, err := os.Stat(logPath + ".lock"); !os.IsNotExist(err) {
		t.Errorf("stale lock directory left behind: %v", err)
	}
}

func TestAuditLogConcurrentIssuance(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	l := newAuditLogger(logPath)

	const n = 30
	var wg sync.WaitGroup
	errs := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			c := auditTestCert(t, int64(1000+i), auditTestHosts)
			errs <- l.logCertificate(c)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append failed: %v", err)
		}
	}

	lines := readAuditLines(t, logPath)
	if len(lines) != n {
		t.Fatalf("audit log has %d complete lines, want %d", len(lines), n)
	}
	seen := map[string]bool{}
	for i, line := range lines {
		var rec auditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("line %d is not a complete JSON record: %v", i, err)
		}
		if seen[rec.SHA256] {
			t.Errorf("fingerprint %q recorded twice", rec.SHA256)
		}
		seen[rec.SHA256] = true
	}
}

// failingAuditFile wraps a real log file and simulates a partial write.
type failingAuditFile struct {
	auditFile
	written, limit int
}

func (f *failingAuditFile) Write(p []byte) (int, error) {
	room := f.limit - f.written
	if room <= 0 {
		return 0, errors.New("simulated write failure")
	}
	if len(p) > room {
		n, _ := f.auditFile.Write(p[:room])
		f.written += n
		return n, errors.New("simulated partial write")
	}
	n, err := f.auditFile.Write(p)
	f.written += n
	return n, err
}

func TestAuditLogPartialWriteFailure(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	first := auditTestCert(t, 200, auditTestHosts)
	second := auditTestCert(t, 201, auditTestHosts)
	wantFirst, err := json.Marshal(newAuditRecord(first))
	if err != nil {
		t.Fatal(err)
	}
	wantFirst = append(wantFirst, '\n')

	l := newAuditLogger(logPath)
	var opens int
	l.open = func(path string) (auditFile, error) {
		opens++
		f, err := openAuditFile(path)
		if err != nil {
			return nil, err
		}
		if opens == 2 {
			// The second issuance gets only a handful of bytes out before
			// failing, leaving a torn fragment unless rollback works.
			return &failingAuditFile{auditFile: f, limit: 7}, nil
		}
		return f, nil
	}

	if err := l.logCertificate(first); err != nil {
		t.Fatalf("first append failed: %v", err)
	}
	if err := l.logCertificate(second); err == nil {
		t.Fatal("partial write must be reported as an error")
	} else if !strings.Contains(err.Error(), "audit") {
		t.Fatalf("error should identify the audit log: %v", err)
	}

	// The torn fragment must have been rolled back: the log contains exactly
	// the first, complete record, byte for byte.
	got, err := ioutil.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if !bytes.Equal(got, wantFirst) {
		t.Errorf("audit log corrupted by partial write:\ngot:  %q\nwant: %q", got, wantFirst)
	}
	lines := readAuditLines(t, logPath)
	if len(lines) != 1 {
		t.Errorf("audit log has %d lines after rollback, want 1", len(lines))
	}
}

func TestAuditLogOpenFailure(t *testing.T) {
	// A directory can't be opened as a regular file for writing.
	dir := t.TempDir()
	l := newAuditLogger(dir)
	c := auditTestCert(t, 300, auditTestHosts)
	if err := l.logCertificate(c); err == nil {
		t.Fatal("expected an error when the log path cannot be opened")
	}
	// No useful record was written, and no lock is left behind.
	if _, err := os.Stat(dir + ".lock"); !os.IsNotExist(err) {
		t.Errorf("unexpected lock state: %v", err)
	}
}

func TestAuditLockTimeout(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	lockPath := logPath + ".lock"
	if err := os.Mkdir(lockPath, 0700); err != nil {
		t.Fatal(err)
	}

	l := newAuditLogger(logPath)
	l.lockTimeout = 100 * time.Millisecond
	c := auditTestCert(t, 400, auditTestHosts)

	start := time.Now()
	err := l.logCertificate(c)
	if err == nil {
		t.Fatal("expected a timeout error while the lock is held")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error should mention the timeout: %v", err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Errorf("returned before the timeout elapsed")
	}

	// A lock we don't own must not be removed.
	if _, err := os.Stat(lockPath); err != nil {
		t.Errorf("the contended lock was wrongly removed: %v", err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("no log file should have been created, got %v", err)
	}
}

func TestAuditLockStaleTakeover(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	lockPath := logPath + ".lock"
	if err := os.Mkdir(lockPath, 0700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * auditLockStaleAfter)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}

	l := newAuditLogger(logPath)
	l.lockTimeout = 5 * time.Second
	c := auditTestCert(t, 500, auditTestHosts)
	if err := l.logCertificate(c); err != nil {
		t.Fatalf("stale lock should be taken over, got: %v", err)
	}

	if lines := readAuditLines(t, logPath); len(lines) != 1 {
		t.Errorf("audit log has %d lines after stale-lock takeover, want 1", len(lines))
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("stale lock was not cleaned up: %v", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
