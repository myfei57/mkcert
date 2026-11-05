// Copyright 2022 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// Optional local audit log for issued certificates.
//
// Every time a certificate is successfully written to disk, a single JSON
// object is appended (JSON Lines format) to the file pointed to by the
// -audit-log flag. The record only contains public certificate metadata:
// the serial number, the issuance and expiration times, the SAN types and
// values, and the SHA-256 fingerprint of the certificate.
//
// Private keys, certificate signing requests and key passwords are never
// logged: the record is built exclusively from the parsed, issued
// certificate.
//
// Records are appended under a cross-process lock in a single write so that
// concurrent issuances never interleave or tear a line. If an audit entry
// cannot be written after the certificate itself has been saved, the
// certificate is left in place and mkcert reports the condition explicitly,
// exiting with auditFailureExitCode. When no log path is configured, this
// file is inert and mkcert behaves exactly as it otherwise would.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// auditFailureExitCode distinguishes "the certificate was generated and
// saved, but the audit log entry could not be written" from ordinary errors,
// which use the default exit status of 1.
const auditFailureExitCode = 2

// auditRecord is the JSON object appended to the audit log for each issued
// certificate. It deliberately contains no secrets: there is no field for a
// private key, CSR material, or a key password.
type auditRecord struct {
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SANs         auditSANs `json:"sans"`
	SHA256       string    `json:"sha256_fingerprint"`
}

// auditSANs groups the subjectAltName entries by type. Every slice is always
// non-nil, so absent types are rendered as [] rather than null.
type auditSANs struct {
	DNS   []string `json:"dns"`
	IP    []string `json:"ip"`
	Email []string `json:"email"`
	URI   []string `json:"uri"`
}

// auditFile is the subset of *os.File used by the audit logger. It exists so
// tests can inject partial write failures.
type auditFile interface {
	io.Writer
	io.Closer
	Truncate(size int64) error
	Sync() error
}

// auditLogger serializes JSONL records into a single file. The mutex keeps
// goroutines within one process from racing; the on-disk lock (see append)
// keeps separate mkcert processes from racing.
type auditLogger struct {
	path string

	mu sync.Mutex

	// lockTimeout bounds how long a process waits for the on-disk lock.
	lockTimeout time.Duration

	// open opens the log file for appending. Overridable in tests.
	open func(path string) (auditFile, error)
}

func newAuditLogger(path string) *auditLogger {
	return &auditLogger{
		path:        path,
		lockTimeout: 10 * time.Second,
		open:        openAuditFile,
	}
}

func openAuditFile(path string) (auditFile, error) {
	// O_APPEND is intentionally not used: the on-disk lock guarantees no
	// other writer, and a plain writable handle can be shortened with
	// Truncate on every platform (Windows restricts that for handles
	// opened for append-only access). Seek to the current end explicitly.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// auditCertificate is the hook called after a certificate has been saved. It
// is a no-op unless an audit log path was configured.
func (m *mkcert) auditCertificate(c *x509.Certificate) {
	if m.auditLog == "" {
		return
	}
	if err := newAuditLogger(m.auditLog).logCertificate(c); err != nil {
		log.Printf("ERROR: the certificate was generated and saved, but the audit log entry could not be written to %q: %s", m.auditLog, err)
		os.Exit(auditFailureExitCode)
	}
}

// logCertificate appends one complete JSONL record describing c.
func (l *auditLogger) logCertificate(c *x509.Certificate) error {
	line, err := json.Marshal(newAuditRecord(c))
	if err != nil {
		return fmt.Errorf("failed to encode audit record: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	return l.append(line)
}

func newAuditRecord(c *x509.Certificate) auditRecord {
	sans := auditSANs{
		DNS:   append([]string{}, c.DNSNames...),
		IP:    []string{},
		Email: append([]string{}, c.EmailAddresses...),
		URI:   []string{},
	}
	for _, ip := range c.IPAddresses {
		sans.IP = append(sans.IP, ip.String())
	}
	for _, u := range c.URIs {
		sans.URI = append(sans.URI, u.String())
	}

	sum := sha256.Sum256(c.Raw)
	return auditRecord{
		SerialNumber: fmt.Sprintf("%x", c.SerialNumber),
		NotBefore:    c.NotBefore.UTC(),
		NotAfter:     c.NotAfter.UTC(),
		SANs:         sans,
		SHA256:       colonHex(sum[:]),
	}
}

// colonHex renders b as uppercase, colon-separated hexadecimal, the
// conventional OpenSSL fingerprint format (e.g. "AB:CD:..").
func colonHex(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, len(b)*3-1)
	for i := range b {
		out[i*3] = digits[b[i]>>4]
		out[i*3+1] = digits[b[i]&0x0f]
		if i+1 < len(b) {
			out[i*3+2] = ':'
		}
	}
	return string(out)
}

// append writes line to the log file as a single, complete record. It takes
// a cross-process lock, remembers the file size, and rolls back to that size
// if the write is partial, so the JSONL file can never end up with a torn
// line.
func (l *auditLogger) append(line []byte) error {
	lockPath := l.path + ".lock"
	if err := acquireAuditLock(lockPath, l.lockTimeout); err != nil {
		return err
	}
	defer os.Remove(lockPath)

	// Size of the log before this record, used to undo a partial write.
	size := int64(0)
	if fi, err := os.Stat(l.path); err == nil {
		size = fi.Size()
	}

	f, err := l.open(l.path)
	if err != nil {
		return fmt.Errorf("failed to open audit log %q: %w", l.path, err)
	}
	defer f.Close()

	n, werr := f.Write(line)
	switch {
	case werr != nil && n > 0:
		f.Truncate(size) // best effort: drop the torn tail
		return fmt.Errorf("failed to append audit record to %q: %w", l.path, werr)
	case werr != nil:
		return fmt.Errorf("failed to append audit record to %q: %w", l.path, werr)
	case n != len(line):
		f.Truncate(size) // best effort: drop the short tail
		return fmt.Errorf("failed to append audit record to %q: short write (%d of %d bytes)", l.path, n, len(line))
	}

	if err := f.Sync(); err != nil {
		// The full record already reached the kernel write, so it is left in
		// place; only the durability guarantee could not be made.
		return fmt.Errorf("failed to flush audit log %q: %w", l.path, err)
	}
	return nil
}

// auditLockStaleAfter is how long an on-disk lock must be held before it is
// presumed abandoned by a crashed process and taken over.
const auditLockStaleAfter = 30 * time.Second

// acquireAuditLock takes an advisory, cross-process lock. Creating a
// directory is atomic on every supported platform (unlike flock, which is
// not available on Windows without external dependencies), so this works
// identically on Unix and Windows.
func acquireAuditLock(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	delay := 5 * time.Millisecond
	for {
		err := os.Mkdir(path, 0700)
		if err == nil {
			return nil
		}
		if !os.IsExist(err) {
			return fmt.Errorf("failed to acquire audit log lock %q: %w", path, err)
		}

		// Take over a lock that has been held far longer than any healthy
		// append (milliseconds) could need: its holder almost certainly died.
		if fi, statErr := os.Stat(path); statErr == nil && time.Since(fi.ModTime()) > auditLockStaleAfter {
			if err := os.Remove(path); err == nil {
				continue
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for the audit log lock %q", timeout, path)
		}
		time.Sleep(delay)
		if delay < 100*time.Millisecond {
			delay *= 2
		}
	}
}
