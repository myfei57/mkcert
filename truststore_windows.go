// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	FirefoxProfiles     = []string{os.Getenv("USERPROFILE") + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"}
	CertutilInstallHelp = "" // certutil unsupported on Windows
	NSSBrowsers         = "Firefox"
)

var (
	modcrypt32                           = syscall.NewLazyDLL("crypt32.dll")
	procCertAddEncodedCertificateToStore = modcrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertCloseStore                   = modcrypt32.NewProc("CertCloseStore")
	procCertDeleteCertificateFromStore   = modcrypt32.NewProc("CertDeleteCertificateFromStore")
	procCertDuplicateCertificateContext  = modcrypt32.NewProc("CertDuplicateCertificateContext")
	procCertEnumCertificatesInStore      = modcrypt32.NewProc("CertEnumCertificatesInStore")
	procCertOpenSystemStoreW             = modcrypt32.NewProc("CertOpenSystemStoreW")
)

func (m *mkcert) installPlatform() bool {
	// Load cert
	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")
	// Decode PEM
	if certBlock, _ := pem.Decode(cert); certBlock == nil || certBlock.Type != "CERTIFICATE" {
		fatalIfErr(fmt.Errorf("invalid PEM data"), "decode pem")
	} else {
		cert = certBlock.Bytes
	}
	// Open root store
	store, err := openWindowsRootStore()
	fatalIfErr(err, "open root store")
	defer store.close()
	// Add cert
	fatalIfErr(store.addCert(cert), "add cert")
	return true
}

func (m *mkcert) uninstallPlatform() bool {
	// We'll just remove all certs with the same serial number
	// Open root store
	store, err := openWindowsRootStore()
	fatalIfErr(err, "open root store")
	defer store.close()
	// Do the deletion
	deletedAny, err := store.deleteCertsWithSerial(m.caCert.SerialNumber)
	if err == nil && !deletedAny {
		err = fmt.Errorf("no certs found")
	}
	fatalIfErr(err, "delete cert")
	return true
}

// planSystemStore builds the read-only dry-run plan for the Windows system
// trust store. It opens the ROOT store and enumerates certificates, but
// never adds or deletes anything.
func (m *mkcert) planSystemStore(install bool) dryRunStore {
	s := dryRunStore{name: `Windows system certificate store "ROOT"`, detected: true}
	priv := adminPrivilegesNote()
	rootCert := filepath.Join(m.CAROOT, rootName)

	store, err := openWindowsRootStore()
	if err != nil {
		s.available = false
		s.diagnostic = fmt.Sprintf("Could not open the ROOT certificate store for a read-only probe: %v. "+
			"Make sure crypt32.dll is available and the current user profile is accessible, then re-run.", err)
		return s
	}
	defer store.close()
	s.available = true

	state := stateUnknown
	var enumErr error
	if m.caCert != nil {
		var found bool
		found, enumErr = store.hasCertWithSerial(m.caCert.SerialNumber)
		if enumErr != nil {
			// Fall back to chain verification if enumeration fails.
			found = m.checkPlatform()
		}
		if install {
			if found {
				state = stateAlready
			} else {
				state = stateWouldInstall
			}
		} else {
			if found {
				state = stateWouldRemove
			} else {
				state = stateAbsent
			}
		}
	}

	action := ""
	if install {
		action = fmt.Sprintf("decode %q and call crypt32 CertAddEncodedCertificateToStore (CERT_STORE_ADD_REPLACE_EXISTING)", rootCert)
	} else {
		action = "call crypt32 CertDeleteCertificateFromStore for every certificate matching the CA serial number"
	}
	s.targets = append(s.targets, dryRunTarget{
		path:       `certificate store "ROOT"`,
		action:     action,
		privileges: priv,
		state:      state,
	})
	if enumErr != nil {
		s.diagnostic = fmt.Sprintf("Read-only certificate enumeration failed (%v); the reported state comes from chain verification instead.", enumErr)
	}
	return s
}

type windowsRootStore uintptr

func openWindowsRootStore() (windowsRootStore, error) {
	rootStr, err := syscall.UTF16PtrFromString("ROOT")
	if err != nil {
		return 0, err
	}
	store, _, err := procCertOpenSystemStoreW.Call(0, uintptr(unsafe.Pointer(rootStr)))
	if store != 0 {
		return windowsRootStore(store), nil
	}
	return 0, fmt.Errorf("failed to open windows root store: %v", err)
}

func (w windowsRootStore) close() error {
	ret, _, err := procCertCloseStore.Call(uintptr(w), 0)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("failed to close windows root store: %v", err)
}

func (w windowsRootStore) addCert(cert []byte) error {
	// TODO: ok to always overwrite?
	ret, _, err := procCertAddEncodedCertificateToStore.Call(
		uintptr(w), // HCERTSTORE hCertStore
		uintptr(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING), // DWORD dwCertEncodingType
		uintptr(unsafe.Pointer(&cert[0])),                              // const BYTE *pbCertEncoded
		uintptr(len(cert)),                                             // DWORD cbCertEncoded
		3,                                                              // DWORD dwAddDisposition (CERT_STORE_ADD_REPLACE_EXISTING is 3)
		0,                                                              // PCCERT_CONTEXT *ppCertContext
	)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("failed adding cert: %v", err)
}

func (w windowsRootStore) deleteCertsWithSerial(serial *big.Int) (bool, error) {
	// Go over each, deleting the ones we find
	var cert *syscall.CertContext
	deletedAny := false
	for {
		// Next enum
		certPtr, _, err := procCertEnumCertificatesInStore.Call(uintptr(w), uintptr(unsafe.Pointer(cert)))
		if cert = (*syscall.CertContext)(unsafe.Pointer(certPtr)); cert == nil {
			if errno, ok := err.(syscall.Errno); ok && errno == 0x80092004 {
				break
			}
			return deletedAny, fmt.Errorf("failed enumerating certs: %v", err)
		}
		// Parse cert
		certBytes := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:cert.Length]
		parsedCert, err := x509.ParseCertificate(certBytes)
		// We'll just ignore parse failures for now
		if err == nil && parsedCert.SerialNumber != nil && parsedCert.SerialNumber.Cmp(serial) == 0 {
			// Duplicate the context so it doesn't stop the enum when we delete it
			dupCertPtr, _, err := procCertDuplicateCertificateContext.Call(uintptr(unsafe.Pointer(cert)))
			if dupCertPtr == 0 {
				return deletedAny, fmt.Errorf("failed duplicating context: %v", err)
			}
			if ret, _, err := procCertDeleteCertificateFromStore.Call(dupCertPtr); ret == 0 {
				return deletedAny, fmt.Errorf("failed deleting certificate: %v", err)
			}
			deletedAny = true
		}
	}
	return deletedAny, nil
}

// hasCertWithSerial reports whether the store contains a certificate with
// the given serial number. It only enumerates the store and never modifies
// it, so it is safe to use during a dry run.
func (w windowsRootStore) hasCertWithSerial(serial *big.Int) (bool, error) {
	var cert *syscall.CertContext
	for {
		certPtr, _, err := procCertEnumCertificatesInStore.Call(uintptr(w), uintptr(unsafe.Pointer(cert)))
		if cert = (*syscall.CertContext)(unsafe.Pointer(certPtr)); cert == nil {
			if errno, ok := err.(syscall.Errno); ok && errno == 0x80092004 {
				break
			}
			return false, fmt.Errorf("failed enumerating certs: %v", err)
		}
		certBytes := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:cert.Length]
		parsedCert, err := x509.ParseCertificate(certBytes)
		if err == nil && parsedCert.SerialNumber != nil && parsedCert.SerialNumber.Cmp(serial) == 0 {
			return true, nil
		}
	}
	return false, nil
}
