// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	hasJava    bool
	hasKeytool bool

	javaHome    string
	cacertsPath string
	keytoolPath string
	storePass   string = "changeit"
)

func init() {
	if runtime.GOOS == "windows" {
		keytoolPath = filepath.Join("bin", "keytool.exe")
	} else {
		keytoolPath = filepath.Join("bin", "keytool")
	}

	if v := os.Getenv("JAVA_HOME"); v != "" {
		hasJava = true
		javaHome = v

		if pathExists(filepath.Join(v, keytoolPath)) {
			hasKeytool = true
			keytoolPath = filepath.Join(v, keytoolPath)
		}

		if pathExists(filepath.Join(v, "lib", "security", "cacerts")) {
			cacertsPath = filepath.Join(v, "lib", "security", "cacerts")
		}

		if pathExists(filepath.Join(v, "jre", "lib", "security", "cacerts")) {
			cacertsPath = filepath.Join(v, "jre", "lib", "security", "cacerts")
		}
	}
}

func (m *mkcert) checkJava() bool {
	if !hasKeytool {
		return false
	}

	ok, out, err := m.javaCertsContainCA()
	fatalIfCmdErr(err, "keytool -list", out)
	return ok
}

// javaCertsContainCA runs the read-only "keytool -list" command and reports
// whether the local CA certificate fingerprint is in the cacerts store.
func (m *mkcert) javaCertsContainCA() (bool, []byte, error) {
	keytoolOutput, err := exec.Command(keytoolPath, "-list", "-keystore", cacertsPath, "-storepass", storePass).CombinedOutput()
	if err != nil {
		return false, keytoolOutput, err
	}
	// keytool outputs SHA1 and SHA256 (Java 9+) certificates in uppercase hex
	// with each octet pair delimitated by ":". Drop them from the keytool output
	keytoolOutput = bytes.Replace(keytoolOutput, []byte(":"), nil, -1)

	// exists returns true if the given x509.Certificate's fingerprint
	// is in the keytool -list output
	exists := func(h hash.Hash) bool {
		h.Write(m.caCert.Raw)
		fp := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		return bytes.Contains(keytoolOutput, []byte(fp))
	}

	// pre-Java 9 uses SHA1 fingerprints
	return exists(sha1.New()) || exists(sha256.New()), keytoolOutput, nil
}

// planJavaStore builds the read-only dry-run plan for the Java cacerts trust
// store. It only runs "keytool -list"; it never imports or deletes aliases.
func (m *mkcert) planJavaStore(install bool) dryRunStore {
	s := dryRunStore{name: "Java trust store (cacerts)"}
	rootCert := filepath.Join(m.CAROOT, rootName)
	priv := "write permission on cacerts for the current user; on Unix mkcert retries with sudo and JAVA_HOME=" + javaHome

	if !hasJava {
		s.detected = false
		s.diagnostic = "Java was not detected: the JAVA_HOME environment variable is not set. " +
			"Set JAVA_HOME to a JDK or JRE installation to manage its cacerts trust store."
		return s
	}
	s.detected = true

	if !hasKeytool {
		s.available = false
		s.diagnostic = fmt.Sprintf("The keytool binary was not found (looked for %q under JAVA_HOME=%q). "+
			"Verify the JDK/JRE installation or set JAVA_HOME correctly, then re-run.",
			filepath.Join(javaHome, keytoolPath), javaHome)
		return s
	}
	if cacertsPath == "" {
		s.available = false
		s.diagnostic = fmt.Sprintf("The cacerts file was not found under JAVA_HOME=%q (looked in "+
			"%q and %q). Install a JRE/JDK that ships cacerts, or point JAVA_HOME at one.",
			javaHome, filepath.Join(javaHome, "lib", "security", "cacerts"),
			filepath.Join(javaHome, "jre", "lib", "security", "cacerts"))
		return s
	}
	s.available = true

	state := stateUnknown
	if m.caCert != nil {
		present, out, err := m.javaCertsContainCA()
		if err != nil {
			s.diagnostic = fmt.Sprintf("The read-only check %q failed: %v\n    %s. "+
				"Verify that cacerts is readable and that the store password is %q.",
				"keytool -list", err, strings.TrimSpace(string(out)), storePass)
		} else if install {
			if present {
				state = stateAlready
			} else {
				state = stateWouldInstall
			}
		} else {
			if present {
				state = stateWouldRemove
			} else {
				state = stateAbsent
			}
		}
	}

	action := ""
	if install {
		action = fmt.Sprintf("%q -importcert -noprompt -keystore %q -storepass %q -file %q -alias %q",
			keytoolPath, cacertsPath, storePass, rootCert, m.caNameOrPlaceholder())
	} else {
		action = fmt.Sprintf("%q -delete -alias %q -keystore %q -storepass %q",
			keytoolPath, m.caNameOrPlaceholder(), cacertsPath, storePass)
	}
	s.targets = append(s.targets, dryRunTarget{
		path:       "cacerts " + cacertsPath,
		action:     action,
		privileges: priv,
		state:      state,
	})
	return s
}

func (m *mkcert) installJava() {
	args := []string{
		"-importcert", "-noprompt",
		"-keystore", cacertsPath,
		"-storepass", storePass,
		"-file", filepath.Join(m.CAROOT, rootName),
		"-alias", m.caUniqueName(),
	}

	out, err := execKeytool(exec.Command(keytoolPath, args...))
	fatalIfCmdErr(err, "keytool -importcert", out)
}

func (m *mkcert) uninstallJava() {
	args := []string{
		"-delete",
		"-alias", m.caUniqueName(),
		"-keystore", cacertsPath,
		"-storepass", storePass,
	}
	out, err := execKeytool(exec.Command(keytoolPath, args...))
	if bytes.Contains(out, []byte("does not exist")) {
		return // cert didn't exist
	}
	fatalIfCmdErr(err, "keytool -delete", out)
}

// execKeytool will execute a "keytool" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func execKeytool(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("java.io.FileNotFoundException")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd = commandWithSudo(cmd.Path)
		cmd.Args = append(cmd.Args, origArgs...)
		cmd.Env = []string{
			"JAVA_HOME=" + javaHome,
		}
		out, err = cmd.CombinedOutput()
	}
	return out, err
}
