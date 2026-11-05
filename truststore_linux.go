// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	FirefoxProfiles = []string{os.Getenv("HOME") + "/.mozilla/firefox/*",
		os.Getenv("HOME") + "/snap/firefox/common/.mozilla/firefox/*"}
	NSSBrowsers = "Firefox and/or Chrome/Chromium"

	SystemTrustFilename string
	SystemTrustCommand  []string
	CertutilInstallHelp string
)

func init() {
	switch {
	case binaryExists("apt"):
		CertutilInstallHelp = "apt install libnss3-tools"
	case binaryExists("yum"):
		CertutilInstallHelp = "yum install nss-tools"
	case binaryExists("zypper"):
		CertutilInstallHelp = "zypper install mozilla-nss-tools"
	}
	if pathExists("/etc/pki/ca-trust/source/anchors/") {
		SystemTrustFilename = "/etc/pki/ca-trust/source/anchors/%s.pem"
		SystemTrustCommand = []string{"update-ca-trust", "extract"}
	} else if pathExists("/usr/local/share/ca-certificates/") {
		SystemTrustFilename = "/usr/local/share/ca-certificates/%s.crt"
		SystemTrustCommand = []string{"update-ca-certificates"}
	} else if pathExists("/etc/ca-certificates/trust-source/anchors/") {
		SystemTrustFilename = "/etc/ca-certificates/trust-source/anchors/%s.crt"
		SystemTrustCommand = []string{"trust", "extract-compat"}
	} else if pathExists("/usr/share/pki/trust/anchors") {
		SystemTrustFilename = "/usr/share/pki/trust/anchors/%s.pem"
		SystemTrustCommand = []string{"update-ca-certificates"}
	}
}

func (m *mkcert) systemTrustFilename() string {
	return fmt.Sprintf(SystemTrustFilename, strings.Replace(m.caUniqueName(), " ", "_", -1))
}

func (m *mkcert) installPlatform() bool {
	if SystemTrustCommand == nil {
		log.Printf("Installing to the system store is not yet supported on this Linux 😣 but %s will still work.", NSSBrowsers)
		log.Printf("You can also manually install the root certificate at %q.", filepath.Join(m.CAROOT, rootName))
		return false
	}

	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")

	cmd := commandWithSudo("tee", m.systemTrustFilename())
	cmd.Stdin = bytes.NewReader(cert)
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "tee", out)

	cmd = commandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, strings.Join(SystemTrustCommand, " "), out)

	return true
}

func (m *mkcert) uninstallPlatform() bool {
	if SystemTrustCommand == nil {
		return false
	}

	cmd := commandWithSudo("rm", "-f", m.systemTrustFilename())
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "rm", out)

	// We used to install under non-unique filenames.
	legacyFilename := fmt.Sprintf(SystemTrustFilename, "mkcert-rootCA")
	if pathExists(legacyFilename) {
		cmd := commandWithSudo("rm", "-f", legacyFilename)
		out, err := cmd.CombinedOutput()
		fatalIfCmdErr(err, "rm (legacy filename)", out)
	}

	cmd = commandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, strings.Join(SystemTrustCommand, " "), out)

	return true
}

// planSystemStore builds the read-only dry-run plan for the Linux system
// trust store. It only stats files and verifies the certificate; it never
// writes an anchor or runs the update command.
func (m *mkcert) planSystemStore(install bool) dryRunStore {
	s := dryRunStore{name: "Linux system trust store", detected: true}
	priv := adminPrivilegesNote()
	rootCert := filepath.Join(m.CAROOT, rootName)
	updateCmd := strings.Join(SystemTrustCommand, " ")

	if SystemTrustCommand == nil {
		s.available = false
		s.diagnostic = "No supported system trust mechanism was detected: none of the anchor directories exist " +
			`(looked for "/etc/pki/ca-trust/source/anchors/", "/usr/local/share/ca-certificates/", ` +
			`"/etc/ca-certificates/trust-source/anchors/" and "/usr/share/pki/trust/anchors"). ` +
			`Install your distribution's ca-certificates package (for example "apt install ca-certificates" ` +
			`or "yum install ca-certificates"), or manually copy "` + rootCert +
			`" into an anchor directory and run its update command as root.`
		return s
	}
	s.available = true

	anchor := fmt.Sprintf(SystemTrustFilename, strings.Replace(m.caNameOrPlaceholder(), " ", "_", -1))
	legacyFilename := fmt.Sprintf(SystemTrustFilename, "mkcert-rootCA")
	installed := m.caCert != nil && m.checkPlatform()

	if install {
		state := stateWouldInstall
		if m.caCert == nil {
			state = stateUnknown
		} else if installed {
			state = stateAlready
		}
		s.targets = append(s.targets, dryRunTarget{
			path:       anchor,
			action:     fmt.Sprintf("write the CA certificate with \"tee %s\" as root, then run \"%s\"", anchor, updateCmd),
			privileges: priv,
			state:      state,
		})
		return s
	}

	if pathExists(anchor) {
		s.targets = append(s.targets, dryRunTarget{
			path:       anchor,
			action:     fmt.Sprintf("remove with \"rm -f %s\" as root, then run \"%s\"", anchor, updateCmd),
			privileges: priv,
			state:      stateWouldRemove,
		})
	} else {
		state := stateAbsent
		if m.caCert == nil {
			state = stateUnknown
		}
		s.targets = append(s.targets, dryRunTarget{
			path:       anchor,
			action:     "no anchor file present; the update command would still run if other entries changed",
			privileges: priv,
			state:      state,
		})
	}
	// The legacy non-unique filename is only removed when actually present.
	if pathExists(legacyFilename) {
		s.targets = append(s.targets, dryRunTarget{
			path:       legacyFilename,
			action:     fmt.Sprintf("remove legacy anchor with \"rm -f %s\" as root", legacyFilename),
			privileges: priv,
			state:      stateWouldRemove,
		})
	}
	return s
}
