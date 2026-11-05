// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	hasNSS       bool
	hasCertutil  bool
	certutilPath string
	nssDBs       = []string{
		filepath.Join(os.Getenv("HOME"), ".pki/nssdb"),
		filepath.Join(os.Getenv("HOME"), "snap/chromium/current/.pki/nssdb"), // Snapcraft
		"/etc/pki/nssdb", // CentOS 7
	}
	firefoxPaths = []string{
		"/usr/bin/firefox",
		"/usr/bin/firefox-nightly",
		"/usr/bin/firefox-developer-edition",
		"/snap/firefox",
		"/Applications/Firefox.app",
		"/Applications/FirefoxDeveloperEdition.app",
		"/Applications/Firefox Developer Edition.app",
		"/Applications/Firefox Nightly.app",
		"C:\\Program Files\\Mozilla Firefox",
	}
)

func init() {
	allPaths := append(append([]string{}, nssDBs...), firefoxPaths...)
	for _, path := range allPaths {
		if pathExists(path) {
			hasNSS = true
			break
		}
	}

	switch runtime.GOOS {
	case "darwin":
		switch {
		case binaryExists("certutil"):
			certutilPath, _ = exec.LookPath("certutil")
			hasCertutil = true
		case binaryExists("/usr/local/opt/nss/bin/certutil"):
			// Check the default Homebrew path, to save executing Ruby. #135
			certutilPath = "/usr/local/opt/nss/bin/certutil"
			hasCertutil = true
		default:
			out, err := exec.Command("brew", "--prefix", "nss").Output()
			if err == nil {
				certutilPath = filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")
				hasCertutil = pathExists(certutilPath)
			}
		}

	case "linux":
		if hasCertutil = binaryExists("certutil"); hasCertutil {
			certutilPath, _ = exec.LookPath("certutil")
		}
	}
}

func (m *mkcert) checkNSS() bool {
	if !hasCertutil {
		return false
	}
	success := true
	if m.forEachNSSProfile(func(profile string) {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run()
		if err != nil {
			success = false
		}
	}) == 0 {
		success = false
	}
	return success
}

func (m *mkcert) installNSS() bool {
	if m.forEachNSSProfile(func(profile string) {
		cmd := exec.Command(certutilPath, "-A", "-d", profile, "-t", "C,,", "-n", m.caUniqueName(), "-i", filepath.Join(m.CAROOT, rootName))
		out, err := execCertutil(cmd)
		fatalIfCmdErr(err, "certutil -A -d "+profile, out)
	}) == 0 {
		log.Printf("ERROR: no %s security databases found", NSSBrowsers)
		return false
	}
	if !m.checkNSS() {
		log.Printf("Installing in %s failed. Please report the issue with details about your environment at https://github.com/FiloSottile/mkcert/issues/new 👎", NSSBrowsers)
		log.Printf("Note that if you never started %s, you need to do that at least once.", NSSBrowsers)
		return false
	}
	return true
}

func (m *mkcert) uninstallNSS() {
	m.forEachNSSProfile(func(profile string) {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run()
		if err != nil {
			return
		}
		cmd := exec.Command(certutilPath, "-D", "-d", profile, "-n", m.caUniqueName())
		out, err := execCertutil(cmd)
		fatalIfCmdErr(err, "certutil -D -d "+profile, out)
	})
}

// execCertutil will execute a "certutil" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func execCertutil(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("SEC_ERROR_READ_ONLY")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd = commandWithSudo(cmd.Path)
		cmd.Args = append(cmd.Args, origArgs...)
		out, err = cmd.CombinedOutput()
	}
	return out, err
}

// planNSSStore builds the read-only dry-run plan for the NSS trust stores
// (Firefox and, on Linux, Chrome/Chromium). It only enumerates profile
// directories and runs "certutil -V"; it never adds or deletes certificates.
func (m *mkcert) planNSSStore(install bool) dryRunStore {
	s := dryRunStore{name: NSSBrowsers + " NSS trust store"}
	priv := "runs as the current user; sudo is only used as a fallback if a security database is read-only"
	rootCert := filepath.Join(m.CAROOT, rootName)
	op := "install"
	if !install {
		op = "uninstall"
	}

	if !hasNSS {
		s.detected = false
		s.diagnostic = fmt.Sprintf("No NSS security database or browser installation was detected at: %s. "+
			"Install %s, or start it at least once so it creates a profile, then re-run.",
			strings.Join(nssSearchPaths(), ", "), NSSBrowsers)
		return s
	}
	s.detected = true

	var profiles []string
	m.forEachNSSProfile(func(profile string) { profiles = append(profiles, profile) })

	if !hasCertutil {
		s.available = false
		if CertutilInstallHelp != "" {
			s.diagnostic = fmt.Sprintf("%q is not available, so the CA can't be %sed automatically. "+
				"Install it with %q, then re-run \"mkcert -%sinstall\".",
				"certutil", op, CertutilInstallHelp, op)
		} else {
			s.diagnostic = fmt.Sprintf("%s support through %q is not available on this platform; manage the browser trust store manually.",
				NSSBrowsers, "certutil")
		}
	} else {
		s.available = true
	}

	if len(profiles) == 0 {
		s.diagnostic += fmt.Sprintf("No NSS security databases (cert9.db/cert8.db) were found in %s. "+
			"If you never started %s, do that at least once to initialize its profile.",
			strings.Join(nssSearchPaths(), ", "), NSSBrowsers)
		return s
	}

	for _, profile := range profiles {
		state := stateUnknown
		if m.caCert != nil && hasCertutil {
			present := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run() == nil
			if install {
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
			action = fmt.Sprintf("%q -A -d %s -t C,, -n %q -i %q", certutilName(), profile, m.caNameOrPlaceholder(), rootCert)
		} else {
			action = fmt.Sprintf("%q -D -d %s -n %q", certutilName(), profile, m.caNameOrPlaceholder())
		}
		s.targets = append(s.targets, dryRunTarget{
			path:       "NSS database " + profile,
			action:     action,
			privileges: priv,
			state:      state,
		})
	}
	return s
}

// certutilName returns the path that would be shown in commands, or the
// bare tool name when it was not found.
func certutilName() string {
	if hasCertutil {
		return certutilPath
	}
	return "certutil"
}

// nssSearchPaths lists the locations probed for NSS databases and browser
// installations. The Unix nssDBs entries are skipped on Windows, where they
// would resolve to meaningless relative paths because HOME is unset.
func nssSearchPaths() []string {
	searched := append([]string{}, FirefoxProfiles...)
	searched = append(searched, firefoxPaths...)
	if runtime.GOOS != "windows" {
		searched = append(searched, nssDBs...)
	}
	return searched
}

func (m *mkcert) forEachNSSProfile(f func(profile string)) (found int) {
	var profiles []string
	profiles = append(profiles, nssDBs...)
	for _, ff := range FirefoxProfiles {
		pp, _ := filepath.Glob(ff)
		profiles = append(profiles, pp...)
	}
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		if pathExists(filepath.Join(profile, "cert9.db")) {
			f("sql:" + profile)
			found++
		} else if pathExists(filepath.Join(profile, "cert8.db")) {
			f("dbm:" + profile)
			found++
		}
	}
	return
}
