// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command mkcert is a simple zero-config tool to make development certificates.
package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

const shortUsage = `Usage of mkcert:

	$ mkcert -install
	Install the local CA in the system trust store.

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate "example.com+4.pem" and "example.com+4-key.pem".

	$ mkcert "*.example.it"
	Generate "_wildcard.example.it.pem" and "_wildcard.example.it-key.pem".

	$ mkcert -uninstall
	Uninstall the local CA (but do not delete it).

`

const advancedUsage = `Advanced options:

	-cert-file FILE, -key-file FILE, -p12-file FILE
	    Customize the output paths.

	-client
	    Generate a certificate for client authentication.

	-ecdsa
	    Generate a certificate with an ECDSA key.

	-pkcs12
	    Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
	    containing certificate and key for legacy applications.

	-csr CSR
	    Generate a certificate based on the supplied CSR. Conflicts with
	    all other flags and arguments except -install and -cert-file.

	-CAROOT
	    Print the CA certificate and key storage location.

	-dry-run
	    With -install or -uninstall, report the trust stores, targets and
	    privilege requirements that would be used, without making any changes.
	    Targets that already contain the CA are reported as already installed.

	$CAROOT (environment variable)
	    Set the CA certificate and key storage location. (This allows
	    maintaining multiple local CAs in parallel.)

	$TRUST_STORES (environment variable)
	    A comma-separated list of trust stores to install the local
	    root CA into. Options are: "system", "java" and "nss" (includes
	    Firefox). Autodetected by default.

`

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func main() {
	if len(os.Args) == 1 {
		fmt.Print(shortUsage)
		return
	}
	log.SetFlags(0)
	var (
		installFlag   = flag.Bool("install", false, "")
		uninstallFlag = flag.Bool("uninstall", false, "")
		pkcs12Flag    = flag.Bool("pkcs12", false, "")
		ecdsaFlag     = flag.Bool("ecdsa", false, "")
		clientFlag    = flag.Bool("client", false, "")
		helpFlag      = flag.Bool("help", false, "")
		carootFlag    = flag.Bool("CAROOT", false, "")
		dryRunFlag    = flag.Bool("dry-run", false, "")
		csrFlag       = flag.String("csr", "", "")
		certFileFlag  = flag.String("cert-file", "", "")
		keyFileFlag   = flag.String("key-file", "", "")
		p12FileFlag   = flag.String("p12-file", "", "")
		versionFlag   = flag.Bool("version", false, "")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
		fmt.Fprintln(flag.CommandLine.Output(), `For more options, run "mkcert -help".`)
	}
	flag.Parse()
	if *helpFlag {
		fmt.Print(shortUsage)
		fmt.Print(advancedUsage)
		return
	}
	if *versionFlag {
		if Version != "" {
			fmt.Println(Version)
			return
		}
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(buildInfo.Main.Version)
			return
		}
		fmt.Println("(unknown)")
		return
	}
	if *carootFlag {
		if *installFlag || *uninstallFlag {
			log.Fatalln("ERROR: you can't set -[un]install and -CAROOT at the same time")
		}
		fmt.Println(getCAROOT())
		return
	}
	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: you can't set -install and -uninstall at the same time")
	}
	if *dryRunFlag && !*installFlag && !*uninstallFlag {
		log.Fatalln("ERROR: -dry-run can only be used with -install or -uninstall")
	}
	if *csrFlag != "" && (*pkcs12Flag || *ecdsaFlag || *clientFlag) {
		log.Fatalln("ERROR: can only combine -csr with -install and -cert-file")
	}
	if *csrFlag != "" && flag.NArg() != 0 {
		log.Fatalln("ERROR: can't specify extra arguments when using -csr")
	}
	(&mkcert{
		installMode: *installFlag, uninstallMode: *uninstallFlag, dryRun: *dryRunFlag,
		csrPath: *csrFlag, pkcs12: *pkcs12Flag, ecdsa: *ecdsaFlag, client: *clientFlag,
		certFile: *certFileFlag, keyFile: *keyFileFlag, p12File: *p12FileFlag,
	}).Run(flag.Args())
}

const rootName = "rootCA.pem"
const rootKeyName = "rootCA-key.pem"

type mkcert struct {
	installMode, uninstallMode bool
	dryRun                     bool
	pkcs12, ecdsa, client      bool
	keyFile, certFile, p12File string
	csrPath                    string

	CAROOT string
	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure bool
}

func (m *mkcert) Run(args []string) {
	m.CAROOT = getCAROOT()
	if m.CAROOT == "" {
		log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
	}
	if m.dryRun {
		// Dry runs never create the CAROOT or the CA, and never touch the
		// system trust stores: only read-only checks are performed.
		caInfo := m.loadCADryRun()
		m.dryRunReport(m.installMode, caInfo, len(args))
		return
	}
	fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
	m.loadCA()

	if m.installMode {
		m.install()
		if len(args) == 0 {
			return
		}
	} else if m.uninstallMode {
		m.uninstall()
		return
	} else {
		var warning bool
		if storeEnabled("system") && !m.checkPlatform() {
			warning = true
			log.Println("Note: the local CA is not installed in the system trust store.")
		}
		if storeEnabled("nss") && hasNSS && CertutilInstallHelp != "" && !m.checkNSS() {
			warning = true
			log.Printf("Note: the local CA is not installed in the %s trust store.", NSSBrowsers)
		}
		if storeEnabled("java") && hasJava && !m.checkJava() {
			warning = true
			log.Println("Note: the local CA is not installed in the Java trust store.")
		}
		if warning {
			log.Println("Run \"mkcert -install\" for certificates to be trusted automatically ⚠️")
		}
	}

	if m.csrPath != "" {
		m.makeCertFromCSR()
		return
	}

	if len(args) == 0 {
		flag.Usage()
		return
	}

	hostnameRegexp := regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)
	for i, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		if email, err := mail.ParseAddress(name); err == nil && email.Address == name {
			continue
		}
		if uriName, err := url.Parse(name); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			continue
		}
		punycode, err := idna.ToASCII(name)
		if err != nil {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email: %s", name, err)
		}
		args[i] = punycode
		if !hostnameRegexp.MatchString(punycode) {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email", name)
		}
	}

	m.makeCert(args)
}

func getCAROOT() string {
	if env := os.Getenv("CAROOT"); env != "" {
		return env
	}

	var dir string
	switch {
	case runtime.GOOS == "windows":
		dir = os.Getenv("LocalAppData")
	case os.Getenv("XDG_DATA_HOME") != "":
		dir = os.Getenv("XDG_DATA_HOME")
	case runtime.GOOS == "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")
	default: // Unix
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, ".local", "share")
	}
	return filepath.Join(dir, "mkcert")
}

func (m *mkcert) install() {
	if storeEnabled("system") {
		if m.checkPlatform() {
			log.Print("The local CA is already installed in the system trust store! 👍")
		} else {
			if m.installPlatform() {
				log.Print("The local CA is now installed in the system trust store! ⚡️")
			}
			m.ignoreCheckFailure = true // TODO: replace with a check for a successful install
		}
	}
	if storeEnabled("nss") && hasNSS {
		if m.checkNSS() {
			log.Printf("The local CA is already installed in the %s trust store! 👍", NSSBrowsers)
		} else {
			if hasCertutil && m.installNSS() {
				log.Printf("The local CA is now installed in the %s trust store (requires browser restart)! 🦊", NSSBrowsers)
			} else if CertutilInstallHelp == "" {
				log.Printf(`Note: %s support is not available on your platform. ℹ️`, NSSBrowsers)
			} else if !hasCertutil {
				log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically installed in %s! ⚠️`, NSSBrowsers)
				log.Printf(`Install "certutil" with "%s" and re-run "mkcert -install" 👈`, CertutilInstallHelp)
			}
		}
	}
	if storeEnabled("java") && hasJava {
		if m.checkJava() {
			log.Println("The local CA is already installed in Java's trust store! 👍")
		} else {
			if hasKeytool {
				m.installJava()
				log.Println("The local CA is now installed in Java's trust store! ☕️")
			} else {
				log.Println(`Warning: "keytool" is not available, so the CA can't be automatically installed in Java's trust store! ⚠️`)
			}
		}
	}
	log.Print("")
}

func (m *mkcert) uninstall() {
	if storeEnabled("nss") && hasNSS {
		if hasCertutil {
			m.uninstallNSS()
		} else if CertutilInstallHelp != "" {
			log.Print("")
			log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically uninstalled from %s (if it was ever installed)! ⚠️`, NSSBrowsers)
			log.Printf(`You can install "certutil" with "%s" and re-run "mkcert -uninstall" 👈`, CertutilInstallHelp)
			log.Print("")
		}
	}
	if storeEnabled("java") && hasJava {
		if hasKeytool {
			m.uninstallJava()
		} else {
			log.Print("")
			log.Println(`Warning: "keytool" is not available, so the CA can't be automatically uninstalled from Java's trust store (if it was ever installed)! ⚠️`)
			log.Print("")
		}
	}
	if storeEnabled("system") && m.uninstallPlatform() {
		log.Print("The local CA is now uninstalled from the system trust store(s)! 👋")
		log.Print("")
	} else if storeEnabled("nss") && hasCertutil {
		log.Printf("The local CA is now uninstalled from the %s trust store(s)! 👋", NSSBrowsers)
		log.Print("")
	}
}

func (m *mkcert) checkPlatform() bool {
	if m.ignoreCheckFailure {
		return true
	}

	_, err := m.caCert.Verify(x509.VerifyOptions{})
	return err == nil
}

func storeEnabled(name string) bool {
	stores := os.Getenv("TRUST_STORES")
	if stores == "" {
		return true
	}
	for _, store := range strings.Split(stores, ",") {
		if store == name {
			return true
		}
	}
	return false
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func fatalIfCmdErr(err error, cmd string, out []byte) {
	if err != nil {
		log.Fatalf("ERROR: failed to execute \"%s\": %s\n\n%s\n", cmd, err, out)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

var sudoWarningOnce sync.Once

func commandWithSudo(cmd ...string) *exec.Cmd {
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	if !binaryExists("sudo") {
		sudoWarningOnce.Do(func() {
			log.Println(`Warning: "sudo" is not available, and mkcert is not running as root. The (un)install operation might fail. ⚠️`)
		})
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("sudo", append([]string{"--prompt=Sudo password:", "--"}, cmd...)...)
}

// adminPrivilegesNote describes how the system trust store commands gain
// privileges. It only inspects the environment; it never escalates.
func adminPrivilegesNote() string {
	if runtime.GOOS == "windows" {
		return "administrator rights may be required for the machine-wide store; Windows may show an interactive security warning"
	}
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		return "running as root, no privilege escalation needed"
	}
	if !binaryExists("sudo") {
		return `ROOT REQUIRED, but "sudo" is not available: run mkcert as root or install sudo`
	}
	return `root privileges through "sudo" (a password prompt may appear)`
}

// Dry-run report machinery. The plan* helpers in the truststore_*.go files
// only perform read-only checks and must never execute the mutating
// install/uninstall commands.

type dryRunState string

const (
	stateWouldInstall dryRunState = "would-install"
	stateAlready      dryRunState = "already-installed"
	stateWouldRemove  dryRunState = "would-remove"
	stateAbsent       dryRunState = "absent"
	stateUnknown      dryRunState = "unknown"
)

// dryRunTarget is a single file, database or keychain entry that an
// install/uninstall operation would check, write or remove.
type dryRunTarget struct {
	path       string
	action     string
	privileges string
	state      dryRunState
}

// dryRunStore describes one trust store (system, NSS or Java) and the state
// of all of its targets.
type dryRunStore struct {
	name       string
	detected   bool   // the relevant software/store exists on this machine
	available  bool   // the tools required to modify it automatically exist
	diagnostic string // actionable remediation when detected/available fail
	targets    []dryRunTarget
}

type dryRunCounters struct {
	change, noop, unknown, blocked, undetected, skipped int
}

func (m *mkcert) dryRunReport(install bool, ca dryRunCAInfo, hostCount int) {
	opWord, opFlag := "INSTALL", "-install"
	if !install {
		opWord, opFlag = "UNINSTALL", "-uninstall"
	}
	log.Printf("DRY RUN — %s plan for the local CA trust stores. No files or trust stores were modified. 🔍", opWord)
	log.Println()

	// Local CA section.
	log.Println("Local CA")
	log.Printf("  CAROOT: %s", m.CAROOT)
	if ca.CAROOTExists {
		log.Println("  - CAROOT directory: exists")
	} else {
		log.Println("  - CAROOT directory: missing (would be created with mode 0755)")
	}
	switch {
	case ca.Err != nil:
		log.Printf("  - %s: found but it could not be read: %v", rootName, ca.Err)
	case ca.CertExists:
		log.Printf("  - %s: exists", rootName)
	default:
		log.Printf("  - %s: missing (a new local CA would be created first)", rootName)
	}
	switch {
	case !ca.CertExists:
		log.Printf("  - %s: would be created together with the CA (mode 0400)", rootKeyName)
	case ca.KeyExists:
		log.Printf("  - %s: exists", rootKeyName)
	default:
		log.Printf("  - %s: missing (keyless mode: the CA can be trusted, but not used to issue certificates)", rootKeyName)
	}
	log.Println()

	var c dryRunCounters
	m.printDryRunStore("system", storeEnabled("system"), m.planSystemStore(install), &c)
	m.printDryRunStore("nss", storeEnabled("nss"), m.planNSSStore(install), &c)
	m.printDryRunStore("java", storeEnabled("java"), m.planJavaStore(install), &c)

	log.Printf("Summary: %d target(s) would change, %d already present or absent (no-op), %d unknown, %d store(s) unavailable, %d not detected, %d skipped via TRUST_STORES.",
		c.change, c.noop, c.unknown, c.blocked, c.undetected, c.skipped)
	log.Printf("Re-run %s without -dry-run to execute these actions. 👈", opFlag)
	if hostCount > 0 {
		log.Printf("Note: -dry-run reports trust store operations only; generation of %d certificate(s) was skipped.", hostCount)
	}
}

func (m *mkcert) printDryRunStore(key string, enabled bool, s dryRunStore, c *dryRunCounters) {
	log.Printf("[%s] %s", key, s.name)
	if !enabled {
		c.skipped++
		log.Println("  SKIPPED: not selected by the TRUST_STORES environment variable.")
		log.Println()
		return
	}
	if !s.detected {
		c.undetected++
		log.Println("  NOT DETECTED: no action would be taken.")
		if s.diagnostic != "" {
			log.Printf("  -> %s", s.diagnostic)
		}
		log.Println()
		return
	}
	if !s.available {
		c.blocked++
		log.Println("  UNAVAILABLE: this trust store can't be modified automatically.")
		if s.diagnostic != "" {
			log.Printf("  -> %s", s.diagnostic)
		}
	}
	if len(s.targets) == 0 && s.available {
		log.Println("  No targets.")
	}
	for _, t := range s.targets {
		switch t.state {
		case stateWouldInstall, stateWouldRemove:
			c.change++
		case stateAlready, stateAbsent:
			c.noop++
		default:
			c.unknown++
		}
		log.Printf("  [%s] %s", dryRunStateLabel(t.state), t.path)
		log.Printf("      action: %s", t.action)
		if t.privileges != "" {
			log.Printf("      privileges: %s", t.privileges)
		}
	}
	if s.available && s.diagnostic != "" {
		log.Printf("  Note: %s", s.diagnostic)
	}
	log.Println()
}

func dryRunStateLabel(state dryRunState) string {
	switch state {
	case stateWouldInstall:
		return "WOULD INSTALL"
	case stateAlready:
		return "ALREADY INSTALLED — no change"
	case stateWouldRemove:
		return "WOULD REMOVE"
	case stateAbsent:
		return "NOT PRESENT — nothing to remove"
	default:
		return "UNKNOWN"
	}
}
