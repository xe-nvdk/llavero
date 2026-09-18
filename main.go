package main

// llavero: a software FIDO2 authenticator for Linux.
//
// It registers a virtual FIDO HID device with the kernel, so browsers discover
// it the same way they discover a hardware security key: no extension, no
// native messaging host, no browser configuration.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

// aaguid identifies the authenticator model, not the user or the installation.
// It is public and intentionally fixed across installs.
var aaguid = [16]byte{
	0x9d, 0x3a, 0x5b, 0x71, 0x2c, 0x84, 0x4e, 0x1f,
	0xa7, 0x60, 0xc3, 0x18, 0xe5, 0x02, 0xbb, 0x46,
}

var verbose bool

func logf(format string, args ...any) {
	fmt.Printf("%s  %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

func vlogf(format string, args ...any) {
	if verbose {
		logf(format, args...)
	}
}

type options struct {
	vaultPath   string
	unlock      string
	rekeyTo     string
	uv          string
	uvStrict    bool
	consent     string
	uvGrace     time.Duration
	list        bool
	forget      string
	mlock       bool
	autoApprove bool
	passFD      int
	newPassFD   int
}

func main() {
	loadBuildInfo()

	var (
		opts        options
		showVersion = flag.Bool("version", false, "print build information and exit")
		tpmSelftest = flag.Bool("tpm-selftest", false, "seal and unseal a test secret, then exit")
		verboseFlag = flag.Bool("v", false, "log every CTAPHID frame")
	)
	flag.StringVar(&opts.vaultPath, "vault", defaultVaultPath(), "path to the encrypted vault file")
	flag.StringVar(&opts.unlock, "unlock", "passphrase", "unlock mode for a NEW vault: passphrase, tpm, or tpm+passphrase")
	flag.StringVar(&opts.rekeyTo, "rekey", "", "re-encrypt an existing vault under this unlock mode, then exit")
	flag.StringVar(&opts.uv, "uv", "fingerprint", "user verification: fingerprint or prompt")
	flag.BoolVar(&opts.uvStrict, "uv-strict", false, "deny when the fingerprint sensor is unusable instead of falling back to the prompt")
	flag.StringVar(&opts.consent, "consent", "prompt", "how to take consent: prompt (click to approve, then touch) or fingerprint (touch only)")
	flag.DurationVar(&opts.uvGrace, "uv-grace", 5*time.Second, "reuse a just-completed fingerprint scan for repeat requests from the SAME site (0 disables)")
	flag.BoolVar(&opts.mlock, "mlock", true, "lock memory so keys cannot be written to swap")
	flag.BoolVar(&opts.list, "list", false, "list stored passkeys, then exit")
	flag.StringVar(&opts.forget, "forget", "", "delete passkeys matching a site or a credential id prefix, then exit")
	flag.BoolVar(&opts.autoApprove, "auto-approve", false, "approve every request without prompting (testing only)")
	flag.IntVar(&opts.passFD, "passphrase-fd", -1, "read the vault passphrase from this file descriptor")
	flag.IntVar(&opts.newPassFD, "new-passphrase-fd", -1, "read the NEW passphrase for -rekey from this file descriptor")
	flag.Parse()
	verbose = *verboseFlag

	if *showVersion {
		fmt.Println(versionLine())
		return
	}

	if *tpmSelftest {
		if err := runTPMSelftest(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		os.Exit(1)
	}
}

// loadVault opens an existing vault or creates one, asking only for the
// factors the vault's own mode requires.
func loadVault(opts options) (*vault, error) {
	_, statErr := os.Stat(opts.vaultPath)
	isNew := errors.Is(statErr, os.ErrNotExist)

	mode := modePassphrase
	if isNew {
		m, err := parseUnlockMode(opts.unlock)
		if err != nil {
			return nil, err
		}
		mode = m
	} else {
		m, err := readVaultHeader(opts.vaultPath)
		if err != nil {
			return nil, err
		}
		mode = m
	}

	if mode.needsTPM() {
		if err := tpmAvailable(); err != nil {
			return nil, err
		}
	}

	var passphrase []byte
	if mode.needsPassphrase() {
		p, err := readPassphrase(opts.passFD, isNew, "")
		if err != nil {
			return nil, err
		}
		defer zero(p)
		passphrase = p
	}

	if isNew {
		v, err := createVault(opts.vaultPath, mode, passphrase)
		if err != nil {
			return nil, err
		}
		logf("created a new vault at %s (unlock: %s)", opts.vaultPath, mode)
		return v, nil
	}

	v, err := openVault(opts.vaultPath, passphrase)
	if err != nil {
		return nil, err
	}
	logf("unlocked %s (unlock: %s, %d passkey(s))", opts.vaultPath, v.mode, v.count())
	return v, nil
}

func runRekey(opts options) error {
	newMode, err := parseUnlockMode(opts.rekeyTo)
	if err != nil {
		return err
	}
	if newMode.needsTPM() {
		if err := tpmAvailable(); err != nil {
			return err
		}
	}

	v, err := loadVault(opts)
	if err != nil {
		return err
	}
	if v.mode == newMode {
		logf("vault is already in %s mode, nothing to do", newMode)
		return nil
	}

	// Back up before touching anything. A failed rekey must never be the
	// reason someone loses their passkeys.
	backup := fmt.Sprintf("%s.bak-%s", opts.vaultPath, time.Now().Format("20060102-150405"))
	if err := copyFile(opts.vaultPath, backup); err != nil {
		return fmt.Errorf("could not back up the vault, refusing to rekey: %w", err)
	}
	logf("backed up the existing vault to %s", backup)

	var newPass []byte
	if newMode.needsPassphrase() {
		p, err := readPassphrase(opts.newPassFD, true, "new ")
		if err != nil {
			return err
		}
		defer zero(p)
		newPass = p
	}

	if err := v.rekey(newMode, newPass); err != nil {
		return fmt.Errorf("rekey failed (your backup at %s is still good): %w", backup, err)
	}
	logf("rekeyed to %s, %d passkey(s) preserved", newMode, v.count())

	// Prove the new file actually opens before declaring success.
	check, err := openVault(opts.vaultPath, newPass)
	if err != nil {
		return fmt.Errorf("the rekeyed vault does not reopen (restore from %s): %w", backup, err)
	}
	if check.count() != v.count() {
		return fmt.Errorf("credential count changed during rekey (restore from %s)", backup)
	}
	logf("verified: the rekeyed vault reopens and still holds %d passkey(s)", check.count())
	return nil
}

func run(opts options) error {
	// First journal line after an upgrade, so a bug report can name the build
	// without asking the user to remember which binary they installed.
	logf("%s", versionLine())

	// Before anything touches a key. Core dumps and ptrace are shut off first
	// so there is no window in which a decrypted vault could escape.
	hardenProcess(opts.mlock, logf)

	if opts.rekeyTo != "" {
		return runRekey(opts)
	}
	if opts.list {
		return runList(opts)
	}
	if opts.forget != "" {
		return runForget(opts)
	}

	// Check device access before asking for a passphrase, so a permissions
	// problem does not cost the user a typed secret first.
	if err := checkUHIDAccess(); err != nil {
		return err
	}

	v, err := loadVault(opts)
	if err != nil {
		return err
	}

	var ap approver
	if opts.autoApprove {
		logf("WARNING: -auto-approve is set. Every request will be granted without asking.")
		ap = autoApprover{}
	} else {
		ap, err = newMenuApprover()
		if err != nil {
			return fmt.Errorf("no approval UI available: %w\n"+
				"       (omarchy-menu-select is required, or run with -auto-approve for testing)", err)
		}
	}

	var verifier *fingerprintVerifier
	switch opts.uv {
	case "fingerprint":
		if opts.autoApprove {
			break // testing mode skips biometrics too
		}
		verifier, err = newFingerprintVerifier(logf)
		if err != nil {
			logf("fingerprint verification unavailable (%v)", err)
			logf("continuing with the desktop prompt as the only check; pass -uv prompt to silence this")
			verifier = nil
		}
	case "prompt":
		logf("user verification is the desktop prompt alone")
	default:
		return fmt.Errorf("unknown -uv value %q (want fingerprint or prompt)", opts.uv)
	}

	fingerprintConsent := false
	switch opts.consent {
	case "prompt":
	case "fingerprint":
		if verifier == nil {
			// Without a sensor this would leave no user interaction at all, so
			// fall back rather than let a page mint passkeys in silence.
			logf("-consent fingerprint needs a working sensor; falling back to the approval prompt")
		} else {
			fingerprintConsent = true
			logf("consent is the fingerprint touch alone; no approval click")
		}
	default:
		return fmt.Errorf("unknown -consent value %q (want prompt or fingerprint)", opts.consent)
	}

	if opts.uvGrace > 0 && verifier != nil {
		logf("repeat requests from the same site within %s reuse the previous scan", opts.uvGrace)
	}

	auth := &authenticator{
		vault:              v,
		approver:           ap,
		uvGrace:            opts.uvGrace,
		verifier:           verifier,
		strictUV:           opts.uvStrict,
		fingerprintConsent: fingerprintConsent,
		aaguid:             aaguid,
		logf:               logf,
	}

	dev, err := openUHID()
	if err != nil {
		return err
	}
	if err := dev.create("Llavero (virtual FIDO2)"); err != nil {
		return err
	}

	// Always tear the device down. A leaked virtual key would keep appearing
	// in the browser's picker with nothing behind it.
	shutdown := func() {
		_ = dev.destroy()
		_ = dev.f.Close()
	}
	defer shutdown()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		logf("shutting down")
		shutdown()
		os.Exit(0)
	}()

	go reportNode()

	stack := newCtapHID(dev, auth.handle, vlogf)

	for {
		ev, err := dev.read()
		if err != nil {
			return fmt.Errorf("reading from /dev/uhid: %w", err)
		}
		switch ev.kind {
		case uhidStart:
			logf("authenticator is live, waiting for a browser")
		case uhidOpen:
			vlogf("device opened by a client")
		case uhidClose:
			vlogf("device closed by a client")
		case uhidStop:
			vlogf("UHID_STOP")
		case uhidOutput:
			stack.handlePacket(ev.data)
		default:
			vlogf("uhid event type %d", ev.kind)
		}
	}
}

// checkUHIDAccess turns the usual permission failure into an actionable
// message, since the fix is a one-line udev rule rather than anything obvious.
func checkUHIDAccess() error {
	f, err := os.OpenFile("/dev/uhid", os.O_RDWR, 0)
	if err == nil {
		f.Close()
		return nil
	}
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("no access to /dev/uhid.\n"+
			"       Install the udev rule that grants it to the logged-in user:\n\n"+
			"         echo 'KERNEL==\"uhid\", SUBSYSTEM==\"misc\", TAG+=\"uaccess\"' | \\\n"+
			"           sudo tee /etc/udev/rules.d/70-uhid-uaccess.rules\n"+
			"         sudo udevadm control --reload-rules && sudo udevadm trigger /dev/uhid\n\n"+
			"       (underlying error: %v)", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("/dev/uhid is missing. Load the module with: sudo modprobe uhid")
	}
	return fmt.Errorf("opening /dev/uhid: %w", err)
}

func readPassphrase(passFD int, confirm bool, adjective string) ([]byte, error) {
	if passFD >= 0 {
		f := os.NewFile(uintptr(passFD), "passphrase")
		if f == nil {
			return nil, fmt.Errorf("file descriptor %d is not open", passFD)
		}
		// Read one byte at a time up to the newline. A buffered reader would
		// read ahead and swallow whatever else the caller piped in, such as
		// the confirmation a later prompt asks for.
		line, err := readLine(f)
		if err != nil && len(line) == 0 {
			return nil, fmt.Errorf("reading passphrase from fd %d: %w", passFD, err)
		}
		if passFD != 0 {
			f.Close()
		}
		return line, nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("no terminal to read the passphrase from (use -passphrase-fd)")
	}

	if confirm {
		fmt.Printf("Choose a %spassphrase (this encrypts every passkey): ", adjective)
		first, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		if len(first) < 8 {
			zero(first)
			return nil, errors.New("passphrase must be at least 8 characters")
		}
		fmt.Print("Confirm passphrase: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		defer zero(second)
		if string(first) != string(second) {
			zero(first)
			return nil, errors.New("passphrases do not match")
		}
		fmt.Println("\nKeep this passphrase safe. There is no recovery path:")
		fmt.Println("lose it and every passkey in the vault is gone.")
		return first, nil
	}

	fmt.Print("Vault passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return pass, err
}

// readLine consumes exactly one line and not a byte more, so the rest of the
// stream stays available to whoever reads next.
func readLine(f *os.File) ([]byte, error) {
	var out []byte
	buf := make([]byte, 1)
	for len(out) < 4096 {
		n, err := f.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			out = append(out, buf[0])
		}
		if err != nil {
			return bytes.TrimRight(out, "\r"), err
		}
	}
	return bytes.TrimRight(out, "\r"), nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// zero overwrites secret material so it does not linger in the heap any longer
// than necessary.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// reportNode tells the user which hidraw node we became, and whether they can
// actually reach it, which is the first thing to check if a browser cannot see
// the key.
func reportNode() {
	time.Sleep(400 * time.Millisecond)
	matches, _ := filepath.Glob("/sys/class/hidraw/hidraw*")
	for _, m := range matches {
		data, err := os.ReadFile(filepath.Join(m, "device", "uevent"))
		if err != nil || !strings.Contains(string(data), "llavero") {
			continue
		}
		node := "/dev/" + filepath.Base(m)
		if f, err := os.OpenFile(node, os.O_RDWR, 0); err == nil {
			f.Close()
			logf("presenting as %s, readable by this user", node)
		} else {
			logf("presenting as %s, but THIS USER CANNOT OPEN IT: %v", node, err)
			logf("browsers will not see the key until that is fixed")
		}
		return
	}
	logf("warning: could not locate our hidraw node")
}

// runTPMSelftest proves the TPM path works on this machine: seal a known
// secret, unseal it, and confirm the bytes survive.
func runTPMSelftest() error {
	if err := tpmAvailable(); err != nil {
		return err
	}
	logf("TPM device is reachable")

	secret := make([]byte, tpmSecretLen)
	for i := range secret {
		secret[i] = byte(i * 7)
	}

	blob, err := sealToTPM(secret)
	if err != nil {
		return err
	}
	logf("sealed a %d-byte secret into a %d-byte blob", len(secret), len(blob))

	got, err := unsealFromTPM(blob)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, secret) {
		return errors.New("unsealed bytes do not match what was sealed")
	}
	logf("unsealed and matched")

	// Two seals of the same secret must differ, or the TPM is not adding its
	// own entropy to the wrapping and something is very wrong.
	blob2, err := sealToTPM(secret)
	if err != nil {
		return err
	}
	if bytes.Equal(blob, blob2) {
		return errors.New("two seals of the same secret produced identical blobs")
	}
	logf("re-sealing produced a distinct blob, as it should")

	bad := append([]byte{}, blob...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := unsealFromTPM(bad); err == nil {
		return errors.New("a corrupted blob unsealed successfully, which must not happen")
	}
	logf("a corrupted blob was correctly rejected")

	fmt.Println("\nTPM selftest passed")
	return nil
}

// runList prints what is in the vault. Useful on its own, and the only way to
// find the id of something worth deleting.
func runList(opts options) error {
	v, err := loadVault(opts)
	if err != nil {
		return err
	}
	creds := v.list()
	if len(creds) == 0 {
		fmt.Println("\nThe vault is empty.")
		return nil
	}
	fmt.Printf("\n%-28s  %-34s  %-16s  %5s  %s\n", "SITE", "ACCOUNT", "CREDENTIAL", "USES", "CREATED")
	for _, c := range creds {
		account := c.UserName
		if account == "" {
			account = c.UserDisplay
		}
		fmt.Printf("%-28s  %-34s  %-16x  %5d  %s\n",
			truncate(c.RPID, 28), truncate(account, 34), c.ID[:8], c.SignCount,
			c.CreatedAt.Local().Format("2006-01-02 15:04"))
	}
	fmt.Printf("\n%d passkey(s).\n", len(creds))
	return nil
}

// runForget deletes credentials by site or by credential id prefix. It always
// shows what it is about to remove and asks first: there is no undo, and a
// deleted passkey may be the only way into an account.
func runForget(opts options) error {
	if serviceHasOpen(opts.vaultPath) {
		return errors.New("the llavero service is running against this vault and holds its own\n" +
			"       copy in memory, so its next write would resurrect anything deleted here.\n" +
			"       Stop it first:  systemctl --user stop llavero.service")
	}

	v, err := loadVault(opts)
	if err != nil {
		return err
	}

	needle := strings.ToLower(opts.forget)
	match := func(c storedCredential) bool {
		return strings.ToLower(c.RPID) == needle ||
			strings.HasPrefix(strings.ToLower(fmt.Sprintf("%x", c.ID)), needle)
	}

	var doomed []storedCredential
	for _, c := range v.list() {
		if match(c) {
			doomed = append(doomed, c)
		}
	}
	if len(doomed) == 0 {
		return fmt.Errorf("nothing in the vault matches %q (try -list)", opts.forget)
	}

	fmt.Printf("\nAbout to delete %d passkey(s):\n\n", len(doomed))
	for _, c := range doomed {
		fmt.Printf("  %s  %s  %x  (used %d time(s))\n", c.RPID, c.UserName, c.ID[:8], c.SignCount)
	}
	// Echo the exact string back. Saying "type the site name" invites a near
	// miss on values like ".dummy", where the leading dot is easy to drop.
	fmt.Printf("\nThis cannot be undone. Type %q to confirm: ", opts.forget)

	var typed string
	fmt.Scanln(&typed)
	if strings.ToLower(strings.TrimSpace(typed)) != needle {
		return fmt.Errorf("confirmation did not match (wanted %q, got %q), nothing was deleted",
			opts.forget, strings.TrimSpace(typed))
	}

	gone, err := v.remove(match)
	if err != nil {
		return err
	}
	logf("deleted %d passkey(s), %d remaining", len(gone), v.count())
	return nil
}

// serviceHasOpen reports whether the running service is using this very vault.
// Editing a different file while the daemon runs is harmless, so the guard is
// scoped to the path rather than refusing whenever the service happens to be up.
func serviceHasOpen(vaultPath string) bool {
	out, err := exec.Command("systemctl", "--user", "is-active", "llavero.service").Output()
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		return false
	}

	// The unit passes no -vault, so the service is on the default path. If it
	// ever gains one, prefer what the unit actually says.
	servicePath := defaultVaultPath()
	if line, err := exec.Command("systemctl", "--user", "show", "-p", "ExecStart",
		"--value", "llavero.service").Output(); err == nil {
		fields := strings.Fields(string(line))
		for i, f := range fields {
			if f == "-vault" && i+1 < len(fields) {
				servicePath = fields[i+1]
			}
		}
	}
	return sameFile(vaultPath, servicePath)
}

// sameFile compares paths after resolving symlinks, falling back to a cleaned
// absolute comparison when a path does not exist yet.
func sameFile(a, b string) bool {
	resolve := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			return real
		}
		return filepath.Clean(p)
	}
	return resolve(a) == resolve(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "\u2026"
}
