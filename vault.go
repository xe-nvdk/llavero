package main

// Encrypted credential store.
//
// On-disk layout, version 2:
//
//	"PKV1" | version(1) | mode(1) | kdfSalt(16) | nonce(12) | AES-256-GCM ciphertext
//
// The whole header is passed to GCM as additional authenticated data, so
// neither the salt nor the unlock mode can be altered to force a weaker
// derivation. Version 1 files (no mode byte, passphrase only) still open, so
// existing vaults keep working.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	vaultMagic      = "PKV1"
	vaultVersion1   = 1
	vaultVersion2   = 2
	kdfIterations   = 600_000 // OWASP 2023 floor for PBKDF2-HMAC-SHA256
	saltLen         = 16
	nonceLen        = 12
	headerLenV1     = 4 + 1 + saltLen + nonceLen     // 33
	headerLenV2     = 4 + 1 + 1 + saltLen + nonceLen // 34
	credentialIDLen = 32
)

// unlockMode records which factors are needed to derive the vault key.
type unlockMode byte

const (
	modePassphrase unlockMode = 0 // passphrase only
	modeTPM        unlockMode = 1 // TPM-sealed secret only, so no typing at boot
	modeTPMPass    unlockMode = 2 // both
)

func (m unlockMode) String() string {
	switch m {
	case modePassphrase:
		return "passphrase"
	case modeTPM:
		return "tpm"
	case modeTPMPass:
		return "tpm+passphrase"
	default:
		return fmt.Sprintf("unknown(%d)", byte(m))
	}
}

func parseUnlockMode(s string) (unlockMode, error) {
	switch s {
	case "passphrase":
		return modePassphrase, nil
	case "tpm":
		return modeTPM, nil
	case "tpm+passphrase":
		return modeTPMPass, nil
	default:
		return 0, fmt.Errorf("unknown unlock mode %q (want passphrase, tpm, or tpm+passphrase)", s)
	}
}

func (m unlockMode) needsPassphrase() bool { return m == modePassphrase || m == modeTPMPass }
func (m unlockMode) needsTPM() bool        { return m == modeTPM || m == modeTPMPass }

var errBadPassphrase = errors.New("wrong passphrase, or vault file is corrupt")

type storedCredential struct {
	ID          []byte    `json:"id"`
	RPID        string    `json:"rp_id"`
	RPName      string    `json:"rp_name,omitempty"`
	UserID      []byte    `json:"user_id"`
	UserName    string    `json:"user_name,omitempty"`
	UserDisplay string    `json:"user_display,omitempty"`
	PrivateKey  []byte    `json:"private_key"` // PKCS#8
	SignCount   uint32    `json:"sign_count"`
	CreatedAt   time.Time `json:"created_at"`
}

type vaultContents struct {
	Credentials []storedCredential `json:"credentials"`
}

type vault struct {
	mu   sync.Mutex
	path string
	key  []byte
	salt []byte
	mode unlockMode
	// upgradedFromV1 means the file on disk is still the old format and will
	// be rewritten as v2 on the next save.
	upgradedFromV1 bool
	contents       vaultContents
}

func defaultVaultPath() string {
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dir, "llavero", "vault.pkv")
}

// tpmBlobPath keeps the sealed secret beside the vault. Both are needed, and
// neither is useful without this machine's TPM.
func tpmBlobPath(vaultPath string) string { return vaultPath + ".tpm" }

// deriveVaultKey combines whichever factors the mode calls for. HKDF is the
// combiner so that adding a factor cannot weaken the result.
//
// legacyV1 selects the original derivation, which used the PBKDF2 output
// directly as the AES key with no HKDF step. Version 1 vaults were written
// that way and must keep opening, so this is not optional and not removable
// while any v1 file might still exist.
func deriveVaultKey(mode unlockMode, salt, passphrase, tpmSecret []byte, legacyV1 bool) ([]byte, error) {
	if legacyV1 {
		if mode != modePassphrase {
			return nil, errors.New("version 1 vaults are passphrase-only")
		}
		return pbkdf2.Key(sha256.New, string(passphrase), salt, kdfIterations, 32)
	}

	var ikm []byte

	if mode.needsPassphrase() {
		stretched, err := pbkdf2.Key(sha256.New, string(passphrase), salt, kdfIterations, 32)
		if err != nil {
			return nil, err
		}
		ikm = append(ikm, stretched...)
	}
	if mode.needsTPM() {
		if len(tpmSecret) != tpmSecretLen {
			return nil, errors.New("TPM secret missing or wrong size")
		}
		ikm = append(ikm, tpmSecret...)
	}
	if len(ikm) == 0 {
		return nil, errors.New("no unlock factors available")
	}

	// The info string pins the derivation to a mode, so the same factors in a
	// different mode produce a different key.
	//
	// DO NOT change this literal. It is an input to the key derivation, not a
	// label: every existing v2 vault was encrypted under it, and editing it
	// (for instance while renaming the project) makes them all undecryptable
	// with no error message that would point at the cause.
	info := "passkey-vault/v2/" + mode.String()
	return hkdf.Key(sha256.New, ikm, salt, info, 32)
}

// readVaultHeader reports the mode a vault file was written in, without
// needing any credentials. Callers use it to know what to ask the user for.
func readVaultHeader(path string) (unlockMode, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(raw) < headerLenV1 || string(raw[0:4]) != vaultMagic {
		return 0, errors.New("not a llavero vault file")
	}
	switch raw[4] {
	case vaultVersion1:
		return modePassphrase, nil
	case vaultVersion2:
		if len(raw) < headerLenV2 {
			return 0, errors.New("vault file is truncated")
		}
		return unlockMode(raw[5]), nil
	default:
		return 0, fmt.Errorf("unsupported vault version %d", raw[4])
	}
}

// openVault decrypts an existing vault. It does not create one; use createVault.
func openVault(path string, passphrase []byte) (*vault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < headerLenV1 || string(raw[0:4]) != vaultMagic {
		return nil, errors.New("not a llavero vault file")
	}

	var (
		mode      unlockMode
		headerLen int
		legacyV1  bool
	)
	switch raw[4] {
	case vaultVersion1:
		mode, headerLen, legacyV1 = modePassphrase, headerLenV1, true
	case vaultVersion2:
		if len(raw) < headerLenV2 {
			return nil, errors.New("vault file is truncated")
		}
		mode, headerLen = unlockMode(raw[5]), headerLenV2
	default:
		return nil, fmt.Errorf("unsupported vault version %d", raw[4])
	}

	saltOff := headerLen - nonceLen - saltLen
	salt := raw[saltOff : saltOff+saltLen]
	nonce := raw[saltOff+saltLen : headerLen]
	ciphertext := raw[headerLen:]

	var tpmSecret []byte
	if mode.needsTPM() {
		blob, err := os.ReadFile(tpmBlobPath(path))
		if err != nil {
			return nil, fmt.Errorf("this vault is TPM-bound but its sealed blob is unreadable: %w", err)
		}
		tpmSecret, err = unsealFromTPM(blob)
		if err != nil {
			return nil, err
		}
	}

	key, err := deriveVaultKey(mode, salt, passphrase, tpmSecret, legacyV1)
	if err != nil {
		return nil, err
	}
	plain, err := decrypt(key, nonce, raw[:headerLen], ciphertext)
	if err != nil {
		if mode.needsTPM() && !mode.needsPassphrase() {
			return nil, errors.New("vault will not decrypt; the sealed blob and the vault file may be from different installs")
		}
		return nil, errBadPassphrase
	}

	// The file opened under the old derivation. Switch the in-memory key to
	// the current one so the next write lands as a consistent v2 file. Until
	// that write happens the file on disk stays v1 and stays readable, so an
	// interrupted upgrade loses nothing.
	if legacyV1 {
		upgraded, err := deriveVaultKey(mode, salt, passphrase, nil, false)
		if err != nil {
			return nil, err
		}
		key = upgraded
	}

	v := &vault{path: path, key: key, salt: salt, mode: mode, upgradedFromV1: legacyV1}
	if err := json.Unmarshal(plain, &v.contents); err != nil {
		return nil, fmt.Errorf("vault contents are malformed: %w", err)
	}
	return v, nil
}

// createVault writes a brand new empty vault in the requested mode, sealing a
// fresh TPM secret if the mode needs one.
func createVault(path string, mode unlockMode, passphrase []byte) (*vault, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	var tpmSecret []byte
	if mode.needsTPM() {
		tpmSecret = make([]byte, tpmSecretLen)
		if _, err := rand.Read(tpmSecret); err != nil {
			return nil, err
		}
		blob, err := sealToTPM(tpmSecret)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(tpmBlobPath(path), blob, 0o600); err != nil {
			return nil, fmt.Errorf("writing sealed blob: %w", err)
		}
	}

	key, err := deriveVaultKey(mode, salt, passphrase, tpmSecret, false)
	if err != nil {
		return nil, err
	}
	v := &vault{path: path, key: key, salt: salt, mode: mode}
	if err := v.save(); err != nil {
		return nil, err
	}
	return v, nil
}

// cloneCredential copies a stored credential so merge/export cannot alias
// the caller's slices.
func cloneCredential(c storedCredential) storedCredential {
	out := c
	out.ID = append([]byte(nil), c.ID...)
	out.UserID = append([]byte(nil), c.UserID...)
	out.PrivateKey = append([]byte(nil), c.PrivateKey...)
	return out
}

func cloneContents(in vaultContents) vaultContents {
	out := vaultContents{Credentials: make([]storedCredential, len(in.Credentials))}
	for i, c := range in.Credentials {
		out.Credentials[i] = cloneCredential(c)
	}
	return out
}

func credentialIdentity(c storedCredential) string {
	return c.RPID + "\x00" + string(c.UserID)
}

// snapshot copies every credential. Export uses it so the live vault is only
// read, even while the service holds the same file open.
func (v *vault) snapshot() vaultContents {
	v.mu.Lock()
	defer v.mu.Unlock()
	return cloneContents(v.contents)
}

// exportPortable writes a passphrase-only copy of this vault to dest. It
// reuses rekey() for the crypto, on a clone so the source path, key, and
// mode are left alone.
func (v *vault) exportPortable(dest string, passphrase []byte) error {
	clone := &vault{path: dest, contents: v.snapshot()}
	return clone.rekey(modePassphrase, passphrase)
}

// mergeCredentials adds incoming passkeys. On a colliding (rpId, userId)
// pair the higher signature counter wins; addCredential would replace
// blindly, which is right for re-registration and wrong for a restore.
func (v *vault) mergeCredentials(incoming []storedCredential) (added, replaced, kept int, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	index := make(map[string]int, len(v.contents.Credentials))
	for i, c := range v.contents.Credentials {
		index[credentialIdentity(c)] = i
	}
	for _, inc := range incoming {
		inc = cloneCredential(inc)
		key := credentialIdentity(inc)
		if i, ok := index[key]; ok {
			if inc.SignCount > v.contents.Credentials[i].SignCount {
				v.contents.Credentials[i] = inc
				replaced++
			} else {
				kept++
			}
			continue
		}
		v.contents.Credentials = append(v.contents.Credentials, inc)
		index[key] = len(v.contents.Credentials) - 1
		added++
	}
	if added == 0 && replaced == 0 {
		return added, replaced, kept, nil
	}
	return added, replaced, kept, v.save()
}

// rekey rewrites an already-open vault under a new mode, preserving every
// credential. The caller is responsible for having backed up the old file.
func (v *vault) rekey(mode unlockMode, passphrase []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	var tpmSecret []byte
	if mode.needsTPM() {
		tpmSecret = make([]byte, tpmSecretLen)
		if _, err := rand.Read(tpmSecret); err != nil {
			return err
		}
		blob, err := sealToTPM(tpmSecret)
		if err != nil {
			return err
		}
		if err := os.WriteFile(tpmBlobPath(v.path), blob, 0o600); err != nil {
			return fmt.Errorf("writing sealed blob: %w", err)
		}
	}

	key, err := deriveVaultKey(mode, salt, passphrase, tpmSecret, false)
	if err != nil {
		return err
	}
	v.key, v.salt, v.mode, v.upgradedFromV1 = key, salt, mode, false
	return v.save()
}

func decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// save rewrites the whole vault. Callers must hold v.mu, except on the
// creation path where no other goroutine can see v yet.
func (v *vault) save() error {
	plain, err := json.Marshal(v.contents)
	if err != nil {
		return err
	}

	// A fresh nonce on every write. Reusing one under the same key would leak
	// plaintext, and we rewrite the file on every registration and sign-in.
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	header := make([]byte, 0, headerLenV2)
	header = append(header, vaultMagic...)
	header = append(header, vaultVersion2)
	header = append(header, byte(v.mode))
	header = append(header, v.salt...)
	header = append(header, nonce...)

	block, err := aes.NewCipher(v.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, header)

	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return err
	}
	// Write-then-rename so a crash mid-write cannot leave half a vault. The
	// temp file shares the directory so the rename stays on one filesystem.
	tmp, err := os.CreateTemp(filepath.Dir(v.path), ".vault-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(header, ciphertext...)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), v.path)
}

// addCredential mints a keypair for a new registration and persists it.
func (v *vault) addCredential(rp rpEntity, user userEntity) (*storedCredential, *ecdsa.PrivateKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	id := make([]byte, credentialIDLen)
	if _, err := rand.Read(id); err != nil {
		return nil, nil, err
	}

	cred := storedCredential{
		ID:          id,
		RPID:        rp.ID,
		RPName:      rp.Name,
		UserID:      user.ID,
		UserName:    user.Name,
		UserDisplay: user.DisplayName,
		PrivateKey:  pkcs8,
		SignCount:   0,
		CreatedAt:   time.Now().UTC(),
	}

	// One passkey per (rpId, userId). Re-registering the same account replaces
	// the old key rather than accumulating credentials the RP will never ask
	// for again.
	replaced := false
	for i := range v.contents.Credentials {
		c := &v.contents.Credentials[i]
		if c.RPID == rp.ID && string(c.UserID) == string(user.ID) {
			v.contents.Credentials[i] = cred
			replaced = true
			break
		}
	}
	if !replaced {
		v.contents.Credentials = append(v.contents.Credentials, cred)
	}

	if err := v.save(); err != nil {
		return nil, nil, err
	}
	return &cred, priv, nil
}

// findForRP returns every credential registered to an RP, newest first.
func (v *vault) findForRP(rpID string, allow []credentialDescriptor) []storedCredential {
	v.mu.Lock()
	defer v.mu.Unlock()

	var out []storedCredential
	for _, c := range v.contents.Credentials {
		if c.RPID != rpID {
			continue
		}
		if len(allow) > 0 && !matchesAllowList(c.ID, allow) {
			continue
		}
		out = append(out, c)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func matchesAllowList(id []byte, allow []credentialDescriptor) bool {
	for _, d := range allow {
		if string(d.ID) == string(id) {
			return true
		}
	}
	return false
}

func (v *vault) hasCredentialFor(rpID string, exclude []credentialDescriptor) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, c := range v.contents.Credentials {
		if c.RPID == rpID && matchesAllowList(c.ID, exclude) {
			return true
		}
	}
	return false
}

// bumpSignCount increments and persists the per-credential counter.
func (v *vault) bumpSignCount(id []byte) (uint32, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.contents.Credentials {
		if string(v.contents.Credentials[i].ID) == string(id) {
			v.contents.Credentials[i].SignCount++
			n := v.contents.Credentials[i].SignCount
			return n, v.save()
		}
	}
	return 0, errors.New("credential not found")
}

// list returns a copy of every stored credential, oldest first.
func (v *vault) list() []storedCredential {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]storedCredential, len(v.contents.Credentials))
	copy(out, v.contents.Credentials)
	return out
}

// remove deletes every credential matching pred and persists the result.
// It returns what was removed so the caller can report it.
func (v *vault) remove(pred func(storedCredential) bool) ([]storedCredential, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	var kept, gone []storedCredential
	for _, c := range v.contents.Credentials {
		if pred(c) {
			gone = append(gone, c)
		} else {
			kept = append(kept, c)
		}
	}
	if len(gone) == 0 {
		return nil, nil
	}
	v.contents.Credentials = kept
	if err := v.save(); err != nil {
		return nil, err
	}
	return gone, nil
}

func (v *vault) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.contents.Credentials)
}

func parsePrivateKey(pkcs8 []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("stored key is not ECDSA")
	}
	return priv, nil
}
