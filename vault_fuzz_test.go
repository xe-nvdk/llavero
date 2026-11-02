package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Import reads vault files from outside, so the parsers in front of the
// decryption, and the merge behind it, must reject anything malformed
// without panicking. The seeds also run under plain go test.

func fuzzSeedVault(f *testing.F) []byte {
	f.Helper()
	path := filepath.Join(f.TempDir(), "seed.pkv")
	v, err := createVault(path, modePassphrase, []byte("fuzz-passphrase"))
	if err != nil {
		f.Fatal(err)
	}
	v.contents.Credentials = []storedCredential{testStoredCred("example.test", "alice", 1, "cred-alice")}
	if err := v.save(); err != nil {
		f.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	return raw
}

func FuzzReadVaultHeader(f *testing.F) {
	f.Add(fuzzSeedVault(f))
	f.Add([]byte(vaultMagic))
	f.Add([]byte(vaultMagic + "\x01"))
	f.Add([]byte(vaultMagic + "\x02\x07"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		path := filepath.Join(t.TempDir(), "v.pkv")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = readVaultHeader(path)
	})
}

func FuzzOpenVault(f *testing.F) {
	seed := fuzzSeedVault(f)
	f.Add(seed)
	f.Add(seed[:headerLenV2])
	f.Add(seed[:headerLenV1])
	f.Fuzz(func(t *testing.T, raw []byte) {
		path := filepath.Join(t.TempDir(), "v.pkv")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		// Only passphrase-mode headers reach the KDF; import refuses the rest
		// before this point, so skip them rather than touch a TPM.
		if mode, err := readVaultHeader(path); err != nil || mode != modePassphrase {
			return
		}
		_, _ = openVault(path, []byte("fuzz-passphrase"))
	})
}

// FuzzMergeImported feeds arbitrary decrypted contents to the merge, which is
// what a crafted backup under a known passphrase can reach.
func FuzzMergeImported(f *testing.F) {
	good, err := json.Marshal(vaultContents{Credentials: []storedCredential{
		testStoredCred("example.test", "alice", 1, "cred-alice"),
		testStoredCred("example.test", "bob", 2, "cred-bob"),
	}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"credentials":[{"id":"","rp_id":""}]}`))
	f.Add([]byte(`{"credentials":null}`))
	f.Fuzz(func(t *testing.T, plain []byte) {
		var incoming vaultContents
		if json.Unmarshal(plain, &incoming) != nil {
			return
		}
		local := testStoredCred("example.test", "alice", 1, "cred-alice")
		v := &vault{path: filepath.Join(t.TempDir(), "vault.pkv"), key: make([]byte, 32), salt: make([]byte, saltLen)}
		v.contents.Credentials = []storedCredential{cloneCredential(local)}
		res, err := v.mergeCredentials(incoming.Credentials, nil)
		if err != nil {
			return
		}
		if got := len(v.list()); got != 1+res.Added {
			t.Fatalf("vault holds %d credentials after %+v, want %d", got, res, 1+res.Added)
		}
		// The local credential must survive whatever the backup says.
		for _, c := range v.list() {
			if string(c.ID) == string(local.ID) {
				if !sameKeyMaterial(c, local) || c.SignCount < local.SignCount {
					t.Fatal("import altered the local credential's key or lowered its counter")
				}
				return
			}
		}
		t.Fatal("import removed the local credential")
	})
}
