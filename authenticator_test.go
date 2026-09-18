package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scriptedApprover returns a prepared reply and records what it was asked.
type scriptedApprover struct {
	reply   string
	title   string
	choices []string
}

func (s *scriptedApprover) confirm(title string, choices []string) (string, error) {
	s.title = title
	s.choices = append([]string(nil), choices...)
	return s.reply, nil
}

func testPrivateKey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pkcs8
}

func testCred(t *testing.T, id, rp, name string, created time.Time) storedCredential {
	t.Helper()
	return storedCredential{
		ID:         []byte(id),
		RPID:       rp,
		UserID:     []byte("user-" + id),
		UserName:   name,
		PrivateKey: testPrivateKey(t),
		CreatedAt:  created,
	}
}

func testVaultWith(t *testing.T, creds ...storedCredential) *vault {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.pkv")
	v, err := createVault(path, modePassphrase, []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	v.contents.Credentials = append([]storedCredential(nil), creds...)
	if err := v.save(); err != nil {
		t.Fatal(err)
	}
	return v
}

func encodeGetAssertion(t *testing.T, rpID string) []byte {
	t.Helper()
	body, err := ctapEncMode.Marshal(getAssertionRequest{
		RPID:           rpID,
		ClientDataHash: bytes.Repeat([]byte{1}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func decodeAssertion(t *testing.T, raw []byte) getAssertionResponse {
	t.Helper()
	if len(raw) < 1 || raw[0] != statusOK {
		t.Fatalf("getAssertion status = 0x%02x, want OK; body=%x", raw[0], raw)
	}
	var resp getAssertionResponse
	if err := ctapDecMode.Unmarshal(raw[1:], &resp); err != nil {
		t.Fatalf("decoding assertion: %v", err)
	}
	return resp
}

// Two accounts that share a username must produce two different picker rows.
// The distinguishing fragment is the credential-id prefix -list uses, and the
// row is the omarchy three-field form so the desktop prompt can show it.
func TestAccountPickerRowsAreUniqueForDuplicateNames(t *testing.T) {
	a := storedCredential{ID: []byte("aaaaaaaaaaaaaaaa"), UserName: "alice"}
	b := storedCredential{ID: []byte("bbbbbbbbbbbbbbbb"), UserName: "alice"}
	p := newAccountPicker([]storedCredential{a, b})

	if p.items[0].name != "alice" || p.items[1].name != "alice" {
		t.Fatalf("names = %q, %q, want alice, alice", p.items[0].name, p.items[1].name)
	}
	if p.items[0].row == p.items[1].row || p.items[0].key == p.items[1].key {
		t.Fatalf("duplicate-name rows collapsed: row %q / %q, key %q / %q",
			p.items[0].row, p.items[1].row, p.items[0].key, p.items[1].key)
	}
	if p.items[0].label == p.items[1].label {
		t.Fatalf("colliding names kept the same visible label %q", p.items[0].label)
	}
	if !strings.Contains(p.items[0].label, credIDPrefix(a.ID)) {
		t.Errorf("label %q should include the first credential-id prefix", p.items[0].label)
	}
	if !strings.Contains(p.items[1].label, credIDPrefix(b.ID)) {
		t.Errorf("label %q should include the second credential-id prefix", p.items[1].label)
	}
	if p.items[0].row != "\t"+p.items[0].key {
		t.Errorf("row = %q, want the omarchy glyph\\tlabel\\tsubtext form", p.items[0].row)
	}
	if p.items[0].id != credIDPrefix(a.ID) || p.items[1].id != credIDPrefix(b.ID) {
		t.Errorf("ids = %q, %q", p.items[0].id, p.items[1].id)
	}
}

// Empty usernames fall back to the same "this account" label; the prefix still
// has to keep those rows apart.
func TestAccountPickerRowsAreUniqueWhenNamesAreMissing(t *testing.T) {
	a := storedCredential{ID: []byte("first-credential")}
	b := storedCredential{ID: []byte("second-credential")}
	p := newAccountPicker([]storedCredential{a, b})

	if p.items[0].name != "this account" || p.items[1].name != "this account" {
		t.Fatalf("fallback names = %q, %q, want this account", p.items[0].name, p.items[1].name)
	}
	if p.items[0].row == p.items[1].row || p.items[0].key == p.items[1].key {
		t.Fatal("nameless accounts produced identical picker rows")
	}
	if p.items[0].label == p.items[1].label {
		t.Fatal("nameless accounts kept the same visible label")
	}
}

func TestAccountPickerKeepsCleanLabelWhenNamesDiffer(t *testing.T) {
	p := newAccountPicker([]storedCredential{
		{ID: []byte("aaaaaaaaaaaaaaaa"), UserName: "alice"},
		{ID: []byte("bbbbbbbbbbbbbbbb"), UserName: "bob"},
	})
	if p.items[0].label != "alice" || p.items[1].label != "bob" {
		t.Fatalf("labels = %q, %q, want alice, bob", p.items[0].label, p.items[1].label)
	}
	if p.items[0].row == p.items[1].row {
		t.Fatal("different names still produced the same row")
	}
}

func TestAccountPickerMatchSelectsByIndexAndCredID(t *testing.T) {
	first := storedCredential{ID: []byte("aaaaaaaaaaaaaaaa"), UserName: "alice"}
	second := storedCredential{ID: []byte("bbbbbbbbbbbbbbbb"), UserName: "alice"}
	p := newAccountPicker([]storedCredential{first, second})

	if i := p.match(p.items[1].key); i != 1 {
		t.Fatalf("omarchy key matched index %d, want 1", i)
	}
	if i := p.match(p.items[1].row); i != 1 {
		t.Fatalf("raw row matched index %d, want 1", i)
	}
	if i := p.match(p.items[0].key); i != 0 {
		t.Fatalf("first key matched index %d, want 0", i)
	}
	if i := p.match(credIDPrefix(second.ID)); i != 1 {
		t.Fatalf("credential-id prefix matched index %d, want 1", i)
	}
}

func TestAccountPickerMatchRejectsAmbiguousBareLabel(t *testing.T) {
	first := storedCredential{ID: []byte("aaaaaaaaaaaaaaaa"), UserName: "alice"}
	second := storedCredential{ID: []byte("bbbbbbbbbbbbbbbb"), UserName: "alice"}
	p := newAccountPicker([]storedCredential{first, second})

	// The old indexOf(labels, choice) path would have returned 0 here.
	if i := p.match("alice"); i != -1 {
		t.Fatalf("bare shared name matched index %d; that is the bug this test exists to prevent", i)
	}
	if i := p.match(""); i != -1 {
		t.Fatalf("empty choice matched index %d, want -1", i)
	}
	if i := p.match("this account"); i != -1 {
		t.Fatalf("unrelated label matched index %d, want -1", i)
	}
}

func TestAccountPickerMatchAcceptsUniqueBareLabel(t *testing.T) {
	p := newAccountPicker([]storedCredential{
		{ID: []byte("aaaaaaaaaaaaaaaa"), UserName: "alice"},
		{ID: []byte("bbbbbbbbbbbbbbbb"), UserName: "bob"},
	})
	if i := p.match("bob"); i != 1 {
		t.Fatalf("unique label matched index %d, want 1", i)
	}
	if i := p.match("alice"); i != 0 {
		t.Fatalf("unique label matched index %d, want 0", i)
	}
}

func TestMenuSelectionKeepsSubtext(t *testing.T) {
	got := menuSelection([]byte("alice\te2f02eed7cb9df6b\n"))
	if got != "alice\te2f02eed7cb9df6b" {
		t.Fatalf("menuSelection = %q, want the label and subtext together", got)
	}
	if got := menuSelection([]byte("Create passkey\n")); got != "Create passkey" {
		t.Fatalf("plain selection = %q, want Create passkey", got)
	}
}

func TestCredIDPrefixMatchesListColumn(t *testing.T) {
	id := []byte("abcdefghijklmnop")
	if got, want := credIDPrefix(id), "6162636465666768"; got != want {
		t.Fatalf("credIDPrefix = %q, want %q (first 8 bytes as hex)", got, want)
	}
	if got := credIDPrefix([]byte("short")); got != "73686f7274" {
		t.Fatalf("short id prefix = %q", got)
	}
	if got := credIDPrefix(nil); got != "" {
		t.Fatalf("empty id prefix = %q, want empty", got)
	}
}

func TestSanitizePickerFieldStripsTabs(t *testing.T) {
	if got := sanitizePickerField("ali\tce\n"); got != "ali ce" {
		t.Fatalf("sanitizePickerField = %q, want %q", got, "ali ce")
	}
}

// The full getAssertion path must sign with the credential the picker
// identified, not the first one that happens to share its username.
func TestGetAssertionDuplicateNamesSelectsChosenCredential(t *testing.T) {
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	first := testCred(t, "aaaaaaaaaaaaaaaa", "example.test", "alice", older)
	second := testCred(t, "bbbbbbbbbbbbbbbb", "example.test", "alice", newer)
	// findForRP reverses storage order, so the picker sees second, then first.
	v := testVaultWith(t, first, second)

	want := newAccountPicker([]storedCredential{second, first}).items[1]
	ap := &scriptedApprover{reply: want.key}
	a := &authenticator{vault: v, approver: ap, logf: func(string, ...any) {}}

	resp := decodeAssertion(t, a.getAssertion(encodeGetAssertion(t, "example.test")))
	if !bytes.Equal(resp.Credential.ID, first.ID) {
		t.Fatalf("signed credential %x, want the older alice %x (the one the picker key named)",
			resp.Credential.ID, first.ID)
	}
	if len(ap.choices) != 2 {
		t.Fatalf("picker offered %d rows, want 2", len(ap.choices))
	}
	if ap.choices[0] == ap.choices[1] {
		t.Fatal("picker offered two identical rows for the two alice accounts")
	}
	expect := newAccountPicker([]storedCredential{second, first})
	if ap.choices[0] != expect.items[0].row || ap.choices[1] != expect.items[1].row {
		t.Fatalf("picker rows = %#v, want newest then oldest", ap.choices)
	}
}

func TestGetAssertionDuplicateNamesBareLabelDenied(t *testing.T) {
	first := testCred(t, "aaaaaaaaaaaaaaaa", "example.test", "alice", time.Now().Add(-time.Hour))
	second := testCred(t, "bbbbbbbbbbbbbbbb", "example.test", "alice", time.Now())
	v := testVaultWith(t, first, second)
	ap := &scriptedApprover{reply: "alice"}
	a := &authenticator{vault: v, approver: ap, logf: func(string, ...any) {}}

	raw := a.getAssertion(encodeGetAssertion(t, "example.test"))
	if raw[0] != statusOperationDenied {
		t.Fatalf("status = 0x%02x, want denied when the picker returns only the shared username", raw[0])
	}
}

func TestGetAssertionSelectsByCredentialIDPrefix(t *testing.T) {
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	first := testCred(t, "aaaaaaaaaaaaaaaa", "example.test", "alice", older)
	second := testCred(t, "bbbbbbbbbbbbbbbb", "example.test", "alice", newer)
	v := testVaultWith(t, first, second)
	ap := &scriptedApprover{reply: credIDPrefix(first.ID)}
	a := &authenticator{vault: v, approver: ap, logf: func(string, ...any) {}}

	resp := decodeAssertion(t, a.getAssertion(encodeGetAssertion(t, "example.test")))
	if !bytes.Equal(resp.Credential.ID, first.ID) {
		t.Fatalf("signed credential %x, want the alice identified by credential id", resp.Credential.ID)
	}
}

func TestGetAssertionAutoApprovePicksNewestWhenNamesCollide(t *testing.T) {
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	first := testCred(t, "aaaaaaaaaaaaaaaa", "example.test", "alice", older)
	second := testCred(t, "bbbbbbbbbbbbbbbb", "example.test", "alice", newer)
	v := testVaultWith(t, first, second)
	a := &authenticator{vault: v, approver: autoApprover{}, logf: func(string, ...any) {}}

	resp := decodeAssertion(t, a.getAssertion(encodeGetAssertion(t, "example.test")))
	if !bytes.Equal(resp.Credential.ID, second.ID) {
		t.Fatalf("auto-approve signed %x, want the newest alice %x", resp.Credential.ID, second.ID)
	}
}
