package main

// The CTAP2 command handlers. This is the layer that turns a decoded request
// into a signed credential or assertion.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

type authenticator struct {
	vault    *vault
	approver approver
	verifier *fingerprintVerifier // nil when biometric UV is off
	strictUV bool                 // if set, a broken sensor denies instead of falling back
	// fingerprintConsent drops the click-to-approve menu and treats the
	// fingerprint touch as both consent and verification, the way Touch ID and
	// Windows Hello do. The notification names the site before the scan, so
	// the user still sees what they are approving.
	fingerprintConsent bool
	// uvGrace lets a second request for the SAME site reuse a scan that just
	// succeeded. Clients routinely fire two getAssertion calls milliseconds
	// apart, and asking for two touches to sign in once reads as a bug.
	uvGrace time.Duration
	aaguid  [16]byte
	logf    func(string, ...any)

	graceMu   sync.Mutex
	graceRP   string
	graceTime time.Time
}

// recentlyVerified reports whether a successful scan for this exact site is
// still inside the grace window. Scoping it to one site matters: a scan for
// one login must never authorise a different one.
func (a *authenticator) recentlyVerified(rpID string) bool {
	if a.uvGrace <= 0 {
		return false
	}
	a.graceMu.Lock()
	defer a.graceMu.Unlock()
	return a.graceRP == rpID && time.Since(a.graceTime) < a.uvGrace
}

func (a *authenticator) markVerified(rpID string) {
	a.graceMu.Lock()
	defer a.graceMu.Unlock()
	a.graceRP, a.graceTime = rpID, time.Now()
}

// consentIsFingerprint reports whether the touch alone stands in for the menu.
// It is only safe when a sensor is actually available: with no verifier there
// would be no user interaction at all, and a page could mint passkeys in
// silence.
func (a *authenticator) consentIsFingerprint() bool {
	return a.fingerprintConsent && a.verifier != nil
}

// requestConsent asks the user to approve an operation, returning false if they
// declined or could not be asked. With fingerprint consent the touch is the
// whole interaction; otherwise the menu runs first and the touch confirms it.
func (a *authenticator) requestConsent(rpID, title, affirmative, reason string) bool {
	if a.consentIsFingerprint() {
		return a.verifyUserFor(rpID, reason)
	}
	choice, err := a.approver.confirm(title, []string{affirmative, "Cancel"})
	if err != nil {
		a.logf("could not ask for approval: %v", err)
		return false
	}
	if choice != affirmative {
		a.logf("declined by user: %s", reason)
		return false
	}
	return a.verifyUserFor(rpID, reason)
}

// verifyUser is the biometric half of user verification. Consent (the menu)
// has already happened by the time this runs.
//
// A sensor that cannot be used is treated differently from a finger that does
// not match. A non-match denies, always. A hardware failure falls back to the
// approval the user just gave, because this laptop's fingerprint reader is
// known to wedge after suspend, and a vault that locks you out of every
// account until you reboot is a worse outcome than one that leans on the
// prompt you already answered. Run with -uv-strict to invert that.
func (a *authenticator) verifyUser(reason string) bool {
	return a.verifyUserFor("", reason)
}

// verifyUserFor runs the biometric check, honouring the grace window when the
// caller names a site.
func (a *authenticator) verifyUserFor(rpID, reason string) bool {
	if a.verifier == nil {
		return true
	}
	if rpID != "" && a.recentlyVerified(rpID) {
		a.logf("reusing the scan from moments ago for %s", rpID)
		return true
	}
	ok, err := a.verifier.verify(reason)
	if err != nil {
		if a.strictUV {
			a.logf("fingerprint unavailable (%v); denying because -uv-strict is set", err)
			notify("Fingerprint unavailable", "Request denied")
			return false
		}
		a.logf("fingerprint unavailable (%v); accepting the desktop approval alone", err)
		notify("Fingerprint unavailable", "Approved on the desktop prompt alone")
		return true
	}
	if !ok {
		a.logf("fingerprint did not match")
		notify("Fingerprint did not match", reason)
		return false
	}
	if rpID != "" {
		a.markVerified(rpID)
	}
	return true
}

// handle decodes one CTAP2 message and returns the raw response, status byte
// first. Every error path returns a CTAP status rather than a Go error,
// because the transport has no other way to report failure.
func (a *authenticator) handle(payload []byte) []byte {
	if len(payload) == 0 {
		return []byte{statusInvalidLength}
	}
	cmd, body := payload[0], payload[1:]

	switch cmd {
	case ctapGetInfo:
		return a.getInfo()
	case ctapMakeCredential:
		return a.makeCredential(body)
	case ctapGetAssertion:
		return a.getAssertion(body)
	case ctapSelection:
		// Used by browsers to ask "is this the key the user wants to use?".
		return a.selection()
	case ctapReset:
		// Wiping every passkey on an unauthenticated USB command is not a
		// trade we want, so this stays refused.
		a.logf("refusing authenticatorReset")
		return []byte{statusOperationDenied}
	default:
		a.logf("unimplemented CTAP2 command 0x%02x", cmd)
		return []byte{statusNotAllowed}
	}
}

func (a *authenticator) getInfo() []byte {
	info := authenticatorInfo{
		Versions: []string{"FIDO_2_0"},
		AAGUID:   a.aaguid[:],
		Options: map[string]bool{
			"rk":   true,  // discoverable credentials, which is what a passkey is
			"up":   true,  // we can test user presence
			"uv":   true,  // and user verification, via the desktop prompt
			"plat": false, // we present as a removable key, not a platform one
		},
		MaxMsgSize: 1200,
	}
	body, err := ctapEncMode.Marshal(info)
	if err != nil {
		a.logf("getInfo encode failed: %v", err)
		return []byte{statusOther}
	}
	return append([]byte{statusOK}, body...)
}

func (a *authenticator) selection() []byte {
	choice, err := a.approver.confirm("Use Llavero for this site?", []string{"Use it", "Cancel"})
	if err != nil || choice != "Use it" {
		return []byte{statusOperationDenied}
	}
	return []byte{statusOK}
}

func (a *authenticator) makeCredential(body []byte) []byte {
	var req makeCredentialRequest
	if err := ctapDecMode.Unmarshal(body, &req); err != nil {
		a.logf("makeCredential: malformed request: %v", err)
		return []byte{statusInvalidParameter}
	}
	if req.RP.ID == "" || len(req.ClientDataHash) != 32 {
		return []byte{statusInvalidParameter}
	}

	// Chrome sends a throwaway registration for the RP ID ".dummy" to force a
	// user gesture without disclosing which credentials we hold. A real
	// authenticator is expected to fail it. Storing it would leave junk in the
	// vault and, worse, cost a fingerprint scan every time a site triggers one.
	// An RP ID is a domain, so a leading or trailing dot can never be a real
	// origin and is safe to refuse outright.
	if !isPlausibleRPID(req.RP.ID) {
		a.logf("makeCredential: refusing throwaway registration for %q", req.RP.ID)
		return []byte{statusUnsupportedAlgo}
	}

	// We only speak ES256. Refusing early gives the browser a clean error
	// instead of a credential it cannot verify.
	if !supportsES256(req.PubKeyCredParams) {
		a.logf("makeCredential: RP %q did not offer ES256", req.RP.ID)
		return []byte{statusUnsupportedAlgo}
	}

	// excludeList is how an RP says "this user already has a key here". The
	// spec wants user presence before we admit it, but a desktop prompt for a
	// duplicate registration is noise, so we answer directly.
	if a.vault.hasCredentialFor(req.RP.ID, req.ExcludeList) {
		a.logf("makeCredential: %s already has a credential in the exclude list", req.RP.ID)
		return []byte{statusCredentialExcluded}
	}

	label := displayName(req.User)
	title := fmt.Sprintf("Create a passkey for %s?", req.RP.ID)
	if label != "" {
		title = fmt.Sprintf("Create a passkey for %s as %s?", req.RP.ID, label)
	}
	reason := fmt.Sprintf("Create a passkey for %s", req.RP.ID)
	if label != "" {
		reason = fmt.Sprintf("Create a passkey for %s as %s", req.RP.ID, label)
	}
	if !a.requestConsent(req.RP.ID, title, "Create passkey", reason) {
		return []byte{statusOperationDenied}
	}

	cred, priv, err := a.vault.addCredential(req.RP, req.User)
	if err != nil {
		a.logf("makeCredential: vault write failed: %v", err)
		return []byte{statusOther}
	}

	attested, err := a.attestedCredentialData(cred.ID, priv)
	if err != nil {
		a.logf("makeCredential: encoding public key failed: %v", err)
		return []byte{statusOther}
	}

	// UV is set because the user just approved interactively against a vault
	// they unlocked with a passphrase at startup.
	flags := byte(flagUserPresent | flagUserVerified | flagAttestedData)
	authData := buildAuthData(req.RP.ID, flags, 0, attested)

	resp := makeCredentialResponse{
		Fmt:      "none", // self-attestation buys nothing for a software key
		AuthData: authData,
		AttStmt:  map[string]any{},
	}
	out, err := ctapEncMode.Marshal(resp)
	if err != nil {
		a.logf("makeCredential: encode failed: %v", err)
		return []byte{statusOther}
	}

	a.logf("registered passkey for %s (%s), credential %x", req.RP.ID, label, cred.ID[:8])
	notify("Passkey created", fmt.Sprintf("%s (%s)", req.RP.ID, label))
	return append([]byte{statusOK}, out...)
}

func (a *authenticator) getAssertion(body []byte) []byte {
	var req getAssertionRequest
	if err := ctapDecMode.Unmarshal(body, &req); err != nil {
		a.logf("getAssertion: malformed request: %v", err)
		return []byte{statusInvalidParameter}
	}
	if req.RPID == "" || len(req.ClientDataHash) != 32 {
		return []byte{statusInvalidParameter}
	}

	matches := a.vault.findForRP(req.RPID, req.AllowList)
	if len(matches) == 0 {
		a.logf("getAssertion: no credential for %s", req.RPID)
		return []byte{statusNoCredentials}
	}

	// With several accounts at one site, let the user pick rather than
	// silently choosing for them. Rows carry a credential-id subtext (and a
	// disambiguated label when names collide) so two "alice" accounts, or two
	// nameless ones that both fall back to "this account", stay distinct.
	// The choice is resolved by index or credential id, never by the first
	// display-name match.
	chosen := matches[0]
	if len(matches) > 1 {
		picker := newAccountPicker(matches)
		choice, err := a.approver.confirm(
			fmt.Sprintf("Sign in to %s as:", req.RPID), picker.rows())
		if err != nil || choice == "" {
			a.logf("getAssertion: declined or timed out for %s", req.RPID)
			return []byte{statusOperationDenied}
		}
		idx := picker.match(choice)
		if idx < 0 {
			a.logf("getAssertion: picker result %q did not identify a credential for %s", choice, req.RPID)
			return []byte{statusOperationDenied}
		}
		chosen = picker.items[idx].cred
		// Choosing an account is itself the consent, so only verification is
		// left to do.
		if !a.verifyUserFor(req.RPID, fmt.Sprintf("Sign in to %s as %s", req.RPID, picker.items[idx].name)) {
			return []byte{statusOperationDenied}
		}
	} else {
		label := displayName(userEntity{Name: chosen.UserName, DisplayName: chosen.UserDisplay})
		title := fmt.Sprintf("Sign in to %s?", req.RPID)
		if label != "" {
			title = fmt.Sprintf("Sign in to %s as %s?", req.RPID, label)
		}
		reason := fmt.Sprintf("Sign in to %s", req.RPID)
		if label != "" {
			reason = fmt.Sprintf("Sign in to %s as %s", req.RPID, label)
		}
		if !a.requestConsent(req.RPID, title, "Sign in", reason) {
			return []byte{statusOperationDenied}
		}
	}

	priv, err := parsePrivateKey(chosen.PrivateKey)
	if err != nil {
		a.logf("getAssertion: stored key unusable: %v", err)
		return []byte{statusOther}
	}

	count, err := a.vault.bumpSignCount(chosen.ID)
	if err != nil {
		a.logf("getAssertion: could not persist sign count: %v", err)
		return []byte{statusOther}
	}

	authData := buildAuthData(req.RPID, flagUserPresent|flagUserVerified, count, nil)

	// The signature covers authData concatenated with the client data hash.
	// Getting this concatenation wrong is the single most common way an
	// authenticator produces assertions no RP will accept.
	signed := append(append([]byte{}, authData...), req.ClientDataHash...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		a.logf("getAssertion: signing failed: %v", err)
		return []byte{statusOther}
	}

	resp := getAssertionResponse{
		Credential: credentialDescriptor{Type: "public-key", ID: chosen.ID},
		AuthData:   authData,
		Signature:  sig,
		User: &userEntity{
			ID:          chosen.UserID,
			Name:        chosen.UserName,
			DisplayName: chosen.UserDisplay,
		},
	}
	out, err := ctapEncMode.Marshal(resp)
	if err != nil {
		a.logf("getAssertion: encode failed: %v", err)
		return []byte{statusOther}
	}

	a.logf("signed assertion for %s (%s), counter now %d", req.RPID, chosen.UserName, count)
	return append([]byte{statusOK}, out...)
}

// attestedCredentialData builds the attestation block embedded in authData at
// registration: aaguid, credential id, then the COSE public key.
func (a *authenticator) attestedCredentialData(credID []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	pub := priv.PublicKey
	key := coseKey{
		Kty: 2, // EC2
		Alg: algES256,
		Crv: 1, // P-256
		// Fixed 32-byte big-endian coordinates. FillBytes matters here:
		// a coordinate with leading zero bytes would otherwise encode short
		// and the RP would reject the key.
		X: pub.X.FillBytes(make([]byte, 32)),
		Y: pub.Y.FillBytes(make([]byte, 32)),
	}
	coseBytes, err := ctapEncMode.Marshal(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, 16+2+len(credID)+len(coseBytes))
	out = append(out, a.aaguid[:]...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(credID)))
	out = append(out, l[:]...)
	out = append(out, credID...)
	out = append(out, coseBytes...)
	return out, nil
}

func buildAuthData(rpID string, flags byte, signCount uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := make([]byte, 0, 37+len(attested))
	out = append(out, h[:]...)
	out = append(out, flags)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], signCount)
	out = append(out, c[:]...)
	out = append(out, attested...)
	return out
}

// isPlausibleRPID rejects RP IDs that cannot correspond to a real origin.
// This is not a validation of the RP ID against the caller's origin, which is
// the browser's job; it only screens out client sentinels like ".dummy".
func isPlausibleRPID(id string) bool {
	if id == "" || strings.HasPrefix(id, ".") || strings.HasSuffix(id, ".") {
		return false
	}
	if strings.Contains(id, "..") || strings.ContainsAny(id, " /\\:") {
		return false
	}
	return true
}

func supportsES256(params []pubKeyCredParam) bool {
	for _, p := range params {
		if p.Type == "public-key" && p.Alg == algES256 {
			return true
		}
	}
	return false
}

// displayName picks the friendliest label for an account. The user handle is
// opaque binary per spec, so it is only used as a last resort and only when it
// happens to be printable, rather than spraying control bytes into a menu.
func displayName(u userEntity) string {
	if u.Name != "" {
		return u.Name
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if s := strings.TrimSpace(string(u.ID)); s != "" && isPrintable(s) {
		return s
	}
	return "this account"
}

func isPrintable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// credIDPrefix is the same fragment -list prints in the CREDENTIAL column, so
// the picker subtext matches what the user already sees in the vault listing.
func credIDPrefix(id []byte) string {
	n := 8
	if len(id) < n {
		n = len(id)
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%x", id[:n])
}

func sanitizePickerField(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

// accountPickerItem is one row in the multi-account sign-in menu.
//
// row is the omarchy-menu-select three-field form (empty glyph, label,
// subtext). key is what that picker returns for such a row — label\tsubtext —
// which is unique because the subtext is the credential-id prefix. name is
// the friendly display name, kept for logs and the UV reason so those still
// read as "alice" rather than "alice · e2f02eed…".
type accountPickerItem struct {
	cred    storedCredential
	name    string
	label   string
	id      string
	subtext string
	row     string
	key     string
}

type accountPicker struct {
	items []accountPickerItem
}

func newAccountPicker(matches []storedCredential) accountPicker {
	names := make([]string, len(matches))
	counts := make(map[string]int, len(matches))
	for i, c := range matches {
		names[i] = displayName(userEntity{Name: c.UserName, DisplayName: c.UserDisplay})
		counts[names[i]]++
	}

	items := make([]accountPickerItem, len(matches))
	for i, c := range matches {
		id := credIDPrefix(c.ID)
		name := names[i]
		label := sanitizePickerField(name)
		if label == "" {
			label = "this account"
		}
		subtext := id
		if !c.CreatedAt.IsZero() {
			subtext = id + " · " + c.CreatedAt.UTC().Format("2006-01-02")
		}
		if counts[name] > 1 {
			// omarchy shows the subtext, but a backend that only renders
			// the label would still present two identical rows. Fold the
			// credential-id prefix into the label when the name is shared.
			if id != "" {
				label = label + " · " + id
			} else {
				label = fmt.Sprintf("%s · #%d", label, i+1)
			}
		}
		label = sanitizePickerField(label)
		subtext = sanitizePickerField(subtext)
		items[i] = accountPickerItem{
			cred:    c,
			name:    name,
			label:   label,
			id:      id,
			subtext: subtext,
			row:     "\t" + label + "\t" + subtext,
			key:     label + "\t" + subtext,
		}
	}
	return accountPicker{items: items}
}

func (p accountPicker) rows() []string {
	out := make([]string, len(p.items))
	for i, it := range p.items {
		out[i] = it.row
	}
	return out
}

// match maps a picker result onto exactly one row. It accepts the option we
// passed (index), the omarchy label\tsubtext key, or a unique credential-id
// prefix. A bare shared display name is refused: that is the indexOf() bug.
func (p accountPicker) match(choice string) int {
	choice = strings.TrimSpace(choice)
	if choice == "" {
		return -1
	}
	for i, it := range p.items {
		if choice == it.row || choice == it.key {
			return i
		}
	}
	if i := p.matchByCredID(choice); i >= 0 {
		return i
	}
	// Other backends may echo only the visible label. Accept that iff the
	// label is unique in this picker. Two "alice" rows must not collapse
	// to the first match.
	found := -1
	for i, it := range p.items {
		if choice == it.label {
			if found >= 0 {
				return -1
			}
			found = i
		}
	}
	return found
}

func (p accountPicker) matchByCredID(choice string) int {
	token := choice
	if i := strings.LastIndexByte(choice, '\t'); i >= 0 {
		token = choice[i+1:]
	}
	if i := strings.Index(token, " · "); i >= 0 {
		token = token[:i]
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return -1
	}
	found := -1
	for i, it := range p.items {
		if it.id != "" && it.id == token {
			if found >= 0 {
				return -1
			}
			found = i
		}
	}
	return found
}
