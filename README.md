# llavero

A software FIDO2 authenticator for Linux. It registers a virtual FIDO HID
device with the kernel, so browsers discover it exactly the way they discover a
hardware security key: no browser extension, no native messaging host, no
account, no daemon socket to go wrong.

Passkeys live in a single AES-256-GCM encrypted file, sealed to this machine's
TPM, and every use requires a fingerprint.

*Llavero* is Spanish for keyring.

```
$ llavero -list
SITE                  ACCOUNT          CREDENTIAL         USES  CREATED
dash.cloudflare.com   89fd29a150f3...  e2f02eed7cb9df6b      8  2026-09-17 20:54
webauthn.io           alice            42e0a5c37ed7ef9e      7  2026-09-17 19:53
```

Tested against Chrome and Firefox on Arch with Hyprland. It should work on any
Linux with a TPM 2.0, `uhid`, and `fprintd`, though those are the only two
browsers and the only desktop it has actually been run on.

## Why this shape

Linux has no platform authenticator. Chrome and Firefox will not talk to a
password manager directly, so every existing option (Bitwarden, KeePassXC,
1Password) intercepts `navigator.credentials` from a browser extension. That is
the part that breaks, and it only ever covers the browsers you installed it in.

Presenting as a USB security key sidesteps all of it.

## Setup

One-time, so the daemon can create HID devices without root:

```sh
echo 'KERNEL=="uhid", SUBSYSTEM=="misc", TAG+="uaccess"' | \
  sudo tee /etc/udev/rules.d/70-uhid-uaccess.rules
sudo udevadm control --reload-rules && sudo udevadm trigger /dev/uhid
```

For TPM binding, grant the active local user access to the TPM resource
manager the same way:

```sh
echo 'SUBSYSTEM=="tpmrm", KERNEL=="tpmrm[0-9]*", TAG+="uaccess"' | \
  sudo tee /etc/udev/rules.d/70-tpmrm-uaccess.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=tpmrm
```

Joining the `tss` group works too, but it is worse in practice. Supplementary
groups are fixed when a process starts, and the `systemd --user` manager
routinely survives a logout and login, so it keeps running with the credentials
it had when you first booted. `usermod` then appears to do nothing and only a
reboot fixes it. The udev rule takes effect immediately because ACLs are
evaluated by UID at `open()` time, and it is narrower than the group: it is
scoped to the active seat session rather than every process you run.

Then:

```sh
go build -o llavero . && install -m755 llavero ~/.local/bin/
llavero -unlock tpm          # creates the vault, no passphrase needed
systemctl --user enable --now llavero.service
```

No udev rule is needed for the HID node itself. Arch already ships
`60-fido-id.rules`, which recognises the FIDO usage page in our report
descriptor, tags the node `uaccess`, and grants the logged-in user an ACL.

### Unlock modes

| Mode | Factors | Starts unattended |
|---|---|---|
| `passphrase` | typed passphrase | no |
| `tpm` | TPM-sealed secret | **yes** |
| `tpm+passphrase` | both | no |

The mode is recorded in the vault header, so the daemon only asks for what that
vault actually needs. Migrate between modes with `-rekey`, which backs the file
up first and refuses to report success until the rewritten vault reopens with
the expected credential count:

```sh
llavero -rekey tpm
```

### Managing passkeys

```sh
llavero -list                    # what is stored
llavero -forget dash.example.com # delete by site
llavero -forget 02fe624b         # or by credential id prefix
```

`-forget` shows what it will delete and asks you to type the site name back.
It refuses to run while the service has that same vault open, because the
daemon holds its own copy in memory and its next write would resurrect
anything deleted underneath it.

### Exporting a portable backup

TPM binding means a copy of `vault.pkv` plus `vault.pkv.tpm` only works on the
machine that sealed it. That is the point, but it also means those files are
not a recovery plan: lose the board and they decrypt to nothing.

To make a copy that opens anywhere with a passphrase, rekey a duplicate rather
than the live vault:

```sh
cp ~/.local/share/llavero/vault.pkv     /tmp/portable.pkv
cp ~/.local/share/llavero/vault.pkv.tpm /tmp/portable.pkv.tpm
llavero -vault /tmp/portable.pkv -rekey passphrase
rm /tmp/portable.pkv.tpm /tmp/portable.pkv.bak-*
```

Both files must be copied: the rekey has to unseal the original secret before
it can re-encrypt under a passphrase. The result holds every credential and is
independent of this machine. The live vault is untouched.

Store it somewhere you would store a recovery code, and redo it after
registering a passkey you care about. Verify it with:

```sh
llavero -vault /tmp/portable.pkv -list
```

### Flags

| Flag | Meaning |
|---|---|
| `-version` | print version, commit and build date, then exit |
| `-vault PATH` | vault file location |
| `-unlock MODE` | unlock mode for a **new** vault |
| `-rekey MODE` | re-encrypt an existing vault, then exit |
| `-uv fingerprint\|prompt` | user verification method |
| `-uv-strict` | deny when the sensor is unusable, instead of falling back |
| `-passphrase-fd N` | read the passphrase from a descriptor (`0` for stdin) |
| `-mlock` | lock memory against swap (default true, degrades with a warning) |
| `-tpm-selftest` | seal and unseal a test secret, then exit |
| `-auto-approve` | approve everything without prompting. Testing only |
| `-v` | log every CTAPHID frame |

## Security model

Two independent layers, each covering what the other cannot:

**TPM binding protects the file at rest.** A 32-byte secret is sealed to this
machine's TPM and mixed into the vault key with HKDF. The sealed blob carries
`FixedTPM` and `FixedParent`, so the TPM refuses to export it. Copy the vault
and the blob to another machine and neither decrypts. Verified: a foreign blob,
a corrupted blob, and a missing blob all fail to open the vault, the corrupted
case being rejected by the TPM itself with `TPM_RC_INTEGRITY`.

It is deliberately **not** bound to PCR values. PCR policies break on firmware
and kernel updates, and a passkey vault that locks you out after a routine
update is worse than one that does not resist an attacker who already has code
execution on your running machine.

**The fingerprint protects the running system.** A TPM-unlocked vault opens
with no typing at login, so the biometric check is what stands between someone
at your unlocked laptop and your accounts. Every registration and every
sign-in requires a scan, on top of an explicit desktop approval that names the
site.

Other properties:

- Private keys are P-256, generated locally, and never leave the vault.
- Attestation is `"none"`. A software authenticator cannot honestly attest to
  anything, and self-attestation would not change that.
- `authenticatorReset` is refused. Wiping every passkey on an unauthenticated
  USB command is not a trade worth making.

What this does **not** protect against:

- **Malware already running as you.** It can ask the TPM to unseal, exactly as
  the daemon does. The fingerprint prompt is the backstop, which is why the
  service runs with `-uv-strict`.
- **Losing the machine's TPM.** A cleared TPM, a board replacement, or a wiped
  `~/.local/share/llavero/` means the passkeys are gone. Keep another
  sign-in method on anything that matters, and back up the vault plus its
  `.tpm` blob, understanding that the pair only works on this machine.

### Process hardening

Applied before the vault is opened, so no decrypted key has ever existed in the
process by the time the protections are in place:

- **Core dumps are disabled**, with `RLIMIT_CORE` set to a hard zero and
  `LimitCORE=0` in the unit. This is the one that mattered most. Without it a
  crash writes the whole process image, every decrypted private key included,
  to wherever `core_pattern` points, which on a systemd machine means
  `/var/lib/systemd/coredump` on disk.
- **`PR_SET_DUMPABLE` is cleared**, which also stops another process running as
  the same user from attaching with `ptrace` and reading keys out of memory.
  The flag is read back with `PR_GET_DUMPABLE` rather than trusted, since there
  is no `/proc` file exposing it and the ownership of `/proc/[pid]` is not the
  indicator it is commonly assumed to be.
- **Memory is locked** with `mlockall(MCL_CURRENT|MCL_FUTURE)` so pages holding
  keys cannot be written to swap. `-mlock=false` turns this off.

None of these are fatal if they fail. A machine that refuses one is still
better served by a working authenticator, and the log says exactly what did not
apply.

#### Locked memory needs two limits raised, not one

`mlockall` fails with `ENOMEM` under the usual 8 MB `RLIMIT_MEMLOCK`, because
that is below the daemon's own resident size. `LimitMEMLOCK=64M` in the user
unit is **not sufficient on its own**: a user unit cannot raise a hard rlimit
above the one the `systemd --user` manager itself holds, since that requires
`CAP_SYS_RESOURCE`. The manager's ceiling has to be raised first:

```sh
sudo mkdir -p /etc/systemd/system/user@.service.d
printf '[Service]\nLimitMEMLOCK=64M\n' | \
  sudo tee /etc/systemd/system/user@.service.d/20-memlock.conf
sudo systemctl daemon-reload
```

Then reboot. A relogin is not enough, because the `systemd --user` manager
commonly survives it and keeps the limits it started with.

Skipping all of this is reasonable if your swap sits on an encrypted volume,
which already covers the threat that locking memory addresses. The daemon says
so in the warning it logs.

### A note on `-uv-strict`

With the flag, a sensor that cannot be reached denies the request. Without it,
the daemon falls back to the desktop approval you just gave and logs loudly.

The installed service sets it. This laptop's fingerprint reader is known to
wedge after suspend when USB re-enumerates, so if that ever locks you out, drop
the flag from the unit or run the daemon by hand with `-uv prompt` until the
sensor is fixed. Failing closed is the right default for a vault that unlocks
itself at login.

## Testing

`cmd/ctaptest` is an independent CTAP2 client. It deliberately redefines the
wire structs rather than importing the daemon's, so an encoding mistake cannot
cancel itself out across both sides.

```sh
go build -o llavero . && go build -o ctaptest ./cmd/ctaptest
./llavero -vault /tmp/test.pkv -auto-approve -passphrase-fd 0 <<< 'testpass123' &
./ctaptest /dev/hidrawN        # the daemon logs which node it became
```

It registers a credential, authenticates with it, and verifies the ECDSA
signature against the public key from registration. It also checks a negative
control (a wrong challenge must fail), that the signature counter advances, and
that an unregistered relying party gets `NO_CREDENTIALS`.

Pass `-state FILE` to register in one run and verify in a later one, which is
how the across-restart and across-rekey checks work.

`llavero -tpm-selftest` exercises the TPM path on its own: seal, unseal,
confirm two seals differ, and confirm a corrupted blob is rejected.



## Browser notes

Everything below was measured against this authenticator on one machine, using
`probe/`. It is recorded because it is not obvious and it cost a while to work
out, not because it is authoritative.

### Firefox is the better client

Measured on the same vault, Firefox goes straight to the fingerprint while
Chrome shows a transport picker first. The reason is architectural, not
cosmetic:

| | Chrome | Firefox |
|---|---|---|
| Hybrid (phone/QR) transport | yes, so a picker is required | none |
| Built-in passkey store | yes, competes for registrations | none |
| `.dummy` sentinel registration | yes | not observed |
| Silent probe calls per request | 2 to 3 | 1 |

Firefox on Linux uses `authenticator-rs`, which speaks USB HID only. With no
phone transport to offer there is nothing to disambiguate, so the request
reaches this authenticator immediately.

The second row matters more than the first. Chrome may quietly register a
passkey into its own profile store instead of this vault, and you would not
find out until you looked. Firefox has no such store, so anything registered
through it lands here.

Prefer Firefox for registering passkeys you intend to keep.

### Chrome's transport picker

Chrome shows a "Passkeys & Security Keys" sheet with a QR code before handing
the request to us. That is Chrome's UI, driven by what the site asks for, and
nothing an authenticator advertises changes it. Measured with `probe/`:

Measured as the delay between the page calling `navigator.credentials.get()`
and the daemon being asked for a fingerprint. That gap is the picker:

| Request shape | Delay before reaching us | Picker |
|---|---|---|
| empty `allowCredentials` (usernameless) | 4.8s | yes |
| `allowCredentials` + `transports: ["usb"]` | 1.0s | no |
| `allowCredentials`, no transport hint | 0.3s | no |
| `hints: ["security-key"]` | 3.8s | some UI |

Naming the credential is what matters. Any site with a username step sends
`allowCredentials` and goes straight to the fingerprint. Only usernameless
flows show the QR sheet, because there Chrome genuinely cannot know whether the
passkey is on this machine or on a phone, and no authenticator-side setting
can or should override that.

### Chrome has its own passkey store

Chrome on Linux now registers passkeys into the browser profile. When a site
does not constrain `authenticatorAttachment`, Chrome may quietly use that
instead of this vault, and our fingerprint prompt is left waiting for a touch
that never comes until it times out.

Tell them apart by `authenticatorAttachment` on the created credential:

- `cross-platform` is this vault
- `platform` with transports `["hybrid","internal"]` is Chrome's own store

Do not use `getTransports()` for this. We advertise CTAP 2.0, which has no
transports field, so Chrome reports `[]` for our credentials and a check for
`"usb"` will mislabel them.

`probe/` is a local page for testing all of this. Serve it with
`python3 -m http.server 8765 --bind 127.0.0.1` and open
<http://localhost:8765/>; `localhost` is a secure context, so WebAuthn works.

### Throwaway probe registrations

Chrome sends a registration for the RP ID `.dummy` to force a user gesture
without revealing which credentials an authenticator holds. A real security key
fails it. We refuse any RP ID that cannot be a domain, which keeps the junk out
of the vault and, more importantly, avoids asking for a fingerprint that
authorises nothing.

Clients also fire two `getAssertion` calls milliseconds apart for a single
sign-in. `-uv-grace` (default 5s) lets the second reuse the scan the first just
completed, scoped to the same site, so one sign-in costs one touch. Set
`-uv-grace 0` to require a scan every time.

## Not implemented

- **CTAP2.1**, credential management over USB, and PIN protocols.
- **CTAPHID_CANCEL during a prompt.** The approval dialog blocks the read loop,
  so a cancelled WebAuthn request times out rather than aborting immediately.

## License

MIT. See [LICENSE](LICENSE).
