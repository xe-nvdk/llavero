# Troubleshooting

Common failures seen while bringing the daemon up:

- **`no access to /dev/uhid`** — the udev rule from Setup is missing or not reloaded. Re-run the `70-uhid-uaccess.rules` block from the README and `udevadm trigger /dev/uhid`.
- **`no access to /dev/tpmrm0` while already in the `tss` group** — the `systemd --user` manager often survives logout and keeps old credentials. Check start time with `ps -o lstart= -p $(pgrep -u $USER -x systemd)` and reboot (or prefer the udev ACL path from the README instead of relying on the group).
- **Browser never offers the key** — confirm the HID node is tagged as a security token:

  ```sh
  udevadm info -q property -n /dev/hidrawN | grep ID_SECURITY_TOKEN
  ```

- **Registrations land in Chrome's own passkey store** — look for a missing `registered passkey for` line in the journal; prefer Firefox for registrations you intend to keep (see Browser notes in the README).

The README's `-uv-strict` discussion is an example of failing closed when a fingerprint sensor wedges, not advice tied to one laptop.
