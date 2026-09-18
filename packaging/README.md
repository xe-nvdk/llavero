# Packaging files

Reference copies of everything that has to be installed outside the binary.
Distro packages should use these rather than asking users to paste from the
top-level README.

| File | Install to |
|---|---|
| `70-uhid-uaccess.rules` | `/usr/lib/udev/rules.d/` |
| `70-tpmrm-uaccess.rules` | `/usr/lib/udev/rules.d/` (only needed for TPM unlock) |
| `llavero.service` | `/usr/lib/systemd/user/` |
| `user@.service.d-20-memlock.conf` | `/etc/systemd/system/user@.service.d/20-memlock.conf` |
| `llavero.1` | `/usr/share/man/man1/llavero.1` |
| `completions/llavero.bash` | `/usr/share/bash-completion/completions/llavero` |
| `completions/_llavero` | `/usr/share/zsh/site-functions/_llavero` |
| `completions/llavero.fish` | `/usr/share/fish/vendor_completions.d/llavero.fish` |

Both udev rules are mandatory for the features they enable, not optional
extras. A package that installs only the binary will look broken: `/dev/uhid`
is root-only and `/dev/tpmrm0` is `root:tss`.

The `user@.service.d` drop-in raises the locked-memory ceiling. It is separate
because a user unit cannot raise a hard rlimit above the one the
`systemd --user` manager holds, so `LimitMEMLOCK` in `llavero.service` is
silently ignored without it. It also needs a reboot, since that manager
commonly survives a logout.

### Man page and completions

`llavero.1` is hand-written, not generated from `-h`. Gzip it at package
build time if the distro expects `.1.gz`.

From a checkout, without installing:

```sh
man ./packaging/llavero.1
```

Completions can be loaded the same way:

```sh
# bash
source packaging/completions/llavero.bash

# zsh — before compinit, or in a new shell after:
fpath=("$PWD/packaging/completions" $fpath)

# fish
mkdir -p ~/.config/fish/completions
cp packaging/completions/llavero.fish ~/.config/fish/completions/
```
