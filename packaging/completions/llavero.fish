# fish completion for llavero
# Install as /usr/share/fish/vendor_completions.d/llavero.fish
# Go flags are old-style long options (-vault), not GNU --vault.

complete -c llavero -f

complete -c llavero -o vault -r -d "Path to the encrypted vault file"
complete -c llavero -o unlock -x -a "passphrase tpm tpm+passphrase" -d "Unlock mode for a new vault"
complete -c llavero -o rekey -x -a "passphrase tpm tpm+passphrase" -d "Re-encrypt an existing vault, then exit"
complete -c llavero -o uv -x -a "fingerprint prompt" -d "User verification method"
complete -c llavero -o uv-strict -d "Deny when the fingerprint sensor is unusable"
complete -c llavero -o consent -x -a "prompt fingerprint" -d "How to take consent"
complete -c llavero -o uv-grace -x -a "0 5s 10s" -d "Reuse a fingerprint scan for the same site"
complete -c llavero -o mlock -d "Lock memory against swap (default true)"
complete -c llavero -o list -d "List stored passkeys, then exit"
complete -c llavero -o forget -x -d "Delete passkeys by site or credential id prefix"
complete -c llavero -o auto-approve -d "Approve every request without prompting (testing only)"
complete -c llavero -o passphrase-fd -x -a "0" -d "Read the vault passphrase from this file descriptor"
complete -c llavero -o new-passphrase-fd -x -a "0" -d "Read the new passphrase for -rekey from this fd"
complete -c llavero -o tpm-selftest -d "Seal and unseal a test secret, then exit"
complete -c llavero -o v -d "Log every CTAPHID frame"
complete -c llavero -o h -d "Print flag defaults and exit"
