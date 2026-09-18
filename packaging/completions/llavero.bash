# bash completion for llavero
# Install as /usr/share/bash-completion/completions/llavero
# or: source packaging/completions/llavero.bash

_llavero() {
	local cur prev
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"

	local modes="passphrase tpm tpm+passphrase"
	local uv="fingerprint prompt"
	local consent="prompt fingerprint"

	case "$prev" in
	-vault)
		COMPREPLY=($(compgen -f -- "$cur"))
		return
		;;
	-unlock|-rekey)
		COMPREPLY=($(compgen -W "$modes" -- "$cur"))
		return
		;;
	-uv)
		COMPREPLY=($(compgen -W "$uv" -- "$cur"))
		return
		;;
	-consent)
		COMPREPLY=($(compgen -W "$consent" -- "$cur"))
		return
		;;
	-uv-grace)
		COMPREPLY=($(compgen -W "0 5s 10s" -- "$cur"))
		return
		;;
	-passphrase-fd|-new-passphrase-fd)
		COMPREPLY=($(compgen -W "0" -- "$cur"))
		return
		;;
	-forget)
		return
		;;
	esac

	# -mlock defaults to true; the useful completion is turning it off.
	local opts="-vault -unlock -rekey -uv -uv-strict -consent -uv-grace
		-mlock -mlock=false -list -forget -auto-approve
		-passphrase-fd -new-passphrase-fd -tpm-selftest -v -h"

	COMPREPLY=($(compgen -W "$opts" -- "$cur"))
}

complete -F _llavero llavero
