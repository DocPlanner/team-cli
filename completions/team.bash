_team() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="login logout accounts roles request requests status approve reject revoke cancel pending sync audit configure"

    case "${COMP_WORDS[1]}" in
        request)
            [[ "$cur" == -* ]] && COMPREPLY=($(compgen -W "--account -a --role -r --duration -d --justification -j --ticket -t --start -s --wait -w --wait-timeout" -- "$cur"))
            return ;;
        accounts)
            [[ "$cur" == -* ]] && COMPREPLY=($(compgen -W "--json" -- "$cur"))
            return ;;
        status|approve|reject|revoke|cancel)
            [[ "$cur" == -* ]] && COMPREPLY=($(compgen -W "--comment -c" -- "$cur"))
            return ;;
        audit)
            [[ "$cur" == -* ]] && COMPREPLY=($(compgen -W "--actor --account --role --from --to --status --json --no-logs --limit" -- "$cur"))
            return ;;
        configure)
            [[ "$cur" == -* ]] && COMPREPLY=($(compgen -W "--show --edit" -- "$cur"))
            return ;;
    esac

    [[ $COMP_CWORD -eq 1 ]] && COMPREPLY=($(compgen -W "$commands" -- "$cur"))
}

complete -F _team team
