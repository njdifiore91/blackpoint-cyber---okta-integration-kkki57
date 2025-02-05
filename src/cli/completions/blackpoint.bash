# BlackPoint CLI bash completion script
# Version: 1.0.0

# Main completion function for blackpoint CLI
_blackpoint_completions() {
    local cur prev words cword
    _init_completion || return

    # Get current and previous words
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Handle global flags
    case "${prev}" in
        --config)
            _filedir yaml
            return
            ;;
        --log-level)
            COMPREPLY=($(compgen -W "debug info warn error" -- "${cur}"))
            return
            ;;
        --output)
            COMPREPLY=($(compgen -W "json yaml table" -- "${cur}"))
            return
            ;;
    esac

    # Handle commands and subcommands
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        # Complete root commands
        COMPREPLY=($(compgen -W "integrate collect configure monitor version help" -- "${cur}"))
        return
    fi

    # Handle command-specific subcommands and flags
    case "${COMP_WORDS[1]}" in
        integrate)
            _blackpoint_integrate_completions
            ;;
        collect)
            _blackpoint_collect_completions
            ;;
        configure)
            _blackpoint_configure_completions
            ;;
        monitor)
            _blackpoint_monitor_completions
            ;;
        help)
            COMPREPLY=($(compgen -W "integrate collect configure monitor" -- "${cur}"))
            ;;
    esac
}

# Integration command completions
_blackpoint_integrate_completions() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    case "${prev}" in
        integrate)
            COMPREPLY=($(compgen -W "new list delete update" -- "${cur}"))
            return
            ;;
        --platform)
            COMPREPLY=($(compgen -W "aws azure okta gcp" -- "${cur}"))
            return
            ;;
        --config)
            _filedir yaml
            return
            ;;
        --format)
            COMPREPLY=($(compgen -W "json yaml" -- "${cur}"))
            return
            ;;
    esac

    # Handle flags for integrate subcommands
    case "${COMP_WORDS[2]}" in
        new|update)
            COMPREPLY=($(compgen -W "--platform --config --format --output" -- "${cur}"))
            ;;
        list)
            COMPREPLY=($(compgen -W "--format --output" -- "${cur}"))
            ;;
        delete)
            COMPREPLY=($(compgen -W "--force" -- "${cur}"))
            ;;
    esac
}

# Collection command completions
_blackpoint_collect_completions() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    case "${prev}" in
        collect)
            COMPREPLY=($(compgen -W "start stop status" -- "${cur}"))
            return
            ;;
        --integration-id)
            # Dynamic completion from available integrations would be implemented here
            return
            ;;
        --batch-size)
            COMPREPLY=($(compgen -W "100 500 1000 5000" -- "${cur}"))
            return
            ;;
    esac

    # Handle flags for collect subcommands
    case "${COMP_WORDS[2]}" in
        start)
            COMPREPLY=($(compgen -W "--integration-id --batch-size --timeout" -- "${cur}"))
            ;;
        stop)
            COMPREPLY=($(compgen -W "--integration-id --force" -- "${cur}"))
            ;;
        status)
            COMPREPLY=($(compgen -W "--integration-id --format" -- "${cur}"))
            ;;
    esac
}

# Configure command completions
_blackpoint_configure_completions() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    case "${prev}" in
        configure)
            COMPREPLY=($(compgen -W "set get list" -- "${cur}"))
            return
            ;;
        --key)
            COMPREPLY=($(compgen -W "log-level output-format batch-size timeout" -- "${cur}"))
            return
            ;;
        --value)
            case "${COMP_WORDS[COMP_CWORD-2]}" in
                log-level)
                    COMPREPLY=($(compgen -W "debug info warn error" -- "${cur}"))
                    ;;
                output-format)
                    COMPREPLY=($(compgen -W "json yaml table" -- "${cur}"))
                    ;;
            esac
            return
            ;;
    esac

    # Handle flags for configure subcommands
    case "${COMP_WORDS[2]}" in
        set)
            COMPREPLY=($(compgen -W "--key --value" -- "${cur}"))
            ;;
        get)
            COMPREPLY=($(compgen -W "--key --format" -- "${cur}"))
            ;;
        list)
            COMPREPLY=($(compgen -W "--format" -- "${cur}"))
            ;;
    esac
}

# Monitor command completions
_blackpoint_monitor_completions() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    case "${prev}" in
        monitor)
            COMPREPLY=($(compgen -W "status metrics alerts events" -- "${cur}"))
            return
            ;;
        --component)
            COMPREPLY=($(compgen -W "collectors processors api-gateway storage" -- "${cur}"))
            return
            ;;
        --timerange)
            COMPREPLY=($(compgen -W "1h 6h 12h 24h 7d 30d" -- "${cur}"))
            return
            ;;
    esac

    # Handle flags for monitor subcommands
    case "${COMP_WORDS[2]}" in
        status)
            COMPREPLY=($(compgen -W "--component --format" -- "${cur}"))
            ;;
        metrics)
            COMPREPLY=($(compgen -W "--component --timerange --format" -- "${cur}"))
            ;;
        alerts)
            COMPREPLY=($(compgen -W "--severity --timerange --format" -- "${cur}"))
            ;;
        events)
            COMPREPLY=($(compgen -W "--type --timerange --format" -- "${cur}"))
            ;;
    esac
}

# Register the completion function
complete -F _blackpoint_completions blackpoint