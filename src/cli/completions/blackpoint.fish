# Fish shell completion script for BlackPoint CLI tool
# Version: 1.0.0

# Helper function to check if no subcommand is used
function __fish_blackpoint_no_subcommand
    __fish_use_subcommand
end

# Helper function to check if specific command is being used
function __fish_blackpoint_using_command
    set -l cmd (commandline -opc)
    if [ (count $cmd) -gt 1 ]
        if [ $argv[1] = $cmd[2] ]
            return 0
        end
    end
    return 1
end

# Helper function to check current option context
function __fish_blackpoint_using_option
    __fish_seen_argument -l $argv[1]
end

# Dynamic helper to list available security platforms
function __fish_blackpoint_get_platforms
    # Query available platforms from CLI cache
    # This would be replaced with actual implementation
    echo "aws\tAWS Security Platform"
    echo "azure\tAzure Security Platform"
    echo "okta\tOkta Identity Platform"
    echo "gcp\tGoogle Cloud Platform"
end

# Global flags
complete -c blackpoint -n '__fish_blackpoint_no_subcommand' -l config -d 'Path to configuration file'
complete -c blackpoint -n '__fish_blackpoint_no_subcommand' -l log-level -x -a "debug\t'Verbose debug logging' info\t'Standard information logging' warn\t'Warning and higher logging' error\t'Error-only logging'" -d 'Set logging level'
complete -c blackpoint -n '__fish_blackpoint_no_subcommand' -l output -x -a "json\t'JSON formatted output' yaml\t'YAML formatted output' table\t'Human-readable table format'" -d 'Set output format'

# Root commands
complete -c blackpoint -f -n '__fish_blackpoint_no_subcommand' -a integrate -d 'Manage platform integrations'
complete -c blackpoint -f -n '__fish_blackpoint_no_subcommand' -a collect -d 'Control data collection'
complete -c blackpoint -f -n '__fish_blackpoint_no_subcommand' -a configure -d 'Set system configuration'
complete -c blackpoint -f -n '__fish_blackpoint_no_subcommand' -a monitor -d 'View system status'

# integrate command completions
complete -c blackpoint -f -n '__fish_blackpoint_using_command integrate' -a new -d 'Create new integration'
complete -c blackpoint -f -n '__fish_blackpoint_using_command integrate' -a list -d 'List existing integrations'
complete -c blackpoint -f -n '__fish_blackpoint_using_command integrate' -a delete -d 'Delete an integration'
complete -c blackpoint -f -n '__fish_blackpoint_using_command integrate' -a update -d 'Update integration configuration'

complete -c blackpoint -n '__fish_blackpoint_using_command integrate' -l platform -x -a "(__fish_blackpoint_get_platforms)" -d 'Security platform type to integrate'
complete -c blackpoint -n '__fish_blackpoint_using_command integrate' -l config -r -d 'Path to integration configuration file'
complete -c blackpoint -n '__fish_blackpoint_using_command integrate' -l integration-id -x -d 'Unique identifier for the integration'

# collect command completions
complete -c blackpoint -f -n '__fish_blackpoint_using_command collect' -a start -d 'Start data collection'
complete -c blackpoint -f -n '__fish_blackpoint_using_command collect' -a stop -d 'Stop data collection'
complete -c blackpoint -f -n '__fish_blackpoint_using_command collect' -a status -d 'Check collection status'

complete -c blackpoint -n '__fish_blackpoint_using_command collect' -l integration-id -x -d 'Integration identifier for collection control'

# configure command completions
complete -c blackpoint -f -n '__fish_blackpoint_using_command configure' -a set -d 'Set configuration value'
complete -c blackpoint -f -n '__fish_blackpoint_using_command configure' -a get -d 'Get configuration value'
complete -c blackpoint -f -n '__fish_blackpoint_using_command configure' -a list -d 'List all configurations'

complete -c blackpoint -n '__fish_blackpoint_using_command configure' -l key -x -d 'Configuration key to manage'
complete -c blackpoint -n '__fish_blackpoint_using_command configure' -l value -x -d 'Value to set for configuration key'

# monitor command completions
complete -c blackpoint -f -n '__fish_blackpoint_using_command monitor' -a status -d 'View system status'
complete -c blackpoint -f -n '__fish_blackpoint_using_command monitor' -a metrics -d 'View performance metrics'
complete -c blackpoint -f -n '__fish_blackpoint_using_command monitor' -a alerts -d 'View system alerts'
complete -c blackpoint -f -n '__fish_blackpoint_using_command monitor' -a events -d 'View security events'

complete -c blackpoint -n '__fish_blackpoint_using_command monitor' -l component -x -a "collectors\t'Data collection components' processors\t'Data processing components' api\t'API services' storage\t'Storage systems'" -d 'System component to monitor'
complete -c blackpoint -n '__fish_blackpoint_using_command monitor' -l timerange -x -a "1h\t'Last hour' 24h\t'Last 24 hours' 7d\t'Last 7 days' 30d\t'Last 30 days'" -d 'Time range for monitoring data'