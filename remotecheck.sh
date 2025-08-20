#!/bin/bash

# SSH Key Checker - Remote Version
# Version: 2.0
# Description: Remotely audits SSH keys across multiple hosts for password protection
# Author: Taz Wake
# Usage: ./remotecheck.sh [options] [hosts...]

set -euo pipefail

# Default values
SSH_USER=""
HOSTS_FILE=""
HOSTS=()
LOG_FILE=""
VERBOSE=false
QUIET=false
TIMEOUT=30
SSH_OPTIONS="-o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display help information
show_help() {
    cat << EOF
SSH Key Checker - Remote Version

Usage: $0 [options] [hosts...]

Options:
  -h, --help            Show this help message
  -u, --user USER       SSH username for remote connections (required)
  -f, --hosts-file FILE File containing list of hosts (one per line)
  -l, --log FILE        Log results to specified file
  -v, --verbose         Enable verbose output
  -q, --quiet           Suppress all output except errors
  -t, --timeout SEC     SSH connection timeout in seconds (default: 30)
  -V, --version         Show version information

Arguments:
  hosts                 Space-separated list of hostnames, IPs, or URIs

Examples:
  $0 -u admin host1.example.com host2.example.com
  $0 -u admin -f hosts.txt
  $0 -u admin -l audit.log host1.example.com
  $0 -u admin -v -f hosts.txt -l audit.log

Hosts file format:
  One host per line, supports hostnames, IPs, and URIs:
  host1.example.com
  192.168.1.100
  user@host2.example.com

Exit Codes:
  0 - Success, all keys are password protected
  1 - Error occurred
  2 - Unprotected keys found
  3 - No SSH keys found
  4 - Connection failures

EOF
}

# Function to display version information
show_version() {
    echo "SSH Key Checker - Remote Version 2.0"
    echo "Copyright (c) 2024 Security Team"
}

# Function to log messages
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Output to console unless quiet mode
    if [[ "$QUIET" == "false" ]]; then
        case "$level" in
            "INFO") echo -e "${BLUE}[INFO]${NC} $message" ;;
            "WARN") echo -e "${YELLOW}[WARN]${NC} $message" ;;
            "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
            "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
            *) echo "[$level] $message" ;;
        esac
    fi
    
    # Log to file if specified
    if [[ -n "$LOG_FILE" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi
}

# Function to validate host format
validate_host() {
    local host="$1"
    
    # Basic validation - host should not be empty
    if [[ -z "$host" ]]; then
        return 1
    fi
    
    # Remove user@ prefix for validation
    local clean_host="${host#*@}"
    
    # Check if it's a valid IP address or hostname
    if [[ "$clean_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # IP address format
        return 0
    elif [[ "$clean_host" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        # Hostname format
        return 0
    else
        return 1
    fi
}

# Function to load hosts from file
load_hosts_from_file() {
    local hosts_file="$1"
    
    if [[ ! -f "$hosts_file" ]]; then
        log_message "ERROR" "Hosts file not found: $hosts_file"
        return 1
    fi
    
    if [[ ! -r "$hosts_file" ]]; then
        log_message "ERROR" "Hosts file not readable: $hosts_file"
        return 1
    fi
    
    # Read hosts from file, skipping empty lines and comments
    while IFS= read -r line; do
        # Skip empty lines and comments
        if [[ -n "$line" ]] && [[ ! "$line" =~ ^[[:space:]]*# ]]; then
            # Remove leading/trailing whitespace
            line=$(echo "$line" | xargs)
            if [[ -n "$line" ]]; then
                HOSTS+=("$line")
            fi
        fi
    done < "$hosts_file"
    
    log_message "INFO" "Loaded ${#HOSTS[@]} hosts from $hosts_file"
}

# Function to check SSH key protection remotely
check_remote_key_protection() {
    local key_file="$1"
    
    # Use ssh-keygen to test if key can be read without passphrase
    if ssh-keygen -y -f "$key_file" -P "" &>/dev/null; then
        return 0  # No passphrase (unprotected)
    else
        return 1  # Passphrase protected
    fi
}

# Function to audit remote host
audit_remote_host() {
    local host="$1"
    local unprotected_keys=()
    local total_keys=0
    
    log_message "INFO" "Auditing host: $host"
    
    # Prepare the remote audit script
    local remote_script=$(cat << 'REMOTE_SCRIPT'
#!/bin/bash
set -euo pipefail

# Remote audit script for SSH key checking
unprotected_keys=()
total_keys=0

# Function to check SSH key protection
check_key_protection() {
    local key_file="$1"
    if ssh-keygen -y -f "$key_file" -P "" &>/dev/null; then
        return 0  # No passphrase (unprotected)
    else
        return 1  # Passphrase protected
    fi
}

# Function to validate SSH key file
is_valid_ssh_key() {
    local key_file="$1"
    
    if [[ ! -f "$key_file" ]] || [[ ! -r "$key_file" ]]; then
        return 1
    fi
    
    if ! grep -q "PRIVATE KEY" "$key_file" 2>/dev/null; then
        return 1
    fi
    
    if [[ "$key_file" == *.pub ]]; then
        return 1
    fi
    
    return 0
}

# Get list of home directories for users with real shells
getent passwd | grep -vE '(/sbin/nologin|/bin/false)$' | while IFS=: read -r username _ _ _ _ homedir _; do
    SSH_DIR="${homedir}/.ssh"
    
    # Check if user's .ssh directory exists and is accessible
    if [[ ! -d "$SSH_DIR" ]] || [[ ! -r "$SSH_DIR" ]]; then
        continue
    fi
    
    # Find SSH private keys in the directory
    find "$SSH_DIR" -maxdepth 1 -type f 2>/dev/null | while IFS= read -r key_file; do
        if is_valid_ssh_key "$key_file"; then
            total_keys=$((total_keys + 1))
            key_name=$(basename "$key_file")
            
            if check_key_protection "$key_file"; then
                # Output unprotected key information
                printf "UNPROTECTED:%s:%s:%s\n" "$username" "$key_name" "$key_file"
            else
                # Output protected key information
                printf "PROTECTED:%s:%s:%s\n" "$username" "$key_name" "$key_file"
            fi
        fi
    done
done

# Output summary
echo "SUMMARY:$total_keys"
REMOTE_SCRIPT
)

    # Execute remote script and capture output
    local remote_output
    if ! remote_output=$(ssh $SSH_OPTIONS -o ConnectTimeout="$TIMEOUT" "${SSH_USER}@${host}" bash <<< "$remote_script" 2>/dev/null); then
        log_message "ERROR" "Failed to connect to $host or execute audit script"
        return 1
    fi
    
    # Process remote output
    local unprotected_count=0
    local protected_count=0
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^UNPROTECTED: ]]; then
            # Parse unprotected key information
            IFS=':' read -r _ username key_name key_path <<< "$line"
            unprotected_keys+=("$host:$username:$key_name:$key_path")
            unprotected_count=$((unprotected_count + 1))
            
            if [[ "$QUIET" == "false" ]]; then
                printf "    [ User: %-15s ] ❌ Key: %-20s - NO PASSPHRASE SET\n" "$username" "$key_name"
            fi
            
            # Log to file if specified
            if [[ -n "$LOG_FILE" ]]; then
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] [UNPROTECTED] Host: $host, User: $username, Key: $key_name, Path: $key_path" >> "$LOG_FILE"
            fi
            
        elif [[ "$line" =~ ^PROTECTED: ]]; then
            # Parse protected key information
            IFS=':' read -r _ username key_name key_path <<< "$line"
            protected_count=$((protected_count + 1))
            
            if [[ "$VERBOSE" == "true" ]] && [[ "$QUIET" == "false" ]]; then
                printf "    [ User: %-15s ] 🔒 Key: %-20s - PASSPHRASE PROTECTED\n" "$username" "$key_name"
            fi
        elif [[ "$line" =~ ^SUMMARY: ]]; then
            # Parse summary information
            IFS=':' read -r _ total_keys <<< "$line"
            total_keys=$total_keys
        fi
    done <<< "$remote_output"
    
    # Display summary for this host
    if [[ "$QUIET" == "false" ]]; then
        echo "    Summary: $total_keys key(s) checked, $unprotected_count unprotected, $protected_count protected"
    fi
    
    # Return unprotected count for this host
    return $unprotected_count
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -V|--version)
                show_version
                exit 0
                ;;
            -u|--user)
                if [[ -z "${2:-}" ]]; then
                    log_message "ERROR" "SSH username not specified"
                    exit 1
                fi
                SSH_USER="$2"
                shift 2
                ;;
            -f|--hosts-file)
                if [[ -z "${2:-}" ]]; then
                    log_message "ERROR" "Hosts file path not specified"
                    exit 1
                fi
                HOSTS_FILE="$2"
                shift 2
                ;;
            -l|--log)
                if [[ -z "${2:-}" ]]; then
                    log_message "ERROR" "Log file path not specified"
                    exit 1
                fi
                LOG_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -t|--timeout)
                if [[ -z "${2:-}" ]]; then
                    log_message "ERROR" "Timeout value not specified"
                    exit 1
                fi
                if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    log_message "ERROR" "Timeout must be a positive integer"
                    exit 1
                fi
                TIMEOUT="$2"
                shift 2
                ;;
            -*)
                log_message "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                # Add to hosts array
                if validate_host "$1"; then
                    HOSTS+=("$1")
                else
                    log_message "ERROR" "Invalid host format: $1"
                    exit 1
                fi
                shift
                ;;
        esac
    done
}

# Function to validate configuration
validate_config() {
    # Check if SSH user is specified
    if [[ -z "$SSH_USER" ]]; then
        log_message "ERROR" "SSH username is required. Use -u or --user option."
        show_help
        exit 1
    fi
    
    # Check if hosts are specified
    if [[ -n "$HOSTS_FILE" ]]; then
        load_hosts_from_file "$HOSTS_FILE"
    fi
    
    if [[ ${#HOSTS[@]} -eq 0 ]]; then
        log_message "ERROR" "No hosts specified. Provide hosts as arguments or use -f/--hosts-file option."
        show_help
        exit 1
    fi
    
    # Validate all hosts
    local valid_hosts=()
    for host in "${HOSTS[@]}"; do
        if validate_host "$host"; then
            valid_hosts+=("$host")
        else
            log_message "WARN" "Skipping invalid host: $host"
        fi
    done
    
    HOSTS=("${valid_hosts[@]}")
    
    if [[ ${#HOSTS[@]} -eq 0 ]]; then
        log_message "ERROR" "No valid hosts specified"
        exit 1
    fi
    
    log_message "INFO" "Validated ${#HOSTS[@]} host(s) for auditing"
}

# Main function
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Validate configuration
    validate_config
    
    # Validate log file if specified
    if [[ -n "$LOG_FILE" ]]; then
        local log_dir=$(dirname "$LOG_FILE")
        if [[ ! -d "$log_dir" ]] && [[ "$log_dir" != "." ]]; then
            log_message "ERROR" "Log directory does not exist: $log_dir"
            exit 1
        fi
        
        # Create log file if it doesn't exist
        touch "$LOG_FILE" 2>/dev/null || {
            log_message "ERROR" "Cannot create log file: $LOG_FILE"
            exit 1
        }
        
        log_message "INFO" "Logging enabled: $LOG_FILE"
    fi
    
    # Display audit information
    if [[ "$QUIET" == "false" ]]; then
        echo "🚀 SSH Key Checker - Remote Version"
        echo "===================================================="
        echo "SSH User: $SSH_USER"
        echo "Target Hosts: ${#HOSTS[@]}"
        echo "Timeout: ${TIMEOUT}s"
        echo "Timestamp: $(date)"
        echo "===================================================="
    fi
    
    # Perform remote audits
    local total_unprotected=0
    local failed_hosts=0
    local successful_hosts=0
    
    for host in "${HOSTS[@]}"; do
        echo ""
        echo "===================================================="
        echo "Auditing: $host"
        echo "===================================================="
        
        if audit_remote_host "$host"; then
            successful_hosts=$((successful_hosts + 1))
            # Get the unprotected count from the return value
            local host_unprotected=$?
            total_unprotected=$((total_unprotected + host_unprotected))
        else
            failed_hosts=$((failed_hosts + 1))
            log_message "ERROR" "Failed to audit host: $host"
        fi
    done
    
    # Display final summary
    echo ""
    echo "===================================================="
    echo "Audit Summary"
    echo "===================================================="
    echo "Total Hosts: ${#HOSTS[@]}"
    echo "Successful: $successful_hosts"
    echo "Failed: $failed_hosts"
    echo "Total Unprotected Keys: $total_unprotected"
    echo "===================================================="
    
    # Exit with appropriate code
    if [[ $failed_hosts -eq ${#HOSTS[@]} ]]; then
        exit 1  # All hosts failed
    elif [[ $total_unprotected -gt 0 ]]; then
        exit 2  # Unprotected keys found
    else
        exit 0  # All keys protected
    fi
}

# Check if script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi