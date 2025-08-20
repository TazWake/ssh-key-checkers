#!/bin/bash

# SSH Key Checker - Local Version
# Version: 2.0
# Description: Checks SSH private keys in a specified directory for password protection
# Author: Taz Wake
# Usage: ./localcheck.sh [directory] [options]

set -euo pipefail

# Default values
DEFAULT_SSH_DIR="$HOME/.ssh"
SSH_DIR="$DEFAULT_SSH_DIR"
LOG_FILE=""
VERBOSE=false
QUIET=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display help information
show_help() {
    cat << EOF
SSH Key Checker - Local Version

Usage: $0 [directory] [options]

Arguments:
  directory              Directory to check for SSH keys (default: \$HOME/.ssh)

Options:
  -h, --help            Show this help message
  -l, --log FILE        Log results to specified file
  -v, --verbose         Enable verbose output
  -q, --quiet           Suppress all output except errors
  -V, --version         Show version information

Examples:
  $0                           # Check current user's .ssh directory
  $0 /path/to/ssh/keys        # Check specific directory
  $0 -l audit.log             # Log results to audit.log
  $0 -v -l audit.log          # Verbose output with logging

Exit Codes:
  0 - Success, all keys are password protected
  1 - Error occurred
  2 - Unprotected keys found
  3 - No SSH keys found

EOF
}

# Function to display version information
show_version() {
    echo "SSH Key Checker - Local Version 2.0"
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

# Function to validate SSH key file
is_valid_ssh_key() {
    local key_file="$1"
    
    # Check if file exists and is readable
    if [[ ! -f "$key_file" ]] || [[ ! -r "$key_file" ]]; then
        return 1
    fi
    
    # Check if it's a private key (contains PRIVATE KEY header)
    if ! grep -q "PRIVATE KEY" "$key_file" 2>/dev/null; then
        return 1
    fi
    
    # Skip public keys
    if [[ "$key_file" == *.pub ]]; then
        return 1
    fi
    
    return 0
}

# Function to check if SSH key is password protected
check_key_protection() {
    local key_file="$1"
    
    # Use ssh-keygen to test if key can be read without passphrase
    if ssh-keygen -y -f "$key_file" -P "" &>/dev/null; then
        return 0  # No passphrase (unprotected)
    else
        return 1  # Passphrase protected
    fi
}

# Function to scan directory for SSH keys
scan_directory() {
    local scan_dir="$1"
    local unprotected_count=0
    local total_count=0
    
    log_message "INFO" "Scanning directory: $scan_dir"
    
    # Check if directory exists and is accessible
    if [[ ! -d "$scan_dir" ]]; then
        log_message "ERROR" "Directory does not exist: $scan_dir"
        return 1
    fi
    
    if [[ ! -r "$scan_dir" ]]; then
        log_message "ERROR" "Directory is not readable: $scan_dir"
        return 1
    fi
    
    # Find all SSH private keys in the directory
    local key_files=()
    while IFS= read -r -d '' file; do
        if is_valid_ssh_key "$file"; then
            key_files+=("$file")
        fi
    done < <(find "$scan_dir" -maxdepth 1 -type f -print0 2>/dev/null)
    
    if [[ ${#key_files[@]} -eq 0 ]]; then
        log_message "WARN" "No SSH private keys found in $scan_dir"
        return 3
    fi
    
    log_message "INFO" "Found ${#key_files[@]} SSH private key(s)"
    echo "----------------------------------------------------"
    
    # Check each key for password protection
    for key_file in "${key_files[@]}"; do
        total_count=$((total_count + 1))
        local key_name=$(basename "$key_file")
        
        if check_key_protection "$key_file"; then
            log_message "WARN" "Key: $key_name - NO PASSPHRASE SET"
            unprotected_count=$((unprotected_count + 1))
        else
            log_message "SUCCESS" "Key: $key_name - PASSPHRASE PROTECTED"
        fi
    done
    
    echo "----------------------------------------------------"
    log_message "INFO" "Scan complete: $total_count key(s) checked, $unprotected_count unprotected"
    
    # Return appropriate exit code
    if [[ $unprotected_count -gt 0 ]]; then
        return 2
    else
        return 0
    fi
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
            -*)
                log_message "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [[ -z "$SSH_DIR" ]] || [[ "$SSH_DIR" == "$DEFAULT_SSH_DIR" ]]; then
                    SSH_DIR="$1"
                else
                    log_message "ERROR" "Multiple directories specified"
                    exit 1
                fi
                shift
                ;;
        esac
    done
}

# Main function
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
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
    
    # Display scan information
    if [[ "$QUIET" == "false" ]]; then
        echo "🔎 SSH Key Checker - Local Version"
        echo "===================================================="
        echo "Target Directory: $SSH_DIR"
        echo "Timestamp: $(date)"
        echo "===================================================="
    fi
    
    # Perform the scan
    scan_directory "$SSH_DIR"
    local scan_result=$?
    
    # Exit with appropriate code
    exit $scan_result
}

# Check if script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi