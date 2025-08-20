#!/bin/bash
# Mini SSH Key Checker - Finds unprotected SSH private keys
# Usage: ./minicheck.sh [directory] [-v]
# Example: ./minicheck.sh ~/.ssh -v
# Exit codes: 0=all protected, 1=error, 2=unprotected found

set -euo pipefail

# Parse arguments
DIR="${1:-$HOME/.ssh}"
VERBOSE="${2:-}"
[[ "$VERBOSE" == "-v" ]] && VERBOSE=true || VERBOSE=false

# Help
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && {
    echo "Usage: $0 [directory] [-v]"
    echo "  directory: Path to check (default: ~/.ssh)"
    echo "  -v: Verbose output"
    echo "  -h: This help"
    exit 0
}

# Show help if no arguments provided (optional - remove this block if you prefer default behavior)
[[ $# -eq 0 ]] && {
    echo "Mini SSH Key Checker - No arguments provided, using default directory: $HOME/.ssh"
    echo "Use '$0 -h' for help or '$0 [directory]' to specify a different path"
    echo ""
}

# Validate directory
[[ ! -d "$DIR" ]] && { echo "ERROR: Directory '$DIR' not found" >&2; exit 1; }
[[ ! -r "$DIR" ]] && { echo "ERROR: Directory '$DIR' not readable" >&2; exit 1; }

# Find and check SSH private keys
UNPROTECTED=0
TOTAL=0

while IFS= read -r -d '' key; do
    # Skip public keys and non-private keys
    [[ "$key" == *.pub ]] && continue
    [[ ! -f "$key" ]] && continue
    grep -q "PRIVATE KEY" "$key" 2>/dev/null || continue
    
    TOTAL=$((TOTAL + 1))
    
    # Test if key has no passphrase
    if ssh-keygen -y -f "$key" -P "" &>/dev/null; then
        echo "UNPROTECTED: $(basename "$key")"
        UNPROTECTED=$((UNPROTECTED + 1))
    elif [[ "$VERBOSE" == true ]]; then
        echo "PROTECTED: $(basename "$key")"
    fi
done < <(find "$DIR" -maxdepth 1 -type f -print0 2>/dev/null)

# Report results
[[ "$VERBOSE" == true ]] && echo "---"
[[ $TOTAL -eq 0 ]] && { echo "No SSH private keys found in $DIR"; exit 0; }
echo "Found $UNPROTECTED unprotected key(s) out of $TOTAL total"
exit $([[ $UNPROTECTED -eq 0 ]] && echo 0 || echo 2)
