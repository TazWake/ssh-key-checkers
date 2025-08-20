# SSH Key Checker

A comprehensive security auditing toolkit for validating SSH key password protection across local and remote systems. This tool helps security professionals and system administrators identify unprotected SSH private keys that could pose security risks.

## Overview

The SSH Key Checker consists of two main scripts designed to audit SSH private keys for password protection:

1. **`localcheck.sh`** - Audits SSH keys on the local system
2. **`remotecheck.sh`** - Remotely audits SSH keys across multiple hosts

Both scripts use the `ssh-keygen` utility to test whether SSH private keys can be read without a passphrase, providing a reliable method to identify unprotected keys.

## Features

### Core Functionality
- **Password Protection Detection**: Uses `ssh-keygen -y` to test key accessibility without passphrase
- **Comprehensive Scanning**: Identifies all SSH private keys in specified directories
- **User Account Discovery**: Automatically discovers user accounts and their SSH directories
- **Detailed Reporting**: Provides clear status indicators for each key (🔒 Protected, ❌ Unprotected)

### Security Features
- **Strict Error Handling**: Implements `set -euo pipefail` for robust error handling
- **Input Validation**: Validates all user inputs and file paths
- **Secure SSH Options**: Uses secure SSH connection parameters for remote operations
- **Logging Capabilities**: Comprehensive logging for audit trails and compliance

### User Experience
- **Color-coded Output**: Easy-to-read status indicators
- **Command-line Options**: Flexible configuration through command-line arguments
- **Help System**: Built-in help and version information
- **Exit Codes**: Meaningful exit codes for automation and scripting

## Scripts

### localcheck.sh

**Purpose**: Audits SSH private keys in a specified directory for password protection.

**Usage**:
```bash
./localcheck.sh [directory] [options]
```

**Arguments**:
- `directory` - Directory to check for SSH keys (default: `$HOME/.ssh`)

**Options**:
- `-h, --help` - Show help message
- `-l, --log FILE` - Log results to specified file
- `-v, --verbose` - Enable verbose output
- `-q, --quiet` - Suppress all output except errors
- `-V, --version` - Show version information

**Examples**:
```bash
# Check current user's .ssh directory
./localcheck.sh

# Check specific directory
./localcheck.sh /path/to/ssh/keys

# Log results to file
./localcheck.sh -l audit.log

# Verbose output with logging
./localcheck.sh -v -l audit.log
```

**Exit Codes**:
- `0` - Success, all keys are password protected
- `1` - Error occurred
- `2` - Unprotected keys found
- `3` - No SSH keys found

### remotecheck.sh

**Purpose**: Remotely audits SSH keys across multiple hosts for password protection.

**Usage**:
```bash
./remotecheck.sh [options] [hosts...]
```

**Required Options**:
- `-u, --user USER` - SSH username for remote connections

**Optional Options**:
- `-f, --hosts-file FILE` - File containing list of hosts (one per line)
- `-l, --log FILE` - Log results to specified file
- `-v, --verbose` - Enable verbose output
- `-q, --quiet` - Suppress all output except errors
- `-t, --timeout SEC` - SSH connection timeout in seconds (default: 30)
- `-h, --help` - Show help message
- `-V, --version` - Show version information

**Arguments**:
- `hosts` - Space-separated list of hostnames, IPs, or URIs

**Examples**:
```bash
# Audit specific hosts
./remotecheck.sh -u admin host1.example.com host2.example.com

# Use hosts file
./remotecheck.sh -u admin -f hosts.txt

# Log results to file
./remotecheck.sh -u admin -l audit.log host1.example.com

# Verbose output with hosts file and logging
./remotecheck.sh -u admin -v -f hosts.txt -l audit.log
```

**Hosts File Format**:
```
# One host per line, supports hostnames, IPs, and URIs
host1.example.com
192.168.1.100
user@host2.example.com
```

**Exit Codes**:
- `0` - Success, all keys are password protected
- `1` - Error occurred
- `2` - Unprotected keys found
- `3` - No SSH keys found
- `4` - Connection failures

## Installation

1. **Download the scripts** to your system
2. **Make them executable**:
   ```bash
   chmod +x localcheck.sh remotecheck.sh
   ```
3. **Ensure SSH tools are available**:
   ```bash
   which ssh-keygen ssh
   ```

## Prerequisites

### Local System
- Bash shell (version 4.0 or higher)
- `ssh-keygen` utility
- Read access to SSH directories

### Remote Systems
- SSH access with appropriate user privileges
- `ssh-keygen` utility on remote systems
- User accounts with accessible home directories

## Security Considerations

### Key Protection Testing
The scripts use `ssh-keygen -y -f keyfile -P ""` to test password protection. This method:
- **Does not modify keys**: Only attempts to read them
- **Is non-intrusive**: Safe for production environments
- **Provides reliable results**: Standard SSH tool behavior

### Access Requirements
- **Local scanning**: Requires read access to SSH directories
- **Remote scanning**: Requires SSH access with user account privileges
- **No elevated privileges**: Scripts run with user-level permissions

### Network Security
- **SSH connections**: Use secure SSH options by default
- **Timeout protection**: Configurable connection timeouts
- **Host validation**: Input validation for host specifications

## Output Examples

### Local Check Output
```
🔎 SSH Key Checker - Local Version
====================================================
Target Directory: /home/user/.ssh
Timestamp: 2024-01-15 14:30:00
====================================================
[INFO] Scanning directory: /home/user/.ssh
[INFO] Found 3 SSH private key(s)
----------------------------------------------------
[SUCCESS] Key: id_rsa - PASSPHRASE PROTECTED
[WARN] Key: id_ed25519 - NO PASSPHRASE SET
[SUCCESS] Key: backup_key - PASSPHRASE PROTECTED
----------------------------------------------------
[INFO] Scan complete: 3 key(s) checked, 1 unprotected
```

Example Local Check 

<img width="701" height="371" alt="image" src="https://github.com/user-attachments/assets/9c79a35e-b247-456a-81e8-71b86ba17e24" />


### Remote Check Output
```
🚀 SSH Key Checker - Remote Version
====================================================
SSH User: admin
Target Hosts: 2
Timeout: 30s
Timestamp: 2024-01-15 14:30:00
====================================================

====================================================
Auditing: host1.example.com
====================================================
[INFO] Auditing host: host1.example.com
    [ User: admin          ] 🔒 Key: id_rsa           - PASSPHRASE PROTECTED
    [ User: admin          ] ❌ Key: backup_key       - NO PASSPHRASE SET
    Summary: 2 key(s) checked, 1 unprotected, 1 protected

====================================================
Audit Summary
====================================================
Total Hosts: 2
Successful: 2
Failed: 0
Total Unprotected Keys: 1
====================================================
```

## Troubleshooting

### Common Issues

**Permission Denied Errors**:
- Ensure read access to SSH directories
- Check SSH key file permissions (should be 600)
- Verify user account access on remote systems

**Connection Failures**:
- Verify SSH connectivity to target hosts
- Check SSH user credentials and permissions
- Ensure SSH service is running on target systems

**No Keys Found**:
- Verify SSH directories exist and contain private keys
- Check file permissions and accessibility
- Ensure keys are in standard SSH key formats

### Debug Mode
Use verbose mode (`-v`) for detailed output:
```bash
./localcheck.sh -v
./remotecheck.sh -u admin -v host1.example.com
```

## Logging

Both scripts support comprehensive logging:
- **Console output**: Real-time status updates
- **File logging**: Persistent audit trails
- **Structured format**: Timestamped entries with log levels

Log entries include:
- Timestamp and log level
- Host and user information
- Key file details
- Protection status

## Automation

The scripts are designed for automation:
- **Exit codes**: Meaningful return values for scripts
- **Quiet mode**: Suppress output for automated execution
- **Logging**: Persistent audit trails for compliance
- **Batch processing**: Support for multiple hosts and directories

## Compliance and Auditing

These tools support various compliance requirements:
- **Security audits**: Identify unprotected SSH keys
- **Compliance reporting**: Detailed logs for regulatory requirements
- **Risk assessment**: Quantify exposure from unprotected keys
- **Remediation tracking**: Monitor security improvements over time

## Contributing

When contributing to these scripts:
- Follow the established coding standards
- Maintain backward compatibility
- Add appropriate error handling
- Include comprehensive testing
- Update documentation

## License

This project is licensed under the terms specified in the project's LICENSE file.

## Support

For issues, questions, or contributions:
- Review the troubleshooting section
- Check script help output (`-h` or `--help`)
- Ensure all prerequisites are met
- Verify system compatibility

---


**Note**: These scripts are designed for security auditing and should be used responsibly. Always ensure you have proper authorization before scanning systems, and respect privacy and security policies in your environment.
