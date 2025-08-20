# SSH Key Checker - Quick Start Guide

## Getting Started in 5 Minutes

### 1. Make Scripts Executable
```bash
chmod +x localcheck.sh remotecheck.sh
```

### 2. Test Local SSH Keys
```bash
# Check your own SSH keys
./localcheck.sh

# Check a specific directory
./localcheck.sh /path/to/ssh/keys

# Save results to a log file
./localcheck.sh -l my_audit.log
```

### 3. Test Remote SSH Keys
```bash
# Check a single host
./remotecheck.sh -u your_username hostname.example.com

# Check multiple hosts
./remotecheck.sh -u your_username host1.example.com host2.example.com

# Use a hosts file
./remotecheck.sh -u your_username -f hosts.txt

# Save results to a log file
./remotecheck.sh -u your_username -f hosts.txt -l remote_audit.log
```

## Common Use Cases

### Security Audit
```bash
# Comprehensive local audit with logging
./localcheck.sh -v -l security_audit.log

# Remote audit across multiple systems
./remotecheck.sh -u admin -f production_hosts.txt -l production_audit.log
```

### Compliance Reporting
```bash
# Generate detailed logs for compliance
./localcheck.sh -l compliance_$(date +%Y%m%d).log
./remotecheck.sh -u auditor -f all_hosts.txt -l compliance_$(date +%Y%m%d).log
```

### Automation
```bash
# Quiet mode for automated scripts
./localcheck.sh -q -l daily_check.log
./remotecheck.sh -u admin -f hosts.txt -q -l daily_check.log

# Check exit codes
if [ $? -eq 2 ]; then
    echo "Unprotected keys found!"
    # Send alert or take action
fi
```

## What to Expect

### Successful Local Check
```
🔎 SSH Key Checker - Local Version
====================================================
Target Directory: /home/user/.ssh
Timestamp: 2024-01-15 14:30:00
====================================================
[INFO] Scanning directory: /home/user/.ssh
[INFO] Found 2 SSH private key(s)
----------------------------------------------------
[SUCCESS] Key: id_rsa - PASSPHRASE PROTECTED
[SUCCESS] Key: id_ed25519 - PASSPHRASE PROTECTED
----------------------------------------------------
[INFO] Scan complete: 2 key(s) checked, 0 unprotected
```

### Unprotected Keys Found
```
[WARN] Key: backup_key - NO PASSPHRASE SET
```

### Remote Check Summary
```
====================================================
Audit Summary
====================================================
Total Hosts: 5
Successful: 5
Failed: 0
Total Unprotected Keys: 2
====================================================
```

## Troubleshooting Quick Fixes

### Permission Issues
```bash
# Fix script permissions
chmod +x localcheck.sh remotecheck.sh

# Check SSH key permissions (should be 600)
chmod 600 ~/.ssh/id_rsa
```

### Connection Issues
```bash
# Test SSH connectivity first
ssh username@hostname

# Use verbose mode for debugging
./remotecheck.sh -u username -v hostname
```

### No Keys Found
```bash
# Check if SSH directory exists
ls -la ~/.ssh/

# Verify SSH key format
file ~/.ssh/id_rsa
```

## Next Steps

1. **Read the full README.md** for comprehensive documentation
2. **Test on a non-production system** first
3. **Set up regular automated checks** for ongoing security monitoring
4. **Integrate with your security tools** using the exit codes and logging

## Need Help?

- Run `./localcheck.sh --help` or `./remotecheck.sh --help`
- Check the troubleshooting section in README.md
- Use verbose mode (`-v`) for detailed debugging information
- Ensure all prerequisites are met (SSH tools, permissions, etc.)
