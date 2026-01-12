# fixperms.sh v2.0 - Permission Fixer for cPanel & DirectAdmin

Automated permission fixer for cPanel and DirectAdmin control panels. This script automatically detects your control panel, fixes CHMOD and CHOWN permissions for mail directories, web directories, subdomains, hidden files, and ensures correct ownership based on panel standards and File Protect status.

**Version:** 2.0  
**Author:** DenialHost SPA

## Features

* **Automatic Panel Detection**: Automatically detects cPanel or DirectAdmin and applies appropriate permissions
* **Comprehensive Permission Fixing**: 
  - Mail directories and files (following official cPanel `mailperm` script standards)
  - Web directories (`public_html`, subdomains, addon domains)
  - Hidden files (`.htaccess`, `.well-known/`, etc.)
  - Executable scripts (`.cgi`, `.pl`, `.sh`)
  - SSL certificates and keys
  - SSH keys and configuration files
* **Smart Domain Detection**: Detects subdomains and addon domains outside `public_html` using cPanel's `/var/cpanel/userdata/` configuration files
* **File Protect Detection**: Automatically detects cPanel File Protect status and sets correct ownership (`user:nobody` or `user:user`)
* **Interactive Mode**: User-friendly TUI (Text User Interface) with numbered menus for account selection and options
* **Dry-Run Mode**: Simulate changes without making actual modifications
* **Logging**: Optional logging to `fixperms.log` with timestamps
* **Progress Tracking**: Real-time progress display with file/directory counters and elapsed time
* **Selective Operations**: Run only CHMOD or only CHOWN operations
* **Batch Processing**: Process all accounts or a single account

## Requirements

* Linux server with cPanel or DirectAdmin
* SSH access as `root` (for processing any account) or as the account owner (for self-service)
* Bash 4.0 or newer
* Standard utilities (`find`, `stat`, `chmod`, `chown`, `grep`, etc.)

## Installation

1. **Download the script:**
```bash
wget https://github.com/denialhost/fixperms/releases/latest/download/fixperms.sh
```

2. **Make it executable:**
```bash
chmod +x fixperms.sh
```

3. **Run the script:**
```bash
./fixperms.sh
```

## Usage

### Interactive Mode

If you run the script without arguments, it will start in interactive mode with a user-friendly menu:

```bash
./fixperms.sh
```

The interactive mode allows you to:
* Select scope (all accounts or a single account)
* Choose how to select the account (list, manual entry with autocomplete)
* Select action (CHMOD only, CHOWN only, or both)
* Enable additional options (dry-run, logging)

### Command Line Options

```bash
./fixperms.sh [OPTIONS]
```

**Options:**
* `--account USER` - Specify the user/account to process
* `--dry-run` - Simulate execution without making real changes
* `--log` - Enable logging to `fixperms.log`
* `--chmod-only` - Only execute CHMOD commands (not CHOWN)
* `--chown-only` - Only execute CHOWN commands (not CHMOD)
* `--help` - Show help message and exit

### Examples

**Simulate changes for a specific user:**
```bash
./fixperms.sh --account my_user --dry-run --log
```

**Only fix ownership (CHOWN) for a user:**
```bash
./fixperms.sh --account my_user --chown-only --log
```

**Only fix permissions (CHMOD) for a user:**
```bash
./fixperms.sh --account my_user --chmod-only --log
```

**Run complete fix with logging for current user:**
```bash
./fixperms.sh --log
```

**Complete dry-run (simulate without making changes):**
```bash
./fixperms.sh --account my_user --dry-run
```

**Run complete fix for specific user:**
```bash
./fixperms.sh --account my_user --log
```

## Permission Standards

### cPanel

**Directories:**
* Home directory: `711`
* `public_html`: `750` (File Protect ON) or `755` (File Protect OFF)
* `mail/`: `751` (all subdirectories)
* `.ssh/`: `700`
* `etc/`: `750`
* `ssl/keys`, `ssl/certs`: `700`
* Standard directories: `755`

**Files:**
* Standard files: `644`
* Executable scripts (`.cgi`, `.pl`): `755`
* Shell scripts (`.sh`): `700` (in home) or `755` (in web directories)
* Mail files: `640` (default)
* Special mail files:
  * `maildirsize`: `600`
  * `dovecot-uidvalidity.*`: `444` (read-only)
* `.htaccess`: `644`
* SSH keys: `600`

**Ownership:**
* Standard: `user:user`
* `public_html` and `.htpasswds`: `user:nobody` (File Protect ON) or `user:user` (File Protect OFF)
* Mail directories: `user:mail`

### DirectAdmin

**Directories:**
* Home directory: `711`
* `domains/`: `711`
* `domains/*/public_html`: Not modified (DirectAdmin manages this)
* `domains/*/private_html`: `755`
* `imap/`: `770`
* `imap/*/Maildir`: `751`
* Standard directories: `755`

**Files:**
* Standard files: `644`
* Executable scripts: `755`
* Mail files: `640`
* Backup files: `600`

**Ownership:**
* Standard: `user:user`
* Mail: `user:mail`

## Special Features

### File Protect Detection (cPanel)

The script automatically detects if File Protect is enabled in cPanel by checking:
* `/var/cpanel/conf/apache/main` for `fileprotect=1` or `mod_ruid2=1`
* Current `public_html` group ownership

If File Protect is active (or cannot be determined), `public_html` and `.htpasswds` are set to `user:nobody`. Otherwise, they are set to `user:user`.

### Domain/Subdomain Detection

The script uses multiple methods to detect domains and subdomains outside `public_html`:

1. **Primary Method**: Reads cPanel's `/var/cpanel/userdata/USER/*` configuration files to get DocumentRoot paths
2. **Heuristic Fallback**: Searches for directories containing web indicators (`index.html`, `index.php`, `.htaccess`, WordPress files, etc.)

This ensures that addon domains and subdomains with custom DocumentRoots are properly fixed.

### Hidden Files Handling

The script specifically handles hidden files and directories:
* `.htaccess` files throughout the home directory are set to `644`
* Hidden directories like `.well-known/` in `public_html` are properly fixed
* All hidden files in `public_html` are explicitly processed

## Logging

When `--log` is enabled, the script creates a `fixperms.log` file in the same directory as the script. The log includes:
* Timestamp for each operation
* Detailed information about what is being processed
* File and directory counts
* Elapsed time
* Any errors or warnings

Log entries are color-stripped for better readability in text editors.

## Security Notes

* The script requires appropriate privileges to modify permissions and ownership
* For cPanel/DirectAdmin, running as `root` allows processing any account
* Running as a regular user only allows processing that user's own account
* The script validates user existence and home directory before processing
* Dry-run mode allows safe testing without making changes
* All operations are logged when `--log` is enabled

## Troubleshooting

**Script doesn't detect the control panel:**
* Ensure you're running on a server with cPanel or DirectAdmin installed
* Check that standard panel directories exist (`/usr/local/cpanel` for cPanel, `/usr/local/directadmin` for DirectAdmin)

**Permissions not applied correctly:**
* Run with `--log` to see detailed information about what's being processed
* Use `--dry-run` first to preview changes
* Check that the account's home directory exists and is accessible

**File Protect detection issues:**
* The script assumes File Protect is active if it cannot determine the status (safer default)
* Check `/var/cpanel/conf/apache/main` manually if needed
* Verify current `public_html` ownership with `ls -ld ~/public_html`

## Roadmap

* Configuration file for custom permission rules
* Scheduled execution support
* Email notifications on completion
* Web interface option

## License and Contributions

fixperms.sh is released as open-source software under the MIT License. Free use, modification, and redistribution are encouraged—the goal of the project is to simplify server administration, not to generate profit. Contributions, bug reports, or enhancements are welcome; feel free to share updates through pull requests or forks.

## About

Permission fixer script for cPanel and DirectAdmin control panels. Automatically detects panel type and applies correct permissions and ownership according to official standards.

### Resources

* [GitHub Repository](https://github.com/denialhost/fixperms)
* [Issues](https://github.com/denialhost/fixperms/issues)
* [Releases](https://github.com/denialhost/fixperms/releases)
