#!/bin/bash

# fixperms.sh - Script to fix CHMOD and CHOWN permissions according to control panel
# Compatible with cPanel and DirectAdmin
# Version: 2.0
# Author: DenialHost SPA

# Global variables
SCRIPT_NAME="fixperms.sh"
SCRIPT_VERSION="2.0"
SCRIPT_AUTHOR="DenialHost SPA"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/fixperms.log"
DRY_RUN=false
LOG_ENABLED=false
CHMOD_ONLY=false
CHOWN_ONLY=false
ACCOUNT=""
OS_TYPE=""
OS_DISTRO=""
OS_VERSION=""
OS_KERNEL=""
PANEL_TYPE=""
SKIP_CHMOD=false
SKIP_CHOWN=false
INTERACTIVE_MODE=false
PROCESS_ALL=false
DA_OFFICIAL_SCRIPT_EXECUTED=false  # Track if the official DirectAdmin script was already executed

# Global variables for interactive menus
MENU_SCOPE_RESULT=""
MENU_HOW_SELECT_RESULT=""
MENU_ACCOUNT_RESULT=""
MENU_USERNAME_RESULT=""
SUGGESTIONS_ARRAY=()

# Variables for progress
PROCESSED_FILES=0
PROCESSED_DIRS=0
CHOWN_PROCESSED_FILES=0
CHOWN_PROCESSED_DIRS=0
TOTAL_FILES=0
TOTAL_DIRS=0
START_TIME=$(date +%s)
SPINNER_INDEX=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Logging function
log_to_file() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [ "$LOG_ENABLED" = true ]; then
        local clean_message=$(echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/\r//g')
        echo "[$timestamp] $clean_message" >> "$LOG_FILE"
    fi
}

# Function to show message
log() {
    local message="$1"
    echo -e "$message"
    log_to_file "$message"
}

# Draw header
draw_header() {
    local width=$(tput cols 2>/dev/null || echo 80)
    
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${BOLD}${WHITE}  $SCRIPT_NAME v$SCRIPT_VERSION${NC}  -  ${GREEN}Permission Fixer${NC}                                    ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${CYAN}Created by:${NC} $SCRIPT_AUTHOR  ${CYAN}│${NC}  ${CYAN}Date:${NC} $(date '+%Y-%m-%d %H:%M:%S')                                ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to repeat characters
repeat_char() {
    local char="$1"
    local count="$2"
    # Validate that count is a number
    if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -le 0 ]; then
        echo -n ""
        return
    fi
    # Use printf with padding
    printf "%${count}s" "" | sed "s/ /${char}/g"
}

# Draw information panel
draw_info_panel() {
    local width=$(tput cols 2>/dev/null || echo 80)
    local dash_len=$((width - 26))
    local panel_display="None"
    local panel_color="${NC}"
    
    if [ "$PANEL_TYPE" = "cpanel" ]; then
        panel_display="cPanel"
        panel_color="${GREEN}"
    elif [ "$PANEL_TYPE" = "directadmin" ]; then
        panel_display="DirectAdmin"
        panel_color="${GREEN}"
    fi
    
    echo -e "${YELLOW}┌─ System Information${NC}$(repeat_char '─' $dash_len)${YELLOW}┐${NC}"
    echo -e "${YELLOW}│${NC} ${CYAN}OS:${NC} $OS_DISTRO $OS_VERSION  ${CYAN}│${NC}  ${CYAN}Kernel:${NC} $OS_KERNEL  ${CYAN}│${NC}  ${CYAN}Panel:${NC} ${panel_color}${panel_display}${NC}  ${CYAN}│${NC}  ${CYAN}User:${NC} ${GREEN}$ACCOUNT${NC}  ${YELLOW}│${NC}"
    dash_len=$((width - 2))
    echo -e "${YELLOW}└$(repeat_char '─' $dash_len)┘${NC}"
    echo ""
}

# Draw output area (border)
draw_output_border() {
    local width=$(tput cols 2>/dev/null || echo 80)
    local dash_len=$((width - 21))
    echo -e "${CYAN}┌─ Process Output${NC}$(repeat_char '─' $dash_len)${CYAN}┐${NC}"
}

draw_output_border_bottom() {
    local width=$(tput cols 2>/dev/null || echo 80)
    local dash_len=$((width - 2))
    echo -e "${CYAN}└$(repeat_char '─' $dash_len)┘${NC}"
}

# Spinner simple
get_spinner_char() {
    local spin_chars='|/-\'
    SPINNER_INDEX=$(((SPINNER_INDEX + 1) % 4))
    echo -n "${spin_chars:$SPINNER_INDEX:1}"
}

# Show progress line (updates in the same place)
show_progress_line() {
    local message="$1"
    local elapsed=$(( $(date +%s) - START_TIME ))
    local mins=$((elapsed / 60))
    local secs=$((elapsed % 60))
    
    local spin=$(get_spinner_char)
    
    # Truncate message if too long
    local display_msg="$message"
    if [ ${#display_msg} -gt 45 ]; then
        display_msg="${display_msg:0:42}..."
    fi
    
    printf "\r${CYAN}[%s]${NC} %-45s ${CYAN}│${NC} ${GREEN}Files:${NC} %d  ${CYAN}│${NC} ${GREEN}Dirs:${NC} %d  ${CYAN}│${NC} ${GREEN}Time:${NC} %dm %ds" \
        "$spin" "$display_msg" "$PROCESSED_FILES" "$PROCESSED_DIRS" "$mins" "$secs"
    
    # Log without spinner and return code
    local log_msg=$(echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g')
    log_to_file "$log_msg [Files: $PROCESSED_FILES, Dirs: $PROCESSED_DIRS, Time: ${mins}m ${secs}s]"
}

# Show help
show_help() {
    cat << EOF
${GREEN}$SCRIPT_NAME${NC} - Script to fix CHMOD and CHOWN permissions according to control panel

${YELLOW}USAGE:${NC}
    $SCRIPT_NAME [OPTIONS]

${YELLOW}OPTIONS:${NC}
    --account USER        Specify the user/account to process
    --dry-run             Simulate execution without making real changes
    --log                 Enable logging to fixperms.log
    --chmod-only          Only execute CHMOD commands (not CHOWN)
    --chown-only          Only execute CHOWN commands (not CHMOD)
    --help                Show this help message and exit

${YELLOW}INTERACTIVE MODE:${NC}
    If no options are provided, the script will run in interactive mode
    with numbered menus to select account, action, and options.

${YELLOW}NOTES:${NC}
    - The script automatically detects the operating system and distribution
    - Automatically detects cPanel or DirectAdmin
    - If --account is not specified, it will attempt to use the current user
    - Log file is created at: $LOG_FILE
    - TUI interface that shows real-time progress

${YELLOW}EXAMPLES:${NC}
    # Simulate changes for a specific user
    ./$SCRIPT_NAME --account my_user --dry-run --log

    # Only fix ownership (CHOWN) for a user
    ./$SCRIPT_NAME --account my_user --chown-only --log

    # Only fix permissions (CHMOD) for a user
    ./$SCRIPT_NAME --account my_user --chmod-only --log

    # Run complete with log for current user
    ./$SCRIPT_NAME --log

    # Complete dry-run (simulate without making changes)
    ./$SCRIPT_NAME --account my_user --dry-run

    # Run complete for specific user
    ./$SCRIPT_NAME --account my_user --log

    # Interactive mode (no arguments)
    ./$SCRIPT_NAME

${YELLOW}STANDARD PERMISSIONS:${NC}
    ${BLUE}cPanel:${NC}
      - Directories: 755
      - Files: 644
      - Executable scripts: 755
      - Owner: user:user
    
    ${BLUE}DirectAdmin:${NC}
      - Directories: 755
      - Files: 644
      - Executable scripts: 755
      - Owner: user:user

EOF
}

# Detect detailed operating system
detect_os() {
    if [[ "$OSTYPE" != "linux-gnu"* ]] && [[ "$OSTYPE" != "linux"* ]]; then
        log "${RED}[ERROR]${NC} Unsupported operating system: $OSTYPE"
        log "${YELLOW}[INFO]${NC} This script is designed for Linux"
        return 1
    fi
    
    OS_TYPE="linux"
    
    # Detect distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_DISTRO="$NAME"
        OS_VERSION="$VERSION_ID"
    elif [ -f /etc/redhat-release ]; then
        OS_DISTRO=$(cat /etc/redhat-release | cut -d' ' -f1)
        OS_VERSION=$(cat /etc/redhat-release | sed -E 's/.*release ([0-9.]+).*/\1/')
    elif [ -f /etc/debian_version ]; then
        OS_DISTRO="Debian"
        OS_VERSION=$(cat /etc/debian_version)
    else
        OS_DISTRO="Linux"
        OS_VERSION="Unknown"
    fi
    
    # Kernel
    OS_KERNEL=$(uname -r)
    
    return 0
}

# Detect File Protect in cPanel
detect_file_protect() {
    # Detect if File Protect is enabled in cPanel
    # If File Protect is active, public_html should be 750 with group nobody
    # If File Protect is disabled, public_html should be 755 with group user
    # IMPORTANT: If we cannot determine the state, assume File Protect is ACTIVE (safer default)
    if [ "$PANEL_TYPE" != "cpanel" ]; then
        return 1
    fi
    
    # Check if File Protect is explicitly disabled in cPanel configuration
    if [ -f "/var/cpanel/conf/apache/main" ]; then
        if grep -q "fileprotect=0" /var/cpanel/conf/apache/main 2>/dev/null; then
            # Explicitly disabled - check if mod_ruid2 is also disabled
            if ! grep -q "mod_ruid2=1" /var/cpanel/conf/apache/main 2>/dev/null; then
                # Check by the current public_html directory group
                local user_home="$1"
                if [ -d "$user_home/public_html" ]; then
                    local pub_html_group=$(stat -c "%G" "$user_home/public_html" 2>/dev/null)
                    if [ "$pub_html_group" != "nobody" ]; then
                        return 1  # File Protect is explicitly disabled
                    fi
                fi
            fi
        fi
    fi
    
    # Check if File Protect is enabled in cPanel configuration
    if [ -f "/var/cpanel/conf/apache/main" ]; then
        if grep -q "fileprotect=1" /var/cpanel/conf/apache/main 2>/dev/null; then
            return 0  # File Protect is active
        fi
    fi
    
    # Check if mod_ruid2 is enabled (alternative to File Protect)
    if [ -f "/var/cpanel/conf/apache/main" ]; then
        if grep -q "mod_ruid2=1" /var/cpanel/conf/apache/main 2>/dev/null; then
            return 0  # File Protect equivalent is active
        fi
    fi
    
    # Check by the current public_html directory group
    local user_home="$1"
    if [ -d "$user_home/public_html" ]; then
        local pub_html_group=$(stat -c "%G" "$user_home/public_html" 2>/dev/null)
        if [ "$pub_html_group" = "nobody" ]; then
            return 0  # File Protect is active (based on current state)
        fi
        # If group is not "nobody", but we can't determine from config, assume active (safer)
    fi
    
    # If we cannot determine the state, assume File Protect is ACTIVE (safer default)
    # This ensures public_html and .htpasswds get usuario:nobody ownership
    return 0  # Assume File Protect is active if state cannot be determined
}

# Detect control panel
detect_panel() {
    # Detect cPanel
    if [ -d "/usr/local/cpanel" ] || [ -f "/usr/local/cpanel/version" ] || [ -d "/var/cpanel" ]; then
        PANEL_TYPE="cpanel"
        local cpanel_version=""
        if [ -f "/usr/local/cpanel/version" ]; then
            cpanel_version=$(cat /usr/local/cpanel/version 2>/dev/null | head -1)
        fi
        log "${GREEN}[INFO]${NC} Panel detected: cPanel $cpanel_version"
        return 0
    fi
    
    # Detect DirectAdmin
    if [ -d "/usr/local/directadmin" ] || [ -f "/usr/local/directadmin/directadmin" ]; then
        PANEL_TYPE="directadmin"
        local da_version=""
        if [ -f "/usr/local/directadmin/scripts/version.sh" ]; then
            da_version=$(bash /usr/local/directadmin/scripts/version.sh 2>/dev/null | head -1)
        fi
        log "${GREEN}[INFO]${NC} Panel detected: DirectAdmin $da_version"
        return 0
    fi
    
    PANEL_TYPE="none"
    log "${YELLOW}[WARNING]${NC} Neither cPanel nor DirectAdmin detected"
    log "${YELLOW}[INFO]${NC} Using standard Linux permissions"
    return 0
}

# Validate user
validate_user() {
    if [ -z "$ACCOUNT" ]; then
        ACCOUNT=$(whoami)
        log "${YELLOW}[INFO]${NC} Using current user: $ACCOUNT"
    fi
    
    if ! id "$ACCOUNT" &>/dev/null; then
        log "${RED}[ERROR]${NC} User '$ACCOUNT' does not exist"
        return 1
    fi
    
    log "${GREEN}[INFO]${NC} User validated: $ACCOUNT"
    return 0
}

# Get home directory
get_user_home() {
    local user_home=""
    
    if [ "$PANEL_TYPE" = "cpanel" ] || [ "$PANEL_TYPE" = "directadmin" ]; then
        user_home="/home/$ACCOUNT"
        if [ ! -d "$user_home" ]; then
            user_home=$(eval echo ~$ACCOUNT)
        fi
    else
        user_home=$(eval echo ~$ACCOUNT)
    fi
    
    # Verify that the home directory exists and is a valid directory
    # Some users may have /dev/null as home (e.g., jetbackups)
    if [ ! -d "$user_home" ]; then
        log "${RED}[ERROR]${NC} Could not determine home directory or it is not a valid directory"
        log "${YELLOW}[INFO]${NC} Home detected: $user_home (may be /dev/null or other special file)"
        return 1
    fi
    
    echo "$user_home"
    return 0
}

# Apply CHMOD with progress
apply_chmod() {
    local user_home="$1"
    
    if [ "$SKIP_CHMOD" = true ]; then
        log "${YELLOW}[INFO]${NC} CHMOD skipped (--chown-only enabled)"
        return 0
    fi
    
    log "${BLUE}[CHMOD]${NC} Applying permissions in: $user_home"
    
    if [ "$DRY_RUN" = true ]; then
        show_progress_line "Analizando permisos actuales..."
        log "${YELLOW}[DRY-RUN]${NC} Analyzing permissions and detecting necessary changes..."
        
        # Optimization: Use find with -printf to get permissions faster
        # Analyze directories that need changes
        local dirs_need_fix=0
        local files_need_fix=0
        local scripts_need_fix=0
        local total_dirs=0
        local total_files=0
        
        # Process directories according to panel
        local expected_dir_perm="755"
        if [ "$PANEL_TYPE" = "cpanel" ]; then
            expected_dir_perm="755"  # Most directories in cPanel are 755, but there are exceptions
        elif [ "$PANEL_TYPE" = "directadmin" ]; then
            expected_dir_perm="755"  # Most directories in DirectAdmin are 755, but there are exceptions
        fi
        
        while IFS= read -r -d '' item; do
            total_dirs=$((total_dirs + 1))
            local current_perm=$(stat -c "%a" "$item" 2>/dev/null)
            local item_path=$(echo "$item" | sed "s|^$user_home/||")
            
            # Determine expected permission according to directory type and panel
            local expected_perm=""
            if [ "$PANEL_TYPE" = "cpanel" ]; then
                case "$item_path" in
                    "") expected_perm="711" ;;  # /home/usuario
                    .ssh*) expected_perm="700" ;;
                    public_html) 
                        if detect_file_protect "$user_home"; then
                            expected_perm="750"
                        else
                            expected_perm="755"
                        fi
                        ;;
                    etc*) expected_perm="750" ;;
                    mail|mail/*) expected_perm="751" ;;  # ALL directories in mail are 751
                    tmp) expected_perm="755" ;;
                    logs) expected_perm="700" ;;
                    .cpanel) expected_perm="700" ;;
                    perl5) expected_perm="755" ;;
                    ssl) expected_perm="700" ;;
                    ssl/keys) expected_perm="700" ;;
                    ssl/certs) expected_perm="700" ;;
                    public_html/cgi-bin) expected_perm="755" ;;
                    *) expected_perm="755" ;;
                esac
            elif [ "$PANEL_TYPE" = "directadmin" ]; then
                case "$item_path" in
                    "") expected_perm="711" ;;  # /home/usuario
                    .ssh*) expected_perm="700" ;;
                    domains) expected_perm="711" ;;
                    domains/*) expected_perm="711" ;;
                    domains/*/public_html) expected_perm="" ;;  # Do not modify
                    domains/*/private_html) expected_perm="755" ;;
                    domains/*/logs) expected_perm="755" ;;
                    imap) expected_perm="770" ;;
                    imap/*) expected_perm="770" ;;
                    imap/*/Maildir) expected_perm="751" ;;
                    imap/*/Maildir/cur) expected_perm="751" ;;
                    imap/*/Maildir/new) expected_perm="751" ;;
                    imap/*/Maildir/tmp) expected_perm="751" ;;
                    tmp) expected_perm="700" ;;
                    backups) expected_perm="700" ;;
                    user_backups) expected_perm="711" ;;
                    .trash) expected_perm="770" ;;
                    .spamassassin) expected_perm="771" ;;
                    *) expected_perm="755" ;;
                esac
            else
                expected_perm="755"
            fi
            
            # Only check if an expected permission was defined
            if [ -n "$expected_perm" ] && [ "$current_perm" != "$expected_perm" ]; then
                dirs_need_fix=$((dirs_need_fix + 1))
            elif [ -z "$expected_perm" ]; then
                # If there's no specific expected permission, check against standard
                if [ "$current_perm" != "755" ]; then
                    dirs_need_fix=$((dirs_need_fix + 1))
                fi
            fi
            
            if [ $((total_dirs % 500)) -eq 0 ]; then
                show_progress_line "Analyzing directories... ($total_dirs found)"
            fi
        done < <(find "$user_home" -type d -print0 2>/dev/null)
        
        # Process files according to panel
        while IFS= read -r -d '' item; do
            total_files=$((total_files + 1))
            local current_perm=$(stat -c "%a" "$item" 2>/dev/null)
            local basename_item=$(basename "$item")
            local item_path=$(echo "$item" | sed "s|^$user_home/||")
            
            # Determine expected permission according to file type and panel
            local expected_perm=""
            if [ "$PANEL_TYPE" = "cpanel" ]; then
                case "$item_path" in
                    .ssh/*) expected_perm="600" ;;
                    etc/*/shadow) expected_perm="640" ;;
                    etc/*/passwd) expected_perm="640" ;;
                    # Files in mail/: 640 by default (according to official cPanel script 11.54+)
                    mail/*/maildirsize) expected_perm="600" ;;  # maildirsize: 600 (special)
                    mail/*/dovecot-uidvalidity.*) expected_perm="444" ;;  # dovecot-uidvalidity.*: 444 (read-only)
                    mail/*) expected_perm="640" ;;  # All other files in mail: 640
                    *.cgi) expected_perm="755" ;;
                    *.pl) expected_perm="755" ;;
                    *.sh) expected_perm="700" ;;
                    .contactemail) expected_perm="644" ;;
                    .lastlogin) expected_perm="644" ;;
                    public_html/cgi-bin/*) expected_perm="755" ;;
                    *) 
                        # Executable scripts
                        if [[ "$basename_item" =~ \.(cgi|pl|sh)$ ]] || [ -x "$item" ]; then
                            if [[ "$basename_item" =~ \.sh$ ]]; then
                                expected_perm="700"
                            else
                                expected_perm="755"
                            fi
                        else
                            expected_perm="644"
                        fi
                        ;;
                esac
            elif [ "$PANEL_TYPE" = "directadmin" ]; then
                case "$item_path" in
                    .ssh/*) expected_perm="600" ;;
                    .shadow) expected_perm="640" ;;
                    backups/*) expected_perm="600" ;;
                    imap/*/Maildir/cur/*) expected_perm="640" ;;
                    imap/*/Maildir/new/*) expected_perm="640" ;;
                    imap/*/Maildir/tmp/*) expected_perm="600" ;;
                    imap/*/Maildir/dovecot-uidvalidity.*) expected_perm="444" ;;
                    imap/*/Maildir/dovecot*) expected_perm="640" ;;
                    imap/*/Maildir/subscriptions) expected_perm="640" ;;
                    imap/*/Maildir/maildirsize) expected_perm="640" ;;
                    imap/*/Maildir/mailbox_format.cpanel) expected_perm="640" ;;
                    imap/*/Maildir/*) expected_perm="640" ;;
                    .trash/*) expected_perm="660" ;;
                    .spamassassin/*) expected_perm="660" ;;
                    imap/*) expected_perm="660" ;;
                    *.cgi) expected_perm="755" ;;
                    *.pl) expected_perm="755" ;;
                    *.sh) expected_perm="755" ;;
                    *) 
                        # Executable scripts
                        if [[ "$basename_item" =~ \.(cgi|pl|sh)$ ]] || [ -x "$item" ]; then
                            expected_perm="755"
                        else
                            expected_perm="644"
                        fi
                        ;;
                esac
            else
                # No panel: standard
                if [[ "$basename_item" =~ \.(cgi|pl|sh)$ ]] || [ -x "$item" ]; then
                    expected_perm="755"
                else
                    expected_perm="644"
                fi
            fi
            
            # Only count if it needs change
            if [ -n "$expected_perm" ] && [ "$current_perm" != "$expected_perm" ]; then
                files_need_fix=$((files_need_fix + 1))
                if [[ "$basename_item" =~ \.(cgi|pl|sh)$ ]] || [ -x "$item" ]; then
                    scripts_need_fix=$((scripts_need_fix + 1))
                fi
            fi
            
            if [ $((total_files % 1000)) -eq 0 ]; then
                show_progress_line "Analyzing files... ($total_files found)"
            fi
        done < <(find "$user_home" -type f -print0 2>/dev/null)
        
        PROCESSED_DIRS=$total_dirs
        PROCESSED_FILES=$total_files
        
        echo ""
        log "${CYAN}[DRY-RUN]${NC} Analysis completed:"
        log "${CYAN}[DRY-RUN]${NC}   - Total directories: $total_dirs (need change: $dirs_need_fix)"
        log "${CYAN}[DRY-RUN]${NC}   - Total files: $total_files (need change: $files_need_fix)"
        if [ $scripts_need_fix -gt 0 ]; then
            log "${CYAN}[DRY-RUN]${NC}   - Executable scripts that need change: $scripts_need_fix"
        fi
        
        # Update counters for summary (only those that need change)
        PROCESSED_DIRS=$dirs_need_fix
        PROCESSED_FILES=$files_need_fix
        return 0
    fi
    
    # If it's DirectAdmin, try to use the official script first
    if [ "$PANEL_TYPE" = "directadmin" ]; then
        local da_script="/usr/local/directadmin/scripts/set_permissions.sh"
        if [ -f "$da_script" ] && [ -x "$da_script" ]; then
            # Only execute the official script if we're not in --chown-only mode
            # because the official script applies both permissions and ownership
            if [ "$CHOWN_ONLY" != true ]; then
                log "${CYAN}[INFO]${NC} Official DirectAdmin script detected: $da_script"
                log "${CYAN}[INFO]${NC} Using permissions from official DirectAdmin script"
                
                show_progress_line "Executing official DirectAdmin script..."
                # Redirect official script output (includes "safe set" logs) to log if enabled, otherwise to /dev/null
                if [ "$LOG_ENABLED" = true ]; then
                    "$da_script" set_user_home "$ACCOUNT" >> "$LOG_FILE" 2>&1
                else
                    "$da_script" set_user_home "$ACCOUNT" >/dev/null 2>&1
                fi
                if [ $? -eq 0 ]; then
                    log "${GREEN}[OK]${NC} Permissions applied using official DirectAdmin script"
                    DA_OFFICIAL_SCRIPT_EXECUTED=true
                    
                    # The official script does NOT modify public_html in set_user_home, but we do want to fix it
                    # Apply permissions to the content of public_html (NOT to the directory itself)
                    show_progress_line "Fixing permissions in public_html..."
                    find "$user_home" -type d -path "*/domains/*/public_html/*" -exec chmod 755 {} \; 2>/dev/null
                    find "$user_home" -type f -path "*/domains/*/public_html/*" -exec chmod 644 {} \; 2>/dev/null
                    
                    # Fix incorrect groups: change all files/directories/links with group "access" to user:user
                    # The official script only modifies specific files and leaves the rest untouched (that's why they remain with group "access")
                    # IMPORTANT: Do not modify files that should have group "mail" or "apache"
                    show_progress_line "Fixing incorrect groups (access -> user)..."
                    # Change directories with group "access" to user:user (including public_html, except those that should be mail/apache)
                    find "$user_home" -type d -group "access" ! -path "*/imap*" ! -path "*/.trash*" ! -path "*/.spamassassin*" ! -path "*/.php*" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
                    # Change files with group "access" to user:user (except those that should be mail/apache)
                    find "$user_home" -type f -group "access" ! -path "*/imap*" ! -path "*/.trash*" ! -path "*/.spamassassin*" ! -path "*/.php*" ! -name ".shadow" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
                    # Change symbolic links with group "access" to user:user (like www -> public_html)
                    find "$user_home" -type l -group "access" -exec chown -h "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
                    
                    # Apply ownership to the content of public_html
                    find "$user_home" -type d -path "*/domains/*/public_html/*" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
                    find "$user_home" -type f -path "*/domains/*/public_html/*" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
                    
                    # Count processed files for summary (the official script applies both CHMOD and CHOWN)
                    PROCESSED_DIRS=$(find "$user_home" -type d 2>/dev/null | wc -l)
                    PROCESSED_FILES=$(find "$user_home" -type f 2>/dev/null | wc -l)
                    CHOWN_PROCESSED_DIRS=$PROCESSED_DIRS
                    CHOWN_PROCESSED_FILES=$PROCESSED_FILES
                    return 0
                else
                    log "${YELLOW}[WARNING]${NC} Error using official script, using default permissions based on official specification"
                    # Continue with our permissions as fallback
                fi
            else
                log "${CYAN}[INFO]${NC} Official script available but skipped (--chown-only mode enabled)"
            fi
        else
            log "${CYAN}[INFO]${NC} Official script not found, using default permissions based on official specification"
        fi
    fi
    
    # Apply permissions according to control panel
    if [ "$PANEL_TYPE" = "directadmin" ]; then
        # DirectAdmin: permissions according to official specification (based on set_permissions.sh)
        show_progress_line "Applying DirectAdmin permissions..."
        
        # Main home directory: 711 (drwx--x--x)
        chmod 711 "$user_home" 2>/dev/null
        
        # .bash* files: 644
        find "$user_home" -maxdepth 1 -type f \( -name ".bashrc" -o -name ".bash_profile" -o -name ".bash_logout" \) -exec chmod 644 {} \; 2>/dev/null
        
        # .ssh: 700 directory, 600 files
        find "$user_home" -type d -path "*/.ssh" -exec chmod 700 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/.ssh/*" -exec chmod 600 {} \; 2>/dev/null
        
        # .shadow: 640 (according to official script)
        find "$user_home" -maxdepth 1 -type f -name ".shadow" -exec chmod 640 {} \; 2>/dev/null
        
        # domains: 711 main directory (according to official script)
        find "$user_home" -type d -path "*/domains" -exec chmod 711 {} \; 2>/dev/null
        # domains/*: 711 subdirectories (according to official script)
        find "$user_home" -type d -path "*/domains/*" ! -path "*/domains/*/public_html" ! -path "*/domains/*/private_html" ! -path "*/domains/*/logs" ! -path "*/domains/default" ! -path "*/domains/sharedip" ! -path "*/domains/suspended" -exec chmod 711 {} \; 2>/dev/null
        
        # domains/default, sharedip, suspended: 755 (according to official script)
        find "$user_home" -type d -path "*/domains/default" -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/domains/sharedip" -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/domains/suspended" -exec chmod 755 {} \; 2>/dev/null
        
        # backups: 700 directory, 600 files (according to official script)
        find "$user_home" -type d -maxdepth 1 -name "backups" -exec chmod 700 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/backups/*" -exec chmod 600 {} \; 2>/dev/null
        
        # user_backups: 711 directory, 755 subdirectories (according to official script)
        find "$user_home" -type d -maxdepth 1 -name "user_backups" -exec chmod 711 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/user_backups/*" -exec chmod 755 {} \; 2>/dev/null
        
        # domains/*/public_html: DO NOT modify the directory itself (may have custom permissions)
        # BUT DO modify files and folders INSIDE public_html (according to official script in set_domaindir)
        # The official script does NOT modify public_html in set_user_home, but DOES do it in set_domaindir
        # Apply recursive permissions to content: 755 directories, 644 files
        find "$user_home" -type d -path "*/domains/*/public_html/*" -exec chmod 755 {} \; 2>/dev/null
        
        # domains/*/public_ftp: 755 directory and subdirectories, 644 files (according to official script)
        find "$user_home" -type d -path "*/domains/*/public_ftp" -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/domains/*/public_ftp/*" -exec chmod 755 {} \; 2>/dev/null
        
        # domains/*/private_html: 755 directory and subdirectories, 644 files (according to official script)
        find "$user_home" -type d -path "*/domains/*/private_html" -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/domains/*/private_html/*" -exec chmod 755 {} \; 2>/dev/null
        
        # domains/*/logs: 755 directory and subdirectories, 644 files (according to official script)
        find "$user_home" -type d -path "*/domains/*/logs" -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/domains/*/logs/*" -exec chmod 755 {} \; 2>/dev/null
        
        # domains/*/.htpasswd: 755 directory and subdirectories, 644 files (according to official script)
        find "$user_home" -type d -path "*/domains/*/.htpasswd" -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/domains/*/.htpasswd/*" -exec chmod 755 {} \; 2>/dev/null
        
        # domains/*/stats: 755 directory and subdirectories, 644 files (according to official script)
        find "$user_home" -type d -path "*/domains/*/stats" -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/domains/*/stats/*" -exec chmod 755 {} \; 2>/dev/null
        
        # imap: 770 main directory (according to official script: recursive 660 files, 770 directories)
        find "$user_home" -type d -maxdepth 1 -name "imap" -exec chmod 770 {} \; 2>/dev/null
        # imap/*: 770 subdirectories (according to official script)
        find "$user_home" -type d -path "*/imap/*" -exec chmod 770 {} \; 2>/dev/null
        
        # .trash: 770 directory, recursive 660 files, 770 directories (according to official script)
        if [ -d "$user_home/.trash" ]; then
            find "$user_home" -type d -maxdepth 1 -name ".trash" -exec chmod 770 {} \; 2>/dev/null
            find "$user_home" -type d -path "*/.trash/*" -exec chmod 770 {} \; 2>/dev/null
        fi
        
        # .spamassassin: 771 directory, recursive 660 files, 771 directories (according to official script)
        if [ -d "$user_home/.spamassassin" ]; then
            find "$user_home" -type d -maxdepth 1 -name ".spamassassin" -exec chmod 771 {} \; 2>/dev/null
            find "$user_home" -type d -path "*/.spamassassin/*" -exec chmod 771 {} \; 2>/dev/null
        fi
        
        # Maildir: according to official script uses recursive 660 files, 770 directories
        # But we maintain the specific permissions you provided earlier
        find "$user_home" -type d -path "*/imap/*/Maildir" -exec chmod 751 {} \; 2>/dev/null
        
        # imap/*/Maildir/cur, new, tmp: 751
        find "$user_home" -type d -path "*/imap/*/Maildir/cur" -exec chmod 751 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/imap/*/Maildir/new" -exec chmod 751 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/imap/*/Maildir/tmp" -exec chmod 751 {} \; 2>/dev/null
        
        # imap/*/Maildir/*: 700 other subdirectories (except cur, new, tmp)
        find "$user_home" -type d -path "*/imap/*/Maildir/*" ! -path "*/imap/*/Maildir/cur" ! -path "*/imap/*/Maildir/new" ! -path "*/imap/*/Maildir/tmp" -exec chmod 700 {} \; 2>/dev/null
        
        # tmp: 700
        find "$user_home" -type d -maxdepth 1 -name "tmp" -exec chmod 700 {} \; 2>/dev/null
        
        # Other standard directories: 755 (excluding the public_html directory itself, but YES its subdirectories)
        find "$user_home" -type d ! -path "$user_home" ! -path "$user_home/.ssh" ! -path "$user_home/.ssh/*" ! -path "$user_home/domains" ! -path "$user_home/domains/*" ! -path "$user_home/imap" ! -path "$user_home/imap/*" ! -path "$user_home/tmp" ! -path "*/domains/*/public_html" -exec chmod 755 {} \; 2>/dev/null
        
        # Files: 644 by default (all files except .ssh, imap/Maildir, backups, .trash, .spamassassin)
        # NOTE: YES we modify files INSIDE public_html (644), but NOT the public_html directory itself
        show_progress_line "Applying 644 to files..."
        PROCESSED_FILES=$(find "$user_home" -type f ! -path "*/.ssh/*" ! -path "*/imap/*/Maildir/*" ! -path "*/imap/*/Maildir/*/*" ! -path "*/backups/*" ! -path "*/.trash/*" ! -path "*/.spamassassin/*" -exec chmod 644 {} \; -print 2>/dev/null | wc -l)
        
        # Files in imap (except Maildir): 660 (according to official script)
        find "$user_home" -type f -path "*/imap/*" ! -path "*/imap/*/Maildir/*" -exec chmod 660 {} \; 2>/dev/null
        
        # Files in .trash: 660 (according to official script)
        find "$user_home" -type f -path "*/.trash/*" -exec chmod 660 {} \; 2>/dev/null
        
        # Files in .spamassassin: 660 (according to official script)
        find "$user_home" -type f -path "*/.spamassassin/*" -exec chmod 660 {} \; 2>/dev/null
        
        # Specific dovecot files in Maildir: 640
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot.index" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot.index.cache" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot.index.log" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot.list.index" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot.list.index.log" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot.mailbox.log" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot-quota" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot-uidlist" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot-uidvalidity" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot-acl-list" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/subscriptions" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/maildirsize" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/imap/*/Maildir/mailbox_format.cpanel" -exec chmod 640 {} \; 2>/dev/null
        
        # dovecot-uidvalidity.*: 444
        find "$user_home" -type f -path "*/imap/*/Maildir/dovecot-uidvalidity.*" -exec chmod 444 {} \; 2>/dev/null
        
        # imap/*/Maildir/cur/*: 640 files inside cur
        find "$user_home" -type f -path "*/imap/*/Maildir/cur/*" -exec chmod 640 {} \; 2>/dev/null
        
        # imap/*/Maildir/new/*: 640 files inside new
        find "$user_home" -type f -path "*/imap/*/Maildir/new/*" -exec chmod 640 {} \; 2>/dev/null
        
        # imap/*/Maildir/tmp/*: 600 files inside tmp
        find "$user_home" -type f -path "*/imap/*/Maildir/tmp/*" -exec chmod 600 {} \; 2>/dev/null
        
        # Executable scripts: 755
        show_progress_line "Applying 755 to executable scripts..."
        find "$user_home" -type f \( -name "*.cgi" -o -name "*.pl" -o -name "*.sh" \) -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type f -perm -u=x ! -perm -4000 ! -perm -2000 -exec chmod 755 {} \; 2>/dev/null
        
        PROCESSED_DIRS=$(find "$user_home" -type d 2>/dev/null | wc -l)
    elif [ "$PANEL_TYPE" = "cpanel" ]; then
        # cPanel: permissions according to official specification
        show_progress_line "Applying cPanel permissions..."
        
        # Main home directory: 711 (drwx--x--x)
        chmod 711 "$user_home" 2>/dev/null
        
        # .bash* files: 644
        find "$user_home" -maxdepth 1 -type f \( -name ".bashrc" -o -name ".bash_profile" -o -name ".bash_logout" \) -exec chmod 644 {} \; 2>/dev/null
        
        # .ssh: 700 directory, 600 files
        find "$user_home" -type d -path "*/.ssh" -exec chmod 700 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/.ssh/*" -exec chmod 600 {} \; 2>/dev/null
        
        # Detect File Protect
        local file_protect_on=false
        if detect_file_protect "$user_home"; then
            file_protect_on=true
            log "${CYAN}[INFO]${NC} File Protect detected: public_html will be 750 with group nobody"
        else
            log "${CYAN}[INFO]${NC} File Protect NOT detected: public_html will be 755 with group user"
        fi
        
        # public_html: 750 with File Protect ON (group nobody) or 755 with File Protect OFF (group user)
        if [ -d "$user_home/public_html" ]; then
            if [ "$file_protect_on" = true ]; then
                chmod 750 "$user_home/public_html" 2>/dev/null
                chown "$ACCOUNT:nobody" "$user_home/public_html" 2>/dev/null
            else
                chmod 755 "$user_home/public_html" 2>/dev/null
                chown "$ACCOUNT:$ACCOUNT" "$user_home/public_html" 2>/dev/null
            fi
        fi
        
        # public_html/*: 755 directories, 644 files
        find "$user_home" -type d -path "*/public_html/*" -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/public_html/*" -exec chmod 644 {} \; 2>/dev/null
        
        # IMPORTANT: Handle hidden files in public_html specifically
        # Hidden files/folders (like .well-known/, .htaccess, etc.) may have incorrect permissions
        if [ -d "$user_home/public_html" ]; then
            chown -R "$ACCOUNT:$ACCOUNT" "$user_home/public_html/.[^.]*" 2>/dev/null
            find "$user_home/public_html" -type d -name ".*" -exec chmod 755 {} \; 2>/dev/null
            find "$user_home/public_html" -type f -name ".*" -exec chmod 644 {} \; 2>/dev/null
        fi
        
        # public_html/cgi-bin: 755 directory
        find "$user_home" -type d -path "*/public_html/cgi-bin" -exec chmod 755 {} \; 2>/dev/null
        
        # IMPORTANT: Detect and fix additional subdomains/domains outside public_html
        # Method 1: Use official cPanel configuration (/var/cpanel/userdata/) - MOST PRECISE
        # This method reads directly the DocumentRoots configured in cPanel
        if [ -d "/var/cpanel/userdata/$ACCOUNT" ]; then
            log "${CYAN}[INFO]${NC} Detecting domains/subdomains using cPanel configuration..."
            # Read DocumentRoot from cPanel configuration files
            # Exclude .cache and _SSL, and filter those that are NOT public_html
            while IFS= read -r document_root; do
                # Verify that DocumentRoot exists and is not public_html
                if [ -n "$document_root" ] && [ "$document_root" != "$user_home/public_html" ] && [ -d "$document_root" ]; then
                    # Normalize path (remove trailing slash if exists)
                    document_root=$(echo "$document_root" | sed 's|/$||')
                    log "${CYAN}[INFO]${NC} Detected domain/subdomain outside public_html: $document_root"
                    
                    # Apply standard permissions
                    find "$document_root" -type d -exec chmod 755 {} \; 2>/dev/null
                    find "$document_root" -type f -exec chmod 644 {} \; 2>/dev/null
                    # Executable scripts: 755
                    find "$document_root" -type f \( -name "*.cgi" -o -name "*.pl" -o -name "*.sh" \) -exec chmod 755 {} \; 2>/dev/null
                    find "$document_root" -type f -perm -u=x ! -perm -4000 ! -perm -2000 -exec chmod 755 {} \; 2>/dev/null
                    # Apply ownership
                    chown -R "$ACCOUNT:$ACCOUNT" "$document_root" 2>/dev/null
                    # Ensure the directory itself has correct permissions
                    chmod 755 "$document_root" 2>/dev/null
                fi
            done < <(grep -i "documentroot" /var/cpanel/userdata/"$ACCOUNT"/* 2>/dev/null | grep -v '.cache\|_SSL' | awk '{print $2}' | grep -v "^$user_home/public_html$" | sort -u)
        fi
        
        # Method 2: Check if /home/user/domains exists (structure similar to DirectAdmin)
        if [ -d "$user_home/domains" ]; then
            log "${CYAN}[INFO]${NC} Detected domain structure in: $user_home/domains"
            # Apply permissions to domains outside public_html
            find "$user_home" -type d -path "*/domains/*" ! -path "*/domains/*/public_html" ! -path "*/domains/*/private_html" ! -path "*/domains/*/logs" -exec chmod 755 {} \; 2>/dev/null
            find "$user_home" -type f -path "*/domains/*" ! -path "*/domains/*/logs/*" -exec chmod 644 {} \; 2>/dev/null
            find "$user_home" -type d -path "*/domains/*/public_html/*" -exec chmod 755 {} \; 2>/dev/null
            find "$user_home" -type f -path "*/domains/*/public_html/*" -exec chmod 644 {} \; 2>/dev/null
        fi
        
        # Method 3: Fallback - Search directories with web indicators (if not found with method 1)
        # Only executes if domains were not found with method 1
        if [ ! -d "/var/cpanel/userdata/$ACCOUNT" ] || ! grep -qi "documentroot" /var/cpanel/userdata/"$ACCOUNT"/* 2>/dev/null | grep -qv '.cache\|_SSL'; then
            for dir in "$user_home"/*; do
                if [ -d "$dir" ] && [ "$dir" != "$user_home/public_html" ]; then
                    local dirname=$(basename "$dir")
                    # Skip known system directories
                    case "$dirname" in
                        .ssh|mail|etc|tmp|logs|.cpanel|perl5|ssl|domains|backups|imap|user_backups|.trash|.spamassassin)
                            continue
                            ;;
                    esac
                    
                    # If it has typical web files, apply standard permissions
                    if [ -f "$dir/index.html" ] || [ -f "$dir/index.php" ] || [ -f "$dir/.htaccess" ] || [ -d "$dir/wp-content" ] || [ -d "$dir/wp-admin" ] || [ -f "$dir/wp-config.php" ]; then
                        log "${CYAN}[INFO]${NC} Detected possible domain/subdomain outside public_html (heuristic): $dirname"
                        find "$dir" -type d -exec chmod 755 {} \; 2>/dev/null
                        find "$dir" -type f -exec chmod 644 {} \; 2>/dev/null
                        # Executable scripts: 755
                        find "$dir" -type f \( -name "*.cgi" -o -name "*.pl" -o -name "*.sh" \) -exec chmod 755 {} \; 2>/dev/null
                        find "$dir" -type f -perm -u=x ! -perm -4000 ! -perm -2000 -exec chmod 755 {} \; 2>/dev/null
                    fi
                fi
            done
        fi
        
        # IMPORTANT: Handle .htaccess files throughout the home (not just in public_html)
        log "${CYAN}[INFO]${NC} Fixing permissions of .htaccess files throughout home..."
        find "$user_home" -type f -name ".htaccess" -exec chmod 644 {} \; 2>/dev/null
        find "$user_home" -type f -name ".htaccess" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
        
        # access-logs: 777 (symlink a domlogs)
        if [ -L "$user_home/access-logs" ]; then
            chmod 777 "$user_home/access-logs" 2>/dev/null
        fi
        
        # etc: 750 directory with mail group
        find "$user_home" -type d -maxdepth 1 -name "etc" -exec chmod 750 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/etc/*" -exec chmod 750 {} \; 2>/dev/null
        
        # etc/*/shadow, etc/*/passwd: 640 with mail group
        find "$user_home" -type f -path "*/etc/*/shadow" -exec chmod 640 {} \; 2>/dev/null
        find "$user_home" -type f -path "*/etc/*/passwd" -exec chmod 640 {} \; 2>/dev/null
        
        # mail: 751 directory (cPanel Maildir)
        find "$user_home" -type d -maxdepth 1 -name "mail" -exec chmod 751 {} \; 2>/dev/null
        
        # Legacy cPanel structure: mail/domain/user/mail/virtual/email@domain.cl/* → 751
        # mail/*: 751 subdirectories (domains)
        find "$user_home" -type d -path "*/mail/*" ! -path "*/mail/*/*" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/*/*: 751 subdirectories of domain/user
        find "$user_home" -type d -path "*/mail/*/*" ! -path "*/mail/*/*/*" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/*/*/mail: 751
        find "$user_home" -type d -path "*/mail/*/*/mail" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/*/*/mail/virtual: 751
        find "$user_home" -type d -path "*/mail/*/*/mail/virtual" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/*/*/mail/virtual/*: 751 (email accounts)
        find "$user_home" -type d -path "*/mail/*/*/mail/virtual/*" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/*/*/mail/virtual/*/sent: 751
        find "$user_home" -type d -path "*/mail/*/*/mail/virtual/*/sent" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/*/*/mail/virtual/*/sent/INBOX: 751
        find "$user_home" -type d -path "*/mail/*/*/mail/virtual/*/sent/INBOX" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/*/*/mail/virtual/*/spam: 751
        find "$user_home" -type d -path "*/mail/*/*/mail/virtual/*/spam" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/*/*/mail/virtual/*/spam/INBOX: 751
        find "$user_home" -type d -path "*/mail/*/*/mail/virtual/*/spam/INBOX" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/virtual: 751 (legacy structure without domain)
        find "$user_home" -type d -path "*/mail/virtual" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/virtual/*: 751 (users in legacy structure)
        find "$user_home" -type d -path "*/mail/virtual/*" ! -path "*/mail/virtual/*/*" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/virtual/*/sent: 751
        find "$user_home" -type d -path "*/mail/virtual/*/sent" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/virtual/*/sent/INBOX: 751
        find "$user_home" -type d -path "*/mail/virtual/*/sent/INBOX" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/virtual/*/spam: 751
        find "$user_home" -type d -path "*/mail/virtual/*/spam" -exec chmod 751 {} \; 2>/dev/null
        
        # mail/virtual/*/spam/INBOX: 751
        find "$user_home" -type d -path "*/mail/virtual/*/spam/INBOX" -exec chmod 751 {} \; 2>/dev/null
        
        # Modern Maildir structure: .mailbox_format.cpanel → 751
        find "$user_home" -type d -path "*/mail/.mailbox_format.cpanel" -exec chmod 751 {} \; 2>/dev/null
        
        # .mailbox_format.cpanel/new, cur, tmp: 751
        find "$user_home" -type d -path "*/mail/.mailbox_format.cpanel/new" -exec chmod 751 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/mail/.mailbox_format.cpanel/cur" -exec chmod 751 {} \; 2>/dev/null
        find "$user_home" -type d -path "*/mail/.mailbox_format.cpanel/tmp" -exec chmod 751 {} \; 2>/dev/null
        
        # Carpetas Maildir modernas (.Drafts, .Sent, .Junk, etc.)
        find "$user_home" -type d -path "*/mail/.*" ! -path "*/mail/.mailbox_format.cpanel" -exec chmod 751 {} \; 2>/dev/null
        
        # IMPORTANT: All directories inside mail must be 751 (according to official script /usr/local/cpanel/scripts/mailperm)
        # This ensures that any legacy or modern structure has correct permissions
        # Applied after specific rules to ensure everything is 751
        find "$user_home" -type d -path "*/mail/*" ! -path "*/mail" -exec chmod 751 {} \; 2>/dev/null
        
        # Files in mail/: apply permissions according to official cPanel script and real system observations
        # IMPORTANT: We apply permissions to ALL files, including those the official script "omits",
        # to be able to fix them if they are broken (as requested by user)
        
        # 1. First the special cases that require specific permissions:
        
        # dovecot-uidvalidity.*: 444 (read-only for all, according to real system observation)
        find "$user_home" -type f -path "*/mail/*" -name "dovecot-uidvalidity*" -exec chmod 444 {} \; 2>/dev/null
        
        # maildirsize: 600 (owner only, according to real system observation)
        find "$user_home" -type f -path "*/mail/*" -name "maildirsize" -exec chmod 600 {} \; 2>/dev/null
        
        # 2. Then all other files in mail/: 640 by default
        # (according to official cPanel script 11.54+, changed from 660 to 640)
        # This includes: dovecot-keywords, dovecot-uidlist, dovecot.index*, dovecot.list.index*,
        # dovecot.mailbox.log, dovecot-quota, dovecot-acl-list, subscriptions, maildirfolder,
        # mailbox_format.cpanel, and all email messages
        find "$user_home" -type f -path "*/mail/*" ! -name "dovecot-uidvalidity*" ! -name "maildirsize" -exec chmod 640 {} \; 2>/dev/null
        
        # tmp: 755 directory
        find "$user_home" -type d -maxdepth 1 -name "tmp" -exec chmod 755 {} \; 2>/dev/null
        
        # logs: 700 directory
        find "$user_home" -type d -maxdepth 1 -name "logs" -exec chmod 700 {} \; 2>/dev/null
        
        # .cpanel: 700 directory
        find "$user_home" -type d -maxdepth 1 -name ".cpanel" -exec chmod 700 {} \; 2>/dev/null
        
        # .contactemail: 644 file
        find "$user_home" -maxdepth 1 -type f -name ".contactemail" -exec chmod 644 {} \; 2>/dev/null
        
        # .lastlogin: 644 file
        find "$user_home" -maxdepth 1 -type f -name ".lastlogin" -exec chmod 644 {} \; 2>/dev/null
        
        # perl5: 755 directory
        find "$user_home" -type d -maxdepth 1 -name "perl5" -exec chmod 755 {} \; 2>/dev/null
        
        # ssl: 700 directory
        find "$user_home" -type d -maxdepth 1 -name "ssl" -exec chmod 700 {} \; 2>/dev/null
        
        # ssl/keys: 700 directory
        find "$user_home" -type d -path "*/ssl/keys" -exec chmod 700 {} \; 2>/dev/null
        
        # ssl/certs: 700 directory
        find "$user_home" -type d -path "*/ssl/certs" -exec chmod 700 {} \; 2>/dev/null
        
        # Executable scripts: 755 for .cgi and .pl, 700 for .sh
        show_progress_line "Applying permissions to executable scripts..."
        find "$user_home" -type f -name "*.cgi" -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type f -name "*.pl" -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type f -name "*.sh" -exec chmod 700 {} \; 2>/dev/null
        
        # Other executable files: 755
        find "$user_home" -type f -perm -u=x ! -perm -4000 ! -perm -2000 ! -name "*.sh" -exec chmod 755 {} \; 2>/dev/null
        
        # Other standard directories: 755
        find "$user_home" -type d ! -path "$user_home" ! -path "$user_home/.ssh" ! -path "$user_home/.ssh/*" ! -path "$user_home/public_html" ! -path "$user_home/public_html/*" ! -path "$user_home/etc" ! -path "$user_home/etc/*" ! -path "$user_home/mail" ! -path "$user_home/mail/*" ! -path "$user_home/tmp" ! -path "$user_home/logs" ! -path "$user_home/.cpanel" ! -path "$user_home/perl5" ! -path "$user_home/ssl" ! -path "$user_home/ssl/*" -exec chmod 755 {} \; 2>/dev/null
        
        # Files: 644 by default (all except .ssh, mail, etc, ssl)
        show_progress_line "Aplicando 644 a archivos..."
        PROCESSED_FILES=$(find "$user_home" -type f ! -path "*/.ssh/*" ! -path "*/mail/*" ! -path "*/etc/*" ! -path "*/ssl/*" -exec chmod 644 {} \; -print 2>/dev/null | wc -l)
        
        PROCESSED_DIRS=$(find "$user_home" -type d 2>/dev/null | wc -l)
    else
        # No panel detected: standard permissions 755/644
        show_progress_line "Applying 755 to directories..."
        PROCESSED_DIRS=$(find "$user_home" -type d -exec chmod 755 {} \; -print 2>/dev/null | wc -l)
        echo ""
        
        show_progress_line "Aplicando 644 a archivos..."
        PROCESSED_FILES=$(find "$user_home" -type f -exec chmod 644 {} \; -print 2>/dev/null | wc -l)
        echo ""
        
        show_progress_line "Aplicando 755 a scripts ejecutables..."
        find "$user_home" -type f \( -name "*.cgi" -o -name "*.pl" -o -name "*.sh" \) -exec chmod 755 {} \; 2>/dev/null
        find "$user_home" -type f -perm -u=x ! -perm -4000 ! -perm -2000 -exec chmod 755 {} \; 2>/dev/null
    fi
    
    echo ""
    TOTAL_DIRS=$(find "$user_home" -type d 2>/dev/null | wc -l)
    TOTAL_FILES=$(find "$user_home" -type f 2>/dev/null | wc -l)
    log "${CYAN}[INFO]${NC} Processed: $TOTAL_DIRS directories, $TOTAL_FILES files"
    echo ""
    
    log "${GREEN}[OK]${NC} CHMOD completed: $PROCESSED_DIRS directories, $PROCESSED_FILES files"
}

# Apply CHOWN with progress
apply_chown() {
    local user_home="$1"
    
    if [ "$SKIP_CHOWN" = true ]; then
        log "${YELLOW}[INFO]${NC} CHOWN skipped (--chmod-only enabled)"
        return 0
    fi
    
    log "${BLUE}[CHOWN]${NC} Applying ownership in: $user_home"
    
    # Determine the correct group according to panel
    local user_group=""
    if [ "$PANEL_TYPE" = "directadmin" ]; then
        # In DirectAdmin according to official specification: user:user (not access)
        user_group="$ACCOUNT"
    else
        # For cPanel and others, use the user's group
        user_group=$(id -gn "$ACCOUNT")
    fi
    
    if [ "$DRY_RUN" = true ]; then
        show_progress_line "Simulating chown -R $ACCOUNT:$user_group"
        echo ""
        log "${YELLOW}[DRY-RUN]${NC} chown -R $ACCOUNT:$user_group $user_home"
        return 0
    fi
    
    # Apply chown according to panel
    if [ "$PANEL_TYPE" = "directadmin" ]; then
        # If official script exists and is executable, check if already used
        local da_script="/usr/local/directadmin/scripts/set_permissions.sh"
        if [ -f "$da_script" ] && [ -x "$da_script" ]; then
            # If the official script was already executed in apply_chmod, ownership is already applied
            if [ "$DA_OFFICIAL_SCRIPT_EXECUTED" = true ]; then
                # The official script does NOT modify public_html, but we do want to fix it
                # Apply ownership to the content of public_html (NOT to the directory itself)
                show_progress_line "Fixing ownership in public_html..."
                find "$user_home" -type d -path "*/domains/*/public_html/*" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
                find "$user_home" -type f -path "*/domains/*/public_html/*" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
                
                # Fix incorrect groups: change all files/directories/links with group "access" to user:user
                # The official script only modifies specific files and leaves the rest untouched (that's why they remain with group "access")
                # IMPORTANT: Do not modify files that should have group "mail" or "apache"
                show_progress_line "Fixing incorrect groups (access -> user)..."
                # Change directories with group "access" to user:user (including public_html, except those that should be mail/apache)
                find "$user_home" -type d -group "access" ! -path "*/imap*" ! -path "*/.trash*" ! -path "*/.spamassassin*" ! -path "*/.php*" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
                # Change files with group "access" to user:user (except those that should be mail/apache)
                find "$user_home" -type f -group "access" ! -path "*/imap*" ! -path "*/.trash*" ! -path "*/.spamassassin*" ! -path "*/.php*" ! -name ".shadow" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
                # Change symbolic links with group "access" to user:user (like www -> public_html)
                find "$user_home" -type l -group "access" -exec chown -h "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
                
                # CHOWN variables were already initialized in apply_chmod
                log "${GREEN}[OK]${NC} Ownership applied by official DirectAdmin script (public_html and groups fixed)"
                return 0
            fi
            
            # If we're in --chown-only mode, execute the official script
            if [ "$CHOWN_ONLY" = true ]; then
                log "${CYAN}[INFO]${NC} Executing official DirectAdmin script for CHOWN..."
                # Redirect official script output to log if enabled, otherwise to /dev/null
                if [ "$LOG_ENABLED" = true ]; then
                    "$da_script" set_user_home "$ACCOUNT" >> "$LOG_FILE" 2>&1
                else
                    "$da_script" set_user_home "$ACCOUNT" >/dev/null 2>&1
                fi
                if [ $? -eq 0 ]; then
                    # Count processed files and directories for summary
                    CHOWN_PROCESSED_DIRS=$(find "$user_home" -type d 2>/dev/null | wc -l)
                    CHOWN_PROCESSED_FILES=$(find "$user_home" -type f 2>/dev/null | wc -l)
                    log "${GREEN}[OK]${NC} Ownership applied using official DirectAdmin script"
                    DA_OFFICIAL_SCRIPT_EXECUTED=true
                    return 0
                else
                    log "${YELLOW}[WARNING]${NC} Error using official script, using default permissions"
                fi
            fi
        fi
        
        # If official script does not exist, use our permissions
        # DirectAdmin: according to official specification
        show_progress_line "Applying DirectAdmin ownership..."
        
        # IMPORTANT: Apply chown BEFORE chmod (according to official script)
        # A file with special permissions (like 4755) resets if chown is done after chmod
        
        # Base: user:user for most
        # NOTE: We do NOT modify the public_html directory itself (may have custom permissions like apache:apache)
        # BUT YES we modify files and folders INSIDE public_html (according to official script in set_domaindir)
        find "$user_home" -type d ! -path "*/domains/*/public_html" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
        find "$user_home" -type f -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
        
        # .shadow: usuario:mail
        if [ -f "$user_home/.shadow" ]; then
            chown "$ACCOUNT:mail" "$user_home/.shadow" 2>/dev/null
        fi
        
        # imap: user:mail (main directory and all its content)
        show_progress_line "Adjusting specific groups (mail)..."
        if [ -d "$user_home/imap" ]; then
            find "$user_home" -type d -maxdepth 1 -name "imap" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
            find "$user_home" -type d -path "*/imap/*" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
            find "$user_home" -type f -path "*/imap/*" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
        fi
        
        # .trash: usuario:mail
        if [ -d "$user_home/.trash" ]; then
            find "$user_home" -type d -maxdepth 1 -name ".trash" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
            find "$user_home" -type d -path "*/.trash/*" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
            find "$user_home" -type f -path "*/.trash/*" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
        fi
        
        # .spamassassin: usuario:mail
        if [ -d "$user_home/.spamassassin" ]; then
            find "$user_home" -type d -maxdepth 1 -name ".spamassassin" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
            find "$user_home" -type d -path "*/.spamassassin/*" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
            find "$user_home" -type f -path "*/.spamassassin/*" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
        fi
        
        # Count processed files and directories for summary
        CHOWN_PROCESSED_DIRS=$(find "$user_home" -type d 2>/dev/null | wc -l)
        CHOWN_PROCESSED_FILES=$(find "$user_home" -type f 2>/dev/null | wc -l)
        
        echo ""
        log "${GREEN}[OK]${NC} Ownership applied: $ACCOUNT:$ACCOUNT (mail: $ACCOUNT:mail)"
    elif [ "$PANEL_TYPE" = "cpanel" ]; then
        # cPanel: apply ownership according to official specification
        show_progress_line "Applying cPanel ownership..."
        
        # Base: user:user for most
        # IMPORTANT: Apply ownership to everything EXCEPT public_html and .htpasswds first
        # We'll handle public_html and .htpasswds separately based on File Protect status
        # Use find with -prune to exclude public_html and .htpasswds from recursive chown
        find "$user_home" \( -path "$user_home/public_html" -o -path "$user_home/.htpasswds" \) -prune -o -type f -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
        find "$user_home" \( -path "$user_home/public_html" -o -path "$user_home/.htpasswds" \) -prune -o -type d -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
        
        # public_html and .htpasswds: group depends on File Protect
        # IMPORTANT: This must be done AFTER excluding them from the recursive chown
        # Also ensure this is done AFTER all other chown operations to prevent overwriting
        # Detect File Protect status once
        local file_protect_detected=false
        if detect_file_protect "$user_home"; then
            file_protect_detected=true
        fi
        
        if [ "$file_protect_detected" = true ]; then
            # File Protect ON: public_html and .htpasswds should be usuario:nobody
            if [ -d "$user_home/public_html" ]; then
                chown "$ACCOUNT:nobody" "$user_home/public_html" 2>/dev/null
                log "${CYAN}[INFO]${NC} public_html ownership set to $ACCOUNT:nobody (File Protect enabled)"
            fi
            if [ -d "$user_home/.htpasswds" ]; then
                chown "$ACCOUNT:nobody" "$user_home/.htpasswds" 2>/dev/null
                log "${CYAN}[INFO]${NC} .htpasswds ownership set to $ACCOUNT:nobody (File Protect enabled)"
            fi
        else
            # File Protect OFF: public_html and .htpasswds should be usuario:usuario
            if [ -d "$user_home/public_html" ]; then
                chown "$ACCOUNT:$ACCOUNT" "$user_home/public_html" 2>/dev/null
                log "${CYAN}[INFO]${NC} public_html ownership set to $ACCOUNT:$ACCOUNT (File Protect disabled)"
            fi
            if [ -d "$user_home/.htpasswds" ]; then
                chown "$ACCOUNT:$ACCOUNT" "$user_home/.htpasswds" 2>/dev/null
                log "${CYAN}[INFO]${NC} .htpasswds ownership set to $ACCOUNT:$ACCOUNT (File Protect disabled)"
            fi
        fi
        
        # etc: usuario:mail
        if [ -d "$user_home/etc" ]; then
            find "$user_home" -type d -path "*/etc" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
            find "$user_home" -type d -path "*/etc/*" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
            find "$user_home" -type f -path "*/etc/*" -exec chown "$ACCOUNT:mail" {} \; 2>/dev/null
        fi
        
        # IMPORTANT: Apply ownership to domains/subdomains outside public_html
        # Method 1: Use official cPanel configuration (already applied in CHMOD, but ensure ownership)
        if [ -d "/var/cpanel/userdata/$ACCOUNT" ]; then
            while IFS= read -r document_root; do
                if [ -n "$document_root" ] && [ "$document_root" != "$user_home/public_html" ] && [ -d "$document_root" ]; then
                    document_root=$(echo "$document_root" | sed 's|/$||')
                    chown -R "$ACCOUNT:$ACCOUNT" "$document_root" 2>/dev/null
                fi
            done < <(grep -i "documentroot" /var/cpanel/userdata/"$ACCOUNT"/* 2>/dev/null | grep -v '.cache\|_SSL' | awk '{print $2}' | grep -v "^$user_home/public_html$" | sort -u)
        fi
        
        # Method 2: If domain structure exists outside public_html
        if [ -d "$user_home/domains" ]; then
            find "$user_home" -type d -path "*/domains/*" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
            find "$user_home" -type f -path "*/domains/*" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
        fi
        
        # IMPORTANT: Ensure that .htaccess files throughout the home have correct ownership
        find "$user_home" -type f -name ".htaccess" -exec chown "$ACCOUNT:$ACCOUNT" {} \; 2>/dev/null
        
        # access-logs: keep as symlink (do not change)
        # Already has correct ownership from previous chown
        
        # IMPORTANT: Re-apply public_html and .htpasswds ownership at the END to ensure they're not overwritten
        # This is a final check to ensure they have the correct ownership based on File Protect
        # Re-detect File Protect status to ensure accuracy
        local file_protect_final=false
        if detect_file_protect "$user_home"; then
            file_protect_final=true
        fi
        
        if [ "$file_protect_final" = true ]; then
            if [ -d "$user_home/public_html" ]; then
                chown "$ACCOUNT:nobody" "$user_home/public_html" 2>/dev/null
                log "${CYAN}[INFO]${NC} Final check: public_html ownership confirmed as $ACCOUNT:nobody (File Protect enabled)"
            fi
            if [ -d "$user_home/.htpasswds" ]; then
                chown "$ACCOUNT:nobody" "$user_home/.htpasswds" 2>/dev/null
                log "${CYAN}[INFO]${NC} Final check: .htpasswds ownership confirmed as $ACCOUNT:nobody (File Protect enabled)"
            fi
        else
            if [ -d "$user_home/public_html" ]; then
                chown "$ACCOUNT:$ACCOUNT" "$user_home/public_html" 2>/dev/null
                log "${CYAN}[INFO]${NC} Final check: public_html ownership confirmed as $ACCOUNT:$ACCOUNT (File Protect disabled)"
            fi
            if [ -d "$user_home/.htpasswds" ]; then
                chown "$ACCOUNT:$ACCOUNT" "$user_home/.htpasswds" 2>/dev/null
                log "${CYAN}[INFO]${NC} Final check: .htpasswds ownership confirmed as $ACCOUNT:$ACCOUNT (File Protect disabled)"
            fi
        fi
        
        echo ""
        log "${GREEN}[OK]${NC} Ownership applied: $ACCOUNT:$ACCOUNT (etc: $ACCOUNT:mail, public_html according to File Protect)"
        
        # Count processed files and directories for summary
        CHOWN_PROCESSED_DIRS=$(find "$user_home" -type d 2>/dev/null | wc -l)
        CHOWN_PROCESSED_FILES=$(find "$user_home" -type f 2>/dev/null | wc -l)
    else
        # No panel detected: apply directly
        show_progress_line "Applying ownership $ACCOUNT:$user_group..."
        chown -R "$ACCOUNT:$user_group" "$user_home" 2>/dev/null
        local chown_exit_code=$?
        echo ""
        
        if [ $chown_exit_code -eq 0 ]; then
            # Count processed files and directories for summary
            CHOWN_PROCESSED_DIRS=$(find "$user_home" -type d 2>/dev/null | wc -l)
            CHOWN_PROCESSED_FILES=$(find "$user_home" -type f 2>/dev/null | wc -l)
            log "${GREEN}[OK]${NC} Ownership applied: $ACCOUNT:$user_group"
        else
            log "${RED}[ERROR]${NC} Error applying ownership (may require root)"
            return 1
        fi
    fi
}

# Show final summary
show_summary() {
    local elapsed=$(( $(date +%s) - START_TIME ))
    local mins=$((elapsed / 60))
    local secs=$((elapsed % 60))
    
    echo ""
    log "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${GREEN}FINAL SUMMARY${NC}"
    log "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
    log "${CYAN}User:${NC} $ACCOUNT"
    log "${CYAN}System:${NC} $OS_DISTRO $OS_VERSION (Kernel: $OS_KERNEL)"
    log "${CYAN}Panel:${NC} $([ "$PANEL_TYPE" = "cpanel" ] && echo "cPanel" || [ "$PANEL_TYPE" = "directadmin" ] && echo "DirectAdmin" || echo "None")"
    log "${CYAN}Mode:${NC} $([ "$DRY_RUN" = true ] && echo "${MAGENTA}DRY-RUN (Simulation)${NC}" || echo "${GREEN}Real Execution${NC}")"
    
    if [ "$SKIP_CHMOD" = false ]; then
        log "${CYAN}CHMOD:${NC} ${GREEN}✓${NC} $PROCESSED_DIRS directories, $PROCESSED_FILES files"
    fi
    
    if [ "$SKIP_CHOWN" = false ]; then
        # Determine the group used according to the panel
        local summary_group=""
        if [ "$PANEL_TYPE" = "directadmin" ]; then
            summary_group="$ACCOUNT"
        else
            summary_group=$(id -gn "$ACCOUNT")
        fi
        # Use CHOWN count variables if available, otherwise use totals
        local chown_dirs=${CHOWN_PROCESSED_DIRS:-$TOTAL_DIRS}
        local chown_files=${CHOWN_PROCESSED_FILES:-$TOTAL_FILES}
        log "${CYAN}CHOWN:${NC} ${GREEN}✓${NC} $chown_dirs directories, $chown_files files (user: $ACCOUNT, group: $summary_group)"
    fi
    
    log "${CYAN}Total time:${NC} ${GREEN}${mins}m ${secs}s${NC}"
    
    if [ "$LOG_ENABLED" = true ]; then
        log "${CYAN}Log saved at:${NC} $LOG_FILE"
    fi
    
    log "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
    log "${GREEN}[COMPLETED]${NC} Process finished successfully"
}

# Function to process an account
process_account() {
    local account="$1"
    ACCOUNT="$account"
    
    # Validate user
    if ! validate_user; then
        return 1
    fi
    
    # Get home directory
    user_home=$(get_user_home)
    if [ -z "$user_home" ] || [ ! -d "$user_home" ]; then
        log "${RED}[ERROR]${NC} Could not access home directory of $account"
        return 1
    fi
    
    log "${GREEN}[INFO]${NC} Processing: ${BOLD}$account${NC} → $user_home"
    
    # Aplicar cambios
    if [ "$SKIP_CHMOD" = false ]; then
        apply_chmod "$user_home"
    fi
    
    if [ "$SKIP_CHOWN" = false ]; then
        apply_chown "$user_home"
    fi
    
    return 0
}

# Main function
main() {
    # Initialize log
    if [ "$LOG_ENABLED" = true ]; then
        echo "=== $SCRIPT_NAME v$SCRIPT_VERSION executed on $(date) ===" > "$LOG_FILE"
        echo "Parameters: $@" >> "$LOG_FILE"
    fi
    
    # Clear and show header
    if [ "$INTERACTIVE_MODE" = false ]; then
        clear
    fi
    draw_header
    
    # Detect operating system
    if ! detect_os; then
        sleep 2
        exit 1
    fi
    
    # Detect panel
    detect_panel
    
    # If processing all accounts
    if [ "$PROCESS_ALL" = true ]; then
        local accounts_array
        mapfile -t accounts_array < <(list_accounts)
        local total_accounts=${#accounts_array[@]}
        
        if [ $total_accounts -eq 0 ]; then
            log "${RED}[ERROR]${NC} No accounts found to process"
            exit 1
        fi
        
        log "${CYAN}[INFO]${NC} Processing ${BOLD}$total_accounts${NC} accounts"
        echo ""
        draw_output_border
        
        local success_count=0
        local fail_count=0
        
        for account in "${accounts_array[@]}"; do
            PROCESSED_FILES=0
            PROCESSED_DIRS=0
            
            if process_account "$account"; then
                success_count=$((success_count + 1))
                log "${GREEN}[OK]${NC} $account procesado correctamente"
            else
                fail_count=$((fail_count + 1))
                log "${RED}[ERROR]${NC} Error processing $account"
            fi
            echo ""
        done
        
        draw_output_border_bottom
        
        # Final summary for all accounts
        echo ""
        log "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        log "${BOLD}${GREEN}RESUMEN FINAL${NC}"
        log "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        log "${CYAN}Total accounts:${NC} $total_accounts"
        log "${CYAN}Exitosas:${NC} ${GREEN}$success_count${NC}"
        log "${CYAN}Fallidas:${NC} $([ $fail_count -gt 0 ] && echo "${RED}$fail_count${NC}" || echo "${GREEN}$fail_count${NC}")"
        
        if [ "$LOG_ENABLED" = true ]; then
            log "${CYAN}Log guardado en:${NC} $LOG_FILE"
        fi
        log "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        
        return 0
    fi
    
    # Process a single account (original code)
    if ! validate_user; then
        sleep 2
        exit 1
    fi
    
    # Show information panel
    draw_info_panel
    
    # Get home directory
    user_home=$(get_user_home)
    if [ -z "$user_home" ] || [ ! -d "$user_home" ]; then
        log "${RED}[ERROR]${NC} Could not access home directory"
        sleep 2
        exit 1
    fi
    
    log "${GREEN}[INFO]${NC} Home directory: $user_home"
    
    # Show operation mode
    if [ "$DRY_RUN" = true ]; then
        log "${MAGENTA}[MODE]${NC} DRY-RUN (simulation, no changes will be made)"
    fi
    
    if [ "$CHMOD_ONLY" = true ]; then
        SKIP_CHOWN=true
        log "${YELLOW}[MODE]${NC} CHMOD only"
    elif [ "$CHOWN_ONLY" = true ]; then
        SKIP_CHMOD=true
        log "${YELLOW}[MODE]${NC} CHOWN only"
    else
        log "${YELLOW}[MODE]${NC} CHMOD and CHOWN"
    fi
    
    echo ""
    draw_output_border
    
    # Aplicar cambios
    if [ "$SKIP_CHMOD" = false ]; then
        apply_chmod "$user_home"
    fi
    
    if [ "$SKIP_CHOWN" = false ]; then
        apply_chown "$user_home"
    fi
    
    draw_output_border_bottom
    
        # Final summary
    show_summary
}

# List available accounts
list_accounts() {
    local accounts=()
    local found_panel=false
    
    # Detect panel first (without showing output)
    if [ -d "/usr/local/cpanel" ] || [ -f "/usr/local/cpanel/version" ] || [ -d "/var/cpanel" ]; then
        # cPanel: list users from /var/cpanel/users
        if [ -d "/var/cpanel/users" ]; then
            found_panel=true
            while IFS= read -r user; do
                if [ -n "$user" ] && id "$user" &>/dev/null 2>&1; then
                    accounts+=("$user")
                fi
            done < <(ls -1 /var/cpanel/users 2>/dev/null)
        fi
    elif [ -d "/usr/local/directadmin" ] || [ -f "/usr/local/directadmin/directadmin" ]; then
        # DirectAdmin: list users from /usr/local/directadmin/data/users
        if [ -d "/usr/local/directadmin/data/users" ]; then
            found_panel=true
            while IFS= read -r user; do
                if [ -n "$user" ] && id "$user" &>/dev/null 2>&1; then
                    accounts+=("$user")
                fi
            done < <(ls -1 /usr/local/directadmin/data/users 2>/dev/null)
        fi
    fi
    
    # If there are no panel accounts or no panel, list system users with home
    if [ ${#accounts[@]} -eq 0 ]; then
        while IFS=: read -r user x uid gid x home shell; do
            if [ -n "$user" ] && [ "$user" != "nobody" ] && [ -d "$home" ] 2>/dev/null && [ "$uid" -ge 1000 ] 2>/dev/null; then
                accounts+=("$user")
            fi
        done < <(getent passwd 2>/dev/null)
        
        # If still none, try only with /home
        if [ ${#accounts[@]} -eq 0 ]; then
            while IFS= read -r user; do
                if [ -n "$user" ] && [ "$user" != "nobody" ] && [ -d "/home/$user" ] 2>/dev/null && id "$user" &>/dev/null 2>&1; then
                    accounts+=("$user")
                fi
            done < <(ls -1 /home 2>/dev/null)
        fi
    fi
    
    # Ordenar y mostrar
    if [ ${#accounts[@]} -gt 0 ]; then
        printf '%s\n' "${accounts[@]}" | sort -u
    fi
}

# Show account menu in columns
menu_select_account() {
    MENU_ACCOUNT_RESULT=""
    
    local accounts_array
    mapfile -t accounts_array < <(list_accounts)
    local count=${#accounts_array[@]}
    
    if [ $count -eq 0 ]; then
        echo -e "${RED}[ERROR]${NC} No accounts found"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}┌─ Select Account──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Select an account:${NC}"
    
    # Calculate number of columns: maximum 35 users per column
    local max_users_per_col=35
    local rows=$max_users_per_col
    
    # Calculate how many columns we need
    local cols=$(( (count + rows - 1) / rows ))
    
    # If there are fewer users than maximum, adjust rows
    if [ $count -lt $max_users_per_col ]; then
        rows=$count
        cols=1
    fi
    
    # Calculate maximum account width for formatting
    local max_account_width=0
    for account in "${accounts_array[@]}"; do
        if [ ${#account} -gt $max_account_width ]; then
            max_account_width=${#account}
        fi
    done
    
    # Limit display width to 30 characters to fit more columns
    if [ $max_account_width -gt 30 ]; then
        max_account_width=30
    fi
    
    # Display in columns
    for ((row=0; row<rows; row++)); do
        printf "${CYAN}│${NC}  "
        local line_printed=false
        for ((col=0; col<cols; col++)); do
            local pos=$((col * rows + row))
            local idx=$((pos + 1))
            if [ $pos -lt $count ]; then
                # Limit account width for better visualization
                local display_account="${accounts_array[$pos]}"
                if [ ${#display_account} -gt $max_account_width ]; then
                    display_account="${display_account:0:$((max_account_width - 3))}..."
                fi
                printf "${GREEN}%3d${NC}. %-${max_account_width}s  " "$idx" "$display_account"
                line_printed=true
            fi
        done
        if [ "$line_printed" = true ]; then
            echo ""
        fi
    done
    
    echo -e "${CYAN}│${NC}  ${YELLOW} 0${NC}. Back"
    echo -e "${CYAN}│${NC}  ${YELLOW}00${NC}. Cancel all"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -ne "${BOLD}Your selection [0-$count, 00]:${NC} "
    
    read -r selection
    
    # Validate input
    if [ -z "$selection" ]; then
        echo -e "${RED}[ERROR]${NC} You must select an option"
        return 1
    fi
    
    if [ "$selection" = "00" ]; then
        echo -e "${YELLOW}Operation cancelled${NC}"
        exit 0
    fi
    
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 0 ] || [ "$selection" -gt $count ]; then
        echo -e "${RED}[ERROR]${NC} Invalid selection. Must be a number between 0 and $count, or 00 to cancel"
        return 1
    fi
    
    if [ "$selection" -eq 0 ]; then
        MENU_ACCOUNT_RESULT="back"
        return 2  # Special code for "back"
    fi
    
    selection=$((selection - 1))
    MENU_ACCOUNT_RESULT="${accounts_array[$selection]}"
}

# Action menu
menu_select_action() {
    echo ""
    echo -e "${CYAN}┌─ Select Action──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}What would you like to do?${NC}"
    echo -e "${CYAN}│${NC}  ${GREEN}1${NC}. CHMOD and CHOWN (both)"
    echo -e "${CYAN}│${NC}  ${GREEN}2${NC}. Solo CHMOD (permisos)"
    echo -e "${CYAN}│${NC}  ${GREEN}3${NC}. CHOWN only (ownership)"
    echo -e "${CYAN}│${NC}  ${YELLOW} 0${NC}. Cancel"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -ne "${BOLD}Your selection [0-3]:${NC} "
    
    read -r selection
    
    if [ -z "$selection" ]; then
        echo -e "${RED}[ERROR]${NC} You must select an option"
        return 1
    fi
    
    case "$selection" in
        1)
            CHMOD_ONLY=false
            CHOWN_ONLY=false
            ;;
        2)
            CHMOD_ONLY=true
            CHOWN_ONLY=false
            ;;
        3)
            CHMOD_ONLY=false
            CHOWN_ONLY=true
            ;;
        0)
            echo -e "${YELLOW}Operation cancelled${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Invalid selection"
            return 1
            ;;
    esac
}

# Additional options menu
menu_options() {
    echo ""
    echo -e "${CYAN}┌─ Additional Options──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Additional options:${NC}"
    echo -e "${CYAN}│${NC}  ${GREEN}1${NC}. DRY-RUN mode (simulate without making changes)"
    echo -e "${CYAN}│${NC}  ${GREEN}2${NC}. Enable log (fixperms.log)"
    echo -e "${CYAN}│${NC}  ${GREEN}3${NC}. Both options"
    echo -e "${CYAN}│${NC}  ${GREEN}0${NC}. None (continue)"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -ne "${BOLD}Your selection [0-3]:${NC} "
    
    read -r selection
    
    if [ -z "$selection" ]; then
        # If no input, use default (none)
        DRY_RUN=false
        LOG_ENABLED=false
        return 0
    fi
    
    case "$selection" in
        1)
            DRY_RUN=true
            LOG_ENABLED=false
            ;;
        2)
            DRY_RUN=false
            LOG_ENABLED=true
            ;;
        3)
            DRY_RUN=true
            LOG_ENABLED=true
            ;;
        0|*)
            DRY_RUN=false
            LOG_ENABLED=false
            ;;
    esac
}

# Search for similar user suggestions
# Returns the suggestions array in a global variable
SUGGESTIONS_ARRAY=()
suggest_accounts() {
    local search_term="$1"
    local accounts_array
    mapfile -t accounts_array < <(list_accounts)
    SUGGESTIONS_ARRAY=()
    
    # Search for users starting with the first letter
    local first_char="${search_term:0:1}"
    for account in "${accounts_array[@]}"; do
        if [[ "${account:0:1}" == "$first_char" ]]; then
            SUGGESTIONS_ARRAY+=("$account")
        fi
    done
    
    # If there are suggestions, show them
    if [ ${#SUGGESTIONS_ARRAY[@]} -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}Did you mean one of these?${NC}"
        local i=1
        for sug in "${SUGGESTIONS_ARRAY[@]:0:10}"; do
            echo -e "  ${GREEN}$i${NC}. $sug"
            i=$((i + 1))
        done
        if [ ${#SUGGESTIONS_ARRAY[@]} -gt 10 ]; then
            echo -e "  ${CYAN}... and $(( ${#SUGGESTIONS_ARRAY[@]} - 10 )) more${NC}"
        fi
    fi
}

# Global variable to store selection
MENU_SCOPE_RESULT=""

# Menu to select all accounts or one
menu_select_scope() {
    MENU_SCOPE_RESULT=""
    
    echo ""
    echo -e "${CYAN}┌─ Select Scope──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}What would you like to do?${NC}"
    echo -e "${CYAN}│${NC}  ${GREEN}1${NC}. Process ALL accounts"
    echo -e "${CYAN}│${NC}  ${GREEN}2${NC}. Process ONE specific account"
    echo -e "${CYAN}│${NC}  ${YELLOW}00${NC}. Cancel all"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -ne "${BOLD}Your selection [1-2, 00]:${NC} "
    
    read -r selection
    
    if [ -z "$selection" ]; then
        echo -e "${RED}[ERROR]${NC} You must select an option"
        return 1
    fi
    
    case "$selection" in
        1)
            MENU_SCOPE_RESULT="all"
            ;;
        2)
            MENU_SCOPE_RESULT="one"
            ;;
        00)
            echo -e "${YELLOW}Operation cancelled${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Invalid selection. Must be 1, 2, or 00 to cancel"
            return 1
            ;;
    esac
}

# Function to autocomplete usernames
_username_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local accounts
    mapfile -t accounts < <(list_accounts 2>/dev/null)
    COMPREPLY=($(compgen -W "${accounts[*]}" -- "$cur"))
}

# Menu to enter username manually
menu_enter_username() {
    MENU_USERNAME_RESULT=""
    
    # Configure autocomplete
    local accounts
    mapfile -t accounts < <(list_accounts 2>/dev/null)
    
    # Clear suggestions at start
    SUGGESTIONS_ARRAY=()
    
    while true; do
        echo ""
        echo -e "${CYAN}┌─ Enter Username──────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${NC} ${YELLOW}Enter the username (Tab for autocomplete):${NC}"
        echo -e "${CYAN}│${NC} ${YELLOW} 0 = Back, 00 = Cancel all${NC}"
        echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -ne "${BOLD}User:${NC} "
        
        # Use read -e to enable line editing and autocomplete
        if [ -n "$BASH_VERSION" ]; then
            # Configure temporary autocomplete
            complete -W "${accounts[*]}" -o default 2>/dev/null
            read -e input_user
            complete -r 2>/dev/null
        else
            read -r input_user
        fi
        
        if [ -z "$input_user" ]; then
            echo -e "${RED}[ERROR]${NC} You must enter a username"
            echo ""
            continue
        fi
        
        # Check if wants to go back or cancel
        if [ "$input_user" = "0" ]; then
            MENU_USERNAME_RESULT="back"
            return 2  # Special code for "back"
        fi
        
        if [ "$input_user" = "00" ]; then
            echo -e "${YELLOW}Operation cancelled${NC}"
            exit 0
        fi
        
        # If it's a number and suggestions are available, select from suggestions
        if [[ "$input_user" =~ ^[0-9]+$ ]] && [ ${#SUGGESTIONS_ARRAY[@]} -gt 0 ]; then
            local selected_idx=$((input_user - 1))
            if [ $selected_idx -ge 0 ] && [ $selected_idx -lt ${#SUGGESTIONS_ARRAY[@]} ]; then
                input_user="${SUGGESTIONS_ARRAY[$selected_idx]}"
                # Continue with validation of selected user
            else
                echo ""
                echo -e "${RED}[ERROR]${NC} Invalid number. Must be between 1 and ${#SUGGESTIONS_ARRAY[@]}"
                echo ""
                continue
            fi
        elif [[ "$input_user" =~ ^[0-9]+$ ]]; then
            # If it's a number but there are no suggestions, reject
            echo ""
            echo -e "${RED}[ERROR]${NC} '$input_user' is not a valid username. Usernames cannot be only numbers."
            echo ""
            continue
        fi
        
        # Validate that user exists
        if ! id "$input_user" &>/dev/null; then
            echo ""
            echo -e "${RED}[ERROR]${NC} User '$input_user' does not exist"
            suggest_accounts "$input_user"
            echo ""
            # Continue directly to next while cycle, which will show the prompt again
            continue
        fi
        
        MENU_USERNAME_RESULT="$input_user"
        return 0
    done
}

# Menu to choose how to select the account
menu_how_select_account() {
    MENU_HOW_SELECT_RESULT=""
    
    echo ""
    echo -e "${CYAN}┌─ Select Account──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}How would you like to select the account?${NC}"
    echo -e "${CYAN}│${NC}  ${GREEN}1${NC}. View account list and select"
    echo -e "${CYAN}│${NC}  ${GREEN}2${NC}. Enter name directly"
    echo -e "${CYAN}│${NC}  ${YELLOW} 0${NC}. Back"
    echo -e "${CYAN}│${NC}  ${YELLOW}00${NC}. Cancel all"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -ne "${BOLD}Your selection [0-2, 00]:${NC} "
    
    read -r selection
    
    if [ -z "$selection" ]; then
        echo -e "${RED}[ERROR]${NC} You must select an option"
        return 1
    fi
    
    case "$selection" in
        1)
            MENU_HOW_SELECT_RESULT="list"
            ;;
        2)
            MENU_HOW_SELECT_RESULT="enter"
            ;;
        0)
            MENU_HOW_SELECT_RESULT="back"
            ;;
        00)
            echo -e "${YELLOW}Operation cancelled${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Invalid selection. Must be a number between 0 and 2, or 00 to cancel"
            return 1
            ;;
    esac
}

# Interactive mode
interactive_mode() {
    while true; do
        clear
        draw_header
        
        echo -e "${BOLD}${CYAN}Interactive Mode${NC}"
        echo -e "${YELLOW}Select options step by step${NC}"
        echo ""
        
        # Step 1: Select scope (all accounts or one)
        menu_select_scope
        if [ $? -ne 0 ] || [ -z "$MENU_SCOPE_RESULT" ]; then
            exit 1
        fi
        
        local scope="$MENU_SCOPE_RESULT"
        
        # No "back" option in the first menu, so we don't need to verify
        
        # If we get here, we have a valid scope, exit the loop
        break
    done
    
    # Continue with normal process
    local scope="$MENU_SCOPE_RESULT"
    
    if [ "$scope" = "all" ]; then
        PROCESS_ALL=true
        echo -e "${GREEN}[OK]${NC} You will process ${BOLD}ALL${NC} accounts"
    else
        PROCESS_ALL=false
        # Step 2: If it's one account, ask how to select it
        while true; do
            menu_how_select_account
            if [ $? -ne 0 ] || [ -z "$MENU_HOW_SELECT_RESULT" ]; then
                exit 1
            fi
            
            local how_select="$MENU_HOW_SELECT_RESULT"
            
            if [ "$how_select" = "list" ]; then
                menu_select_account
                local account_result=$?
                if [ $account_result -eq 2 ]; then
                    # Back to previous menu
                    continue
                elif [ $account_result -ne 0 ] || [ -z "$MENU_ACCOUNT_RESULT" ]; then
                    exit 1
                fi
                ACCOUNT="$MENU_ACCOUNT_RESULT"
            elif [ "$how_select" = "back" ]; then
                # Back to previous menu
                continue
            else
                menu_enter_username
                local username_result=$?
                if [ $username_result -eq 2 ]; then
                    # Back to previous menu
                    continue
                elif [ $username_result -ne 0 ] || [ -z "$MENU_USERNAME_RESULT" ]; then
                    exit 1
                fi
                ACCOUNT="$MENU_USERNAME_RESULT"
            fi
            
            # If we get here, we have a valid account
            break
        done
        
        echo -e "${GREEN}[OK]${NC} Account selected: ${BOLD}$ACCOUNT${NC}"
    fi
    
    echo ""
    
    # Step 3: Select action
    menu_select_action
    if [ $? -ne 0 ]; then
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} Action configured"
    echo ""
    
    # Step 4: Additional options
    menu_options
    if [ $? -ne 0 ]; then
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} Options configured"
    echo ""
    
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}Configuration Summary:${NC}"
    if [ "$PROCESS_ALL" = true ]; then
        echo -e "${CYAN}Scope:${NC} ${MAGENTA}ALL accounts${NC}"
    else
        echo -e "${CYAN}Account:${NC} ${GREEN}$ACCOUNT${NC}"
    fi
    # Determine the action correctly
    local action_text=""
    if [ "$CHMOD_ONLY" = true ]; then
        action_text="${YELLOW}CHMOD only${NC}"
    elif [ "$CHOWN_ONLY" = true ]; then
        action_text="${YELLOW}CHOWN only${NC}"
    else
        action_text="${GREEN}CHMOD and CHOWN${NC}"
    fi
    echo -e "${CYAN}Action:${NC} $action_text"
    echo -e "${CYAN}DRY-RUN:${NC} $([ "$DRY_RUN" = true ] && echo "${GREEN}Yes${NC}" || echo "${RED}No${NC}")"
    echo -e "${CYAN}Log:${NC} $([ "$LOG_ENABLED" = true ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -ne "${BOLD}Continue? [Y/n]:${NC} "
    read -r confirm
    
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}Operation cancelled${NC}"
        exit 0
    fi
    
    echo ""
    INTERACTIVE_MODE=true
}

# Parse arguments
parse_arguments() {
    # If no arguments, activate interactive mode
    if [ $# -eq 0 ]; then
        INTERACTIVE_MODE=true
        return 0
    fi
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --account)
                ACCOUNT="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --log)
                LOG_ENABLED=true
                shift
                ;;
            --chmod-only)
                CHMOD_ONLY=true
                shift
                ;;
            --chown-only)
                CHOWN_ONLY=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}[ERROR]${NC} Unknown option: $1"
                echo "Use --help to see available options"
                exit 1
                ;;
        esac
    done
    
    if [ "$CHMOD_ONLY" = true ] && [ "$CHOWN_ONLY" = true ]; then
        echo -e "${RED}[ERROR]${NC} Cannot use --chmod-only and --chown-only simultaneously"
        exit 1
    fi
}

# Execute script
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    parse_arguments "$@"
    
    # If interactive mode, execute interactive function
    if [ "$INTERACTIVE_MODE" = true ]; then
        interactive_mode
    fi
    
    main
fi
