#!/bin/bash
set -euo pipefail

# Script Variables
SCRIPT_PATH=$(mktemp)
trap 'rm -f "$SCRIPT_PATH"' EXIT
SCRIPT_VERSION="1.1"
LOCK_FILE="/var/run/system_hardening.lock"
LOG_FILE="/var/log/system_hardening.log"
BACKUP_DIR="/root/system_hardening_backups/$(date +%Y%m%d_%H%M%S)"

validate_user() {
    local username=$1
    
    # Check if username is empty
    if [[ -z "$username" ]]; then
        return 1
    fi

    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        return 1
    fi

    # Check if home directory exists
    local user_home
    user_home=$(getent passwd "$username" | cut -d: -f6)
    if [[ ! -d "$user_home" ]]; then
        return 1
    fi

    return 0
}

get_user_shell() {
    local username=$1
    getent passwd "$username" | cut -d: -f7
}

is_system_user() {
    local username=$1
    local uid
    uid=$(id -u "$username")
    [[ "$uid" -lt 1000 ]]
}

install_prerequisites() {
    log "INFO" "Installing prerequisites..."
    
    apt-get update || {
        log "ERROR" "Failed to update package lists"
        return 1
    }
    
    if ! apt-get install -y wget curl systemd; then
        log "ERROR" "Failed to install prerequisites"
        return 1
    fi

    # Verify systemd is running
    if ! command -v systemd-detect-virt >/dev/null 2>&1 || ! systemd-detect-virt --container | grep -q "lxc"; then
        if ! pidof systemd >/dev/null 2>&1; then
            log "WARNING" "systemd installed but not running. A system reboot is required."
            echo "System needs to be rebooted to complete systemd installation."
            read -r -p "Would you like to reboot now? (y/n): " response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                log "INFO" "Rebooting system..."
                reboot
            else
                log "ERROR" "Cannot continue without systemd running"
                return 1
            fi
        fi
    fi

    log "INFO" "All prerequisites are installed"
    return 0
}

# System Requirements
MIN_RAM_MB=400
MIN_DISK_MB=400
MIN_SWAP_MB=400
if systemd-detect-virt --container | grep -q "lxc"; then
    REQUIRED_COMMANDS=(wget curl ping)
else
    REQUIRED_COMMANDS=(systemctl wget curl ping)
fi

# Trap handlers
trap 'handle_error $LINENO' ERR
trap 'cleanup' EXIT

# Core Functions
handle_error() {
    local exit_code=$?
    local line_no=$1
    log "ERROR" "Script failed at line ${line_no} with exit code ${exit_code}"
    log "ERROR" "Command: $(sed -n ${line_no}p "$SCRIPT_PATH")"
    log "ERROR" "Starting cleanup and rollback procedures..."
    cleanup
    exit "$exit_code"
}

cleanup() {
    log "INFO" "Performing cleanup..."
    rm -f "$LOCK_FILE"
    [[ -d /tmp/system_hardening ]] && rm -rf /tmp/system_hardening
    log "INFO" "Cleanup completed"
}

log() {
    local level=$1; shift
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo "$msg" | tee -a "$LOG_FILE"
    
    # Send critical errors to syslog
    if [[ "$level" == "ERROR" ]]; then
        logger -p user.err "System Hardening: $*"
    fi
}

create_backup() {
    local file=$1
    if [[ ! -f "$file" ]]; then
        log "WARNING" "Cannot backup $file - file does not exist"
        return 0
    fi

    mkdir -p "$BACKUP_DIR" || {
        log "ERROR" "Failed to create backup directory"
        return 1
    }

    local backup_file="$BACKUP_DIR/$(basename "$file")"
    
    if ! cp -p "$file" "$backup_file"; then
        log "ERROR" "Failed to create backup of $file"
        return 1
    fi

    if ! cmp -s "$file" "$backup_file"; then
        log "ERROR" "Backup verification failed for $file"
        return 1
    fi

    log "INFO" "Successfully backed up $file to $backup_file"
    return 0
}

check_requirements() {
    log "INFO" "Checking system requirements..."
    
    # Check for required commands
    for cmd in "${REQUIRED_COMMANDS[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log "ERROR" "Required command '$cmd' not found"
            exit 1
        fi
    done

    # Check if running as root
    if [[ "$EUID" -ne 0 ]]; then
        log "ERROR" "This script must be run as root"
        exit 1
    fi

    # Modify systemd check to handle LXC
    if systemd-detect-virt --container | grep -q "lxc"; then
        log "INFO" "Running in LXC container - skipping systemd check"
    else
        if ! pidof systemd >/dev/null 2>&1; then
            log "ERROR" "systemd is required but not running"
            exit 1
        fi
    fi
}

check_system() {
    log "INFO" "Performing system checks..."

    check_interactive

    # Memory check
    local available_mem=$(free -m | awk '/^Mem:/{print $7}')
    if (( available_mem < MIN_RAM_MB )); then
        log "WARNING" "Less than ${MIN_RAM_MB}MB RAM available (Current: ${available_mem}MB)"
        read -r -p "Continue despite low memory? (y/n): " response
        [[ ! "$response" =~ ^[Yy]$ ]] && exit 1
    fi
    
    # Disk space check
    local free_space=$(df -m / | awk 'NR==2 {print $4}')
    if (( free_space < MIN_DISK_MB )); then
        log "WARNING" "Less than ${MIN_DISK_MB}MB disk space available (Current: ${free_space}MB)"
        read -r -p "Continue despite low disk space? (y/n): " response
        [[ ! "$response" =~ ^[Yy]$ ]] && exit 1
    fi

    # CPU check
    local cpu_cores=$(nproc)
    if (( cpu_cores < 2 )); then
        log "WARNING" "System has limited CPU resources (Cores: ${cpu_cores})"
        read -r -p "Continue with limited CPU resources? (y/n): " response
        [[ ! "$response" =~ ^[Yy]$ ]] && exit 1
    fi
    
    # Swap check
    local swap_available=$(free -m | awk '/^Swap:/{print $2}')
    if (( swap_available < MIN_SWAP_MB )); then
        log "WARNING" "Limited swap space available (Current: ${swap_available}MB)"
        read -r -p "Continue with limited swap? (y/n): " response
        [[ ! "$response" =~ ^[Yy]$ ]] && exit 1
    fi

    # Network connectivity check (multiple DNS servers)
    local dns_servers=("8.8.8.8" "1.1.1.1" "8.8.4.4")
    local connected=false
    
    for dns in "${dns_servers[@]}"; do
        if ping -c 1 -W 5 "$dns" >/dev/null 2>&1; then
            connected=true
            break
        fi
    done

    if ! $connected; then
        log "ERROR" "No internet connectivity detected"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        log "INFO" "Detected OS: $OS $OS_VERSION"
    else
        log "ERROR" "Cannot detect OS version"
        exit 1
    fi

    # Verify supported OS
    case "$OS" in
        ubuntu|debian)
            ;;
        *)
            log "ERROR" "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

check_interactive() {
    if [[ ! -t 0 ]]; then
        log "ERROR" "This script must be run interactively. Please run: bash -i /tmp/hardening.sh"
        exit 1
    fi
}

fix_locale() {
    log "INFO" "Fixing locale settings..."
    
    # Check if locales are properly generated
    if ! locale -a | grep -q "en_US.utf8"; then
        log "INFO" "Generating en_US.UTF-8 locale..."
        echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
        locale-gen
    fi

    # Set correct environment variables
    cat > /etc/default/locale <<EOF
LANG=en_US.UTF-8
LC_ALL=en_US.UTF-8
LANGUAGE=en_US:en
EOF

    # Export for current session
    export LANG=en_US.UTF-8
    export LC_ALL=en_US.UTF-8
    export LANGUAGE=en_US:en

    # Source the new settings
    . /etc/default/locale

    log "INFO" "Locale settings updated"
}

verify_changes() {
    local file=$1
    local expected_content=$2
    
    if [[ ! -f "$file" ]]; then
        log "ERROR" "Configuration file $file does not exist"
        return 1
    fi

    if ! grep -q "$expected_content" "$file"; then
        log "ERROR" "Configuration verification failed for $file"
        return 1
    fi
    
    log "INFO" "Configuration verified for $file"
    return 0
}

# Script initialization
log "INFO" "Starting system hardening script v${SCRIPT_VERSION}"

# Check for existing lock file
if [[ -f "$LOCK_FILE" ]]; then
    log "ERROR" "Another instance of the script is running"
    exit 1
fi

# Create lock file with error handling
if ! touch "$LOCK_FILE" 2>/dev/null; then
    log "ERROR" "Cannot create lock file at $LOCK_FILE. Check permissions."
    exit 1
fi

# Create log directory with error handling
if ! mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null; then
    log "ERROR" "Cannot create log directory at $(dirname "$LOG_FILE"). Check permissions."
    rm -f "$LOCK_FILE"
    exit 1
fi

install_prerequisites || exit 1

# Initial checks
check_requirements
check_system
detect_os
check_interactive
fix_locale

# Package Management Functions
install_package() {
    local package=$1
    local max_attempts=3
    local attempt=1
    
    while (( attempt <= max_attempts )); do
        log "INFO" "Installing package $package (Attempt $attempt/$max_attempts)"
        if ! dpkg -l | grep -q "^ii.*$package"; then
            if apt-get install -y "$package" 2>/dev/null; then
                log "INFO" "Successfully installed $package"
                return 0
            else
                log "WARNING" "Failed to install $package on attempt $attempt"
                (( attempt++ ))
                sleep 5
            fi
        else
            log "INFO" "Package $package is already installed"
            return 0
        fi
    done
    
    log "ERROR" "Failed to install package $package after $max_attempts attempts"
    return 1
}

update_system() {
    log "INFO" "Updating package lists..."
    if ! apt-get update; then
        log "ERROR" "Failed to update package lists"
        return 1
    fi

    log "INFO" "Upgrading installed packages..."
    if ! apt-get upgrade -y; then
        log "ERROR" "Failed to upgrade packages"
        return 1
    fi
    
    log "INFO" "Performing distribution upgrade..."
    if ! apt-get dist-upgrade -y; then
        log "ERROR" "Failed to perform distribution upgrade"
        return 1
    fi

    log "INFO" "Removing unused packages..."
    apt-get autoremove -y
    apt-get clean

    return 0
}

# Add SSH keys for users
configure_ssh_keys() {
    local user_home=$1
    local username=$(basename "$user_home")
    local auth_keys_file="$user_home/.ssh/authorized_keys"
    
    # Initialize temp_key_file at the beginning
    local temp_key_file=""

    # Skip root user
    [[ "$username" == "root" ]] && return 0
    
    # Skip if not a valid home directory
    [[ ! -d "$user_home" ]] && return 0
    
    log "INFO" "Checking SSH keys for user: $username"
    
    # Create .ssh directory if it doesn't exist
    if [[ ! -d "$user_home/.ssh" ]]; then
        mkdir -p "$user_home/.ssh"
        chmod 700 "$user_home/.ssh"
        chown "$username:$username" "$user_home/.ssh"
    fi
    
    # Check for existing authorized_keys
    if [[ ! -f "$auth_keys_file" ]]; then
        log "INFO" "No authorized_keys file found for user: $username"
        
        read -r -p "Do you want to add an SSH key for user $username? (y/n): " add_key
        if [[ "$add_key" =~ ^[Yy]$ ]]; then
            # Create temporary file for key input
            local temp_key_file
            temp_key_file=$(mktemp) || {
                log "ERROR" "Failed to create temporary file for key input"
                return 1
            }
            
            # Cleanup handler for temporary file
            trap 'rm -f "$temp_key_file"' RETURN
            
            echo "Please paste the SSH public key for user $username (press Ctrl+D when done):"
            cat > "$temp_key_file"
            
            # Validate SSH key format
            if ! ssh-keygen -l -f "$temp_key_file" >/dev/null 2>&1; then
                log "ERROR" "Invalid SSH key format provided for user $username"
                return 1
            fi
            
            # Create authorized_keys with proper permissions
            cat "$temp_key_file" > "$auth_keys_file"
            chmod 600 "$auth_keys_file"
            chown "$username:$username" "$auth_keys_file"
            
            log "INFO" "SSH key added successfully for user $username"
            
            # Display key fingerprint for verification
            local key_fingerprint
            key_fingerprint=$(ssh-keygen -l -f "$auth_keys_file")
            log "INFO" "Key fingerprint: $key_fingerprint"
            
            # Ask for verification
            read -r -p "Does this key fingerprint look correct? (y/n): " verify_key
            if [[ ! "$verify_key" =~ ^[Yy]$ ]]; then
                log "WARNING" "Removing added key based on user verification"
                rm -f "$auth_keys_file"
                return 1
            fi
        else
            log "INFO" "Skipping SSH key configuration for user $username"
        fi
    else
        log "INFO" "Existing authorized_keys file found for user $username"
        
        # Display existing key fingerprints
        log "INFO" "Existing key fingerprints:"
        while read -r key; do
            [[ -n "$key" && "$key" != \#* ]] && {
                echo "$key" | ssh-keygen -l -f - 2>/dev/null || \
                    log "WARNING" "Invalid key found in authorized_keys"
            }
        done < "$auth_keys_file"
        
        # Option to add additional key
        read -r -p "Do you want to add an additional SSH key for user $username? (y/n): " add_key
        if [[ "$add_key" =~ ^[Yy]$ ]]; then
            echo "Please paste the additional SSH public key (press Ctrl+D when done):"
            local temp_key_file
            temp_key_file=$(mktemp) || {
                log "ERROR" "Failed to create temporary file for key input"
                return 1
            }
            
            trap 'rm -f "$temp_key_file"' RETURN
            cat > "$temp_key_file"
            
            # Validate new key
            if ! ssh-keygen -l -f "$temp_key_file" >/dev/null 2>&1; then
                log "ERROR" "Invalid SSH key format provided"
                return 1
            fi
            
            # Check for duplicate keys
            if grep -qf "$temp_key_file" "$auth_keys_file"; then
                log "WARNING" "This key is already present in authorized_keys"
                return 1
            fi
            
            # Append new key
            cat "$temp_key_file" >> "$auth_keys_file"
            chmod 600 "$auth_keys_file"
            chown "$username:$username" "$auth_keys_file"
            
            log "INFO" "Additional SSH key added successfully"
        fi
    fi
    
    return 0
}

configure_user_environment() {
    local user_home=$1
    local username=$(basename "$user_home")
    
    log "INFO" "Configuring environment for user: $username"

    # Skip if not a valid home directory
    [[ ! -d "$user_home" ]] && {
        log "WARNING" "Invalid home directory for user: $username"
        return 0
    }

    # Backup existing configuration files
    local config_files=(
        "$user_home/.bashrc"
        "$user_home/.bash_profile"
        "$user_home/.profile"
    )

    for file in "${config_files[@]}"; do
        if [[ -f "$file" ]]; then
            create_backup "$file" || {
                log "WARNING" "Failed to backup $file"
                continue
            }
        fi
    done

    # Configure bash environment
    if [[ -f "$user_home/.bashrc" ]]; then
        # Configure color prompt
        if grep -q "^#force_color_prompt=yes" "$user_home/.bashrc"; then
            sed -i 's/^#force_color_prompt=yes/force_color_prompt=yes/' "$user_home/.bashrc"
        elif ! grep -q "^force_color_prompt=yes" "$user_home/.bashrc"; then
            echo "force_color_prompt=yes" >> "$user_home/.bashrc"
        fi

        # Configure PS1 prompt based on user and OS
        local PS1_CONFIG
        if [[ "$username" == "root" ]]; then
            PS1_CONFIG='\[\033[01;31m\]\u\[\033[01;32m\]@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
        else
            PS1_CONFIG='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
        fi

        # Update PS1 in .bashrc
        sed -i '/^if \[ "\$color_prompt" = yes \]/,/^fi/c\
if [ "$color_prompt" = yes ]; then\
    PS1="'"${PS1_CONFIG}"'"\
else\
    PS1="${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ "\
fi' "$user_home/.bashrc"

        # Add additional bash configurations
        cat >> "$user_home/.bashrc" <<'EOF'

# Security aliases
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias ls='ls --color=auto'
alias ll='ls -lah'
alias grep='grep --color=auto'
alias sudo='sudo '

# History settings
HISTCONTROL=ignoreboth:erasedups
HISTSIZE=1000
HISTFILESIZE=2000
HISTTIMEFORMAT="%F %T "
PROMPT_COMMAND="history -a"
shopt -s histappend

# Security measures
umask 027
export TMOUT=900  # 15 minutes timeout

# Enable bash completion
if ! shopt -oq posix; then
    if [ -f /usr/share/bash-completion/bash_completion ]; then
        . /usr/share/bash-completion/bash_completion
    elif [ -f /etc/bash_completion ]; then
        . /etc/bash_completion
    fi
fi

# Path configuration
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Set default editor
export EDITOR=vim
export VISUAL=vim

# Locale settings
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Default less options
export LESS='-R -i -g -c -W'

# Colored GCC warnings and errors
export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'
EOF
    fi

    # Configure vim settings
    cat > "$user_home/.vimrc" <<'EOF'
" Basic Settings
set nocompatible
syntax on
filetype plugin indent on

" Security Settings
set modelines=0
set nomodeline

" Editor Settings
set encoding=utf-8
set backspace=indent,eol,start
set hidden
set nobackup
set noswapfile
set noundofile
set directory=/tmp
set history=1000

" UI Settings
set ruler
set showcmd
set showmode
set showmatch
set laststatus=2
set wildmenu
set visualbell
set t_vb=

" Search Settings
set hlsearch
set incsearch
set ignorecase
set smartcase

" Indentation Settings
set autoindent
set smartindent
set expandtab
set tabstop=4
set shiftwidth=4
set softtabstop=4
set wrap
set textwidth=79
set formatoptions=qrn1
set colorcolumn=80

" Performance Settings
set lazyredraw
set ttyfast

" Security Settings
set secure
EOF

    # Configure SSH directory and permissions
    local ssh_dir="$user_home/.ssh"
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir" || {
            log "ERROR" "Failed to create SSH directory for user $username"
            return 1
        }
    fi
    chmod 700 "$ssh_dir"
    chown "$username:$username" "$ssh_dir"

    # Configure authorized_keys file if it doesn't exist
    local auth_keys="$ssh_dir/authorized_keys"
    if [[ ! -f "$auth_keys" ]]; then
        touch "$auth_keys" || {
            log "ERROR" "Failed to create authorized_keys file for user $username"
            return 1
        }
        chmod 600 "$auth_keys"
        chown "$username:$username" "$auth_keys"
    fi

    # Configure bash_logout
    cat > "$user_home/.bash_logout" <<'EOF'
# Clear screen on logout
clear

# Clean history
cat /dev/null > "$HOME/.bash_history"
history -c

# Secure SSH agent
if [ -n "$SSH_AGENT_PID" ]; then
    eval "$(ssh-agent -k)" >/dev/null 2>&1
fi

# Clear SSH keys from memory
ssh-add -D >/dev/null 2>&1

# Clear clipboard if available
if command -v xsel >/dev/null 2>&1; then
    xsel -c
elif command -v xclip >/dev/null 2>&1; then
    xclip -i /dev/null
fi

# Clear temporary files
rm -rf "$HOME/.local/share/Trash"/*
rm -rf "$HOME/tmp"/*
EOF

    # Set proper ownership and permissions for all configuration files
    local config_files=(
        "$user_home/.vimrc"
        "$user_home/.bash_logout"
        "$user_home/.bashrc"
    )

    for file in "${config_files[@]}"; do
        if [[ -f "$file" ]]; then
            chown "$username:$username" "$file"
            chmod 644 "$file"
        fi
    done

    # Add SSH keys for users if running interactively
    if [[ -t 0 && -t 1 ]]; then
        configure_ssh_keys "$user_home" || {
            log "WARNING" "Failed to configure SSH keys for user $username"
        }
    fi

    log "INFO" "Completed environment configuration for user: $username"
    return 0
}

setup_sudo_user() {
    log "INFO" "Configuring sudo access..."
    
    # Check if running in non-interactive mode
    if [[ ! -t 0 ]]; then
        log "ERROR" "This script must be run interactively for sudo configuration"
        log "INFO" "Please run: bash -i /tmp/hardening.sh"
        return 1
    fi
    
    if ! command -v sudo >/dev/null 2>&1; then
        log "INFO" "Installing sudo package..."
        install_package sudo || return 1
    fi

    # Show available users and configure sudo access
    local users=()
    while IFS= read -r -d '' dir; do
        local username=$(basename "$dir")
        if [[ "$username" != "root" && -d "/home/$username" ]]; then
            users+=("$username")
        fi
    done < <(find /home -maxdepth 1 -mindepth 1 -type d -print0)

    if (( ${#users[@]} == 0 )); then
        log "WARNING" "No regular users found to grant sudo access"
        return 0
    fi

    echo "Available users:"
    PS3="Select user to grant sudo access (enter number): "
    select username in "${users[@]}"; do
        if [[ -n "$username" ]]; then
            log "INFO" "Adding user $username to sudo group"
            usermod -aG sudo "$username"
            
            # Configure sudo settings
            echo "$username ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/$username"
            chmod 440 "/etc/sudoers.d/$username"
            
            log "INFO" "Successfully configured sudo access for $username"
            break
        else
            echo "Invalid selection. Please try again."
            continue
        fi
    done
    return 0
}

# Main package installation
install_base_packages() {
    log "INFO" "Installing base packages..."
    
    local BASE_PACKAGES=(
        curl
        rsyslog
        wget
        socat
        bash-completion
        wireguard
        vim
        net-tools
        htop
        iftop
        iotop
        nmap
        tcpdump
        fail2ban
        unattended-upgrades
    )

    # Add OS-specific packages
    [[ "$OS" == "debian" ]] && BASE_PACKAGES+=(dnsmasq)

    for package in "${BASE_PACKAGES[@]}"; do
        if ! install_package "$package"; then
            log "ERROR" "Failed to install package: $package"
            return 1
        fi
    done

    log "INFO" "Base package installation completed"
    return 0
}

# Config dnsmasq
configure_dnsmasq() {
    if [[ "$OS" == "debian" ]]; then
        log "INFO" "Configuring dnsmasq for Debian..."
        
        # Check if dnsmasq is installed
        if ! command -v dnsmasq >/dev/null 2>&1; then
            log "INFO" "Installing dnsmasq..."
            if ! install_package dnsmasq; then
                log "ERROR" "Failed to install dnsmasq"
                return 1
            fi
        fi
        
        # Backup existing configuration
        create_backup /etc/dnsmasq.conf

        # Create new configuration
        cat > /etc/dnsmasq.conf <<EOF
no-resolv
server=8.8.8.8
server=8.8.4.4
EOF

        # Set proper permissions
        chmod 644 /etc/dnsmasq.conf

        # Restart dnsmasq service
        systemctl restart dnsmasq

        # Verify service status
        if ! systemctl is-active --quiet dnsmasq; then
            log "ERROR" "dnsmasq service failed to start"
            return 1
        fi

        log "INFO" "dnsmasq configuration completed successfully"
    else
        log "INFO" "Skipping dnsmasq configuration (not Debian)"
    fi
}

# Execute system updates and package installation
if ! update_system; then
    log "ERROR" "System update failed"
    exit 1
fi

if ! install_base_packages; then
    log "ERROR" "Base package installation failed"
    exit 1
fi

configure_dnsmasq

# Configure sudo access
setup_sudo_user

# Configure user environments
configure_users() {
    log "INFO" "Starting user environment configuration..."

    # Create temporary file for error handling
    local temp_file
    temp_file=$(mktemp) || {
        log "ERROR" "Failed to create temporary file"
        return 1
    }
    
    # Add cleanup trap
    trap 'rm -f "$temp_file"' RETURN

    # Configure regular users
    log "INFO" "Configuring regular user environments..."
    while IFS= read -r -d '' user_dir; do
        # Skip if not a directory
        [[ ! -d "$user_dir" ]] && continue
        
        # Get username and validate
        username=$(basename "$user_dir")
        if ! id "$username" >/dev/null 2>&1; then
            log "WARNING" "User $username does not exist in system"
            continue
        fi

        # Get user shell
        shell=$(getent passwd "$username" | cut -d: -f7)
        
        # Skip system users (UID < 1000)
        uid=$(id -u "$username")
        if [[ "$uid" -lt 1000 ]]; then
            log "INFO" "Skipping system user $username (UID: $uid)"
            continue
        fi

        # Only configure for users with valid shells
        case "$shell" in
            */bash|*/sh)
                log "INFO" "Configuring environment for user: $username (Shell: $shell)"
                if ! configure_user_environment "$user_dir"; then
                    log "WARNING" "Failed to configure environment for user: $username"
                    echo "$username" >> "$temp_file"
                fi
                ;;
            *)
                log "INFO" "Skipping user $username (non-standard shell: $shell)"
                ;;
        esac
    done < <(find /home -mindepth 1 -maxdepth 1 -type d -print0)

    # Configure root separately
    if [[ -d "/root" ]]; then
        log "INFO" "Configuring root environment..."
        if ! configure_user_environment "/root"; then
            log "WARNING" "Failed to configure root environment"
            echo "root" >> "$temp_file"
        fi
    else
        log "WARNING" "Root directory not found"
    fi

    # Check for any failures
    if [[ -s "$temp_file" ]]; then
        log "WARNING" "Failed to configure some user environments:"
        while IFS= read -r failed_user; do
            log "WARNING" "- $failed_user"
        done < "$temp_file"
        return 1
    fi

    log "INFO" "User environment configuration completed successfully"
    return 0
}

# Execute user configuration
if ! configure_users; then
    log "ERROR" "User environment configuration had some failures"
    # Continue script execution despite failures
fi

# Disable ssh.socket in LXC
check_ssh_socket() {
    log "INFO" "Checking SSH service configuration..."
    
    # Check if running in LXC container
    if systemd-detect-virt --container | grep -q "lxc"; then
        log "INFO" "LXC container detected, checking ssh.socket status"
        
        local socket_active=false
        local socket_enabled=false
        
        # Check if ssh.socket is active
        if systemctl is-active ssh.socket >/dev/null 2>&1; then
            socket_active=true
            log "INFO" "ssh.socket is currently active"
        fi
        
        # Check if ssh.socket is enabled
        if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
            socket_enabled=true
            log "INFO" "ssh.socket is currently enabled"
        fi
        
        # If socket is active or enabled, switch to service
        if $socket_active || $socket_enabled; then
            log "INFO" "Switching from ssh.socket to ssh.service..."
            
            # Stop and disable socket
            if $socket_active; then
                log "INFO" "Stopping ssh.socket..."
                if ! systemctl stop ssh.socket; then
                    log "ERROR" "Failed to stop ssh.socket"
                    return 1
                fi
            fi
            
            if $socket_enabled; then
                log "INFO" "Disabling ssh.socket..."
                if ! systemctl disable ssh.socket; then
                    log "ERROR" "Failed to disable ssh.socket"
                    return 1
                fi
            fi
            
            # Enable and start ssh service
            log "INFO" "Enabling and starting ssh.service..."
            if ! systemctl enable ssh.service; then
                log "ERROR" "Failed to enable ssh.service"
                return 1
            fi
            
            if ! systemctl start ssh.service; then
                log "ERROR" "Failed to start ssh.service"
                return 1
            fi
            
            # Verify service status
            if systemctl is-active ssh.service >/dev/null 2>&1; then
                log "INFO" "Successfully switched to ssh.service"
            else
                log "ERROR" "ssh.service failed to start properly"
                return 1
            fi
        else
            log "INFO" "ssh.socket is not active or enabled, no changes needed"
        fi
    else
        log "INFO" "Not running in LXC container, skipping socket check"
    fi
    
    return 0
}

# Security Configuration Functions
configure_ssh() {
    log "INFO" "Configuring SSH security settings..."

    check_ssh_socket || {
        log "ERROR" "Failed to configure SSH socket/service"
        return 1
    }
    
    create_backup /etc/ssh/sshd_config
    
    # Generate new SSH host keys
    log "INFO" "Regenerating SSH host keys..."
    rm -f /etc/ssh/ssh_host_*
    dpkg-reconfigure openssh-server
    
    # Configure SSH hardening settings
    cat > /etc/ssh/sshd_config.d/hardening.conf <<EOF
# Security Options
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
MaxStartups 3:50:10
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
AuthenticationMethods publickey

# Session
ClientAliveInterval 60
ClientAliveCountMax 10
TCPKeepAlive no
Compression no

# Security
IgnoreRhosts yes
HostbasedAuthentication no
StrictModes yes
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Logging
LogLevel VERBOSE
EOF

    chmod 600 /etc/ssh/sshd_config.d/hardening.conf

    # Verify configuration
    if ! sshd -t; then
        log "ERROR" "SSH configuration validation failed"
        return 1
    fi

    # Restart SSH service
    if [[ "$OS" == "ubuntu" ]]; then
        systemctl restart ssh
    else
        systemctl restart sshd
    fi

    log "INFO" "SSH configuration completed successfully"
}

configure_firewall() {
    log "INFO" "Configuring firewall..."

    check_interactive

    # Ask for confirmation before configuring UFW
    read -r -p "Do you want to configure UFW firewall rules? (y/n): " configure_ufw
    if [[ ! "$configure_ufw" =~ ^[Yy]$ ]]; then
        log "INFO" "Skipping UFW configuration"
        return 0
    fi

    if ! command -v ufw >/dev/null 2>&1; then
        install_package ufw || return 1
    fi

    # Backup existing rules
    create_backup /etc/ufw/user.rules
    
    # Reset UFW
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Download and execute UFW rules
    local ufw_script="/tmp/ufw_rules.sh"
    log "INFO" "Downloading UFW rules..."
    
    if ! wget -q "https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/ufw.sh" -O "$ufw_script"; then
        log "ERROR" "Failed to download UFW rules"
        return 1
    fi

    # Verify download
    if [[ ! -s "$ufw_script" ]]; then
        log "ERROR" "Downloaded UFW rules file is empty"
        return 1
    fi

    # Show the rules before applying
    log "INFO" "UFW rules to be applied:"
    cat "$ufw_script"

    # Ask for confirmation before applying rules
    read -r -p "Do you want to apply these UFW rules? (y/n): " apply_rules
    if [[ ! "$apply_rules" =~ ^[Yy]$ ]]; then
        log "INFO" "Skipping UFW rules application"
        rm -f "$ufw_script"
        return 0
    fi

    # Make script executable
    chmod +x "$ufw_script"

    # Execute UFW rules
    log "INFO" "Applying UFW rules..."
    if ! bash "$ufw_script"; then
        log "ERROR" "Failed to apply UFW rules"
        return 1
    fi

    # Enable logging
    ufw logging on
    
    # Enable firewall
    ufw --force enable

    # Cleanup
    rm -f "$ufw_script"
    
    # Verify UFW status
    local ufw_status=$(ufw status verbose)
    log "INFO" "UFW Status:\n$ufw_status"
    
    log "INFO" "Firewall configuration completed"
}

configure_fail2ban() {
    log "INFO" "Configuring Fail2ban..."

    create_backup /etc/fail2ban/jail.local
    
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = ufw
backend = systemd

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[sshd-ddos]
enabled = true
port = $ssh_port
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 7200

#[http-auth]
#enabled = true
#filter = nginx-http-auth
#port = http,https
#logpath = /var/log/nginx/error.log
#maxretry = 3
#bantime = 3600
#findtime = 600
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log "INFO" "Fail2ban configuration completed"
}

configure_sysctl() {
    log "INFO" "Configuring system kernel parameters..."

    create_backup /etc/sysctl.conf
    
    # Check if running in LXC container
    local is_lxc=false
    if systemd-detect-virt --container | grep -q "lxc"; then
        is_lxc=true
        log "WARNING" "Running in LXC - skipping kernel.* parameters"
    fi

    cat > /etc/sysctl.d/99-security.conf <<EOF
# Network Security
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_timestamps = 0
EOF

    if ! $is_lxc; then
        # Add non-LXC specific parameters
        cat >> /etc/sysctl.d/99-security.conf <<EOF
# Proxy Network Improvement
fs.file-max = 1024000
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 52428800
net.core.wmem_default = 52428800
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_forward = 1
net.ipv4.icmp_echo_ignore_all = 0
net.core.netdev_budget=3000
net.core.netdev_budget_usecs=20000
net.netfilter.nf_conntrack_max = 65535
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Kernel Security
kernel.printk = 3 4 1 3
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
EOF
    fi

    # Apply sysctl settings with error handling
    if ! sysctl -p /etc/sysctl.d/99-security.conf 2>/dev/null; then
        log "WARNING" "Some sysctl parameters could not be applied. This is normal in containers."
    fi
    
    log "INFO" "System kernel parameters configured (with container awareness)"
    return 0
}

configure_automatic_updates() {
    log "INFO" "Configuring automatic security updates..."

    if [[ "$OS" == "ubuntu" ]]; then
        cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESM:\${distro_codename}";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "auto";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

        cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    fi

    systemctl enable unattended-upgrades
    systemctl restart unattended-upgrades
    
    log "INFO" "Automatic security updates configured"
}

detect_ssh_port() {
    local current_port

    # Try to get port from sshd_config first
    if [[ -f /etc/ssh/sshd_config ]]; then
        current_port=$(grep -E "^Port [0-9]+" /etc/ssh/sshd_config | awk '{print $2}')
    fi

    # If not found in config, try to detect from running service
    if [[ -z "$current_port" ]]; then
        current_port=$(ss -tlpn | grep sshd | awk '{print $4}' | cut -d':' -f2 | head -1)
    fi

    # Default to 22 if still not found
    echo "${current_port:-22}"
}

current_ssh_port=$(detect_ssh_port)
log "INFO" "Current SSH port: $current_ssh_port"

read -r -p "Do you want to modify the SSH port? (y/n): " modify_ssh_port
if [[ "$modify_ssh_port" =~ ^[Yy]$ ]]; then
    while true; do
        read -r -p "Enter new SSH port [current: $current_ssh_port]: " new_ssh_port
        
        # If user just pressed enter, keep current port
        if [[ -z "$new_ssh_port" ]]; then
            ssh_port=$current_ssh_port
            break
        fi
        
        # Validate port number
        if [[ "$new_ssh_port" =~ ^[0-9]+$ ]] && \
           (( new_ssh_port >= 1 && new_ssh_port <= 65535 )) && \
           (( new_ssh_port != 21 && new_ssh_port != 80 && new_ssh_port != 443 )); then
            ssh_port=$new_ssh_port
            break
        else
            log "ERROR" "Invalid port number. Please enter a number between 1-65535 (excluding 21, 80, 443)"
        fi
    done
else
    ssh_port=$current_ssh_port
fi

log "INFO" "SSH port will be set to: $ssh_port"

configure_ssh
configure_firewall
configure_fail2ban
configure_sysctl
configure_automatic_updates

# Auditing and Monitoring Functions
configure_audit_system() {
    log "INFO" "Configuring system auditing..."

    # Check if running in LXC
    if systemd-detect-virt --container | grep -q "lxc"; then
        log "INFO" "Running in LXC container - using modified audit configuration"
        
        # Install auditd without enabling the service
        if ! command -v auditd >/dev/null 2>&1; then
            install_package auditd
        fi

        create_backup /etc/audit/auditd.conf
        
        # Configure auditd with LXC-compatible settings
        cat > /etc/audit/auditd.conf <<EOF
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = adm
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
max_log_file = 8
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SYSLOG
disk_full_action = SYSLOG
disk_error_action = SYSLOG
use_libwrap = yes
##tcp_listen_queue = 5
##tcp_max_per_addr = 1
##tcp_client_max_idle = 0
enable_krb5 = no
EOF

        # Configure audit rules for LXC
        cat > /etc/audit/rules.d/hardening.rules <<EOF
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# User, Group, and Password Databases
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Login Records
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Network Environment
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
EOF

        # Start auditd without systemd
        if ! /etc/init.d/auditd start; then
            log "WARNING" "Failed to start auditd using init.d script in LXC"
            # Continue anyway as this is not critical in LXC
        fi

        log "INFO" "Audit configuration completed for LXC environment"
        return 0
    else
        systemctl enable auditd
        service auditd restart
        log "INFO" "System auditing configured"
    fi
}

# Also modify the process_accounting function for LXC
configure_process_accounting() {
    log "INFO" "Configuring process accounting..."

    if systemd-detect-virt --container | grep -q "lxc"; then
        log "INFO" "Process accounting configuration for LXC environment"
        
        # Install accounting package if not present
        if ! command -v accton >/dev/null 2>&1; then
            log "INFO" "Installing process accounting package..."
            if ! install_package acct; then
                log "WARNING" "Failed to install process accounting package in LXC"
                return 0  # Non-critical in LXC, continue script
            fi
        fi

        # Create and set permissions for accounting files
        local ACCT_FILES=(
            "/var/log/wtmp"
            "/var/log/btmp"
            "/var/log/lastlog"
            "/var/account/pacct"
        )

        # Ensure /var/account directory exists
        mkdir -p /var/account

        for file in "${ACCT_FILES[@]}"; do
            if [[ ! -f "$file" ]]; then
                touch "$file"
                log "INFO" "Created accounting file: $file"
            fi

            # Set appropriate permissions
            case "$file" in
                "/var/log/wtmp"|"/var/log/lastlog")
                    chmod 664 "$file"
                    chown root:utmp "$file"
                    ;;
                "/var/log/btmp")
                    chmod 660 "$file"
                    chown root:utmp "$file"
                    ;;
                "/var/account/pacct")
                    chmod 640 "$file"
                    chown root:root "$file"
                    ;;
            esac
        done

        # Start accounting using traditional method for LXC
        if ! /usr/sbin/accton /var/account/pacct; then
            log "WARNING" "Failed to enable process accounting in LXC"
            return 0  # Non-critical in LXC, continue script
        fi

        # Add daily rotation of accounting files via cron
        if [[ ! -f /etc/cron.daily/accounting ]]; then
            cat > /etc/cron.daily/accounting <<'EOF'
#!/bin/bash
# Daily accounting file rotation
ACCT_FILE="/var/account/pacct"
ACCT_FILE_OLD="${ACCT_FILE}.1"

if [ -f "$ACCT_FILE" ]; then
    /usr/sbin/accton off
    mv "$ACCT_FILE" "$ACCT_FILE_OLD"
    touch "$ACCT_FILE"
    chmod 640 "$ACCT_FILE"
    /usr/sbin/accton "$ACCT_FILE"
fi

# Cleanup old accounting files (keep last 7 days)
find /var/account -name 'pacct.*' -mtime +7 -delete
EOF
            chmod 755 /etc/cron.daily/accounting
        fi

        log "INFO" "Process accounting configured for LXC environment"
        
    else
        log "INFO" "Configuring process accounting for non-LXC environment"
        
        # Install accounting package
        if ! command -v accton >/dev/null 2>&1; then
            if ! install_package acct; then
                log "ERROR" "Failed to install process accounting package"
                return 1
            fi
        fi

        # Create backup of existing configuration
        if [[ -f /etc/default/acct ]]; then
            create_backup /etc/default/acct
        fi

        # Configure accounting settings
        cat > /etc/default/acct <<EOF
# Process accounting configuration
ACCT_ENABLE="yes"
ACCT_FILE="/var/account/pacct"
SAVETIME="7"
EOF

        # Create and set permissions for accounting files
        local ACCT_FILES=(
            "/var/log/wtmp"
            "/var/log/btmp"
            "/var/log/lastlog"
            "/var/account/pacct"
        )

        mkdir -p /var/account

        for file in "${ACCT_FILES[@]}"; do
            if [[ ! -f "$file" ]]; then
                touch "$file"
                log "INFO" "Created accounting file: $file"
            fi

            # Set appropriate permissions
            case "$file" in
                "/var/log/wtmp"|"/var/log/lastlog")
                    chmod 664 "$file"
                    chown root:utmp "$file"
                    ;;
                "/var/log/btmp")
                    chmod 660 "$file"
                    chown root:utmp "$file"
                    ;;
                "/var/account/pacct")
                    chmod 640 "$file"
                    chown root:root "$file"
                    ;;
            esac
        done

        # Configure logrotate for accounting files
        cat > /etc/logrotate.d/accounting <<EOF
/var/account/pacct {
    rotate 7
    daily
    compress
    delaycompress
    notifempty
    missingok
    create 0640 root root
    postrotate
        /usr/sbin/accton /var/account/pacct
    endscript
}
EOF

        # Enable and start accounting service
        if ! systemctl is-enabled acct >/dev/null 2>&1; then
            if ! systemctl enable acct; then
                log "ERROR" "Failed to enable accounting service"
                return 1
            fi
        fi

        if ! systemctl is-active --quiet acct; then
            if ! systemctl start acct; then
                log "ERROR" "Failed to start accounting service"
                return 1
            fi
        fi

        # Verify accounting is active
        if ! /usr/sbin/accton | grep -q "Accounting enabled"; then
            log "WARNING" "Process accounting may not be properly enabled"
        fi

        log "INFO" "Process accounting configured successfully for non-LXC environment"
    fi

    # Final verification for both environments
    if [[ -f /var/account/pacct ]]; then
        log "INFO" "Process accounting file exists and is ready"
    else
        log "WARNING" "Process accounting file not found after configuration"
    fi

    return 0
}

harden_filesystem() {
    log "INFO" "Hardening filesystem..."

    # Check if running in LXC
    if systemd-detect-virt --container | grep -q "lxc"; then
        log "WARNING" "Running in LXC container - some filesystem modifications will be skipped"
        return 0
    fi

    # Update fstab with secure mount options
    create_backup /etc/fstab
    
    # Add nodev, nosuid, noexec where appropriate
    while read -r line || [[ -n "$line" ]]; do
        if [[ $line =~ ^[^#] ]]; then
            mountpoint=$(echo "$line" | awk '{print $2}')
            case "$mountpoint" in
                /tmp)
                    sed -i "\\#$mountpoint#s/defaults/defaults,nodev,nosuid,noexec/" /etc/fstab
                    ;;
                /var/tmp)
                    sed -i "\\#$mountpoint#s/defaults/defaults,nodev,nosuid,noexec/" /etc/fstab
                    ;;
                /home)
                    sed -i "\\#$mountpoint#s/defaults/defaults,nodev/" /etc/fstab
                    ;;
            esac
        fi
    done < /etc/fstab

    # Create separate mount points if they don't exist
    for dir in /tmp /var/tmp; do
        if ! mountpoint -q "$dir"; then
            mount -o remount,nodev,nosuid,noexec "$dir" 2>/dev/null || true
        fi
    done
    
    log "INFO" "Filesystem hardening completed"
}

# Config IPv6 and Snap
configure_ipv6_and_snap() {
    log "INFO" "Configuring IPv6 and Snap settings..."

    check_interactive

    # IPv6 Disable Option
    read -r -p "Do you want to disable IPv6? (y/n): " disable_ipv6
    if [[ "$disable_ipv6" =~ ^[Yy]$ ]]; then
        log "INFO" "Disabling IPv6..."
        
        # Backup GRUB configuration
        create_backup /etc/default/grub

        # Modify GRUB parameters
        if ! grep -q "ipv6.disable=1" /etc/default/grub; then
            sed -i '/GRUB_CMDLINE_LINUX_DEFAULT=/ s/"$/ ipv6.disable=1"/' /etc/default/grub
            sed -i '/GRUB_CMDLINE_LINUX=/ s/"$/ ipv6.disable=1"/' /etc/default/grub
            
            # Update GRUB
            if ! update-grub; then
                log "ERROR" "Failed to update GRUB configuration"
                return 1
            fi
            
            log "INFO" "IPv6 has been disabled. System reboot required for changes to take effect."
        else
            log "INFO" "IPv6 is already disabled in GRUB configuration"
        fi

    fi

    # Remove Snap (Ubuntu only)
    if [[ "$OS" == "ubuntu" ]]; then
        log "INFO" "Checking Snap packages..."
        
        if command -v snap >/dev/null 2>&1; then
            log "INFO" "Removing Snap and preventing its reinstallation..."
            
            # Remove all snap packages
            local snap_packages
            snap_packages=$(snap list 2>/dev/null | awk 'NR>1 {print $1}')
            
            if [[ -n "$snap_packages" ]]; then
                while read -r pkg; do
                    log "INFO" "Removing snap package: $pkg"
                    if ! snap remove --purge "$pkg" 2>/dev/null; then
                        log "WARNING" "Failed to remove snap package: $pkg"
                    fi
                done <<< "$snap_packages"
            fi
            
            # Remove snapd completely
            log "INFO" "Removing snapd package..."
            if apt remove --purge snapd -y; then
                # Clean up snap directories
                rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd /usr/lib/snapd
                
                # Prevent snapd from being installed again
                cat > /etc/apt/preferences.d/nosnap.pref <<EOL
Package: snapd
Pin: release a=*
Pin-Priority: -1
EOL
                
                log "INFO" "Snap has been removed and blocked from future installation"
            else
                log "WARNING" "Failed to remove snapd package"
            fi
        else
            log "INFO" "Snap is not installed on this system"
        fi
    fi

    return 0
}

configure_time_sync() {
    log "INFO" "Configuring time synchronization..."

    check_interactive

    read -r -p "Do you want to sync time with time.nist.gov? (y/n): " sync_time
    if [[ "$sync_time" =~ ^[Yy]$ ]]; then
        log "INFO" "Setting up time synchronization with time.nist.gov..."

        # Set timezone to Asia/Taipei
        log "INFO" "Setting timezone to Asia/Taipei..."
        if timedatectl set-timezone Asia/Taipei; then
            log "INFO" "Timezone set to Asia/Taipei successfully"
        else
            log "WARNING" "Failed to set timezone to Asia/Taipei"
            return 1
        fi

        # Stop and disable existing time sync services
        local time_services=("systemd-timesyncd" "ntp" "chronyd")
        for service in "${time_services[@]}"; do
            if systemctl is-active --quiet "$service"; then
                log "INFO" "Stopping $service service..."
                systemctl stop "$service" 2>/dev/null || \
                    log "WARNING" "Failed to stop $service"
            fi
            if systemctl is-enabled --quiet "$service" 2>/dev/null; then
                log "INFO" "Disabling $service service..."
                systemctl disable "$service" 2>/dev/null || \
                    log "WARNING" "Failed to disable $service"
            fi
        done

        # Remove chrony if installed
        if dpkg-query -W chrony 2>/dev/null; then
            log "INFO" "Removing chrony package..."
            if ! apt remove --purge chrony -y; then
                log "WARNING" "Failed to remove chrony package"
            fi
        fi

        # Install ntpdate if not present
        if ! command -v ntpdate >/dev/null 2>&1; then
            log "INFO" "Installing ntpdate package..."
            if ! apt-get update; then
                log "ERROR" "Failed to update package lists"
                return 1
            fi
            if ! install_package ntpdate; then
                log "ERROR" "Failed to install ntpdate"
                return 1
            fi
        fi

        # Perform initial time sync
        log "INFO" "Performing initial time synchronization..."
        if ! ntpdate -4 time.nist.gov; then
            log "WARNING" "Initial time sync with time.nist.gov failed, trying alternatives..."
            # Try alternative NTP servers
            local ntp_servers=("tw.pool.ntp.org" "pool.ntp.org" "0.pool.ntp.org")
            local sync_success=false
            
            for server in "${ntp_servers[@]}"; do
                log "INFO" "Trying alternative NTP server: $server"
                if ntpdate -4 "$server"; then
                    sync_success=true
                    log "INFO" "Time sync successful with $server"
                    break
                fi
            done

            if ! $sync_success; then
                log "ERROR" "Time synchronization failed with all servers"
                return 1
            fi
        else
            log "INFO" "Initial time sync successful with time.nist.gov"
        fi

        # Configure cron job for periodic sync
        log "INFO" "Configuring cron job for root user..."
        
        # Backup existing root crontab
        local crontab_backup="/root/crontab.backup.$(date +%Y%m%d_%H%M%S)"
        if crontab -l 2>/dev/null | grep -q "ntpdate -4 -s"; then
            log "INFO" "Created backup of existing crontab: $crontab_backup"
        else
            log "INFO" "No existing crontab found, creating new one"
            touch "$crontab_backup"
        fi

        # Create temporary file for new cron entries
        local temp_crontab
        temp_crontab=$(mktemp) || {
            log "ERROR" "Failed to create temporary file for crontab"
            return 1
        }

        # Get existing crontab content
        crontab -l > "$temp_crontab" 2>/dev/null || true

        # Check if time sync entry already exists
        if ! grep -q "ntpdate -4 -s" "$temp_crontab"; then
            # Add comments for clarity
            echo "# Time synchronization with NTP servers" >> "$temp_crontab"
            echo "00 */6 * * * ntpdate -4 -s tw.pool.ntp.org || ntpdate -4 -s time.nist.gov" >> "$temp_crontab"
            echo "" >> "$temp_crontab"
            echo "# Fallback NTP servers (will only sync if time is severely off)" >> "$temp_crontab"
            echo "30 */6 * * * [ \$(date '+\%s') -lt \$(date -d '1 day ago' +\%s) ] && (ntpdate -4 -s pool.ntp.org || ntpdate -4 -s 0.pool.ntp.org)" >> "$temp_crontab"
            
            # Install new crontab
            if crontab "$temp_crontab"; then
                log "INFO" "Time synchronization cron jobs added successfully"
            else
                log "ERROR" "Failed to install new crontab"
                rm -f "$temp_crontab"
                return 1
            fi
        else
            log "INFO" "Time sync cron job already exists, skipping crontab modification"
        fi
        
        # Clean up
        rm -f "$temp_crontab"

        # Verify crontab installation
        if crontab -l | grep -q "ntpdate -4 -s"; then
            log "INFO" "Verified crontab installation"
        else
            log "WARNING" "Crontab verification failed"
        fi

        # Display current time settings
        log "INFO" "Current time settings:"
        log "INFO" "Timezone: $(timedatectl | grep "Time zone")"
        log "INFO" "Local time: $(date)"

        log "INFO" "Time synchronization configuration completed successfully"
    else
        log "INFO" "Skipping time synchronization configuration"
    fi

    return 0
}

final_system_checks() {
    log "INFO" "Performing final system checks..."

    # Check running services
    local running_services=$(systemctl list-units --type=service --state=running --no-pager | grep "running")
    log "INFO" "Running services:\n$running_services"

    # Check listening ports
    local listening_ports=$(ss -tuln)
    log "INFO" "Listening ports:\n$listening_ports"

    # Check loaded kernel modules
    local kernel_modules=$(lsmod)
    log "INFO" "Loaded kernel modules:\n$kernel_modules"

    # Verify critical file permissions
    local critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/gshadow"
        "/etc/ssh/sshd_config"
        "/etc/sudoers"
    )

    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]]; then
            local perms=$(stat -c "%a %u %g" "$file")
            log "INFO" "Permissions for $file: $perms"
        fi
    done
}

generate_system_report() {
    local report_file="/root/system_hardening_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=== System Hardening Report ==="
        echo "Date: $(date)"
        echo "Hostname: $(hostname)"
        echo "OS: $OS"
        echo "Kernel: $(uname -r)"
        echo
        echo "=== Security Configurations ==="
        echo "SSH Port: $ssh_port"
        echo "Firewall Status: $(ufw status verbose)"
        echo "Fail2ban Status: $(fail2ban-client status)"
        echo
        echo "=== System Services ==="
        systemctl list-units --type=service --state=running
        echo
        echo "=== Network Connections ==="
        ss -tuln
        echo
        echo "=== System Logs ==="
        tail -n 50 /var/log/auth.log
    } > "$report_file"

    log "INFO" "System report generated: $report_file"
}

cleanup_and_finish() {
    log "INFO" "Performing final cleanup..."

    # Remove temporary files
    rm -rf /tmp/system_hardening*

    # Clear bash history
    history -c
    
    # Generate system report
    generate_system_report

    log "INFO" "System hardening completed successfully"
    log "INFO" "Please review the system report and reboot the system"
    
    # Remove lock file
    rm -f "$LOCK_FILE"
}

# Execute final configurations
configure_audit_system
configure_process_accounting
harden_filesystem
configure_ipv6_and_snap
configure_time_sync
final_system_checks
cleanup_and_finish

echo "================================================================="
echo "System hardening completed. Please review the logs and system report"
echo "in /root/system_hardening_report_*.txt"
echo "It is recommended to reboot the system now."
echo "================================================================="

read -r -p "Would you like to reboot now? (y/n): " reboot_response
if [[ "$reboot_response" =~ ^[Yy]$ ]]; then
    log "INFO" "System rebooting..."
    shutdown -r now
fi
