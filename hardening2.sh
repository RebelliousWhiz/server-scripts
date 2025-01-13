#!/bin/bash
set -euo pipefail

# Script Variables
SCRIPT_PATH=$(mktemp)
trap 'rm -f "$SCRIPT_PATH"' EXIT
SCRIPT_VERSION="1.1"
LOCK_FILE="/var/run/system_hardening.lock"
LOG_FILE="/var/log/system_hardening.log"
BACKUP_DIR="/root/system_hardening_backups/$(date +%Y%m%d_%H%M%S)"

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

    log "INFO" "All prerequisites are installed"
    return 0
}

# System Requirements
MIN_RAM_MB=400
MIN_DISK_MB=400
MIN_SWAP_MB=400
REQUIRED_COMMANDS=(systemctl wget curl ping)

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

    mkdir -p "$BACKUP_DIR"
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

    # Check if systemd is available
    if ! pidof systemd >/dev/null 2>&1; then
        log "ERROR" "systemd is required but not running"
        exit 1
    fi
}

check_system() {
    log "INFO" "Performing system checks..."
    
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

configure_user_environment() {
    local user_home=$1
    local username=$(basename "$user_home")
    
    log "INFO" "Configuring environment for user: $username"

    # Skip if not a valid home directory
    [[ ! -d "$user_home" ]] && return 0

    # Handle force_color_prompt for all users
    if [[ -f "$user_home/.bashrc" ]]; then
        create_backup "$user_home/.bashrc"
        
        if grep -q "^#force_color_prompt=yes" "$user_home/.bashrc"; then
            sed -i "s/^#force_color_prompt=yes/force_color_prompt=yes/" "$user_home/.bashrc"
        else
            echo "force_color_prompt=yes" >> "$user_home/.bashrc"
        fi

        # Modify PS1 prompt based on OS
        if [[ "$username" == "root" ]]; then
            if [[ "$OS" == "ubuntu" ]]; then
                sed -i '/^if \[ "\$color_prompt" = yes \]; then/,/^unset color_prompt force_color_prompt$/c\
                if [ "$color_prompt" = yes ]; then\
                    PS1='\'${debian_chroot:+($debian_chroot)}\\[\\033[01;31m\\]\\u\\[\\033[01;32m\\]@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '\''\
                else\
                    PS1='\'${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '\''\
                fi\
                unset color_prompt force_color_prompt' "$user_home/.bashrc"
            elif [[ "$OS" == "debian" ]]; then
                echo "PS1='${debian_chroot:+($debian_chroot)}\\[\\033[01;31m\\]\\u\\[\\033[01;32m\\]@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '" >> "$user_home/.bashrc"

                # Add additional configurations for Debian
                cat >> "$user_home/.bashrc" << 'EOF'
alias ls='ls --color=auto'
if ! shopt -oq posix; then
    if [ -f /usr/share/bash-completion/bash_completion ]; then
        . /usr/share/bash-completion/bash_completion
    elif [ -f /etc/bash_completion ]; then
        . /etc/bash_completion
    fi
fi
EOF
            fi
        fi

        # Rest of the existing .bashrc configurations...
        cat >> "$user_home/.bashrc" <<'EOF'

# Security aliases
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias ls='ls --color=auto'
alias ll='ls -lah'
alias grep='grep --color=auto'

# History settings
HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000
HISTTIMEFORMAT="%F %T "

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
EOF
    fi

    # Configure vim
    cat > "$user_home/.vimrc" <<'EOF'
syntax on
set nocompatible
set backspace=2
filetype on
filetype plugin on
filetype indent on
set expandtab
set tabstop=2
set shiftwidth=2
set softtabstop=2
set autoindent
set ruler
set hlsearch
set incsearch
set ignorecase
set smartcase
set backup
set backupdir=/tmp
set writebackup
set history=500
set showcmd
set showmode
set showmatch
set visualbell
set nowrap
set encoding=utf-8
EOF

    # Configure SSH directory
    local ssh_dir="$user_home/.ssh"
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
    fi

    # Configure bash_logout
    cat > "$user_home/.bash_logout" <<'EOF'
# Clear screen on logout
clear

# Clean history
cat /dev/null > ~/.bash_history
history -c

# Secure SSH agent
if [ -n "$SSH_AGENT_PID" ]; then
    eval "$(ssh-agent -k)"
fi
EOF

    # Set proper ownership and permissions
    chown -R "$username:$username" "$user_home/.vimrc" "$user_home/.bash_logout"
    chmod 644 "$user_home/.vimrc" "$user_home/.bash_logout"

    log "INFO" "Completed environment configuration for user: $username"
}

setup_sudo_user() {
    log "INFO" "Configuring sudo access..."
    
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
            log "ERROR" "Invalid selection"
            return 1
        fi
    done
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
for user_home in /root /home/*; do
    configure_user_environment "$user_home"
done

# Security Configuration Functions
configure_ssh() {
    log "INFO" "Configuring SSH security settings..."
    
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
UsePrivilegeSeparation sandbox
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

    # Ask for confirmation before configuring UFW
    read -r -p "Do you want to configure UFW firewall rules? (y/n): " configure_ufw
    if [[ ! "$configure_ufw" =~ ^[Yy]$ ]]; then
        log "INFO" "Skipping UFW configuration"
        return 0
    }

    if ! command -v ufw >/dev/null 2>&1; then
        install_package ufw || return 1
    }

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
    }

    # Verify download
    if [[ ! -s "$ufw_script" ]]; then
        log "ERROR" "Downloaded UFW rules file is empty"
        return 1
    }

    # Show the rules before applying
    log "INFO" "UFW rules to be applied:"
    cat "$ufw_script"

    # Ask for confirmation before applying rules
    read -r -p "Do you want to apply these UFW rules? (y/n): " apply_rules
    if [[ ! "$apply_rules" =~ ^[Yy]$ ]]; then
        log "INFO" "Skipping UFW rules application"
        rm -f "$ufw_script"
        return 0
    }

    # Make script executable
    chmod +x "$ufw_script"

    # Execute UFW rules
    log "INFO" "Applying UFW rules..."
    if ! bash "$ufw_script"; then
        log "ERROR" "Failed to apply UFW rules"
        return 1
    }

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
        log "WARNING" "Running in LXC container - some sysctl parameters may not apply"
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

# Execute security configurations
read -r -p "Enter desired SSH port [22]: " ssh_port
ssh_port=${ssh_port:-22}

if ! [[ "$ssh_port" =~ ^[0-9]+$ ]] || (( ssh_port < 1 || ssh_port > 65535 )); then
    log "ERROR" "Invalid SSH port number"
    exit 1
fi

configure_ssh
configure_firewall
configure_fail2ban
configure_sysctl
configure_automatic_updates

# Auditing and Monitoring Functions
configure_audit_system() {
    log "INFO" "Configuring system auditing..."

    if ! command -v auditd >/dev/null 2>&1; then
        install_package auditd
    fi

    create_backup /etc/audit/auditd.conf
    
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
space_left_action = EMAIL
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
EOF

    # Configure audit rules
    cat > /etc/audit/rules.d/hardening.rules <<EOF
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Date and Time
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User, Group, and Password Databases
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# System Startup Scripts
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init
-w /etc/systemd/ -p wa -k init

# Login Records
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Network Environment
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
EOF

    systemctl enable auditd
    service auditd restart
    
    log "INFO" "System auditing configured"
}

configure_process_accounting() {
    log "INFO" "Configuring process accounting..."

    if ! command -v acct >/dev/null 2>&1; then
        install_package acct
    fi

    touch /var/log/wtmp
    touch /var/log/btmp
    chmod 640 /var/log/wtmp
    chmod 640 /var/log/btmp
    
    systemctl enable acct
    systemctl start acct
    
    log "INFO" "Process accounting configured"
}

harden_filesystem() {
    log "INFO" "Hardening filesystem..."

    # Update fstab with secure mount options
    create_backup /etc/fstab
    
    # Add nodev, nosuid, noexec where appropriate
    while read -r line; do
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

# Config IPv6 and Snap
configure_ipv6_and_snap() {
    log "INFO" "Configuring IPv6 and Snap settings..."

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
            echo "30 */6 * * * [ \$(date +\%s) -lt \$(date -d '1 day ago' +\%s) ] && (ntpdate -4 -s pool.ntp.org || ntpdate -4 -s 0.pool.ntp.org)" >> "$temp_crontab"
            
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
