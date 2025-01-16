#!/usr/bin/env bash

# Server Initialization and Hardening Script
# Version: 3.5
# Description: Initializes and hardens Debian/Ubuntu systems
# Supports: Debian 12, Ubuntu 22.04, and their derivatives
# Environment: Bare metal, VM, and LXC containers
# Author: RebelliousWhiz
# License: GLP 3.0
# In memory of Yunfei Shan, a good man, a good friend.

# Initialize script with strict error checking
set -euo pipefail
IFS=$'\n\t'

# Configuration Variables
readonly SCRIPT_VERSION="3.5"
readonly PACKAGES=(curl rsyslog wget socat bash-completion wireguard vim sudo)
readonly SSH_PORT_DEFAULT=22
readonly BACKUP_DIR="/root/.script_backups/$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="/var/log/server_init.log"
readonly SYSCTL_URL="https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/sysctl.conf"
readonly VIMRC_URL="https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/main/.vimrc"

# Color definitions (using printf for better compatibility)
RED=$(printf '\033[0;31m')
GREEN=$(printf '\033[0;32m')
YELLOW=$(printf '\033[1;33m')
NC=$(printf '\033[0m')

# Global Variables
declare -g is_debian=false
declare -g is_lxc=false
declare -g is_container=false
declare -g distro=""
declare -g selected_sudo_user=""

# Enhanced Error Handling
trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR

error_handler() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    local last_command=$4
    local func_trace=$5
    log "Error on line ${line_no}: '${last_command}' exited with status ${exit_code}"
    cleanup
    exit "$exit_code"
}

cleanup() {
    log "Performing cleanup..."
    for backup in "${BACKUP_DIR}"/*; do
        if [ -f "$backup" ]; then
            local original_file="${backup##*/}"
            original_file="${original_file//_//}"
            log "Restoring backup: $original_file"
            cp "$backup" "/${original_file}"
        fi
    done
}

# Enhanced Logging
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf "${GREEN}[%s]${NC} %s\n" "$timestamp" "$message" | tee -a "$LOG_FILE"
}

error() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf "${RED}[ERROR]${NC} [%s] %s\n" "$timestamp" "$message" | tee -a "$LOG_FILE" >&2
    exit 1
}

warn() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf "${YELLOW}[WARNING]${NC} [%s] %s\n" "$timestamp" "$message" | tee -a "$LOG_FILE"
}

# Security Functions
validate_ssh_key() {
    local key="$1"
    if [[ ! $key =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256) ]]; then
        error "Invalid SSH key format"
        return 1
    fi
    return 0
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        mkdir -p "$BACKUP_DIR"
        cp "$file" "${BACKUP_DIR}/${file//\//_}"
        log "Backed up: $file"
    fi
}

# Enhanced LXC Detection
detect_environment() {
    is_lxc=false
    is_container=false

    # Method 1: Check systemd-detect-virt
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        if [ "$(systemd-detect-virt)" = "lxc" ]; then
            is_lxc=true
            is_container=true
        fi
    fi

    # Method 2: Check container environment variable
    if [ -f /proc/1/environ ] && grep -q container=lxc /proc/1/environ; then
        is_lxc=true
        is_container=true
    fi

    # Method 3: Check cgroup
    if [ -f /proc/1/cgroup ] && grep -q ":/lxc/" /proc/1/cgroup; then
        is_lxc=true
        is_container=true
    fi

    # Method 4: Check for LXC specific files
    if [ -d /dev/lxd ] || [ -f /.lxc ]; then
        is_lxc=true
        is_container=true
    fi

    export is_lxc
    export is_container
    log "Environment detection: LXC=$is_lxc, Container=$is_container"
}

# User Input with Timeout
read_input() {
    local prompt="$1"
    local default="$2"
    local timeout="${3:-30}"
    local result
    
    read -t "$timeout" -p "$prompt" result || true
    if [ -z "$result" ]; then
        echo "$default"
        warn "Input timed out, using default: $default"
    else
        echo "$result"
    fi
}

# System Detection
detect_system() {
    if [ -f /etc/os-release ]; then
        # Read ID from os-release file
        distro=$(grep -E "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
        
        case "$distro" in
            "ubuntu")
                is_debian=true
                distro="ubuntu"
                ;;
            "debian")
                is_debian=true
                distro="debian"
                ;;
            *)
                error "Unsupported distribution"
                ;;
        esac
    else
        error "Cannot detect distribution: /etc/os-release not found"
    fi
    
    export is_debian
    export distro
    log "System detection: Distribution=$distro"
}

remove_snap() {
    if [ "${distro}" != "ubuntu" ]; then
        return 0
    fi

    log "Checking Snap packages..."
    
    if ! command -v snap >/dev/null 2>&1; then
        log "Snap is not installed on this system"
        return 0
    fi

    log "Removing Snap and preventing its reinstallation..."
    
    # Stop snapd services
    systemctl stop snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
    systemctl disable snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true

    # Remove snap packages
    local snap_packages
    snap_packages=$(snap list 2>/dev/null | awk 'NR>1 {print $1}')
    
    if [ -n "$snap_packages" ]; then
        while IFS= read -r pkg; do
            if [ -n "$pkg" ]; then
                log "Removing snap package: $pkg"
                snap remove --purge "$pkg" >/dev/null 2>&1 || \
                    warn "Failed to remove snap package: $pkg"
            fi
        done <<< "$snap_packages"
    fi
    
    # Remove snapd package
    log "Removing snapd package..."
    apt-get remove --purge snapd -y || warn "Failed to remove snapd package"
    apt-get autoremove --purge -y

    # Clean up snap directories
    local snap_dirs=("/snap" "/var/snap" "/var/lib/snapd" "/var/cache/snapd" "/usr/lib/snapd")
    for dir in "${snap_dirs[@]}"; do
        if [ -d "$dir" ]; then
            rm -rf "$dir"
            log "Removed directory: $dir"
        fi
    done

    # Prevent snapd from being installed again
    log "Blocking snap from future installation..."
    cat > /etc/apt/preferences.d/nosnap.pref << EOF
Package: snapd
Pin: release a=*
Pin-Priority: -1
EOF

    # Remove snap-related apt source
    if [ -f /etc/apt/sources.list.d/snap-*.list ]; then
        rm -f /etc/apt/sources.list.d/snap-*.list
        log "Removed snap repository configuration"
    fi

    # Update package list after removal
    apt-get update

    log "Snap has been removed and blocked from future installation"
    return 0
}

configure_ssh_for_user() {
    local user=$1
    local user_home="/home/${user}"
    local ssh_dir="${user_home}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"

    mkdir -p "${ssh_dir}"
    touch "${auth_keys}"

    # Always prompt for SSH key for new users
    if [ ! -s "${auth_keys}" ]; then
        log "No SSH key found for ${user}. Adding new key..."
        local ssh_key=$(read_input "Enter SSH public key for ${user}: " "")
        if [ -n "$ssh_key" ]; then
            validate_ssh_key "$ssh_key" && echo "${ssh_key}" > "${auth_keys}"
        fi
    else
        log "Existing SSH keys for ${user}:"
        cat "${auth_keys}"
        local replace_keys=$(read_input "Replace existing keys? (y/n): " "n")
        if [[ $replace_keys =~ ^[Yy]$ ]]; then
            local ssh_key=$(read_input "Enter new SSH public key: " "")
            if [ -n "$ssh_key" ]; then
                validate_ssh_key "$ssh_key" && echo "${ssh_key}" > "${auth_keys}"
            fi
        fi
    fi

    chown "${user}:${user}" "${ssh_dir}"
    chmod 700 "${ssh_dir}"
    chown "root:${user}" "${auth_keys}"
    chmod 640 "${auth_keys}"
}

configure_root_bashrc() {
    local bashrc="/root/.bashrc"
    backup_file "$bashrc"

    if [ "${distro}" = "debian" ]; then
        # Debian specific configuration
        local debian_config='force_color_prompt=yes
PS1='"'"'${debian_chroot:+($debian_chroot)}\[\033[01;31m\]\u\[\033[01;32m\]@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '"'"'
alias ls='"'"'ls --color=auto'"'"'
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi'

        # Check if configurations exist and append if they don't
        if ! grep -q "force_color_prompt=yes" "$bashrc"; then
            echo "$debian_config" >> "$bashrc"
            log "Added color prompt and bash completion to root bashrc"
        fi
    elif [ "${distro}" = "ubuntu" ]; then
        # Ubuntu specific configuration
        sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/' "$bashrc"

        # Check if the old PS1 configuration exists and needs to be updated
        if grep -q '^\s*PS1=.*\\\[\\033\[01;32m\\\]\\u@\\h' "$bashrc"; then
            # Replace the existing PS1 configuration with the new one
            sed -i 's/PS1=.*$/PS1='"'"'${debian_chroot:+($debian_chroot)}\[\033[01;31m\]\u\[\033[01;32m\]@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '"'"'/' "$bashrc"
            log "Updated root bashrc PS1 configuration for Ubuntu"
        fi
    fi
}

configure_user_security() {
    local user=$1
    local user_home="/home/${user}"
    
    # Configure .bash_logout
    local bash_logout="${user_home}/.bash_logout"
    if [ -f "$bash_logout" ]; then
        backup_file "$bash_logout"
    else
        touch "$bash_logout"
    fi
    
    # Check and add history commands if not present
    if ! grep -q "history -c" "$bash_logout"; then
        echo "history -c" >> "$bash_logout"
    fi
    if ! grep -q "history -w" "$bash_logout"; then
        echo "history -w" >> "$bash_logout"
    fi
    
    # Set ownership and permissions for .bash_logout
    chown root:root "$bash_logout"
    chmod 644 "$bash_logout"
    log "Configured .bash_logout for ${user}"
}

configure_system_ssh() {
    backup_file "/etc/ssh/sshd_config"
    
    # Get current SSH port
    local current_port=$(grep -i "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
    log "Current SSH port: ${current_port}"

    # Ensure we have a valid port number
    if [[ ! "$current_port" =~ ^[0-9]+$ ]]; then
        current_port="22"
        log "Using default port: ${current_port}"
    fi

    local change_port=$(read_input "Change SSH port? (y/n): " "n")
    if [[ $change_port =~ ^[Yy]$ ]]; then
        local new_port=$(read_input "Enter new SSH port: " "$SSH_PORT_DEFAULT")
        if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ]; then
            sed -i '/^Port /d' /etc/ssh/sshd_config
            echo "Port ${new_port}" >> /etc/ssh/sshd_config
            log "SSH port changed to: ${new_port}"
        else
            warn "Invalid port number. Keeping current port: ${current_port}"
        fi
    fi

    # SSH hardening
    cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
MaxStartups 3:50:10
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
AuthenticationMethods publickey
ClientAliveInterval 60
ClientAliveCountMax 10
TCPKeepAlive no
Compression no
EOF

    # Handle SSH service based on distribution and environment
    if [ "${distro}" = "debian" ]; then
        if [ "${is_lxc}" = true ]; then
            log "Debian LXC detected: Configuring SSH services..."
            systemctl disable ssh.socket
            systemctl stop ssh.socket
            systemctl enable ssh.service
            systemctl start ssh.service
        elif [ "${is_lxc}" = false ]; then
            log "Debian standard system detected: Reloading SSH..."
            systemctl reload ssh
        fi
    else
        # For Ubuntu (both LXC and standard), no reload needed
        log "Ubuntu detected: SSH configuration updated, no service reload required"
    fi
}

configure_system_packages() {
    log "Updating package lists..."
    apt-get update >/dev/null 2>&1

    log "Upgrading existing packages..."
    # Run upgrade without background process to avoid hanging
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

    log "Installing required packages..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}"
}

configure_user_environment() {
    local user=$1
    local user_home

    # Set correct home directory based on user
    if [ "$user" = "root" ]; then
        user_home="/root"
    else
        user_home="/home/${user}"
    fi

    # Configure bash
    if [ -f "${user_home}/.bashrc" ]; then
        backup_file "${user_home}/.bashrc"
        sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/' "${user_home}/.bashrc"
        
        # Set custom prompt for non-root users
        if [ "$user" != "root" ]; then
            local ps1_config='PS1='"'"'\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '"'"
            sed -i "/^PS1=/c\\$ps1_config" "${user_home}/.bashrc"
        fi
    fi

    # Configure vim
    log "Downloading .vimrc for ${user}..."
    if wget -q "$VIMRC_URL" -O "${user_home}/.vimrc"; then
        chown "${user}:${user}" "${user_home}/.vimrc"
        chmod 644 "${user_home}/.vimrc"
        log "Successfully configured .vimrc for ${user}"
    else
        warn "Failed to download .vimrc for ${user}"
    fi
}

configure_system_parameters() {
    if [ "${is_lxc}" = false ]; then
        # IPv6 configuration
        local disable_ipv6=$(read_input "Disable IPv6? (y/n): " "n")
        if [[ $disable_ipv6 =~ ^[Yy]$ ]]; then
            backup_file "/etc/default/grub"
            sed -i '/GRUB_CMDLINE_LINUX_DEFAULT=/s/"$/ ipv6.disable=1"/' /etc/default/grub
            sed -i '/GRUB_CMDLINE_LINUX=/s/"$/ ipv6.disable=1"/' /etc/default/grub
            update-grub
        fi

        # Time synchronization
        local config_ntp=$(read_input "Configure NTP sync with time.nist.gov? (y/n): " "y")
        if [[ $config_ntp =~ ^[Yy]$ ]]; then
            systemctl stop systemd-timesyncd ntp chronyd 2>/dev/null || true
            systemctl disable systemd-timesyncd ntp chronyd 2>/dev/null || true
            apt-get install -y ntpdate
            ntpdate -4 time.nist.gov
            (crontab -l 2>/dev/null; echo "0 */6 * * * /usr/sbin/ntpdate -4 -s time.nist.gov") | sort - | uniq - | crontab -
        fi
    fi

    # Sysctl configuration
    local modify_sysctl=$(read_input "Modify sysctl.conf? (y/n): " "y")
    if [[ $modify_sysctl =~ ^[Yy]$ ]]; then
        backup_file "/etc/sysctl.conf"
        log "Downloading sysctl configuration..."
        
        if ! wget -q "$SYSCTL_URL" -O /tmp/sysctl.conf; then
            error "Failed to download sysctl configuration"
        fi
        
        if [ "${is_lxc}" = true ]; then
            log "Filtering sysctl parameters for LXC environment..."
            touch /tmp/sysctl_lxc.conf
            
            while IFS= read -r line || [ -n "$line" ]; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                [[ -z "${line// }" ]] && continue
                
                local param=$(echo "$line" | cut -d= -f1 | tr -d ' ')
                local value=$(echo "$line" | cut -d= -f2- | tr -d ' ')
                
                [[ "$param" =~ ^kernel\. ]] && continue
                [[ "$param" =~ ^fs\. ]] && continue
                
                if sysctl -q "$param" >/dev/null 2>&1; then
                    if sysctl -w "$param=$value" >/dev/null 2>&1; then
                        echo "$line" >> /tmp/sysctl_lxc.conf
                        log "Parameter available and writable: $param"
                    else
                        warn "Parameter exists but not writable: $param"
                    fi
                else
                    warn "Skipping unavailable parameter: $param"
                fi
            done < /tmp/sysctl.conf
            
            if [ -s /tmp/sysctl_lxc.conf ]; then
                mv /tmp/sysctl_lxc.conf /etc/sysctl.conf
                log "Applying working sysctl parameters..."
                sysctl -p /etc/sysctl.conf 2>/dev/null || true
            else
                warn "No applicable sysctl parameters found for LXC environment"
            fi
        else
            cp /tmp/sysctl.conf /etc/sysctl.conf
            sysctl -p
        fi
        
        rm -f /tmp/sysctl.conf /tmp/sysctl_lxc.conf
    fi
}

configure_sudo_access() {
    local sudo_users=$(getent group sudo | cut -d: -f4)
    if [ -z "${sudo_users}" ]; then
        log "No users in sudo group. Select user to add:"
        select user in $(ls /home); do
            if [ -n "${user}" ]; then
                usermod -aG sudo "${user}"
                echo "${user} ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/init-${user}"
                chmod 440 "/etc/sudoers.d/init-${user}"
                log "Added ${user} to sudo group with initial passwordless access"
                selected_sudo_user="${user}"
                break
            fi
        done
    fi
}

display_summary() {
    # Capitalize distribution name
    local display_distro
    case "${distro}" in
        "debian")
            display_distro="Debian"
            ;;
        "ubuntu")
            display_distro="Ubuntu"
            ;;
        *)
            display_distro="${distro^}"  # Capitalize first letter as fallback
            ;;
    esac

    log "Configuration Summary:"
    echo "  • System Information:"
    echo "    - Distribution: ${display_distro}"
    echo "    - Environment: $([ "$is_lxc" = true ] && echo "LXC Container" || echo "Standard System")"
    echo
    echo "  • Security Changes:"
    echo "    - SSH configuration hardened"
    echo "    - Root login disabled"
    echo "    - Password authentication disabled"
    [ -n "${selected_sudo_user}" ] && echo "    - Sudo access configured for: ${selected_sudo_user}"
    echo
    echo "  • System Optimizations:"
    echo "    - System packages updated"
    echo "    - Sysctl parameters configured"
    [ "${is_lxc}" = false ] && echo "    - Time synchronization configured"
    echo
    echo "  • Backup Information:"
    echo "    - Backup directory: ${BACKUP_DIR}"
    echo "    - Log file: ${LOG_FILE}"
}

main() {
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    log "Starting server initialization script v${SCRIPT_VERSION}"
    
    # Check root privileges
    if [ "$(id -u)" != "0" ]; then
        error "This script must be run as root"
    fi

    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    # Detect environment and system
    detect_environment
    detect_system

    # Remove snap from Ubuntu
    remove_snap

    # Comment CDROM source in Debian
    if [ "${distro}" = "debian" ] && [ "${is_lxc}" = false ]; then
        if grep -q "^deb cdrom:" /etc/apt/sources.list; then
            log "Commenting out CDROM source..."
            backup_file "/etc/apt/sources.list"
            sed -i 's/^deb cdrom:/#deb cdrom:/' /etc/apt/sources.list
        fi
    fi

    # System updates and package installation
    configure_system_packages

    # User management
    if [ -z "$(ls -A /home)" ]; then
        log "No users found. Creating new user..."
        local username=$(read_input "Enter username: " "")
        if [ -n "$username" ]; then
            adduser "$username"
        else
            error "Username cannot be empty"
        fi
    fi

    # Configure sudo access
    configure_sudo_access

    # Configure users in /home/
    for user in $(ls /home); do
        configure_ssh_for_user "${user}"
        configure_user_environment "${user}"
        configure_user_security "${user}"
    done

    # Configure root
    configure_root_bashrc
    configure_user_environment "root"

    # Configure system SSH
    configure_system_ssh

    # Configure system parameters
    configure_system_parameters

    # Lock root account on Debian
    if [ "${distro}" = "debian" ]; then
        if [ -n "${selected_sudo_user:-}" ]; then
            log "Testing sudo access..."
            if su - "${selected_sudo_user}" -c "sudo whoami" >/dev/null 2>&1; then
                log "Sudo access confirmed for ${selected_sudo_user}"
                rm -f "/etc/sudoers.d/init-${selected_sudo_user}"
                passwd -l root
                log "Root account locked"
                warn "Note: Sudo access now requires password"
            else
                error "Failed to verify sudo access"
            fi
        fi
    fi

    # Display configuration summary
    display_summary

    # Prompt for reboot
    local do_reboot=$(read_input "Would you like to reboot now to apply all changes? (y/n): " "n")
    if [[ $do_reboot =~ ^[Yy]$ ]]; then
        log "Initiating system reboot..."
        sleep 2
        reboot
    else
        log "Please remember to reboot your system at your convenience"
        echo "Thank you for using the server initialization script! 🚀"
    fi
}

# Execute main function
main "$@"
