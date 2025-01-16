#!/usr/bin/env bash

# Server Initialization and Hardening Script
# Version: 3.0
# Description: Initializes and hardens Debian/Ubuntu systems
# Supports: Debian 12, Ubuntu 22.04, and their derivatives
# Environment: Bare metal, VM, and LXC containers
# Author: RebelliousWhiz
# License: GLP 3.0
# In memory of Yunfei Shan, a good man, a good friend.

# Initialize script with strict error checking
set -euo pipefail
IFS=$'\n\t'

# Color definitions (using printf for better compatibility)
RED=$(printf '\033[0;31m')
GREEN=$(printf '\033[0;32m')
YELLOW=$(printf '\033[1;33m')
NC=$(printf '\033[0m')

# Helper functions
log() {
    printf "${GREEN}[%s]${NC} %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
    exit 1
}

warn() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

configure_ssh_for_user() {
    local user=$1
    local user_home="/home/${user}"
    local ssh_dir="${user_home}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"

    mkdir -p "${ssh_dir}"
    touch "${auth_keys}"

    if groups "${user}" | grep -q "\bsudo\b"; then
        if [ ! -s "${auth_keys}" ]; then
            log "No SSH key found for ${user}. Adding new key..."
            read -r -p "Enter SSH public key: " ssh_key
            echo "${ssh_key}" > "${auth_keys}"
        else
            log "Existing SSH keys for ${user}:"
            cat "${auth_keys}"
            read -p "Replace existing keys? (y/n): " replace_keys
            if [[ $replace_keys =~ ^[Yy]$ ]]; then
                read -r -p "Enter new SSH public key: " ssh_key
                echo "${ssh_key}" > "${auth_keys}"
            fi
        fi
    fi

    chown "${user}:${user}" "${ssh_dir}"
    chmod 700 "${ssh_dir}"
    chown root:root "${auth_keys}"
    chmod 644 "${auth_keys}"
}

# Check root privileges
if [ "$(id -u)" != "0" ]; then
    error "This script must be run as root"
fi

# Detect system and environment
is_debian=false
is_lxc=false
distro=""

if [ -f /etc/debian_version ]; then
    is_debian=true
    if grep -qi debian /etc/os-release; then
        distro="debian"
    else
        distro="ubuntu"
    fi
fi

if [ -f /proc/1/environ ] && grep -q container=lxc /proc/1/environ; then
    is_lxc=true
fi

# Comment CDROM source in Debian
if [ "${distro}" = "debian" ] && [ "${is_lxc}" = false ]; then
    if grep -q "^deb cdrom:" /etc/apt/sources.list; then
        log "Commenting out CDROM source..."
        sed -i 's/^deb cdrom:/#deb cdrom:/' /etc/apt/sources.list
    fi
fi

# Update system
log "Updating system..."
apt-get update
apt-get upgrade -y

# Install packages
log "Installing required packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl \
    rsyslog \
    wget \
    socat \
    bash-completion \
    wireguard \
    vim \
    sudo

# Install dnsmasq if desired
if [ "${distro}" = "debian" ] && [ "${is_lxc}" = false ]; then
    read -p "Install dnsmasq? (y/n): " install_dnsmasq
    if [[ $install_dnsmasq =~ ^[Yy]$ ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq
        log "Configuring dnsmasq..."
        cat > /etc/dnsmasq.conf << 'EOF'
no-resolv
server=8.8.8.8
server=8.8.4.4
EOF
        systemctl restart dnsmasq
    fi
fi

# User management
if [ -z "$(ls -A /home)" ]; then
    log "No users found. Creating new user..."
    read -p "Enter username: " username
    adduser "${username}"
fi

# Sudo group management for Debian
if [ "${distro}" = "debian" ]; then
    sudo_users=$(getent group sudo | cut -d: -f4)
    if [ -z "${sudo_users}" ]; then
        log "No users in sudo group. Select user to add:"
        select user in $(ls /home); do
            if [ -n "${user}" ]; then
                usermod -aG sudo "${user}"
                # Create sudo configuration for passwordless sudo initially
                echo "${user} ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/init-${user}"
                chmod 440 "/etc/sudoers.d/init-${user}"
                log "Added ${user} to sudo group with initial passwordless access"
                selected_sudo_user="${user}"
                break
            fi
        done
    fi
fi

# SSH configuration for users
for user in $(ls /home); do
    configure_ssh_for_user "${user}"
done

# Lock root account on Debian
if [ "${distro}" = "debian" ]; then
    if [ -n "${selected_sudo_user:-}" ]; then
        log "Testing sudo access..."
        if su - "${selected_sudo_user}" -c "sudo whoami" >/dev/null 2>&1; then
            log "Sudo access confirmed for ${selected_sudo_user}"
            # Remove passwordless sudo and require password
            rm -f "/etc/sudoers.d/init-${selected_sudo_user}"
            passwd -l root
            log "Root account locked"
            warn "Note: Sudo access now requires password. Please set a password for ${selected_sudo_user} if not already set."
        else
            error "Failed to verify sudo access. Please check configuration manually."
        fi
    elif [ -n "$(getent group sudo | cut -d: -f4)" ]; then
        current_sudo_user=$(getent group sudo | cut -d: -f4 | cut -d, -f1)
        log "Found existing sudo user: ${current_sudo_user}"
    fi
fi

# Bash configuration
bash_completion_config="if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi"

if [ "${distro}" = "debian" ]; then
    # Root bashrc configuration
    cat >> /root/.bashrc << 'EOF'
force_color_prompt=yes
PS1='\[\033[01;31m\]\u\[\033[01;32m\]@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
alias ls='ls --color=auto'
EOF
    echo "${bash_completion_config}" >> /root/.bashrc
elif [ "${distro}" = "ubuntu" ]; then
    sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/' /root/.bashrc
    sed -i '/^if \[ "\$color_prompt" = yes \]; then/,/^unset color_prompt force_color_prompt$/c\
if [ "$color_prompt" = yes ]; then\
    PS1='\''\[\033[01;31m\]\u\[\033[01;32m\]@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '\''\
else\
    PS1='\''\u@\h:\w\$ '\''\
fi\
unset color_prompt force_color_prompt' /root/.bashrc
fi

# User bashrc configuration
for user in $(ls /home); do
    sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/' "/home/${user}/.bashrc"
done

# Download .vimrc for all users
wget -q https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/main/.vimrc -O /root/.vimrc
for user in $(ls /home); do
    wget -q https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/main/.vimrc -O "/home/${user}/.vimrc"
    chown "${user}:${user}" "/home/${user}/.vimrc"
done

# Get current SSH port, default to 22 if not explicitly set
current_port=$(grep -i "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
log "Current SSH port: ${current_port}"

# Ensure we have a valid port number
if [[ ! "$current_port" =~ ^[0-9]+$ ]]; then
    current_port="22"
    log "Using default port: ${current_port}"
fi

read -p "Change SSH port? (y/n): " change_port

if [[ $change_port =~ ^[Yy]$ ]]; then
    read -p "Enter new SSH port: " new_port
    if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ]; then
        sed -i '/^Port /d' /etc/ssh/sshd_config  # Remove existing Port line if any
        echo "Port ${new_port}" >> /etc/ssh/sshd_config
        log "SSH port changed to: ${new_port}"
    else
        log "Invalid port number. Keeping current port: ${current_port}"
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

if [ "${is_lxc}" = true ]; then
    systemctl disable ssh.socket || true
    systemctl enable ssh.service
fi

# IPv6 and system configuration for non-LXC
if [ "${is_lxc}" = false ]; then
    # IPv6 configuration
    read -p "Disable IPv6? (y/n): " disable_ipv6
    if [[ $disable_ipv6 =~ ^[Yy]$ ]]; then
        sed -i '/GRUB_CMDLINE_LINUX_DEFAULT=/s/"$/ ipv6.disable=1"/' /etc/default/grub
        sed -i '/GRUB_CMDLINE_LINUX=/s/"$/ ipv6.disable=1"/' /etc/default/grub
        update-grub
    fi

    # Time synchronization
    read -p "Configure NTP sync with time.nist.gov? (y/n): " config_ntp
    if [[ $config_ntp =~ ^[Yy]$ ]]; then
        systemctl stop systemd-timesyncd ntp chronyd || true
        systemctl disable systemd-timesyncd ntp chronyd || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y ntpdate
        ntpdate -4 time.nist.gov
        (crontab -l 2>/dev/null; echo "00 */6 * * * ntpdate -4 -s time.nist.gov") | crontab -
    fi
fi

# Sysctl configuration
read -p "Modify sysctl.conf? (y/n): " modify_sysctl
if [[ $modify_sysctl =~ ^[Yy]$ ]]; then
    log "Downloading sysctl configuration..."
    wget -q https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/sysctl.conf -O /tmp/sysctl.conf
    
    if [ "${is_lxc}" = true ]; then
        log "Filtering sysctl parameters for LXC environment..."
        touch /tmp/sysctl_lxc.conf
        
        while IFS= read -r line || [ -n "$line" ]; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            
            # Extract parameter name and value
            param=$(echo "$line" | cut -d= -f1 | tr -d ' ')
            value=$(echo "$line" | cut -d= -f2- | tr -d ' ')
            
            # Skip kernel and fs parameters in LXC
            [[ "$param" =~ ^kernel\. ]] && continue
            [[ "$param" =~ ^fs\. ]] && continue
            
            # Test if parameter exists and can be set
            if sysctl -q "$param" >/dev/null 2>&1; then
                # Try to set the parameter to test write access
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
        
        # If we found any working parameters, apply them
        if [ -s /tmp/sysctl_lxc.conf ]; then
            mv /tmp/sysctl_lxc.conf /etc/sysctl.conf
            log "Applying working sysctl parameters..."
            sysctl -p /etc/sysctl.conf 2>/dev/null || true
        else
            warn "No applicable sysctl parameters found for LXC environment"
        fi
    else
        # Non-LXC environment, use all parameters
        cp /tmp/sysctl.conf /etc/sysctl.conf
        sysctl -p
    fi
    
    # Cleanup
    rm -f /tmp/sysctl.conf /tmp/sysctl_lxc.conf
fi

log "Configuration complete. System reboot recommended."
read -p "Reboot now? (y/n): " do_reboot
if [[ $do_reboot =~ ^[Yy]$ ]]; then
    reboot
fi

# Final configuration and reboot prompt
log "Configuration complete! 🎉"
log "Summary of changes:"
echo "  • System packages updated and secured"
echo "  • SSH hardened and configured"
echo "  • User permissions and sudo access configured"
echo "  • System parameters optimized"
echo "  • Security measures implemented"

if [ "${is_lxc}" = true ]; then
    echo "  • LXC-specific optimizations applied"
fi

echo
log "Next steps:"
echo "  1. Review the changes made"
echo "  2. Test SSH access with the configured key"
echo "  3. Verify sudo access for the configured user"
if [ "${is_lxc}" = false ]; then
    echo "  4. Check system performance after reboot"
fi

echo
read -p "Would you like to reboot now to apply all changes? (y/n): " do_reboot
if [[ $do_reboot =~ ^[Yy]$ ]]; then
    log "Initiating system reboot..."
    sleep 2
    reboot
else
    log "Please remember to reboot your system at your convenience."
    echo "Thank you for using the server initialization script! 🚀"
fi
