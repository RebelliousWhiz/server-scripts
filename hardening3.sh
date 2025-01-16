#!/usr/bin/env bash

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

# Update system and install packages
log "Updating system and installing required packages..."
apt-get update
apt-get upgrade -y

# Define base packages (using double quotes here)
base_packages="curl rsyslog wget socat bash-completion wireguard vim sudo"

if [ "$distro" = "debian" ] && [ "$is_lxc" = false ]; then
    read -p "Install dnsmasq? (y/n): " install_dnsmasq
    if [[ $install_dnsmasq =~ ^[Yy]$ ]]; then
        base_packages="$base_packages dnsmasq"
    fi
fi

# Install all packages in a single command (important: no quotes around $base_packages)
apt-get install -y $base_packages

# Configure dnsmasq if installed
if command -v dnsmasq >/dev/null 2>&1; then
    log "Configuring dnsmasq..."
    cat > /etc/dnsmasq.conf << EOF
no-resolv
server=8.8.8.8
server=8.8.4.4
EOF
    systemctl restart dnsmasq
fi

# User management
if [ -z "$(ls -A /home)" ]; then
    log "No users found. Creating new user..."
    read -p "Enter username: " username
    adduser "$username"
fi

# Sudo group management for Debian
if [ "$distro" = "debian" ]; then
    sudo_users=$(getent group sudo | cut -d: -f4)
    if [ -z "$sudo_users" ]; then
        log "No users in sudo group. Select user to add:"
        select user in $(ls /home); do
            if [ -n "$user" ]; then
                usermod -aG sudo "$user"
                break
            fi
        done
    fi
fi

# SSH configuration for users
for user in $(ls /home); do
    user_home="/home/$user"
    ssh_dir="$user_home/.ssh"
    auth_keys="$ssh_dir/authorized_keys"

    # Create .ssh directory if it doesn't exist
    if [ ! -d "$ssh_dir" ]; then
        mkdir -p "$ssh_dir"
        chown "`$user:$`user" "$ssh_dir"
        chmod 700 "$ssh_dir"
    fi

    # Create authorized_keys if it doesn't exist
    if [ ! -f "$auth_keys" ]; then
        touch "$auth_keys"
    fi

    # SSH key management for sudo users
    if groups "$user" | grep -q "\bsudo\b"; then
        if [ ! -s "$auth_keys" ]; then
            log "No SSH key found for $user. Adding new key..."
            read -r -p "Enter SSH public key: " ssh_key
            echo "`$ssh_key" > "$`auth_keys"
        else
            log "Existing SSH keys for $user:"
            cat "$auth_keys"
            read -p "Replace existing keys? (y/n): " replace_keys
            if [[ `$replace_keys =~ ^[Yy]$` ]]; then
                read -r -p "Enter new SSH public key: " ssh_key
                echo "`$ssh_key" > "$`auth_keys"
            fi
        fi
    fi

    # Set proper permissions
    chown root:root "$auth_keys"
    chmod 644 "$auth_keys"
done

# Lock root account on Debian
if [ "$distro" = "debian" ]; then
    sudo_user=$(getent group sudo | cut -d: -f4 | cut -d, -f1)
    if [ -n "$sudo_user" ]; then
        log "Testing sudo access for $sudo_user..."
        if su - "$sudo_user" -c "sudo true" >/dev/null 2>&1; then
            passwd -l root
            log "Root account locked"
        else
            error "Sudo test failed. Not locking root account."
        fi
    fi
fi

# Bash configuration
if [ "$distro" = "debian" ]; then
    # Root bashrc configuration
    root_bashrc_content="force_color_prompt=yes
PS1='```math
\[\033[01;31m\]
```\u```math
\[\033[01;32m\]
```@\h```math
\[\033[00m\]
```:```math
\[\033[01;34m\]
```\w```math
\[\033[00m\]
```\$ '
alias ls='ls --color=auto'
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi"

    for line in $root_bashrc_content; do
        if ! grep -qF "$line" /root/.bashrc; then
            echo "$line" >> /root/.bashrc
        fi
    done
elif [ "$distro" = "ubuntu" ]; then
    # Ubuntu specific bashrc modifications
    sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/' /root/.bashrc
    sed -i '/^if ```math
 \[ "\$color_prompt" = yes \]
 ```; then/,/^unset color_prompt force_color_prompt$/c\
if [ "$color_prompt" = yes ]; then\
    PS1='\''```math
\[\033[01;31m\]
```\u```math
\[\033[01;32m\]
```@\h```math
\[\033[00m\]
```:```math
\[\033[01;34m\]
```\w```math
\[\033[00m\]
```\$ '\''\
else\
    PS1='\''\u@\h:\w\$ '\''\
fi\
unset color_prompt force_color_prompt' /root/.bashrc
fi

# User bashrc configuration
for user in $(ls /home); do
    user_bashrc="/home/$user/.bashrc"
    sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/' "$user_bashrc"
done

# Download .vimrc for all users
wget -q https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/main/.vimrc -O /root/.vimrc
for user in $(ls /home); do
    wget -q https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/main/.vimrc -O "/home/$user/.vimrc"
    chown "`$user:$`user" "/home/$user/.vimrc"
done

# SSH server configuration
current_port=`$(grep -i "^Port" /etc/ssh/sshd_config | awk '{print $`2}')
log "Current SSH port: ${current_port:-22}"
read -p "Change SSH port? (y/n): " change_port
if [[ `$change_port =~ ^[Yy]$` ]]; then
    read -p "Enter new SSH port: " new_port
    sed -i "s/^#\?Port .*/Port $new_port/" /etc/ssh/sshd_config
fi

# SSH hardening
cat > /etc/ssh/sshd_config.d/hardening.conf << EOF
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

if [ "$is_lxc" = true ]; then
    systemctl disable ssh.socket
    systemctl enable ssh.service
fi

# IPv6 configuration
if [ "$is_lxc" = false ]; then
    read -p "Disable IPv6? (y/n): " disable_ipv6
    if [[ `$disable_ipv6 =~ ^[Yy]$` ]]; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1 /' /etc/default/grub
        sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="ipv6.disable=1 /' /etc/default/grub
        update-grub
    fi

    # Time synchronization
    read -p "Configure NTP sync with time.nist.gov? (y/n): " config_ntp
    if [[ `$config_ntp =~ ^[Yy]$` ]]; then
        systemctl stop systemd-timesyncd ntp chronyd || true
        systemctl disable systemd-timesyncd ntp chronyd || true
        apt-get install -y ntpdate
        ntpdate -4 time.nist.gov
        (crontab -l 2>/dev/null; echo "00 */6  * * *   ntpdate -4 -s time.nist.gov") | crontab -
    fi
fi

# Sysctl configuration
read -p "Modify sysctl.conf? (y/n): " modify_sysctl
if [[ `$modify_sysctl =~ ^[Yy]$` ]]; then
    wget -q https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/sysctl.conf -O /tmp/sysctl.conf
    if [ "$is_lxc" = true ]; then
        # Remove LXC-incompatible settings
        grep -v "kernel.printk\|fs.file-max\|net.ipv4.ip_forward" /tmp/sysctl.conf > /etc/sysctl.conf
    else
        cp /tmp/sysctl.conf /etc/sysctl.conf
    fi
    sysctl -p
fi

log "Configuration complete. System reboot recommended."
read -p "Reboot now? (y/n): " do_reboot
if [[ `$do_reboot =~ ^[Yy]$` ]]; then
    reboot
fi
