#!/bin/bash
set -euo pipefail

LOCK_FILE="/var/run/system_hardening.lock"
LOG_FILE="/var/log/system_hardening.log"
BACKUP_DIR="/root/system_hardening_backups/$(date +%Y%m%d_%H%M%S)"

trap 'handle_error $LINENO' ERR
trap 'cleanup' EXIT

handle_error() {
    local exit_code=$?
    log "ERROR" "Error on line $1: Exit code $exit_code"
    cleanup
    exit $exit_code
}

cleanup() {
    rm -f "$LOCK_FILE"
    [[ -d /tmp/system_hardening ]] && rm -rf /tmp/system_hardening
}

log() {
    local level=$1; shift
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

create_backup() {
    local file=$1
    mkdir -p "$BACKUP_DIR"
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file")" || return 1
    fi
}

check_system() {
    local available_mem=$(free -m | awk '/^Mem:/{print $7}')
    local free_space=$(df -m / | awk 'NR==2 {print $4}')
    
    if (( available_mem < 512 )); then
        log "WARNING" "Less than 512MB RAM available"
        read -r -p "Continue? (y/n): " response
        [[ ! "$response" =~ ^[Yy]$ ]] && exit 1
    fi
    
    if (( free_space < 1024 )); then
        log "WARNING" "Less than 1GB disk space available"
        read -r -p "Continue? (y/n): " response
        [[ ! "$response" =~ ^[Yy]$ ]] && exit 1
    fi

    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        log "ERROR" "No internet connectivity"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
    else
        log "ERROR" "Cannot detect OS version"
        exit 1
    fi
}

install_package() {
    local package=$1
    if ! dpkg -l | grep -q "^ii.*$package"; then
        apt install -y "$package" || return 1
    fi
}

configure_ssh() {
    create_backup /etc/ssh/sshd_config
    
    cat > /etc/ssh/sshd_config.d/hardening.conf <<EOF
Protocol 2
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PasswordAuthentication no
PermitRootLogin no
EOF

    if [[ "$OS" == "ubuntu" ]]; then
        systemctl restart ssh
    else
        systemctl restart sshd
    fi
}

configure_ufw() {
    if ! command -v ufw >/dev/null 2>&1; then
        install_package ufw
    fi
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$ssh_port"/tcp
    ufw --force enable
}

configure_time_sync() {
    systemctl stop systemd-timesyncd 2>/dev/null || true
    systemctl disable systemd-timesyncd 2>/dev/null || true
    
    install_package ntpdate
    ntpdate -4 time.nist.gov
    
    if ! grep -q "ntpdate -4 -s time.nist.gov" /etc/crontab; then
        echo "0 */6 * * * root ntpdate -4 -s time.nist.gov" >> /etc/crontab
    fi
}

[[ "$EUID" -ne 0 ]] && { echo "Please run as root"; exit 1; }
[[ -f "$LOCK_FILE" ]] && { echo "Another instance is running"; exit 1; }
touch "$LOCK_FILE"

mkdir -p "$(dirname "$LOG_FILE")"
check_system
detect_os

log "INFO" "Starting system hardening..."

log "INFO" "Running system updates..."
apt update && apt upgrade -y

log "INFO" "Installing base packages..."
PACKAGES="curl rsyslog wget socat bash-completion wireguard vim"
[[ "$OS" == "debian" ]] && PACKAGES+=" dnsmasq"

for pkg in $PACKAGES; do
    install_package "$pkg"
done

if ! command -v sudo >/dev/null 2>&1; then
    log "INFO" "Installing sudo..."
    install_package sudo
    
    echo "Available users:"
    select username in $(ls /home); do
        [[ -n "$username" ]] && {
            usermod -aG sudo "$username"
            log "INFO" "Added $username to sudo group"
            break
        }
        log "ERROR" "Invalid selection"
        exit 1
    done
fi

log "INFO" "Configuring user environments..."
for user_home in /root /home/*; do
    [[ ! -d "$user_home" ]] && continue
    
    # Configure bash prompt
    if [[ -f "$user_home/.bashrc" ]]; then
        create_backup "$user_home/.bashrc"
        sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/' "$user_home/.bashrc"
        
        if [[ "$OS" == "debian" ]]; then
            cat >> "$user_home/.bashrc" <<'EOF'
PS1='${debian_chroot:+($debian_chroot)}\[\033[01;31m\]\u\[\033[01;32m\]@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
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

    # Configure vim
    cat > "$user_home/.vimrc" <<'EOF'
syntax on
set nocompatible
set backspace=2
filetype on
filetype plugin on
set expandtab
set tabstop=2
set hlsearch
EOF

    username=$(basename "$user_home")
    chown "$username:$username" "$user_home/.vimrc"

    # Configure SSH directory
    ssh_dir="$user_home/.ssh"
    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
        chown "$username:$username" "$ssh_dir"
    fi

    # Configure bash_logout
    if [[ -f "$user_home/.bash_logout" ]]; then
        create_backup "$user_home/.bash_logout"
        echo -e "clear\nhistory -c\nhistory -w" > "$user_home/.bash_logout"
        chmod 644 "$user_home/.bash_logout"
    fi
done

log "INFO" "Configuring SSH..."
read -r -p "Enter desired SSH port [22]: " ssh_port
ssh_port=${ssh_port:-22}
if ! [[ "$ssh_port" =~ ^[0-9]+$ ]] || (( ssh_port < 1 || ssh_port > 65535 )); then
    log "ERROR" "Invalid port number"
    exit 1
fi

configure_ssh

log "INFO" "Configuring firewall..."
configure_ufw

read -r -p "Disable IPv6? (y/n): " disable_ipv6
if [[ "$disable_ipv6" =~ ^[Yy]$ ]]; then
    create_backup /etc/default/grub
    sed -i '/GRUB_CMDLINE_LINUX_DEFAULT=/ s/"$/ ipv6.disable=1"/' /etc/default/grub
    sed -i '/GRUB_CMDLINE_LINUX=/ s/"$/ ipv6.disable=1"/' /etc/default/grub
    update-grub
fi

if [[ "$OS" == "ubuntu" ]]; then
    log "INFO" "Removing Snap..."
    snap list 2>/dev/null | awk 'NR>1 {print $1}' | while read -r pkg; do
        snap remove --purge "$pkg" 2>/dev/null
    done
    apt remove --purge snapd -y
    rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd /usr/lib/snapd
    
    cat > /etc/apt/preferences.d/nosnap.pref <<EOF
Package: snapd
Pin: release a=*
Pin-Priority: -1
EOF
fi

log "INFO" "Configuring time synchronization..."
configure_time_sync

log "INFO" "Configuring system controls..."
create_backup /etc/sysctl.conf
cat >> /etc/sysctl.conf <<EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.conf.all.log_martians = 1
EOF
sysctl -p

log "INFO" "System hardening completed successfully"
log "INFO" "Please reboot the system for all changes to take effect"

cleanup
exit 0
