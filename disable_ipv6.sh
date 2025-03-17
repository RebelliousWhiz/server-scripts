#!/usr/bin/env bash

# IPv6 Disabling Script
# Description: Disables IPv6 on Debian/Ubuntu systems
# Supports: Debian 12, Ubuntu 22.04, and their derivatives
# Environment: Bare metal, VM (not for LXC containers)

# Initialize script with strict error checking
set -euo pipefail
IFS=$'\n\t'

# Color definitions
RED=$(printf '\033[0;31m')
GREEN=$(printf '\033[0;32m')
YELLOW=$(printf '\033[1;33m')
NC=$(printf '\033[0m')

# Logging functions
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf "${GREEN}[%s]${NC} %s\n" "$timestamp" "$message"
}

error() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf "${RED}[ERROR]${NC} [%s] %s\n" "$timestamp" "$message" >&2
    exit 1
}

warn() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf "${YELLOW}[WARNING]${NC} [%s] %s\n" "$timestamp" "$message"
}

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    error "This script must be run as root"
fi

# Detect container environment
detect_environment() {
    is_container=false
    is_lxc=false

    # Use multiple detection methods
    if grep -q container=lxc /proc/1/environ 2>/dev/null || 
       grep -q ":/lxc/" /proc/1/cgroup 2>/dev/null || 
       grep -q ":name=lxc:" /proc/1/cgroup 2>/dev/null ||
       [ -d /dev/lxd ] || [ -f /.lxc ]; then
        is_lxc=true
        is_container=true
        warn "LXC container detected. IPv6 modifications in GRUB are not applicable."
        return
    fi

    # Check for other container types
    if [ -f /.dockerenv ] || 
       grep -q ":/docker/" /proc/1/cgroup 2>/dev/null || 
       grep -q container=docker /proc/1/environ 2>/dev/null; then
        is_container=true
        warn "Docker container detected. IPv6 modifications in GRUB are not applicable."
        return
    fi
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        local backup_file="${file}.bak-$(date +%Y%m%d-%H%M%S)"
        cp "$file" "$backup_file"
        log "Backed up $file to $backup_file"
    fi
}

disable_ipv6_grub() {
    log "Disabling IPv6 through GRUB configuration..."

    if [ ! -f /etc/default/grub ]; then
        warn "GRUB configuration not found. Skipping GRUB configuration."
        return 1
    fi

    backup_file "/etc/default/grub"

    # Check if ipv6.disable=1 exists in GRUB_CMDLINE_LINUX_DEFAULT
    local default_disabled=0
    if grep -q "ipv6.disable=1" <(grep "GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub 2>/dev/null); then
        default_disabled=1
        log "IPv6 already disabled in GRUB_CMDLINE_LINUX_DEFAULT"
    fi

    # Check if ipv6.disable=1 exists in GRUB_CMDLINE_LINUX
    local linux_disabled=0
    if grep -q "ipv6.disable=1" <(grep "GRUB_CMDLINE_LINUX=" /etc/default/grub | grep -v "DEFAULT" 2>/dev/null); then
        linux_disabled=1
        log "IPv6 already disabled in GRUB_CMDLINE_LINUX"
    fi

    # Modify GRUB_CMDLINE_LINUX_DEFAULT if needed
    if [ $default_disabled -eq 0 ]; then
        local default_value=$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | cut -d'"' -f2)
        if [ -n "$default_value" ]; then
            # Value exists, add with space
            sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\".*\"/GRUB_CMDLINE_LINUX_DEFAULT=\"${default_value} ipv6.disable=1\"/" /etc/default/grub
        else
            # No value, add without space
            sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"/' /etc/default/grub
        fi
        log "Added ipv6.disable=1 to GRUB_CMDLINE_LINUX_DEFAULT"
    fi

    # Modify GRUB_CMDLINE_LINUX if needed
    if [ $linux_disabled -eq 0 ]; then
        local linux_value=$(grep '^GRUB_CMDLINE_LINUX=' /etc/default/grub | cut -d'"' -f2)
        if [ -n "$linux_value" ]; then
            # Value exists, add with space
            sed -i "s/^GRUB_CMDLINE_LINUX=\".*\"/GRUB_CMDLINE_LINUX=\"${linux_value} ipv6.disable=1\"/" /etc/default/grub
        else
            # No value, add without space
            sed -i 's/^GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ipv6.disable=1"/' /etc/default/grub
        fi
        log "Added ipv6.disable=1 to GRUB_CMDLINE_LINUX"
    fi

    # Update GRUB
    if command -v update-grub >/dev/null 2>&1; then
        log "Updating GRUB configuration..."
        update-grub
    else
        log "update-grub not found. Trying grub2-mkconfig..."
        if command -v grub2-mkconfig >/dev/null 2>&1; then
            grub2-mkconfig -o /boot/grub2/grub.cfg
        else
            warn "Could not update GRUB configuration. Manual update required."
            return 1
        fi
    fi

    log "GRUB configuration updated. A reboot is required to complete IPv6 disabling."
    return 0
}

main() {
    log "Starting IPv6 disabling script"
    
    # Detect environment
    detect_environment
    
    if [ "$is_container" = true ]; then
        warn "Script is running in a container. GRUB modifications will be skipped."
        log "Note: For containers, IPv6 should typically be managed at the host level."
    else
        disable_ipv6_grub
    fi
    
    log "IPv6 disable configuration complete. System requires a reboot to apply changes."
    echo "Would you like to reboot now? (y/n)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        log "Rebooting system now..."
        reboot
    else
        log "Please remember to reboot your system to apply the changes."
    fi
}

main "$@"
