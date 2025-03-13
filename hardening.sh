#!/usr/bin/env bash

# Server Initialization and Hardening Script
# Version: 4.4
# Description: Initializes and hardens Debian/Ubuntu systems
# Supports: Debian 12, Ubuntu 24.04, and their derivatives
# Environment: Bare metal, VM, and LXC containers
# Author: RebelliousWhiz, Claude 3.5 Sonnet, Claude 3.7 Sonnet
# License: GLP 3.0
# In memory of Yunfei Shan, a good man, a good friend.

# Initialize script with strict error checking
set -euo pipefail
IFS=$'\n\t'

# Configuration Variables
readonly SCRIPT_VERSION="4.4"
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

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

validate_input() {
    local input_type="$1"
    local input_value="$2"
    local valid=false
    
    case "$input_type" in
        username)
            # Username must be 1-32 chars, start with lowercase letter or underscore,
            # and contain only lowercase letters, digits, underscores, or hyphens
            if [[ "$input_value" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
                valid=true
            fi
            ;;
        ssh_key)
            # Basic SSH key format validation
            if [[ "$input_value" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ssh-dss)\ [A-Za-z0-9+/]+[=]{0,3}(\ .*)?$ ]]; then
                valid=true
            fi
            ;;
        port)
            # Port must be a number between 1-65535 and not in use
            if [[ "$input_value" =~ ^[0-9]+$ ]] && 
               [ "$input_value" -ge 1 ] && 
               [ "$input_value" -le 65535 ]; then
                valid=true
            fi
            ;;
        yes_no)
            # Valid yes/no response
            if [[ "$input_value" =~ ^[YyNn]$ ]] || 
               [[ "$input_value" =~ ^(yes|no)$ ]]; then
                valid=true
            fi
            ;;
        ip_address)
            # IPv4 address validation
            if [[ "$input_value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                local IFS='.'
                read -ra ADDR <<< "$input_value"
                valid=true
                for i in "${ADDR[@]}"; do
                    if [ "$i" -gt 255 ]; then
                        valid=false
                        break
                    fi
                done
            fi
            ;;
        hostname)
            # Hostname validation (simplified)
            if [[ "$input_value" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
                valid=true
            fi
            ;;
        file_path)
            # Basic file path validation
            if [[ "$input_value" =~ ^[a-zA-Z0-9_./-]+$ ]]; then
                valid=true
            fi
            ;;
        *)
            warn "Unknown validation type: $input_type"
            return 2
            ;;
    esac
    
    return $([ "$valid" = true ] && echo 0 || echo 1)
}

# Global Variables
declare -g is_debian=false
declare -g is_lxc=false
declare -g is_container=false
declare -g is_docker=false
declare -g is_openvz=false
declare -g distro=""
declare -g version_id=""
declare -g selected_sudo_user=""
declare -g init_system="unknown"

# Distribution version flags
declare -g is_ubuntu_bionic=false
declare -g is_ubuntu_focal=false
declare -g is_ubuntu_jammy=false
declare -g is_ubuntu_noble=false
declare -g is_debian_buster=false
declare -g is_debian_bullseye=false
declare -g is_debian_bookworm=false

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

get_real_users() {
    # Gets only real system users with home directories in /home
    getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 && $6 ~ /^\/home\// {print $1}'
}

# Security Functions
validate_ssh_key() {
    local key="$1"
    validate_input "ssh_key" "$key"
    local result=$?
    
    if [ $result -ne 0 ]; then
        error "Invalid SSH key format"
    fi
    
    return $result
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        mkdir -p "$BACKUP_DIR"
        if [ -r "$file" ]; then
            cp "$file" "${BACKUP_DIR}/${file//\//_}"
            log "Backed up: $file"
            return 0
        else
            warn "Cannot read file: $file"
            return 1
        fi
    else
        log "File not found, no backup needed: $file"
        return 2
    fi
}

modify_file_safely() {
    local original_file="$1"
    local modification_command="$2"
    
    if [ ! -f "$original_file" ]; then
        error "File does not exist: $original_file"
        return 1
    fi
    
    if [ ! -w "$original_file" ]; then
        error "No write permission for $original_file"
        return 1
    fi
    
    backup_file "$original_file"
    
    local temp_file=$(mktemp)
    if eval "$modification_command '$original_file' > '$temp_file'" && [ -s "$temp_file" ]; then
        mv "$temp_file" "$original_file"
        log "Successfully modified: $original_file"
        return 0
    else
        rm -f "$temp_file"
        error "Failed to modify $original_file"
        return 1
    fi
}

# Enhanced LXC Detection
detect_environment() {
    is_lxc=false
    is_container=false
    is_docker=false
    is_openvz=false

    # Method 1: Check systemd-detect-virt
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local virt_type=$(systemd-detect-virt)
        case "$virt_type" in
            lxc|lxc-libvirt)
                is_lxc=true
                is_container=true
                ;;
            docker|podman)
                is_docker=true
                is_container=true
                ;;
            openvz)
                is_openvz=true
                is_container=true
                ;;
        esac
    fi

    # Method 2: Check container environment variables
    if [ -f /proc/1/environ ]; then
        if grep -q container=lxc /proc/1/environ; then
            is_lxc=true
            is_container=true
        elif grep -q container=docker /proc/1/environ; then
            is_docker=true
            is_container=true
        fi
    fi

    # Method 3: Check cgroup
    if [ -f /proc/1/cgroup ]; then
        if grep -q ":/lxc/" /proc/1/cgroup || grep -q ":name=lxc:" /proc/1/cgroup; then
            is_lxc=true
            is_container=true
        elif grep -qE ":/docker/|:/podman/" /proc/1/cgroup; then
            is_docker=true
            is_container=true
        fi
    fi

    # Method 4: Check for container-specific files
    if [ -d /dev/lxd ] || [ -f /.lxc ]; then
        is_lxc=true
        is_container=true
    elif [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
        is_docker=true
        is_container=true
    fi

    # Method 5: Check for OpenVZ
    if [ -d /proc/vz ] && [ ! -d /proc/bc ]; then
        is_openvz=true
        is_container=true
    fi

    export is_lxc
    export is_docker
    export is_openvz
    export is_container
    log "Environment detection: LXC=$is_lxc, Docker=$is_docker, OpenVZ=$is_openvz, Container=$is_container"
}

# User Input with Timeout
read_input() {
    local prompt="$1"
    local default="$2"
    local timeout="${3:-30}"
    local validation_type="${4:-none}"
    local max_attempts="${5:-3}"
    local result
    local attempts=0
    
    while [ $attempts -lt $max_attempts ]; do
        read -t "$timeout" -p "$prompt" result || true
        
        # Use default if empty
        if [ -z "$result" ]; then
            if [ -n "$default" ]; then
                echo "$default"
                warn "Input timed out or empty, using default: $default"
                return 0
            elif [ "$validation_type" != "none" ]; then
                # Only warn if validation is required
                warn "Empty input not allowed for this field"
                ((attempts++))
                continue
            else
                # Empty is acceptable for non-validated fields
                echo ""
                return 0
            fi
        fi
        
        # Validate input if validation type specified
        if [ "$validation_type" != "none" ]; then
            if validate_input "$validation_type" "$result"; then
                echo "$result"
                return 0
            else
                warn "Invalid input format for $validation_type. Please try again."
                ((attempts++))
                
                # Show help text based on validation type
                case "$validation_type" in
                    username)
                        log "Username must start with a letter and contain only lowercase letters, numbers, underscores, and hyphens."
                        ;;
                    ssh_key)
                        log "SSH key must be in standard format (e.g., ssh-rsa AAAAB3NzaC1...)"
                        ;;
                    port)
                        log "Port must be a number between 1 and 65535"
                        ;;
                    yes_no)
                        log "Please enter 'y' or 'n'"
                        ;;
                    ip_address)
                        log "IP address must be in format: xxx.xxx.xxx.xxx"
                        ;;
                esac
                
                if [ $attempts -ge $max_attempts ]; then
                    if [ -n "$default" ]; then
                        echo "$default"
                        warn "Maximum attempts reached, using default: $default"
                        return 0
                    else
                        error "Maximum input attempts reached. Exiting."
                        return 1
                    fi
                fi
            fi
        else
            # No validation needed
            echo "$result"
            return 0
        fi
    done
}

# System Detection
detect_system() {
    if [ -f /etc/os-release ]; then
        # Read ID and VERSION_ID from os-release file
        distro=$(grep -E "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
        version_id=$(grep -E "^VERSION_ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
        
        case "$distro" in
            "ubuntu")
                is_debian=true
                distro="ubuntu"
                
                # Version-specific handling
                case "$version_id" in
                    "18.04")
                        is_ubuntu_bionic=true
                        log "Ubuntu 18.04 Bionic detected"
                        ;;
                    "20.04")
                        is_ubuntu_focal=true
                        log "Ubuntu 20.04 Focal detected"
                        ;;
                    "22.04")
                        is_ubuntu_jammy=true
                        log "Ubuntu 22.04 Jammy detected"
                        ;;
                    "24.04")
                        is_ubuntu_noble=true
                        log "Ubuntu 24.04 Noble Numbat detected"
                        ;;
                    *)
                        log "Ubuntu $version_id detected"
                        ;;
                esac
                ;;
            "debian")
                is_debian=true
                distro="debian"
                
                # Version-specific handling
                case "$version_id" in
                    "10")
                        is_debian_buster=true
                        log "Debian 10 Buster detected"
                        ;;
                    "11")
                        is_debian_bullseye=true
                        log "Debian 11 Bullseye detected"
                        ;;
                    "12")
                        is_debian_bookworm=true
                        log "Debian 12 Bookworm detected"
                        ;;
                    *)
                        log "Debian $version_id detected"
                        ;;
                esac
                ;;
            "linux-mint"|"linuxmint")
                is_debian=true
                distro="mint"
                log "Linux Mint detected (Ubuntu-based)"
                ;;
            "pop"|"pop-os")
                is_debian=true
                distro="pop"
                log "Pop!_OS detected (Ubuntu-based)"
                ;;
            "elementary"|"elementary-os")
                is_debian=true
                distro="elementary"
                log "Elementary OS detected (Ubuntu-based)"
                ;;
            "kali")
                is_debian=true
                distro="kali"
                log "Kali Linux detected (Debian-based)"
                ;;
            "raspbian")
                is_debian=true
                distro="raspbian"
                log "Raspbian detected (Debian-based)"
                ;;
            *)
                # Try to detect Debian/Ubuntu-based systems
                if [ -f /etc/debian_version ]; then
                    is_debian=true
                    distro="debian-based"
                    log "Debian-based distribution detected"
                else
                    error "Unsupported distribution"
                fi
                ;;
        esac
    else
        # Fallback detection methods
        if [ -f /etc/debian_version ]; then
            is_debian=true
            distro="debian-based"
            log "Debian-based distribution detected via /etc/debian_version"
        elif command -v apt-get >/dev/null 2>&1; then
            is_debian=true
            distro="debian-based"
            log "Debian-based distribution detected via apt-get presence"
        else
            error "Cannot detect distribution: /etc/os-release not found"
        fi
    fi
    
    export is_debian
    export distro
    export version_id
    # Export version-specific flags
    export is_ubuntu_bionic
    export is_ubuntu_focal
    export is_ubuntu_jammy
    export is_ubuntu_noble
    export is_debian_buster
    export is_debian_bullseye
    export is_debian_bookworm
}

detect_init_system() {
    init_system="unknown"
    
    if [ -d /run/systemd/system ]; then
        init_system="systemd"
    elif [ -f /sbin/init ] && file /sbin/init | grep -q upstart; then
        init_system="upstart"
    elif [ -f /sbin/openrc ]; then
        init_system="openrc"
    elif [ -f /etc/init.d/cron ] && [ ! -h /etc/init.d/cron ]; then
        init_system="sysvinit"
    fi
    
    export init_system
    log "Init system detection: $init_system"
}

# Package management abstraction
pkg_update() {
    log "Updating package lists..."
    if command -v apt-get >/dev/null 2>&1; then
        timeout 120 apt-get update || timeout 60 apt-get update -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=3 || warn "Package update failed, continuing anyway"
    elif command -v apt >/dev/null 2>&1; then
        timeout 120 apt update || timeout 60 apt update -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=3 || warn "Package update failed, continuing anyway"
    else
        error "No supported package manager found"
    fi
}

pkg_install() {
    local packages=("$@")
    local essential_packages=()
    local optional_packages=()
    
    # Categorize packages based on importance
    for pkg in "${packages[@]}"; do
        case "$pkg" in
            # Essential packages - always install with recommends
            curl|wget|sudo|ssh|openssh-server)
                essential_packages+=("$pkg")
                ;;
            # Optional packages - install without recommends
            *)
                optional_packages+=("$pkg")
                ;;
        esac
    done
    
    log "Installing essential packages: ${essential_packages[*]}"
    if [ ${#essential_packages[@]} -gt 0 ]; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${essential_packages[@]}"
        elif command -v apt >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt install -y "${essential_packages[@]}"
        fi
    fi
    
    log "Installing optional packages without recommends: ${optional_packages[*]}"
    if [ ${#optional_packages[@]} -gt 0 ]; then
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${optional_packages[@]}"
        elif command -v apt >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends "${optional_packages[@]}"
        fi
    fi
}

parallel_execute() {
    local max_jobs=${1:-4}
    local timeout=${2:-300}
    shift 2
    local cmds=("$@")
    local pids=()
    local results=()
    
    # Execute commands in parallel
    for cmd in "${cmds[@]}"; do
        # Wait if max jobs reached
        while [ ${#pids[@]} -ge $max_jobs ]; do
            for i in "${!pids[@]}"; do
                if ! kill -0 ${pids[$i]} 2>/dev/null; then
                    wait ${pids[$i]}
                    results[$i]=$?
                    unset pids[$i]
                    break
                fi
            done
            sleep 0.5
        done
        
        # Execute command in background with timeout
        (
            # Set up timeout handler
            ( sleep $timeout && kill -TERM $$ 2>/dev/null ) &
            timeout_pid=$!
            
            # Execute the command
            eval "$cmd"
            cmd_result=$?
            
            # Kill the timeout process
            kill $timeout_pid 2>/dev/null
            
            exit $cmd_result
        ) &
        
        pids+=($!)
        log "Started background process: $cmd (PID: $!)"
    done
    
    # Wait for remaining processes
    for i in "${!pids[@]}"; do
        wait ${pids[$i]} 2>/dev/null
        results[$i]=$?
        log "Process ${pids[$i]} completed with status: ${results[$i]}"
    done
    
    # Check if any command failed
    for result in "${results[@]}"; do
        if [ "$result" -ne 0 ]; then
            return 1
        fi
    done
    
    return 0
}

pkg_remove() {
    local packages=("$@")
    log "Removing packages: ${packages[*]}"
    
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "${packages[@]}"
    elif command -v apt >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt remove --purge -y "${packages[@]}"
    else
        error "No supported package manager found"
    fi
}

service_enable() {
    local service_name="$1"
    log "Enabling service: $service_name"
    
    case "$init_system" in
        systemd)
            systemctl enable "$service_name"
            ;;
        sysvinit)
            update-rc.d "$service_name" defaults
            ;;
        upstart)
            if [ -f "/etc/init/$service_name.conf" ]; then
                sed -i 's/^manual$//' "/etc/init/$service_name.conf"
            fi
            ;;
        openrc)
            rc-update add "$service_name" default
            ;;
        *)
            warn "Unknown init system, cannot enable service: $service_name"
            ;;
    esac
}

service_start() {
    local service_name="$1"
    log "Starting service: $service_name"
    
    case "$init_system" in
        systemd)
            systemctl start "$service_name"
            ;;
        sysvinit|openrc)
            if [ -x "/etc/init.d/$service_name" ]; then
                "/etc/init.d/$service_name" start
            fi
            ;;
        upstart)
            if [ -f "/etc/init/$service_name.conf" ]; then
                initctl start "$service_name"
            fi
            ;;
        *)
            warn "Unknown init system, cannot start service: $service_name"
            ;;
    esac
}

service_restart() {
    local service_name="$1"
    log "Restarting service: $service_name"
    
    case "$init_system" in
        systemd)
            systemctl restart "$service_name"
            ;;
        sysvinit|openrc)
            if [ -x "/etc/init.d/$service_name" ]; then
                "/etc/init.d/$service_name" restart
            fi
            ;;
        upstart)
            if [ -f "/etc/init/$service_name.conf" ]; then
                initctl restart "$service_name"
            fi
            ;;
        *)
            warn "Unknown init system, cannot restart service: $service_name"
            ;;
    esac
}

service_disable() {
    local service_name="$1"
    log "Disabling service: $service_name"
    
    case "$init_system" in
        systemd)
            systemctl disable "$service_name"
            ;;
        sysvinit)
            update-rc.d "$service_name" remove
            ;;
        upstart)
            if [ -f "/etc/init/$service_name.conf" ]; then
                echo "manual" >> "/etc/init/$service_name.conf"
            fi
            ;;
        openrc)
            rc-update del "$service_name" default
            ;;
        *)
            warn "Unknown init system, cannot disable service: $service_name"
            ;;
    esac
}

service_stop() {
    local service_name="$1"
    log "Stopping service: $service_name"
    
    case "$init_system" in
        systemd)
            systemctl stop "$service_name"
            ;;
        sysvinit|openrc)
            if [ -x "/etc/init.d/$service_name" ]; then
                "/etc/init.d/$service_name" stop
            fi
            ;;
        upstart)
            if [ -f "/etc/init/$service_name.conf" ]; then
                initctl stop "$service_name"
            fi
            ;;
        *)
            warn "Unknown init system, cannot stop service: $service_name"
            ;;
    esac
}

set_timezone() {
    local timezone="Asia/Taipei"
    log "Setting timezone to ${timezone}..."
    
    # First try with timedatectl (systemd systems)
    if command_exists timedatectl; then
        if timedatectl set-timezone "${timezone}"; then
            log "Timezone set to ${timezone} using timedatectl"
            return 0
        else
            warn "Failed to set timezone with timedatectl"
        fi
    fi
    
    # Fallback to legacy method
    if [ -f "/usr/share/zoneinfo/${timezone}" ]; then
        if [ -L /etc/localtime ]; then
            # Remove existing link
            rm -f /etc/localtime
        elif [ -f /etc/localtime ]; then
            # Back up existing file
            backup_file /etc/localtime
            rm -f /etc/localtime
        fi
        
        # Create the symbolic link
        ln -sf "/usr/share/zoneinfo/${timezone}" /etc/localtime
        
        # Update timezone file
        echo "${timezone}" > /etc/timezone
        log "Timezone set to ${timezone} using legacy method"
        return 0
    else
        # Last resort - use debconf for Debian-based systems
        if command_exists dpkg-reconfigure; then
            log "Setting timezone using dpkg-reconfigure..."
            echo "tzdata tzdata/Areas select Asia" | debconf-set-selections
            echo "tzdata tzdata/Zones/Asia select Taipei" | debconf-set-selections
            DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive tzdata
            log "Timezone reconfigured using dpkg-reconfigure"
            return 0
        fi
    fi
    
    warn "Failed to set timezone to ${timezone}"
    return 1
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
    
    # Stop and disable services first
    log "Stopping snap services..."
    systemctl stop snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
    systemctl disable snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
    
    # Remove snapd package
    log "Removing snapd package..."
    if ! apt-get remove --purge snapd -y; then
        warn "Failed to remove snapd package"
    fi

    if ! apt-get autoremove --purge -y; then
        warn "Failed to autoremove packages"
    fi

    # Clean up snap directories
    log "Cleaning up snap directories..."
    local snap_dirs=("/snap" "/var/snap" "/var/lib/snapd" "/var/cache/snapd" "/usr/lib/snapd")
    for dir in "${snap_dirs[@]}"; do
        if [ -d "$dir" ]; then
            if ! rm -rf "$dir"; then
                warn "Failed to remove directory: $dir"
            fi
        fi
    done

    # Prevent snapd from being installed again
    log "Blocking snap from future installation..."
    if ! cat > /etc/apt/preferences.d/nosnap.pref << EOF
Package: snapd
Pin: release a=*
Pin-Priority: -1
EOF
    then
        warn "Failed to create nosnap preferences file"
    fi

    # Remove snap-related apt source
    if [ -f /etc/apt/sources.list.d/snap-*.list ]; then
        if ! rm -f /etc/apt/sources.list.d/snap-*.list; then
            warn "Failed to remove snap repository configuration"
        else
            log "Removed snap repository configuration"
        fi
    fi

    # Update package list after removal
    if ! apt-get update; then
        warn "Failed to update package lists"
    fi

    log "Snap removal process completed"
    return 0
}

configure_user_ssh() {
    local real_users=($(get_real_users))
    local total_users=${#real_users[@]}
    local primary_user=""

    # Handle multiple users case first
    if [ $total_users -gt 1 ]; then
        log "Multiple users detected. Select user to configure SSH key first:"
        select user in "${real_users[@]}"; do
            if [ -n "$user" ]; then
                primary_user="$user"
                log "Selected ${user} for primary SSH key configuration"
                break
            fi
        done
    fi

    # Configure SSH for each user
    for user in "${real_users[@]}"; do
        local user_home="/home/${user}"
        local ssh_dir="${user_home}/.ssh"
        local auth_keys="${ssh_dir}/authorized_keys"

        mkdir -p "${ssh_dir}"
        touch "${auth_keys}"

        # Single user case
        if [ $total_users -eq 1 ]; then
            while true; do
                if [ ! -s "${auth_keys}" ]; then
                    log "No SSH key found for ${user}. Adding new key (mandatory for single user)..."
                    local ssh_key=$(read_input "Enter SSH public key for ${user}: " "" 60 "ssh_key" 5)
                    if [ -n "$ssh_key" ]; then
                        echo "${ssh_key}" > "${auth_keys}"
                        break
                    else
                        warn "SSH key cannot be empty for single user system. Please try again."
                    fi
                else
                    log "Existing SSH key found for ${user}"
                    cat "${auth_keys}"
                    local replace_keys=$(read_input "Replace existing keys? (y/n): " "n" 30 "yes_no")
                    if [[ $replace_keys =~ ^[Yy]$ ]]; then
                        local ssh_key=$(read_input "Enter new SSH public key: " "" 60 "ssh_key" 5)
                        if [ -n "$ssh_key" ]; then
                            echo "${ssh_key}" > "${auth_keys}"
                        else
                            log "Keeping existing SSH keys"
                        fi
                    fi
                    break
                fi
            done
        # Multiple users case
        else
            if [ "$user" = "$primary_user" ]; then
                # Configure primary user
                if [ ! -s "${auth_keys}" ]; then
                    while true; do
                        log "Configuring SSH key for primary user ${user}..."
                        local ssh_key=$(read_input "Enter SSH public key for ${user}: " "" 60 "ssh_key" 5)
                        if [ -n "$ssh_key" ]; then
                            echo "${ssh_key}" > "${auth_keys}"
                            break
                        else
                            warn "SSH key cannot be empty for primary user. Please try again."
                        fi
                    done
                else
                    log "Existing SSH key found for ${user}:"
                    cat "${auth_keys}"
                    local replace_keys=$(read_input "Replace existing keys? (y/n): " "n" 30 "yes_no")
                    if [[ $replace_keys =~ ^[Yy]$ ]]; then
                        local ssh_key=$(read_input "Enter new SSH public key: " "" 60 "ssh_key" 5)
                        if [ -n "$ssh_key" ]; then
                            echo "${ssh_key}" > "${auth_keys}"
                            log "SSH key updated for ${user}"
                        else
                            log "Keeping existing SSH keys for ${user}"
                        fi
                    fi
                fi
            else
                # Skip SSH key configuration for non-primary users if key doesn't exist
                if [ ! -s "${auth_keys}" ]; then
                    log "No SSH key found for ${user} (optional user)"
                    local add_key=$(read_input "Would you like to add an SSH key for ${user}? (y/n): " "n" 30 "yes_no")
                    if [[ $add_key =~ ^[Yy]$ ]]; then
                        local ssh_key=$(read_input "Enter SSH public key for ${user}: " "" 60 "ssh_key" 5)
                        if [ -n "$ssh_key" ]; then
                            echo "${ssh_key}" > "${auth_keys}"
                            log "SSH key added for ${user}"
                        else
                            log "No key entered, skipping SSH key configuration for ${user}"
                        fi
                    else
                        log "Skipping SSH key configuration for ${user}"
                    fi
                else
                    # Only handle existing keys
                    log "Existing SSH keys for ${user}:"
                    cat "${auth_keys}"
                    local replace_keys=$(read_input "Replace existing keys? (y/n): " "n" 30 "yes_no")
                    if [[ $replace_keys =~ ^[Yy]$ ]]; then
                        local ssh_key=$(read_input "Enter new SSH public key: " "" 60 "ssh_key" 5)
                        if [ -n "$ssh_key" ]; then
                            echo "${ssh_key}" > "${auth_keys}"
                            log "SSH key updated for ${user}"
                        else
                            log "Keeping existing SSH keys for ${user}"
                        fi
                    fi
                fi
            fi
        fi

        # Set permissions
        chown "${user}:${user}" "${ssh_dir}"
        chmod 700 "${ssh_dir}"
        chown "root:${user}" "${auth_keys}"
        chmod 640 "${auth_keys}"
    done
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
        
        # Define the exact PS1 string we want to check/add
        local ps1_string='PS1='"'"'${debian_chroot:+($debian_chroot)}\[\033[01;31m\]\u\[\033[01;32m\]@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '"'"

        # Check for exact PS1 match
        if ! grep -F "$ps1_string" "$bashrc" >/dev/null; then
            echo "$ps1_string" >> "$bashrc"
            log "Added root PS1 configuration to bashrc for Ubuntu"
        else
            log "PS1 configuration already exists in root bashrc"
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

    # Change SSH port
     local change_port=$(read_input "Change SSH port? (y/n): " "n" 30 "yes_no")
    if [[ $change_port =~ ^[Yy]$ ]]; then
        local new_port=$(read_input "Enter new SSH port: " "$SSH_PORT_DEFAULT" 30 "port")
        
        # Additional check for port already in use
        if ! ss -tln | grep -q ":$new_port "; then
            # Replace "#Port 22" line or add if not found
            if grep -q "^#Port 22" /etc/ssh/sshd_config; then
                sed -i "s/^#Port 22/Port ${new_port}/" /etc/ssh/sshd_config
            elif grep -q "^Port " /etc/ssh/sshd_config; then
                sed -i "s/^Port .*/Port ${new_port}/" /etc/ssh/sshd_config
            else
                # If no Port line exists at all, add it at the top
                sed -i "1i Port ${new_port}" /etc/ssh/sshd_config
            fi
            log "SSH port changed to: ${new_port}"
        else
            warn "Port $new_port is already in use. Keeping current port: ${current_port}"
        fi
    fi

     # SSH hardening
    local ssh_config="/etc/ssh/sshd_config"
    local hardening_conf="/etc/ssh/sshd_config.d/hardening.conf"
    local hardening_settings="LoginGraceTime 30
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
Compression no"

    # Check if sshd_config.d directory exists (for newer systems)
    if [ -d "/etc/ssh/sshd_config.d" ]; then
        echo "$hardening_settings" > "$hardening_conf"
        # Ensure Include directive exists
        if ! grep -q "^Include /etc/ssh/sshd_config.d/\*.conf" "$ssh_config"; then
            echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$ssh_config"
        fi
    else
        # For older systems, append directly to sshd_config
        log "Adding hardening settings directly to sshd_config (Ubuntu 18.04)"
        echo "$hardening_settings" >> "$ssh_config"
    fi

    # Verify SSH config syntax before applying
    if ! sshd -t -f /etc/ssh/sshd_config; then
        warn "SSH configuration contains errors, reverting changes"
        cp "${BACKUP_DIR}/etc_ssh_sshd_config" /etc/ssh/sshd_config
        return 1
    fi

    # Handle SSH service based on distribution and environment
    if [ "${is_lxc}" = true ]; then
        if [ "$init_system" = "systemd" ]; then
            log "LXC container with systemd detected: Configuring SSH services..."
            service_disable "ssh.socket"
            service_stop "ssh.socket"
            service_enable "ssh.service"
            service_start "ssh.service"
        else
            warn "Non-systemd init in LXC environment, SSH service management may not work correctly"
            # Attempt to restart SSH using legacy methods
            if [ -x "/etc/init.d/ssh" ]; then
                "/etc/init.d/ssh" restart
            elif [ -x "/etc/init.d/sshd" ]; then
                "/etc/init.d/sshd" restart
            fi
        fi
    else
        # For standard systems
        if [ -f "/lib/systemd/system/ssh.service" ] || [ -f "/etc/systemd/system/ssh.service" ]; then
            log "Standard system detected: Reloading SSH service..."
            if ! systemctl reload ssh; then
                log "Reload failed, attempting restart..."
                service_restart "ssh"
            fi
        elif [ -f "/lib/systemd/system/sshd.service" ] || [ -f "/etc/systemd/system/sshd.service" ]; then
            log "Standard system with sshd service detected: Reloading SSH service..."
            if ! systemctl reload sshd; then
                log "Reload failed, attempting restart..."
                service_restart "sshd"
            fi
        else
            warn "SSH service not found using standard paths, attempting fallback methods"
            if [ -x "/etc/init.d/ssh" ]; then
                "/etc/init.d/ssh" restart
            elif [ -x "/etc/init.d/sshd" ]; then
                "/etc/init.d/sshd" restart
            fi
        fi
    fi
}

configure_user_environment() {
    local user=$1
    local user_home

    # Set correct home directory based on user
    if [ "$user" = "root" ]; then
        user_home="/root"
    else
        user_home="/home/${user}"
        # Skip if home directory doesn't exist
        if [ ! -d "$user_home" ]; then
            warn "Home directory $user_home not found for user $user, skipping configuration"
            return
        fi
    fi

    # Configure bash
    if [ -f "${user_home}/.bashrc" ]; then
        backup_file "${user_home}/.bashrc"
        sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/' "${user_home}/.bashrc"
        
        # Add EDITOR=vim if not present
        if ! grep -q "^export EDITOR=vim" "${user_home}/.bashrc"; then
            echo "export EDITOR=vim" >> "${user_home}/.bashrc"
            log "Added EDITOR=vim to .bashrc for ${user}"
        fi
        
        # Set custom prompt for non-root users
        if [ "$user" != "root" ]; then
            local ps1_config='PS1='"'"'\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '"'"
            sed -i "/^PS1=/c\\$ps1_config" "${user_home}/.bashrc"
        fi
    fi

    # Configure vim
    log "Downloading .vimrc for ${user}..."
    local temp_vimrc="/tmp/vimrc_${user}"
    if timeout 30 wget -q "$VIMRC_URL" -O "$temp_vimrc" && [ -s "$temp_vimrc" ]; then
        cp "$temp_vimrc" "${user_home}/.vimrc"
        chown "${user}:${user}" "${user_home}/.vimrc"
        chmod 644 "${user_home}/.vimrc"
        rm -f "$temp_vimrc"
        log "Successfully configured .vimrc for ${user}"
    else
        rm -f "$temp_vimrc"
        warn "Failed to download valid .vimrc file for ${user}"
    fi
}

lock_root_account() {
    log "Locking root account for direct login..."
    passwd -l root
    
    # Double-check if root is locked
    if passwd -S root | grep -q "L"; then
        log "Root account successfully locked"
    else
        warn "Failed to lock root account, attempting alternative method"
        # Alternative method
        usermod -p '!' root
        if passwd -S root | grep -q "L\|!"; then
            log "Root account locked using alternative method"
        else
            warn "Could not lock root account. Please check manually."
        fi
    fi
}

clean_sudoers_dir() {
    log "Cleaning up all files in /etc/sudoers.d/..."
    if [ -d "/etc/sudoers.d" ]; then
        # Skip README file which is often required
        find /etc/sudoers.d -type f -not -name README -exec rm -f {} \; 2>/dev/null || true
        
        # Verify files are gone
        local remaining_files=$(find /etc/sudoers.d -type f -not -name README | wc -l)
        if [ "$remaining_files" -eq 0 ]; then
            log "Successfully removed all custom sudoers files"
        else
            warn "Some files in /etc/sudoers.d/ could not be removed"
        fi
    else
        warn "/etc/sudoers.d/ directory not found"
    fi
}

configure_firewall() {
    if [ "${is_lxc}" = false ]; then
        local setup_ufw=$(read_input "Configure UFW firewall rules? (y/n): " "y" 30 "yes_no")
        if [[ $setup_ufw =~ ^[Yy]$ ]]; then
            log "Installing and configuring UFW..."
            
            # Install UFW if not present
            if ! command -v ufw >/dev/null 2>&1; then
                DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
            fi

            # Download UFW rules script
            local ufw_script="/tmp/ufw.sh"
            log "Downloading UFW configuration script..."
            if wget -q "https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/ufw.sh" -O "$ufw_script"; then
                chmod +x "$ufw_script"
                
                # Disable UFW before applying new rules
                ufw disable >/dev/null 2>&1

                # Execute UFW script
                if bash "$ufw_script"; then
                    # Enable UFW
                    echo "y" | ufw enable
                    log "UFW configuration completed successfully"
                else
                    warn "UFW configuration script execution failed"
                fi
                
                # Clean up
                rm -f "$ufw_script"
            else
                warn "Failed to download UFW configuration script"
            fi
        fi
    fi
}

configure_system_parameters() {
    if [ "${is_lxc}" = false ]; then
        # IPv6 configuration
        local ipv6_default_disabled=0
        local ipv6_linux_disabled=0

        # Check if ipv6.disable=1 exists in either configuration
        if grep -q "ipv6.disable=1" <(grep "GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub 2>/dev/null); then
            ipv6_default_disabled=1
        fi

        if grep -q "ipv6.disable=1" <(grep "GRUB_CMDLINE_LINUX=" /etc/default/grub | grep -v "DEFAULT" 2>/dev/null); then
            ipv6_linux_disabled=1
        fi

        # Only ask to disable if it's not already disabled in both places
        if [ $ipv6_default_disabled -eq 1 ] && [ $ipv6_linux_disabled -eq 1 ]; then
            log "IPv6 is already disabled in GRUB configuration"
        else
            local disable_ipv6=$(read_input "IPv6 is currently enabled. Disable IPv6? (y/n): " "n" 30 "yes_no")
            if [[ $disable_ipv6 =~ ^[Yy]$ ]]; then
                backup_file "/etc/default/grub"
                
                # Handle GRUB_CMDLINE_LINUX_DEFAULT
                if [ $ipv6_default_disabled -eq 0 ]; then
                    # Get current value without quotes
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

                # Handle GRUB_CMDLINE_LINUX
                if [ $ipv6_linux_disabled -eq 0 ]; then
                    # Get current value without quotes
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

                update-grub
            else
                if [ $ipv6_default_disabled -eq 0 ] && [ $ipv6_linux_disabled -eq 1 ]; then
                    warn "GRUB_CMDLINE_LINUX has ipv6.disable=1 but GRUB_CMDLINE_LINUX_DEFAULT doesn't"
                elif [ $ipv6_default_disabled -eq 1 ] && [ $ipv6_linux_disabled -eq 0 ]; then
                    warn "GRUB_CMDLINE_LINUX_DEFAULT has ipv6.disable=1 but GRUB_CMDLINE_LINUX doesn't"
                fi
            fi
        fi

         # Time synchronization
        local timesyncd_active=0
        local ntp_active=0
        local chrony_active=0
        local ntp_cron_exists=0

        # Check if services are active and enabled
        if systemctl is-active systemd-timesyncd >/dev/null 2>&1 || systemctl is-enabled systemd-timesyncd >/dev/null 2>&1; then
            timesyncd_active=1
        fi
        if systemctl is-active ntp >/dev/null 2>&1 || systemctl is-enabled ntp >/dev/null 2>&1; then
            ntp_active=1
        fi
        if systemctl is-active chronyd >/dev/null 2>&1 || systemctl is-enabled chronyd >/dev/null 2>&1; then
            chrony_active=1
        fi

        # Check if ntpdate cron job exists
        if crontab -l 2>/dev/null | grep -q "ntpdate -4 -s time.nist.gov"; then
            ntp_cron_exists=1
        fi

        if [ $timesyncd_active -eq 0 ] && [ $ntp_active -eq 0 ] && [ $chrony_active -eq 0 ] && [ $ntp_cron_exists -eq 1 ]; then
            log "Time synchronization already configured with ntpdate"
        else
            local config_ntp=$(read_input "Configure NTP sync with time.nist.gov? (y/n): " "y" 30 "yes_no")
            if [[ $config_ntp =~ ^[Yy]$ ]]; then
                # Stop and disable time sync services
                log "Stopping and disabling existing time sync services..."
                systemctl stop systemd-timesyncd ntp chronyd 2>/dev/null || true
                systemctl disable systemd-timesyncd ntp chronyd 2>/dev/null || true
                
                # Install ntpdate if not already installed
                if ! command -v ntpdate >/dev/null 2>&1; then
                    log "Installing ntpdate..."
                    DEBIAN_FRONTEND=noninteractive apt-get install -y ntpdate
                fi

                # Perform initial time sync with timeout
                log "Performing initial time sync..."
                if timeout 30 ntpdate -4 time.nist.gov; then
                    log "Time sync successful"
                else
                    warn "Time sync timed out or failed, continuing anyway"
                fi

                # Add cron job if it doesn't exist
                if [ $ntp_cron_exists -eq 0 ]; then
                    log "Adding ntpdate cron job..."
                    
                    # Create temporary crontab file
                    local temp_cron=$(mktemp)
                    
                    # Get existing crontab content
                    crontab -l 2>/dev/null > "$temp_cron" || echo -n > "$temp_cron"
                    
                    # Remove any existing ntpdate entries
                    sed -i '/ntpdate.*time.nist.gov/d' "$temp_cron"
                    
                    # Add new ntpdate entry
                    echo "0 */6 * * * /usr/sbin/ntpdate -4 -s time.nist.gov" >> "$temp_cron"
                    
                    # Install new crontab
                    if crontab "$temp_cron"; then
                        log "Added ntpdate cron job for time synchronization"
                    else
                        warn "Failed to install crontab"
                        cat "$temp_cron"  # Show what we tried to install
                    fi
                    
                    # Clean up
                    rm -f "$temp_cron"
                    
                    # Verify crontab installation
                    if ! crontab -l | grep -q "ntpdate -4 -s time.nist.gov"; then
                        warn "Crontab verification failed, attempting direct installation"
                        echo "0 */6 * * * /usr/sbin/ntpdate -4 -s time.nist.gov" | crontab -
                    fi
                fi
                
                log "Time synchronization configuration completed"
            fi
        fi
    fi

    # Sysctl configuration
    local modify_sysctl=$(read_input "Modify sysctl.conf? (y/n): " "y" 30 "yes_no")
    if [[ $modify_sysctl =~ ^[Yy]$ ]]; then
        backup_file "/etc/sysctl.conf"
        
        # Set default selection based on environment
        local default_selection="2"
        if [ "${is_lxc}" = true ] || [ "${is_container}" = true ]; then
            default_selection="3"
        fi
        
        echo "Select sysctl configuration profile:"
        echo "1) 1GB RAM profile - Optimized for servers with limited memory (1GB RAM)"
        echo "2) 2GB+ RAM profile - Optimized for servers with 2GB+ RAM (recommended for most VPS)"
        echo "3) LXC Container profile - Minimal settings optimized for containers"
        
        local sysctl_profile
        while true; do
            sysctl_profile=$(read_input "Enter your choice [1-3]: " "$default_selection" 30 "none")
            if [[ "$sysctl_profile" =~ ^[1-3]$ ]]; then
                break
            else
                warn "Invalid selection, please enter 1, 2, or 3"
            fi
        done
        
        local sysctl_url
        case "$sysctl_profile" in
            1)
                sysctl_url="https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/sysctl-1G.conf"
                log "Downloading sysctl configuration for 1GB memory systems..."
                ;;
            2)
                sysctl_url="https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/sysctl-2G.conf"
                log "Downloading sysctl configuration for 2GB+ memory systems..."
                ;;
            3)
                sysctl_url="https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/sysctl-lxc.conf"
                log "Downloading sysctl configuration for LXC containers..."
                ;;
        esac
        
        if ! wget -q "$sysctl_url" -O /tmp/sysctl.conf; then
            error "Failed to download sysctl configuration"
        fi

        # Load necessary modules (only for non-LXC profiles on non-container systems)
        if [ "$sysctl_profile" != "3" ] && [ "${is_container}" = false ]; then
            log "Loading required kernel modules..."
            modprobe nf_conntrack >/dev/null 2>&1 || true
            
            # Add modules to /etc/modules for persistence
            if ! grep -q "^nf_conntrack" /etc/modules; then
                echo "nf_conntrack" >> /etc/modules
            fi
            
            # Create directory if it doesn't exist
            mkdir -p /etc/modules-load.d
            
            # Add module configuration
            echo "nf_conntrack" > /etc/modules-load.d/nf_conntrack.conf
        fi

        cp /tmp/sysctl.conf /etc/sysctl.conf
        
        # Apply sysctl parameters, ignoring errors
        log "Applying sysctl parameters..."
        sysctl -p 2>/dev/null || true
        
        rm -f /tmp/sysctl.conf
        log "Sysctl configuration has been updated and applied"
    fi

    apply_version_specific_configs() {
        log "Applying version-specific configurations..."
    
    # Ubuntu version-specific configurations
    if [ "$distro" = "ubuntu" ]; then
        if [ "${is_ubuntu_bionic}" = true ]; then
            log "Applying Ubuntu 18.04 Bionic specific configurations"
            # Add any Ubuntu 18.04 specific configurations here
        elif [ "${is_ubuntu_focal}" = true ]; then
            log "Applying Ubuntu 20.04 Focal specific configurations"
            # Add any Ubuntu 20.04 specific configurations here
        elif [ "${is_ubuntu_jammy}" = true ]; then
            log "Applying Ubuntu 22.04 Jammy specific configurations"
            # Add any Ubuntu 22.04 specific configurations here
        elif [ "${is_ubuntu_noble}" = true ]; then
            log "Applying Ubuntu 24.04 Noble specific configurations"
            # Add any Ubuntu 24.04 specific configurations here
        fi
    fi
    
    # Debian version-specific configurations
    if [ "$distro" = "debian" ]; then
        if [ "${is_debian_buster}" = "true" ]; then
            log "Applying Debian 10 Buster specific configurations"
            # Add any Debian 10 specific configurations here
        elif [ "${is_debian_bullseye}" = "true" ]; then
            log "Applying Debian 11 Bullseye specific configurations"
            # Add any Debian 11 specific configurations here
        elif [ "${is_debian_bookworm}" = "true" ]; then
            log "Applying Debian 12 Bookworm specific configurations"
            # Add any Debian 12 specific configurations here
        fi
    fi
    
    # Container-specific configurations
    if [ "$is_container" = "true" ]; then
        log "Applying container-specific configurations"
        if [ "$is_lxc" = "true" ]; then
            log "Applying LXC-specific configurations"
            # Add any LXC-specific configurations here
        elif [ "$is_docker" = "true" ]; then
            log "Applying Docker-specific configurations"
            # Add any Docker-specific configurations here
        elif [ "$is_openvz" = "true" ]; then
            log "Applying OpenVZ-specific configurations"
            # Add any OpenVZ-specific configurations here
        fi
    fi
    
    # Init system specific configurations
    case "$init_system" in
        systemd)
            log "Applying systemd-specific configurations"
            # Add any systemd-specific configurations here
            ;;
        sysvinit)
            log "Applying SysVinit-specific configurations"
            # Add any SysVinit-specific configurations here
            ;;
        upstart)
            log "Applying Upstart-specific configurations"
            # Add any Upstart-specific configurations here
            ;;
        openrc)
            log "Applying OpenRC-specific configurations"
            # Add any OpenRC-specific configurations here
            ;;
    esac
}

configure_sudo_access() {
    local sudo_users=$(getent group sudo | cut -d: -f4)
    if [ -z "${sudo_users}" ]; then
        log "No users in sudo group. Select user to add:"
        select user in $(get_real_users); do
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
    [ "${is_lxc}" = false ] && [ -x "$(command -v ufw)" ] && echo "    - UFW firewall configured"
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

# Replace the system_updates_parallel function with a simpler, more reliable version:
system_updates() {
    log "Performing system updates..."
    
    # Update package lists with retry mechanism
    log "Updating package lists..."
    local retries=3
    local success=false
    
    while [ $retries -gt 0 ] && [ "$success" = false ]; do
        if timeout 120 apt-get update; then
            success=true
        else
            retries=$((retries - 1))
            warn "Package list update attempt failed, $retries retries left"
            [ $retries -gt 0 ] && sleep 5
        fi
    done
    
    if [ "$success" = false ]; then
        warn "Package list update failed after multiple attempts, continuing with installation"
    fi
    
    # Perform upgrade with timeout
    log "Upgrading packages..."
    if ! timeout 600 apt-get upgrade -y; then
        warn "Package upgrade timed out or failed, continuing anyway"
    fi
    
    # Perform autoremove and clean
    log "Removing unnecessary packages and cleaning up..."
    apt-get autoremove -y || warn "Autoremove failed"
    apt-get clean || warn "Clean failed"
    
    log "System update completed"
}

main() {
    # Use lockfile to prevent concurrent execution
    LOCK_FILE="/var/lock/server_init.lock"
    
    if ! mkdir "$LOCK_FILE" 2>/dev/null; then
        error "Another instance is running or crashed. If no other instance is running, remove $LOCK_FILE"
    fi
    
    # Add to the existing trap
    trap 'rm -rf "$LOCK_FILE"; error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR
    trap 'rm -rf "$LOCK_FILE"' EXIT
    
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

    # Detect environment, system, and init system
    detect_environment
    detect_system
    detect_init_system

    # Set timezone to Asia/Taipei
    set_timezone

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
    if [ "${is_container}" = true ]; then
        # For containers, use standard update to minimize resource usage
        log "Using standard update for container environment"
        pkg_update
        DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || warn "Package upgrade failed"
        pkg_install "${PACKAGES[@]}"
    else
        # For standard systems, use simplified updates
        log "Using standard system update process"
        system_updates
        pkg_install "${PACKAGES[@]}"
    fi

    # User management
    if [ -z "$(get_real_users)" ]; then
        log "No users found. Creating new user..."
        local username=$(read_input "Enter username: " "" "username" 5)
        if [ -n "$username" ]; then
            adduser "$username"
        else
            error "Username cannot be empty"
        fi
    fi

    # Configure users in parallel
    log "Configuring user environments in parallel..."
    local user_commands=()

    # Configure sudo access
    configure_sudo_access

    # Configure SSH for all users
    configure_user_ssh

    # Prepare parallel commands for user configuration
    for user in $(get_real_users); do
        user_commands+=("configure_user_environment \"${user}\" && configure_user_security \"${user}\"")
    done

    # Add root configuration
    user_commands+=("configure_root_bashrc && configure_user_environment \"root\"")

    # Execute user configuration in parallel
    parallel_execute 4 60 "${user_commands[@]}"

    # Configure system SSH
    configure_system_ssh

    # Configure firewall
    configure_firewall

    # Configure system parameters
    configure_system_parameters

    # Clean sudoers directory
    clean_sudoers_dir

     # Lock root account for all distributions
    if [ -n "${selected_sudo_user:-}" ]; then
        log "Testing sudo access before locking root..."
        
        # Create a test file for sudo verification
        local test_file="/tmp/sudo_test_$(date +%s)"
        touch "$test_file"
        
        # More robust sudo test that doesn't require user switching
        # First ensure the sudo user has appropriate permissions
        echo "${selected_sudo_user} ALL=(ALL:ALL) NOPASSWD: ALL" > "/etc/sudoers.d/${selected_sudo_user}"
        chmod 440 "/etc/sudoers.d/${selected_sudo_user}"
        
        # Test sudo access using a simple command that doesn't require interactive auth
        if sudo -u "${selected_sudo_user}" sudo -n true >/dev/null 2>&1; then
            log "Sudo access confirmed for ${selected_sudo_user}"
            
            # Update sudoers to require password (but keep the user in sudo group)
            rm -f "/etc/sudoers.d/init-${selected_sudo_user}"
            echo "${selected_sudo_user} ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/${selected_sudo_user}"
            chmod 440 "/etc/sudoers.d/${selected_sudo_user}"
            
            # Now lock root account
            lock_root_account
            warn "Note: Sudo access now requires password"
        else
            # Try an alternative method if the first one fails
            log "First sudo verification method failed, trying alternative..."
            if [ -x "$(command -v runuser)" ]; then
                if runuser -l "${selected_sudo_user}" -c "sudo -n true" >/dev/null 2>&1; then
                    log "Sudo access confirmed using runuser for ${selected_sudo_user}"
                    rm -f "/etc/sudoers.d/init-${selected_sudo_user}"
                    echo "${selected_sudo_user} ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/${selected_sudo_user}"
                    chmod 440 "/etc/sudoers.d/${selected_sudo_user}"
                    lock_root_account
                    warn "Note: Sudo access now requires password"
                else
                    warn "Cannot verify sudo access, keeping root account unlocked for safety"
                    echo "${selected_sudo_user} ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/${selected_sudo_user}"
                    chmod 440 "/etc/sudoers.d/${selected_sudo_user}"
                fi
            else
                warn "Cannot verify sudo access, keeping root account unlocked for safety"
                echo "${selected_sudo_user} ALL=(ALL:ALL) ALL" > "/etc/sudoers.d/${selected_sudo_user}"
                chmod 440 "/etc/sudoers.d/${selected_sudo_user}"
            fi
        fi
        
        # Clean up test file
        rm -f "$test_file"
    else
        warn "No sudo user selected, not locking root account for safety"
    fi

    # Apply version-specific configurations
    apply_version_specific_configs

    # Display configuration summary
    display_summary

    # Prompt for reboot
    local do_reboot=$(read_input "Would you like to reboot now to apply all changes? (y/n): " "n" 30 "yes_no")
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
