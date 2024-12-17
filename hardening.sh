#!/bin/bash

# Function to determine if the system is Debian or Ubuntu
detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
  else
    echo "Cannot detect OS version. Exiting."
    exit 1
  fi
}

# Ensure the script is run as root
if [[ "$EUID" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

echo "Starting system hardening..."

# Detect the operating system
detect_os

# 1. Uncomment the force_color_prompt for all users, including root
for user_home in /root /home/*; do
  if [[ -d "$user_home" ]]; then
    if grep -q "^#force_color_prompt=yes" "$user_home/.bashrc"; then
      sed -i "s/^#force_color_prompt=yes/force_color_prompt=yes/" "$user_home/.bashrc"
    fi
  fi
done

# 2. Change specific PS1 prompt in /root/.bashrc
sed -i '/^if \[ "\$color_prompt" = yes \]; then/,/^unset color_prompt force_color_prompt$/c\
if [ "$color_prompt" = yes ]; then\
    PS1='\''${debian_chroot:+($debian_chroot)}\\[\\033[01;31m\\]\\u\\[\\033[01;32m\\]@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '\''\
else\
    PS1='\''${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '\''\
fi\
unset color_prompt force_color_prompt' /root/.bashrc

# 3. Create .vimrc for all users and root
for user_home in /root /home/*; do
  if [[ -d "$user_home" ]]; then
    cat > "$user_home/.vimrc" <<'EOL'
if has("syntax")
  syntax on
endif

if filereadable("/etc/vim/vimrc.local")
  source /etc/vim/vimrc.local
endif

set nocompatible
set backspace=2
filetype on
filetype plugin on
set expandtab
set tabstop=2
set hlsearch
EOL
    chown $(basename $user_home):$(basename $user_home) "$user_home/.vimrc"
  fi
done

# 4. Modify user files
for user_home in /home/*; do
  if [[ -d "$user_home/.ssh" ]]; then
    chown root:root "$user_home/.ssh"
    chmod 755 "$user_home/.ssh"
  fi

  if [[ -e "$user_home/.ssh/authorized_keys" ]]; then
    chown root:root "$user_home/.ssh/authorized_keys"
    chmod 644 "$user_home/.ssh/authorized_keys"
  fi

  if [[ -e "$user_home/.bash_logout" ]]; then
    chown root:root "$user_home/.bash_logout"
    chmod 644 "$user_home/.bash_logout"
    echo -e "\n# Clear history\nhistory -c\nhistory -w" >> "$user_home/.bash_logout"
  fi
done

# 5. Check and potentially change the SSH port
current_port_line=$(grep -Ei "^[^#]*port [0-9]+" /etc/ssh/sshd_config)
current_port=${current_port_line##* }

if [[ -z "$current_port_line" || "$current_port_line" == "#Port 22" ]]; then
  # Default configuration or commented default port
  change_port="y"
else
  # Current active port configuration in use
  read -p "The current SSH port is $current_port. Do you want to change it? (y/n): " change_port
fi

if [[ "$change_port" =~ ^[Yy]$ ]]; then
  read -p "Please enter the desired SSH port: " ssh_port
  if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || [[ "$ssh_port" -lt 1 ]] || [[ "$ssh_port" -gt 65535 ]]; then
    echo "Invalid port number. Please enter a number between 1 and 65535."
    exit 1
  fi
  sed -i "s/^#\?Port .*/Port $ssh_port/" /etc/ssh/sshd_config
fi

# Update remaining SSH settings
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# 6. Restart SSH based on OS type
if [[ "$OS" == "debian" ]]; then
  systemctl restart sshd
elif [[ "$OS" == "ubuntu" ]]; then
  systemctl restart ssh
else
  echo "Unsupported OS for SSH restart. Please check the OS type."
fi

# 7. IPv6 Disable Option
read -p "Do you want to disable IPv6? (y/n): " disable_ipv6
if [[ "$disable_ipv6" =~ ^[Yy]$ ]]; then
    # Backup the original grub file
    cp /etc/default/grub /etc/default/grub.backup
    
    # Modify GRUB_CMDLINE_LINUX_DEFAULT
    if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub; then
        current_default=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub | cut -d'"' -f2)
        if [ -z "$current_default" ]; then
            # Empty value
            sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"/' /etc/default/grub
        else
            # Has existing value
            sed -i '/GRUB_CMDLINE_LINUX_DEFAULT=/ s/"$/ ipv6.disable=1"/' /etc/default/grub
        fi
    else
        echo 'GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"' >> /etc/default/grub
    fi
    
    # Modify GRUB_CMDLINE_LINUX
    if grep -q "^GRUB_CMDLINE_LINUX=" /etc/default/grub; then
        current_linux=$(grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub | cut -d'"' -f2)
        if [ -z "$current_linux" ]; then
            # Empty value
            sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ipv6.disable=1"/' /etc/default/grub
        else
            # Has existing value
            sed -i '/GRUB_CMDLINE_LINUX=/ s/"$/ ipv6.disable=1"/' /etc/default/grub
        fi
    else
        echo 'GRUB_CMDLINE_LINUX="ipv6.disable=1"' >> /etc/default/grub
    fi
    
    # Update grub
    if [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
        update-grub
    else
        echo "Unsupported OS for grub update. Please update grub manually."
    fi
    
    echo "IPv6 has been disabled. Please reboot your system for changes to take effect."
fi

# 8. Remove Snap and prevent its installation (Ubuntu only)
if [[ "$OS" == "ubuntu" ]]; then
    echo "Removing Snap and preventing its reinstallation..."
    
    # Remove all snap packages
    snap list 2>/dev/null | awk 'NR>1 {print $1}' | while read pkg; do
        snap remove --purge "$pkg" 2>/dev/null
    done
    
    # Remove snapd completely
    apt remove --purge snapd -y
    rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd /usr/lib/snapd
    
    # Prevent snapd from being installed again
    cat > /etc/apt/preferences.d/nosnap.pref <<EOL
Package: snapd
Pin: release a=*
Pin-Priority: -1
EOL
    
    echo "Snap has been removed and blocked from future installation."
fi

echo "System hardening completed."

# 9. UFW Configuration
read -p "Do you want to configure UFW firewall? (y/n): " configure_ufw
if [[ "$configure_ufw" =~ ^[Yy]$ ]]; then
    # Check if UFW is installed
    if ! command -v ufw >/dev/null 2>&1; then
        echo "UFW is not installed. Installing UFW..."
        apt update
        apt install -y ufw
    fi
    
    # Reset UFW to default settings
    echo "Resetting UFW to default settings..."
    ufw --force reset
    
    # Download and execute UFW configuration script
    echo "Downloading and executing UFW configuration script..."
    wget https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/ufw.sh
    if [[ -f "ufw.sh" ]]; then
        chmod +x ufw.sh
        bash ./ufw.sh
        rm -f ufw.sh
        
        # Enable UFW
        echo "Enabling UFW..."
        ufw --force enable
    else
        echo "Failed to download UFW configuration script."
    fi
fi

# 10. Time Synchronization
read -p "Do you want to sync time with time.nist.gov? (y/n): " sync_time
if [[ "$sync_time" =~ ^[Yy]$ ]]; then
    echo "Configuring time synchronization..."
    
    # Stop and disable existing time sync services
    systemctl stop systemd-timesyncd 2>/dev/null
    systemctl disable systemd-timesyncd 2>/dev/null
    systemctl stop ntp 2>/dev/null
    systemctl disable ntp 2>/dev/null
    systemctl stop chronyd 2>/dev/null
    systemctl disable chronyd 2>/dev/null
    
    # Remove chrony if installed (optional, but prevents conflicts)
    if dpkg -l | grep -q "chrony"; then
        apt remove --purge chrony -y
    fi
    
    # Check and install ntpdate and ntp if needed
    if ! command -v ntpdate >/dev/null 2>&1; then
        echo "Installing ntpdate and ntp..."
        apt update
        apt install -y ntpdate ntp
    fi
    
    # Perform initial time sync
    echo "Performing initial time sync..."
    ntpdate -4 time.nist.gov
    
    # Add cron job for periodic sync
    if ! grep -q "ntpdate -4 -s time.nist.gov" /etc/crontab; then
        echo "00 */6  * * *   root  ntpdate -4 -s time.nist.gov" >> /etc/crontab
        echo "Cron job added for periodic time sync every 6 hours"
    else
        echo "Time sync cron job already exists"
    fi
    
    echo "Time synchronization configured successfully"
fi

# Self-delete the script
rm -- "$0"

exit 0
