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

# Detect the operating system
detect_os

# Install the base packages
apt update && apt install -y curl rsyslog wget socat bash-completion wireguard vim

# Check if the system is Debian, and if so, install dnsmasq
if [[ "$OS" == "debian" ]]; then
  echo "Debian detected, installing dnsmasq..."
  apt update && apt install -y dnsmasq
fi

# Ensure sudo is installed
if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is not installed. Installing sudo..."
  apt update
  apt install -y sudo

  # Ask user which user account should be added to the sudo group
  echo "Available users with home directories:"
  select username in $(ls /home); do
    if [[ -n "$username" ]]; then
      usermod -aG sudo "$username"
      echo "User '$username' has been added to the sudo group."
    else
      echo "Invalid selection. Please try again."
    fi
    break
  done

  # If select did not return a valid username
  if [[ -z "$username" ]]; then
    echo "No valid user selected or no user exists in /home."
    exit 1
  fi
fi

echo "Starting system hardening..."

# 1. Handle 'force_color_prompt' for all users, including root
for user_home in /root /home/*; do
  if [[ -d "$user_home" ]]; then
    if grep -q "^#force_color_prompt=yes" "$user_home/.bashrc"; then
      sed -i "s/^#force_color_prompt=yes/force_color_prompt=yes/" "$user_home/.bashrc"
    else
      echo "force_color_prompt=yes" >> "$user_home/.bashrc"
    fi
  fi
done

# 2. Modify PS1 prompt in /root/.bashrc and add additional configurations for Debian
if [[ "$OS" == "ubuntu" ]]; then
  sed -i '/^if \[ "\$color_prompt" = yes \]; then/,/^unset color_prompt force_color_prompt$/c\
  if [ "$color_prompt" = yes ]; then\
    PS1='\''${debian_chroot:+($debian_chroot)}\\[\\033[01;31m\\]\\u\\[\\033[01;32m\\]@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '\''\
  else\
    PS1='\''${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '\''\
  fi\
  unset color_prompt force_color_prompt' /root/.bashrc
elif [[ "$OS" == "debian" ]]; then
  echo "PS1='${debian_chroot:+($debian_chroot)}\\[\\033[01;31m\\]\\u\\[\\033[01;32m\\]@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '" >> /root/.bashrc

  # Add additional lines for Debian
  cat >> /root/.bashrc << 'EOF'
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
    chown $(basename "$user_home"):$(basename "$user_home") "$user_home/.vimrc"
  fi
done

# 4. Modify user files
for user_home in /home/*; do
  if [[ -d "$user_home" ]]; then
    username=$(basename "$user_home")
    ssh_dir="$user_home/.ssh"

    if [[ ! -d "$ssh_dir" ]]; then
      read -r -p "The directory $ssh_dir does not exist. Do you want to create it? (y/n): " create_ssh_dir
      if [[ "$create_ssh_dir" =~ ^[Yy]$ ]]; then
        mkdir -p "$ssh_dir"
        chown $username:$username "$ssh_dir"
        chmod 700 "$ssh_dir"
        echo "$ssh_dir has been created with appropriate permissions."
      fi
    fi

    # Check and optionally create the authorized_keys file
    authorized_keys_file="$ssh_dir/authorized_keys"
    if [[ -d "$ssh_dir" ]]; then
      if [[ ! -e "$authorized_keys_file" ]]; then
        read -r -p "The file $authorized_keys_file does not exist. Do you want to create it? (y/n): " create_auth_keys
        if [[ "$create_auth_keys" =~ ^[Yy]$ ]]; then
          echo "Please enter the content for the authorized_keys file. Type 'END' on a new line to finish:"
          ssh_key_content=""
          while IFS= read -r line; do
            [[ $line == "END" ]] && break
            ssh_key_content+="$line"$'\n'
          done
          echo -n "$ssh_key_content" > "$authorized_keys_file"
          chown $username:$username "$authorized_keys_file"
          chmod 600 "$authorized_keys_file"
          echo "authorized_keys file has been created and populated for $username."
        fi
      fi
    fi

    # Subsequent processing of existing .ssh directories and files
    if [[ -d "$ssh_dir" ]]; then
      chown root:root "$ssh_dir"
      chmod 755 "$ssh_dir"
    fi

    if [[ -e "$authorized_keys_file" ]]; then
      chown root:root "$authorized_keys_file"
      chmod 644 "$authorized_keys_file"
    fi

    if [[ -e "$user_home/.bash_logout" ]]; then
      chown root:root "$user_home/.bash_logout"
      chmod 644 "$user_home/.bash_logout"
      if ! grep -q "history -c" "$user_home/.bash_logout"; then
        echo -e "\n# Clear history\nhistory -c\nhistory -w" >> "$user_home/.bash_logout"
      fi
    fi
  fi
done

# 5. Check and potentially change the SSH port
current_port_line=$(grep -Ei "^[ \t]*Port[ \t]+[0-9]+" /etc/ssh/sshd_config)
current_port=${current_port_line##* }

if [[ -z "$current_port_line" ]]; then
  echo "No SSH port configuration found. Default port is likely 22."
  change_port="y"
else
  echo "The current SSH port is $current_port."
  read -r -p "Do you want to change it? (y/n): " change_port
fi

if [[ "$change_port" =~ ^[Yy]$ ]]; then
  read -r -p "Please enter the desired SSH port: " ssh_port
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
if systemctl is-active ssh &>/dev/null || systemctl is-active sshd &>/dev/null; then
  if [[ "$OS" == "ubuntu" ]]; then
    systemctl restart ssh
  else
    systemctl restart sshd
  fi
else
  echo "SSH service not found. Please check your SSH installation."
fi

# 7. IPv6 Disable Option
read -r -p "Do you want to disable IPv6? (y/n): " disable_ipv6
if [[ "$disable_ipv6" =~ ^[Yy]$ ]]; then
  cp /etc/default/grub /etc/default/grub.backup

  sed -i '/GRUB_CMDLINE_LINUX_DEFAULT=/ s/"$/ ipv6.disable=1"/' /etc/default/grub
  sed -i '/GRUB_CMDLINE_LINUX=/ s/"$/ ipv6.disable=1"/' /etc/default/grub
  
  update-grub
  
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
read -r -p "Do you want to configure UFW firewall? (y/n): " configure_ufw
if [[ "$configure_ufw" =~ ^[Yy]$ ]]; then
  if ! command -v ufw >/dev/null 2>&1; then
    echo "UFW is not installed. Installing UFW..."
    apt update
    apt install -y ufw
  fi
  
  echo "Resetting UFW to default settings..."
  ufw --force reset

  wget -q https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/ufw.sh -O ufw.sh
  if [[ -f "ufw.sh" ]]; then
    chmod +x ufw.sh
    ./ufw.sh
    rm -f ufw.sh
    
    echo "Enabling UFW..."
    ufw --force enable
  else
    echo "Failed to download UFW configuration script."
  fi
fi

# 10. Time Synchronization
read -r -p "Do you want to sync time with time.nist.gov? (y/n): " sync_time
if [[ "$sync_time" =~ ^[Yy]$ ]]; then
  echo "Configuring time synchronization..."
  
  systemctl stop systemd-timesyncd 2>/dev/null
  systemctl disable systemd-timesyncd 2>/dev/null
  systemctl stop ntp 2>/dev/null
  systemctl disable ntp 2>/dev/null
  systemctl stop chronyd 2>/dev/null
  systemctl disable chronyd 2>/dev/null
  
  if dpkg-query -W chrony; then
    apt remove --purge chrony -y
  fi
  
  if ! command -v ntpdate >/dev/null 2>&1; then
    echo "Installing ntpdate..."
    apt update
    apt install -y ntpdate
  fi
  
  echo "Performing initial time sync..."
  ntpdate -4 time.nist.gov
  
  if ! grep -q "ntpdate -4 -s time.nist.gov" /etc/crontab; then
    echo "00 */6  * * *   root  ntpdate -4 -s time.nist.gov" >> /etc/crontab
    echo "Cron job added for periodic time sync every 6 hours"
  else
    echo "Time sync cron job already exists"
  fi
  
  echo "Time synchronization configured successfully"
fi

# 11 Step to modify /etc/sysctl.conf
read -r -p "Do you want to modify /etc/sysctl.conf with custom settings? (y/n): " modify_sysctl
if [[ "$modify_sysctl" =~ ^[Yy]$ ]]; then
  file_url="https://raw.githubusercontent.com/RebelliousWhiz/server-scripts/refs/heads/main/sysctl.conf"
  echo "Downloading custom sysctl configuration..."
  if curl -fsSL "$file_url" -o sysctl.custom.conf; then
    cat sysctl.custom.conf >> /etc/sysctl.conf
    rm -f sysctl.custom.conf
    echo "Custom configuration appended to /etc/sysctl.conf"

    echo "Applying the changes with sysctl -p..."
    sysctl -p
  else
    echo "Failed to download the custom sysctl configuration."
  fi
fi

# Self-delete the script
rm -- "$0"

exit 0
