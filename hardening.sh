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

echo "System hardening completed."

# Self-delete the script
rm -- "$0"

exit 0
