#!/bin/bash

# Setup script for WireGuard monitoring
# This script automates the installation and configuration of the WireGuard monitoring service

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_PATH="/root/wg_monitor.sh"
SERVICE_NAME="wg-monitor"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_FILE="/var/log/wg_monitor.log"

# Function to print status messages
print_status() {
    echo -e "${BLUE}[*] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_error() {
    echo -e "${RED}[!] $1${NC}" >&2
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

print_status "Starting WireGuard monitor setup..."

# Check if WireGuard is installed
if ! command -v wg &> /dev/null; then
    print_warning "WireGuard doesn't appear to be installed."
    read -p "Would you like to install WireGuard now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f /etc/debian_version ]; then
            print_status "Installing WireGuard on Debian/Ubuntu..."
            apt update
            apt install -y wireguard
        else
            print_error "Unsupported distribution. Please install WireGuard manually."
            exit 1
        fi
    else
        print_warning "Proceeding without installing WireGuard. Script may not work correctly."
    fi
fi

# Create the WireGuard monitor script
print_status "Creating WireGuard monitor script at $SCRIPT_PATH..."
cat > "$SCRIPT_PATH" << 'EOF'
#!/bin/bash

# WireGuard Interface Monitoring Script
# This script checks each WireGuard interface by using curl with each interface
# If an interface fails to respond, it will restart that interface up to a maximum number of attempts

# Configuration
CHECK_INTERVAL=300  # Check every 5 minutes (300 seconds)
TIMEOUT=10          # Timeout for curl command in seconds
LOG_FILE="/var/log/wg_monitor.log"
MAX_FAILURES=3      # Maximum number of continuous failures before giving up
FAILURE_RESET=21600 # Reset failure counter after 6 hours (21600 seconds) of successful operation

# Declare associative array to track failures
declare -A failure_count
declare -A last_success_time

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to check if we should reset failure counter
should_reset_failures() {
    local interface=$1
    local current_time
    current_time=$(date +%s)
    
    # If we have a record of last success and it was more than FAILURE_RESET ago
    if [[ -n "${last_success_time[$interface]}" ]] && \
       (( current_time - ${last_success_time[$interface]} >= FAILURE_RESET )); then
        return 0  # true - reset the counter
    fi
    return 1  # false - don't reset
}

# Create log file if it doesn't exist
touch "$LOG_FILE"
log_message "WireGuard monitoring script started"

# Main monitoring loop
while true; do
    # Get list of WireGuard interfaces
    interfaces=$(wg show interfaces 2>/dev/null)
    
    if [ -z "$interfaces" ]; then
        log_message "No WireGuard interfaces found. Waiting for next check."
    else
        for interface in $interfaces; do
            log_message "Checking interface: $interface"
            
            # Check if we should reset the failure counter
            if should_reset_failures "$interface"; then
                log_message "Resetting failure counter for $interface after successful operation period"
                failure_count[$interface]=0
            fi
            
            # Check if interface is up
            if ! ip link show dev "$interface" &>/dev/null; then
                log_message "Interface $interface does not exist or is down. Attempting to start it."
                wg-quick up "$interface" &>> "$LOG_FILE"
                continue
            fi
            
            # Try to curl with the interface
            if ! curl --interface "$interface" --max-time "$TIMEOUT" --silent --output /dev/null myip.wtf; then
                # Increment failure counter
                failure_count[$interface]=$((${failure_count[$interface]:-0} + 1))
                
                log_message "Interface $interface failed to reach myip.wtf. Failure count: ${failure_count[$interface]}/$MAX_FAILURES"
                
                if [ "${failure_count[$interface]}" -le "$MAX_FAILURES" ]; then
                    log_message "Attempting to restart $interface (Attempt ${failure_count[$interface]}/$MAX_FAILURES)"
                    log_message "Running: wg-quick down $interface"
                    wg-quick down "$interface" &>> "$LOG_FILE"
                    sleep 2
                    log_message "Running: wg-quick up $interface"
                    wg-quick up "$interface" &>> "$LOG_FILE"
                    sleep 5
                    
                    # Verify the interface is working after restart
                    if curl --interface "$interface" --max-time "$TIMEOUT" --silent --output /dev/null myip.wtf; then
                        ip=$(curl --interface "$interface" --silent myip.wtf)
                        log_message "Interface $interface successfully restarted and is working. IP: $ip"
                        failure_count[$interface]=0
                        last_success_time[$interface]=$(date +%s)
                    else
                        log_message "Interface $interface still not working after restart attempt ${failure_count[$interface]}/$MAX_FAILURES"
                    fi
                else
                    log_message "WARNING: Interface $interface has failed $MAX_FAILURES times consecutively. Skipping until next cycle."
                fi
            else
                ip=$(curl --interface "$interface" --silent myip.wtf)
                log_message "Interface $interface is working correctly. IP: $ip"
                failure_count[$interface]=0
                last_success_time[$interface]=$(date +%s)
            fi
        done
    fi
    
    log_message "Completed check cycle. Next check in $CHECK_INTERVAL seconds."
    sleep "$CHECK_INTERVAL"
done
EOF

# Make it executable
chmod +x "$SCRIPT_PATH"
print_success "Created and set executable permissions for the monitor script"

# Create systemd service
print_status "Creating systemd service at $SERVICE_PATH..."
cat > "$SERVICE_PATH" << EOF
[Unit]
Description=WireGuard Interface Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart=$SCRIPT_PATH
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start the service
print_status "Configuring systemd service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# Check for curl
if ! command -v curl &> /dev/null; then
    print_warning "curl is not installed but required by the monitoring script."
    read -p "Would you like to install curl now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Installing curl..."
        apt update
        apt install -y curl
    else
        print_error "curl is required for the script to function. Please install it manually."
        exit 1
    fi
fi

# Start the service
print_status "Starting the WireGuard monitoring service..."
systemctl start "$SERVICE_NAME"

# Check if service started successfully
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    print_success "WireGuard monitoring service started successfully!"
else
    print_error "Failed to start the WireGuard monitoring service. Check with: journalctl -u $SERVICE_NAME"
    exit 1
fi

# Create a small utility script for monitoring
UTIL_SCRIPT="/root/wg_monitor_util.sh"
print_status "Creating utility script at $UTIL_SCRIPT..."
cat > "$UTIL_SCRIPT" << EOF
#!/bin/bash
# WireGuard Monitor Utility Script

case "\$1" in
    start)
        systemctl start $SERVICE_NAME
        echo "WireGuard monitor service started"
        ;;
    stop)
        systemctl stop $SERVICE_NAME
        echo "WireGuard monitor service stopped"
        ;;
    restart)
        systemctl restart $SERVICE_NAME
        echo "WireGuard monitor service restarted"
        ;;
    status)
        systemctl status $SERVICE_NAME
        ;;
    log)
        if [ -n "\$2" ] && [ "\$2" = "follow" ]; then
            journalctl -u $SERVICE_NAME -f
        else
            journalctl -u $SERVICE_NAME | tail -n 50
        fi
        ;;
    view)
        tail -n 100 $LOG_FILE
        ;;
    config)
        vi $SCRIPT_PATH
        echo "If you made changes, restart the service with: ./wg_monitor_util.sh restart"
        ;;
    *)
        echo "WireGuard Monitor Utility"
        echo "Usage: \$0 {start|stop|restart|status|log|view|config}"
        echo ""
        echo "  start   - Start the monitoring service"
        echo "  stop    - Stop the monitoring service"
        echo "  restart - Restart the monitoring service"
        echo "  status  - Check the status of the service"
        echo "  log     - View service logs (add 'follow' to watch logs: ./wg_monitor_util.sh log follow)"
        echo "  view    - View the monitoring log file"
        echo "  config  - Edit the configuration in the monitor script"
        ;;
esac
EOF

chmod +x "$UTIL_SCRIPT"
print_success "Created utility script with executable permissions"

# Setup log rotation
setup_logrotate() {
    print_status "Setting up log rotation for WireGuard monitor logs..."
    cat > /etc/logrotate.d/wg-monitor << EOF
/var/log/wg_monitor.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        systemctl kill -s HUP $SERVICE_NAME >/dev/null 2>&1 || true
    endscript
}
EOF
    print_success "Log rotation configured. Logs will be rotated daily and kept for 7 days."
}

# Call the setup function
setup_logrotate

# Display summary
echo ""
echo -e "${GREEN}=======================================================${NC}"
echo -e "${GREEN}WireGuard Monitor Setup Complete!${NC}"
echo -e "${GREEN}=======================================================${NC}"
echo ""
echo -e "Monitor script: ${BLUE}$SCRIPT_PATH${NC}"
echo -e "Log file: ${BLUE}$LOG_FILE${NC}"
echo -e "Service name: ${BLUE}$SERVICE_NAME${NC}"
echo ""
echo -e "The monitoring service is now ${GREEN}active and enabled${NC} to start on boot."
echo ""
echo -e "Use the utility script to manage the service:"
echo -e "  ${YELLOW}./wg_monitor_util.sh${NC} - Show all available commands"
echo -e "  ${YELLOW}./wg_monitor_util.sh status${NC} - Check service status"
echo -e "  ${YELLOW}./wg_monitor_util.sh log follow${NC} - Watch logs in real-time"
echo -e "  ${YELLOW}./wg_monitor_util.sh config${NC} - Modify configuration"
echo ""
echo -e "${GREEN}Happy monitoring!${NC}"
