#!/bin/bash
# SOC Lab: Ubuntu Hardening Script
# Author: [Your Name]
# CIS Benchmark Level: 1

# 1. Strict Mode: Exit on error, unset variable, or pipe failure
set -euo pipefail

# 2. Configuration
AUDIT_LOG="/var/log/hardening_audit.log"
SCRIPT_NAME="HardeningScript"

# 3. Logging Function
log_action() {
  local message="$1"
  # Log to system syslog
  logger -t "$SCRIPT_NAME" "$message"
  # Log to local file with timestamp
  # We use 'sudo tee' here to ensure we can write to /var/log even if the script logic changes context
  echo "$(date '+%F %T') - $message" | sudo tee -a "$AUDIT_LOG" > /dev/null
}

# 4. Root Check
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# 5. Execution Start
log_action "Script execution started."

# ---------------------------------------------------------
# Function: Harden Services
# Purpose: Disable non-essential services to reduce attack surface
# ---------------------------------------------------------
harden_services() {
  log_action "Starting Service Hardening..."
  
  # EXPANDED Whitelist: Includes essential desktop & security services
  local allowed_services=(
    "ssh" "ufw" "cron" "systemd-journald" "networking" 
    "systemd-resolved" "dbus" "rsyslog" "apparmor" 
    "NetworkManager" "wpa_supplicant" "avahi-daemon" 
    "power-profiles-daemon" "thermald" "udisks2" 
    "accounts-daemon" "gdm" "snapd" "unattended-upgrades"
  )
  
  # FIX: Skip the header row by using 'tail -n +2'
  # This ensures "UNIT" is never processed as a service name
  local all_services=$(systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | tail -n +2 | awk '{print $1}' | sed 's/.service//' || true)
  
  # echo "DEBUG: Found services: $all_services"

  if [[ -z "$all_services" ]]; then
    log_action "ERROR: Service list is empty. Skipping service hardening."
    return 1
  fi

  for service in $all_services; do
    # Skip empty lines or numbers if any slip through
    if [[ ! "$service" =~ ^[a-zA-Z] ]]; then
      continue
    fi

    if [[ ! " ${allowed_services[@]} " =~ " ${service} " ]]; then
      echo "Found non-essential service: $service"
      # systemctl disable --now "$service"
      log_action "FLAGGED for disable: $service"
    fi
  done
  
  log_action "Service Hardening complete."
}   

# ---------------------------------------------------------
# Function: Harden Firewall (UFW)
# Purpose: Configure default deny policy
# ---------------------------------------------------------
harden_firewall() {
  log_action "Starting Firewall Hardening..."
  
  # 1. Reset UFW to clean state
  ufw --force reset > /dev/null
  log_action "UFW reset complete."
  
  # 2. Set Defaults
  ufw default deny incoming > /dev/null
  ufw default allow outgoing > /dev/null
  log_action "UFW defaults set: Deny Incoming, Allow Outgoing."
  
  # 3. Allow Essential Services
  ufw allow ssh comment 'Allow SSH for Admin' > /dev/null
  ufw allow in on lo > /dev/null
  ufw allow out on lo > /dev/null
  
  # 4. Enable Firewall
  # SAFETY: Uncomment the line below only when you are sure SSH is allowed
  echo "Ready to enable UFW. SSH is allowed."
  # ufw --force enable 
  
  log_action "Firewall Hardening complete (Pending Enable)."
}

# ---------------------------------------------------------
# Main Execution Flow
# ---------------------------------------------------------
harden_services
harden_firewall

log_action "Script execution finished."
echo "Hardening complete. Check $AUDIT_LOG for details."   
