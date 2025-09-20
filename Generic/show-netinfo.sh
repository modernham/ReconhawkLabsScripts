#!/usr/bin/env bash
# /usr/local/bin/show-netinfo.sh
# Produce a plain-text "network info" block suitable for /etc/issue and console printing.
# Safe (no interactive dialogs). Intended to be run as root at boot.
#Place in /usr/local/bin/
#Place this in /root/.bashrc
#[ -t 1 ] || exit 0
#case $- in
#  *i*) 
#    # interactive shell - safe to show banners or whiptail
#    /usr/local/bin/show-netinfo.sh >/dev/null 2>&1
#    ;;
#  *)
#    ;;
#esac

outfile="/run/show-netinfo.txt"   # ephemeral copy we can write
issuefile="/etc/issue"            # persistent pre-login banner file (getty)
tty_to_print="/dev/tty1"          # physical console to print to

# Build output
{
  echo "======================================="
  echo "   System Network Information"
  echo "   Generated: $(date -u +"%Y-%m-%d %H:%M:%SZ")"
  echo "======================================="

  # Primary adapter used for default route
  IFACE=$(ip route get 1 2>/dev/null | awk '{print $5; exit}' || true)
  if [ -z "$IFACE" ]; then
    IFACE="(none)"
  fi
  echo "Adapter: $IFACE"

  # IP addresses for the adapter (list IPv4 addresses)
  if [ "$IFACE" != "(none)" ]; then
    ip -4 addr show dev "$IFACE" 2>/dev/null | awk '/inet / {print "IP Address: "$2}'
  else
    echo "IP Address: (none)"
  fi

  # Default gateway(s)
  ip route show default 2>/dev/null | awk '{print "Gateway: "$3}' || echo "Gateway: (none)"

  # DNS servers
  if [ -f /etc/resolv.conf ]; then
    awk '/^nameserver/ { printf("DNS: %s ", $2) } END { print "" }' /etc/resolv.conf
  else
    echo "DNS: (none)"
  fi

  # Helpful commands section
  echo "---------------------------------------"
  echo "Commands:"
  echo " Set Static IP or DHCP: netset"
  echo " Start a network scan:  scan"
  echo " Share reports (web):   share"
  echo "---------------------------------------"
} > "$outfile"

# update /etc/issue so local getty shows it prior to login
# Back up first
if [ -w "$issuefile" ] || [ ! -e "$issuefile" ]; then
  cp -f "$issuefile" "${issuefile}.bak-$(date +%s)" 2>/dev/null || true
  # /etc/issue often contains "\n" sequences or escape bits; keep plain text safe
  cp -f "$outfile" "$issuefile"
fi

# Also write to console "/dev/tty1" so it appears on the physical screen immediately
# Only attempt if tty exists and is writable
if [ -w "$tty_to_print" ]; then
  # Use a short pause to ensure the console is ready
  sleep 0.5
  cat "$outfile" > "$tty_to_print" 2>/dev/null || true
fi

# leave /run/show-netinfo.txt for other processes to read if needed