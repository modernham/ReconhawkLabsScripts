#!/bin/bash

INTERFACES_FILE="/etc/network/interfaces"
WPA_SUPPLICANT_SERVICE="/etc/systemd/system/wpa_supplicant.service"
DHCLIENT_SERVICE="/etc/systemd/system/dhclient.service"

detect_ethernet_interface() {
    ip link show | grep -E '^[0-9]+: e' | grep -v '@' | head -1 | cut -d':' -f2 | tr -d ' '
}

detect_wifi_interface() {
    ip link show | grep -E '^[0-9]+: w' | grep -v '@' | head -1 | cut -d':' -f2 | tr -d ' '
}

get_configured_ethernet_interface() {
    local file="$1"
    # Look for ethernet interface patterns: en*, eth*, em*, eno*, enp*, ens*
    grep -oE '(auto|iface|allow-hotplug)\s+(e[nmt][pso]?[0-9a-z]+|eth[0-9]+)' "$file" | \
    awk '{print $2}' | sort -u | head -1
}

get_configured_wifi_interface() {
    local file="$1"
    # Look for wifi interface patterns: wl*, wlan*
    grep -oE '(auto|iface|allow-hotplug)\s+(wl[a-z0-9]+|wlan[0-9]+)' "$file" | \
    awk '{print $2}' | sort -u | head -1
}

update_interfaces_file() {
    local current_eth=$(detect_ethernet_interface)
    local current_wifi=$(detect_wifi_interface)
    local service_files_updated=false

    if [ -z "$current_eth" ]; then
        echo "Warning: No ethernet interface detected"
        return 1
    fi

    if [ -z "$current_wifi" ]; then
        echo "Warning: No wifi interface detected"
        return 1
    fi

    echo "Detected ethernet interface: $current_eth"
    echo "Detected wifi interface: $current_wifi"

    if [ ! -f "$INTERFACES_FILE" ]; then
        echo "Error: Interfaces file not found at $INTERFACES_FILE"
        return 1
    fi

    # Get currently configured interfaces from the file
    local configured_eth=$(get_configured_ethernet_interface "$INTERFACES_FILE")
    local configured_wifi=$(get_configured_wifi_interface "$INTERFACES_FILE")

    echo "Configured ethernet interface in file: ${configured_eth:-none}"
    echo "Configured wifi interface in file: ${configured_wifi:-none}"

    # Create backup
    sudo cp "$INTERFACES_FILE" "$INTERFACES_FILE.backup"

    # Replace ethernet interface if found and different
    if [ -n "$configured_eth" ] && [ "$configured_eth" != "$current_eth" ]; then
        sudo sed -i "s/\b$configured_eth\b/$current_eth/g" "$INTERFACES_FILE"
        echo "Replaced $configured_eth with $current_eth in interfaces file"
    elif [ "$configured_eth" = "$current_eth" ]; then
        echo "Ethernet interface already correctly configured"
    fi

    # Replace wifi interface if found and different
    if [ -n "$configured_wifi" ] && [ "$configured_wifi" != "$current_wifi" ]; then
        sudo sed -i "s/\b$configured_wifi\b/$current_wifi/g" "$INTERFACES_FILE"
        echo "Replaced $configured_wifi with $current_wifi in interfaces file"
    elif [ "$configured_wifi" = "$current_wifi" ]; then
        echo "Wifi interface already correctly configured"
    fi

    # Update wpa_supplicant service file
    if [ -f "$WPA_SUPPLICANT_SERVICE" ]; then
        local configured_wifi_service=$(get_configured_wifi_interface "$WPA_SUPPLICANT_SERVICE")
        echo "Configured wifi interface in wpa_supplicant service: ${configured_wifi_service:-none}"
        
        sudo cp "$WPA_SUPPLICANT_SERVICE" "$WPA_SUPPLICANT_SERVICE.backup"
        
        if [ -n "$configured_wifi_service" ] && [ "$configured_wifi_service" != "$current_wifi" ]; then
            sudo sed -i "s/\b$configured_wifi_service\b/$current_wifi/g" "$WPA_SUPPLICANT_SERVICE"
            echo "Updated wpa_supplicant service file: replaced $configured_wifi_service with $current_wifi"
            service_files_updated=true
        elif [ "$configured_wifi_service" = "$current_wifi" ]; then
            echo "wpa_supplicant service already correctly configured"
        fi
        echo "Backup saved as $WPA_SUPPLICANT_SERVICE.backup"
    else
        echo "Warning: wpa_supplicant service file not found at $WPA_SUPPLICANT_SERVICE"
    fi

    # Update dhclient service file
    if [ -f "$DHCLIENT_SERVICE" ]; then
        local configured_wifi_dhclient=$(get_configured_wifi_interface "$DHCLIENT_SERVICE")
        echo "Configured wifi interface in dhclient service: ${configured_wifi_dhclient:-none}"
        
        sudo cp "$DHCLIENT_SERVICE" "$DHCLIENT_SERVICE.backup"
        
        if [ -n "$configured_wifi_dhclient" ] && [ "$configured_wifi_dhclient" != "$current_wifi" ]; then
            sudo sed -i "s/\b$configured_wifi_dhclient\b/$current_wifi/g" "$DHCLIENT_SERVICE"
            echo "Updated dhclient service file: replaced $configured_wifi_dhclient with $current_wifi"
            service_files_updated=true
        elif [ "$configured_wifi_dhclient" = "$current_wifi" ]; then
            echo "dhclient service already correctly configured"
        fi
        echo "Backup saved as $DHCLIENT_SERVICE.backup"
    else
        echo "Warning: dhclient service file not found at $DHCLIENT_SERVICE"
    fi

    if [ "$service_files_updated" = true ]; then
        echo "Reloading systemd daemon due to service file changes..."
        sudo systemctl daemon-reload
        echo "Systemd daemon reloaded successfully"
    fi

    echo "Interfaces file update complete"
    echo "Backup saved as $INTERFACES_FILE.backup"
}

update_interfaces_file
