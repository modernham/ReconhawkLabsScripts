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

    sudo cp "$INTERFACES_FILE" "$INTERFACES_FILE.backup"

    sudo sed -i "s/enp0s31f6/$current_eth/g" "$INTERFACES_FILE"
    sudo sed -i "s/wlp4s0/$current_wifi/g" "$INTERFACES_FILE"

    if [ -f "$WPA_SUPPLICANT_SERVICE" ]; then
        sudo cp "$WPA_SUPPLICANT_SERVICE" "$WPA_SUPPLICANT_SERVICE.backup"
        sudo sed -i "s/wlp4s0/$current_wifi/g" "$WPA_SUPPLICANT_SERVICE"
        echo "Updated wpa_supplicant service file with current wifi adapter"
        echo "Backup saved as $WPA_SUPPLICANT_SERVICE.backup"
        service_files_updated=true
    else
        echo "Warning: wpa_supplicant service file not found at $WPA_SUPPLICANT_SERVICE"
    fi

    if [ -f "$DHCLIENT_SERVICE" ]; then
        sudo cp "$DHCLIENT_SERVICE" "$DHCLIENT_SERVICE.backup"
        sudo sed -i "s/wlp4s0/$current_wifi/g" "$DHCLIENT_SERVICE"
        echo "Updated dhclient service file with current wifi adapter"
        echo "Backup saved as $DHCLIENT_SERVICE.backup"
        service_files_updated=true
    else
        echo "Warning: dhclient service file not found at $DHCLIENT_SERVICE"
    fi

    if [ "$service_files_updated" = true ]; then
        echo "Reloading systemd daemon due to service file changes..."
        sudo systemctl daemon-reload
        echo "Systemd daemon reloaded successfully"
    fi

    echo "Updated interfaces file with current adapters"
    echo "Backup saved as $INTERFACES_FILE.backup"
}

update_interfaces_file