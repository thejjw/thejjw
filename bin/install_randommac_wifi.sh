#!/bin/bash
# (mac/linux/deb/ubuntu)(bash) This script installs the 'randommac_wifi' alias specific to your OS.
# 2025.6 @thejjw

OS_TYPE=$(uname)

if [ "$OS_TYPE" = "Darwin" ]; then
    TARGET_SHELL_RC="$HOME/.zshrc"
    ALIAS_NAME="randommac_wifi"

    echo "Detected macOS. Installing '$ALIAS_NAME' alias to $TARGET_SHELL_RC..."

    # Use a here-document to append the macOS alias definition
    cat << 'MAC_ALIAS_EOF' >> "$TARGET_SHELL_RC"

# Alias to randomize MAC address and toggle Wi-Fi on macOS
alias randommac_wifi='
    WIFI_SERVICE=$(networksetup -listallnetworkservices | grep -i wi-fi)
    if [ -z "$WIFI_SERVICE" ]; then
        echo "Error: Wi-Fi service not found."
        return 1
    fi

    # Disable Wi-Fi
    sudo networksetup -setnetworkserviceenabled "$WIFI_SERVICE" off

    # Generate and set a random MAC address for en0 (primary interface)
    sudo ifconfig en0 ether $(openssl rand -hex 6 | sed "s/../&:/g; s/:$//")

    # Re-enable Wi-Fi
    sudo networksetup -setnetworkserviceenabled "$WIFI_SERVICE" on

    echo "MAC address randomized and Wi-Fi toggled."
'

MAC_ALIAS_EOF
    echo "Installation complete. Please run 'source $TARGET_SHELL_RC' or restart your terminal to use the 'randommac_wifi' alias."

elif [ "$OS_TYPE" = "Linux" ]; then
    # On Linux, install to .bashrc
    TARGET_SHELL_RC="$HOME/.bashrc"
    ALIAS_NAME="randommac_wifi"

    echo "Detected Linux. Installing '$ALIAS_NAME' alias to $TARGET_SHELL_RC..."

    # Use a here-document to append the Linux alias definition
    cat << 'LINUX_ALIAS_EOF' >> "$TARGET_SHELL_RC"

# Alias to randomize MAC address and toggle network interface on Linux
alias randommac_wifi='
    # Check if NETWORK_INTERFACE is already set in the environment
    if [ -z "$NETWORK_INTERFACE" ]; then
        # Attempt to auto-detect if not set (prioritize wireless, then wired)
        DETECTED_INTERFACE=$(ip -br link show | awk '\''$1 ~ /^wl/ {print $1; exit} $1 ~ /^e/ {print $1; exit}'\'')
        if [ -n "$DETECTED_INTERFACE" ]; then
            NETWORK_INTERFACE="$DETECTED_INTERFACE"
            echo "Auto-detected network interface: $NETWORK_INTERFACE"
        else
            echo "Error: No active network interface found automatically."
            echo "Please set the NETWORK_INTERFACE environment variable before running, e.g.:"
            echo "  NETWORK_INTERFACE=wlan0 randommac_wifi"
            echo "Or find your interface name using '\''ip a'\'' or '\''ip link show'\''."
            return 1
        fi
    else
        echo "Using pre-set network interface: $NETWORK_INTERFACE"
    fi

    # Proceed with the network interface operations
    echo "Processing interface: $NETWORK_INTERFACE"

    # Bring the interface down
    sudo ip link set dev "$NETWORK_INTERFACE" down

    # Generate and set a random MAC address
    # Prefer macchanger if installed for more robust randomization
    if command -v macchanger &> /dev/null; then
        echo "Using macchanger for MAC randomization."
        sudo macchanger -r "$NETWORK_INTERFACE"
    else
        echo "macchanger not found. Generating a random MAC address manually."
        sudo ip link set dev "$NETWORK_INTERFACE" address $(openssl rand -hex 6 | sed "s/../&:/g; s/:$//")
    fi

    # Bring the interface up
    sudo ip link set dev "$NETWORK_INTERFACE" up

    echo "MAC address randomized and network interface toggled."
'

LINUX_ALIAS_EOF
    echo "Installation complete. Please run 'source $TARGET_SHELL_RC' or restart your terminal to use the 'randommac_wifi' alias."

else
    echo "Error: Unsupported operating system ($OS_TYPE). This installer script currently supports macOS and Linux only."
    exit 1
fi
