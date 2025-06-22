#!/bin/bash
# (mac/linux/deb/ubuntu)(bash) This script installs the 'randommac_wifi' alias specific to your OS.
# more notes in the end
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

# more on networksetup:
# The networksetup command in macOS is used to manage network settings, including Wi-Fi connections,
# from the command line. You can use it to enable or disable Wi-Fi, join and leave networks, 
# and configure various network parameters. The airport command, though related to Wi-Fi management, 
# has been deprecated and is not recommended for use in newer macOS versions. 
# https://www.engadget.com/2010-05-06-use-networksetup-to-change-airport-networks-from-the-command-lin.html#:~:text=Over%20at%20Macworld%2C%20Rob%20Griffiths,when%20Snow%20Leopard%20was%20released.)

# more on macchanger:
# https://manpages.ubuntu.com/manpages/man1/macchanger.1.html
# www.gnu.org/software/macchanger
# https://github.com/alobbs/macchanger
#        macchanger is a GNU/Linux utility for viewing/manipulating the MAC address for network interfaces.
#        -r, --random
#               Set fully random MAC.
#        -a, --another
#               Set random vendor MAC of the same kind.
#         EXAMPLE
#               macchanger -A eth1
# To reset your Wi-Fi MAC address on Ubuntu using macchanger, you first need to identify your network interface, then bring it down, change the MAC address, bring it back up, and finally verify the change. Here's a step-by-step guide:
# 1. Identify the Network Interface:
# Open a terminal.
# Use the command ip link to list all network interfaces. Look for your Wi-Fi interface, which is typically named wlan0 or similar. 
# Note the interface name (e.g., wlan0). 
# 2. Disable the Interface:
# Use the command sudo ip link set <interface_name> down (replace <interface_name> with your interface name, e.g., sudo ip link set wlan0 down) to disable the interface. 
# 3. Change the MAC Address:
# Use the command sudo macchanger -r <interface_name> to generate a random MAC address (e.g., sudo macchanger -r wlan0). 
# Alternatively, use sudo macchanger -m <new_mac_address> <interface_name> to set a specific MAC address (e.g., sudo macchanger -m 00:11:22:33:44:55 wlan0). 
# 4. Enable the Interface:
# Use the command sudo ip link set <interface_name> up to enable the interface (e.g., sudo ip link set wlan0 up). 
# 5. Verify the Change:
# Use the command ip link again and check the MAC address associated with your Wi-Fi interface. 
# You can also use macchanger -s <interface_name> to view the current and permanent MAC addresses. 
