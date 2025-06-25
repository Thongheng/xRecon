#!/bin/bash

# Color codes
C_OKCYAN='\033[96m'
C_OKGREEN='\033[92m'
C_WARNING='\033[93m'
C_FAIL='\033[91m'
C_ENDC='\033[0m'

# List of tools to check/install
TOOLS=(
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "gobuster:github.com/OJ/gobuster/v3@latest"
    "ffuf:github.com/ffuf/ffuf@latest"
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
    "subzy:github.com/LukaSikic/subzy@latest"
    "wafw00f:github.com/EnableSecurity/wafw00f@latest"
    "gowitness:github.com/sensepost/gowitness@latest"
    "whatweb:github.com/urbanadventurer/whatweb@latest"
    "dnsrecon:github.com/darkoperator/dnsrecon@latest"
)

# Tools requiring apt
APT_TOOLS=(
    "nmap"
    "zaproxy"
)

# Check for Go installation
check_go() {
    if ! command -v go &> /dev/null; then
        echo -e "${C_FAIL}Error: Go is not installed. Please install Go first (https://golang.org/doc/install).${C_ENDC}"
        exit 1
    fi
}

# Check for apt
check_apt() {
    if ! command -v apt-get &> /dev/null; then
        echo -e "${C_WARNING}Warning: apt-get not found. Skipping installation of nmap and zaproxy. Install manually if needed.${C_ENDC}"
        return 1
    fi
    return 0
}

# Install Go-based tools
install_go_tool() {
    local tool_name=$1
    local tool_path=$2
    if ! command -v "$tool_name" &> /dev/null; then
        echo -e "${C_OKCYAN}Installing $tool_name...${C_ENDC}"
        go install "$tool_path"
        if [ $? -eq 0 ]; then
            echo -e "${C_OKGREEN}$tool_name Installed successfully.${C_ENDC}"
        else
            echo -e "${C_FAIL}Failed to install $tool_name. Check your Go environment.${C_ENDC}"
        fi
    else
        echo -e "${C_OKGREEN}$tool_name is already installed.${C_ENDC}"
    fi
}

# Install apt-based tools
install_apt_tool() {
    local tool_name=$1
    if ! command -v "$tool_name" &> /dev/null; then
        echo -e "${C_OKCYAN}Installing $tool_name via apt...${C_ENDC}"
        sudo apt-get update && sudo apt-get install -y "$tool_name"
        if [ $? -eq 0 ]; then
            echo -e "${C_OKGREEN}$tool_name Installed successfully.${C_ENDC}"
        else
            echo -e "${C_FAIL}Failed to install $tool_name. Check your apt permissions or package availability.${C_ENDC}"
        fi
    else
        echo -e "${C_OKGREEN}$tool_name is already installed.${C_ENDC}"
    fi
}

echo -e "${C_OKCYAN}Starting dependency setup for All-in-One Recon Tool...${C_ENDC}"

# Check and install Go-based tools
check_go
for tool in "${TOOLS[@]}"; do
    IFS=":" read -r tool_name tool_path <<< "$tool"
    install_go_tool "$tool_name" "$tool_path"
done

# Check and install apt-based tools
if check_apt; then
    for tool in "${APT_TOOLS[@]}"; do
        install_apt_tool "$tool"
    done
else
    echo -e "${C_WARNING}Skipping apt-based tools installation. Ensure nmap and zaproxy are installed manually if needed.${C_ENDC}"
fi

echo -e "${C_OKGREEN}Dependency setup complete. Ensure Go binaries are in your PATH (e.g., ~/go/bin).${C_ENDC}"
echo -e "${C_OKCYAN}Run the recon tool with: ./recon.sh <target> <scan_flag>${C_ENDC}"