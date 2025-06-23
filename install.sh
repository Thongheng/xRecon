#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Install system dependencies and tools for recon.py
echo "Checking and installing system dependencies..."
sudo apt update

# Check and install each dependency individually
if ! command_exists python3; then
    echo "Installing Python3..."
    sudo apt install -y python3
else
    echo "Python3 is already installed."
fi

if ! command_exists pip3; then
    echo "Installing pip3..."
    sudo apt install -y python3-pip
else
    echo "pip3 is already installed."
fi

if ! command_exists nmap; then
    echo "Installing nmap..."
    sudo apt install -y nmap
else
    echo "nmap is already installed."
fi

if ! command_exists zaproxy; then
    echo "Installing zaproxy..."
    sudo apt install -y zaproxy
else
    echo "zaproxy is already installed."
fi

if ! command_exists dirb; then
    echo "Installing dirb..."
    sudo apt install -y dirb
else
    echo "dirb is already installed."
fi

if ! command_exists go; then
    echo "Installing golang..."
    sudo apt install -y golang-go
else
    echo "golang is already installed."
fi

# Check if seclists is installed (this is trickier since it's not a command)
if [ ! -d "/usr/share/seclists" ]; then
    echo "Installing seclists..."
    sudo apt install -y seclists
else
    echo "seclists is already installed."
fi

# Install Python dependencies from requirements.txt
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Install Go-based tools
echo "Checking and installing Go-based recon tools..."

# Add Go bin to PATH temporarily for the installation check
export PATH=$PATH:$HOME/go/bin

# Check and install each Go tool
if ! command_exists amass; then
    echo "Installing Amass..."
    go install -v github.com/OWASP/Amass/v3/cmd/amass@latest
else
    echo "Amass is already installed."
fi

if ! command_exists subfinder; then
    echo "Installing Subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
else
    echo "Subfinder is already installed."
fi

if ! command_exists httpx; then
    echo "Installing Httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
else
    echo "Httpx is already installed."
fi

if ! command_exists ffuf; then
    echo "Installing Ffuf..."
    go install -v github.com/lc/ffuf@latest
else
    echo "Ffuf is already installed."
fi

if ! command_exists subzy; then
    echo "Installing Subzy..."
    go install -v github.com/LukaSikic/subzy@latest
else
    echo "Subzy is already installed."
fi

if ! command_exists nuclei; then
    echo "Installing Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
else
    echo "Nuclei is already installed."
fi

if ! command_exists katana; then
    echo "Installing Katana..."
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
else
    echo "Katana is already installed."
fi

# Ensure Go binaries are in PATH
echo "Ensuring Go binaries are in PATH..."
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc

echo "Installation complete. Ensure config.yaml is set up before running recon.py."