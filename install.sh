#!/bin/bash
# Minimal, corrected installation script for recon tools.
# Must be run with sudo privileges (e.g., sudo ./install.sh)

set -e # Exit script immediately if any command fails

# 1. Install system packages from apt
echo "[*] Installing system packages (apt)..."
apt-get update
apt-get install -y nmap python3 python3-pip golang-go libpcap-dev

# 2. Install Python packages from requirements.txt
echo "[*] Installing Python packages (pip)..."
pip3 install -r requirements.txt

# 3. Install Go-based tools
echo "[*] Installing Go-based tools (go install)..."
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$PATH

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/PentestPad/subzy@latest # Corrected path

echo "--- Installation Complete ---"