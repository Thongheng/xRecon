#!/bin/bash
# Minimal installation script for recon tools.
# Must be run with sudo privileges (e.g., sudo ./install.sh)

set -e # Exit script immediately if any command fails

# 1. Install system packages from apt
echo "[*] Installing system dependencies (nmap, go, etc)..."
apt-get update
apt-get install -y nmap golang-go libpcap-dev

# 2. Install Go-based recon tools
echo "[*] Installing Go-based tools..."
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$PATH

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/PentestPad/subzy@latest

# --- Final Essential Instructions ---
echo " "
echo "--- IMPORTANT ---"
echo "1. Manual Step: Install OWASP ZAP from https://www.zaproxy.org/download/"
echo "   (Required for option 10)."
echo "2. Add Go tools to your PATH by running:"
echo "   echo 'export PATH=\$PATH:\$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc"
echo "--- Installation Complete ---"