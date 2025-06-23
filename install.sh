#!/bin/bash

# Install system dependencies and tools for recon.py
echo "Installing system dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip nmap zaproxy dirb golang-go seclists

# Install Python dependencies from requirements.txt
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Install Go-based tools
echo "Installing Go-based recon tools..."
go install -v github.com/OWASP/Amass/v3/cmd/amass@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/ffuf@latest
go install -v github.com/LukaSikic/subzy@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Ensure Go binaries are in PATH
echo "Ensuring Go binaries are in PATH..."
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc

echo "Installation complete. Ensure config.yaml is set up before running recon.py."