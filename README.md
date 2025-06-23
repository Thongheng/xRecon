# ReconX: All-in-One Reconnaissance Tool

ReconX automates various cybersecurity reconnaissance tasks using popular tools, ideal for penetration testers and security researchers.

## Features
- Active Subdomain Enumeration (ffuf)
- Passive Subdomain Enumeration (Subfinder)
- Network Scanning (Nmap)
- Web Server Validation (Httpx)
- Web App Scanning (OWASP ZAP)
- Directory & VHost Brute-Forcing (ffuf)
- Subdomain Takeover Check (Subzy)
- Vulnerability Scanning (Nuclei)
- Web Crawling (Katana)

## Installation

### Automated (Linux)
```bash
chmod +x install.sh
./install.sh
```

### Manual (Linux)
Install dependencies:
```bash
sudo apt update && sudo apt install -y python3 python3-pip nmap zaproxy golang-go seclists
pip3 install -r requirements.txt
pip3 install pyyaml
```
Install Go-based tools:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/ffuf@latest
go install -v github.com/LukaSikic/subzy@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
export PATH=$PATH:$HOME/go/bin
```

### macOS
Use Homebrew:
```bash
brew install python3 nmap zaproxy go seclists
```
Then follow manual Go tool installation above.

## Configuration
Edit `config.yaml` to set tool paths if needed.

## Usage
```bash
python3 ReconX.py [target] [-o OUTPUT_DIRECTORY]
```
- Results saved in output directory (default: current directory)
- Menu-driven interface for tool selection

## Notes
- Some tools depend on others (e.g., Subzy needs Subfinder output)
- For issues or contributions, submit via GitHub

## License
Open-source.
