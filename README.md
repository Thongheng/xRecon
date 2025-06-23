# ReconX: All-in-One Reconnaissance Tool

ReconX is a comprehensive cybersecurity reconnaissance tool that automates and streamlines various reconnaissance techniques. It integrates multiple industry-standard security tools into a single, easy-to-use interface, making it perfect for penetration testers, bug bounty hunters, and security researchers.

## Features

ReconX provides a menu-driven interface to run the following security reconnaissance tasks:

1. **Passive Subdomain Enumeration** - Using Amass
2. **Active Subdomain Enumeration** - Using Subfinder
3. **Network Scanning** - Using Nmap
4. **Web Server Validation** - Using Httpx
5. **Web App Scanning** - Using OWASP ZAP
6. **Directory Brute-Forcing** - Using ffuf
7. **Subdomain Takeover Check** - Using Subzy
8. **Vulnerability Scanning** - Using Nuclei
9. **VHost Scanning** - Using ffuf
10. **Web Crawling** - Using Katana

## Prerequisites

- Python 3.x
- pip3
- Go (for Go-based tools)
- Required system packages: nmap, zaproxy, dirb, golang-go, seclists

## Installation

### Automated Installation

Run the installation script to set up all dependencies:

```bash
chmod +x install.sh
./install.sh
```

This script will:
- Install system dependencies
- Install required Python packages
- Install Go-based security tools
- Configure PATH settings for Go binaries

### Manual Installation

1. Install system dependencies:

```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap zaproxy dirb golang-go seclists
```

2. Install Python dependencies:

```bash
pip3 install -r requirement.txt
```

3. Install Go-based tools:

```bash
go install -v github.com/OWASP/Amass/v3/cmd/amass@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/ffuf@latest
go install -v github.com/LukaSikic/subzy@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

4. Add Go binaries to your PATH:

```bash
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
```

## Configuration

ReconX uses a `config.yaml` file to specify tool paths and settings. The default configuration looks like this:

```yaml
tools:
  amass:
    path: /usr/local/bin/amass
  subfinder:
    path: subfinder
  nmap:
    path: /usr/bin/nmap
  httpx:
    path: httpx
  zaproxy:
    path: zaproxy
  ffuf:
    path: ffuf
    wordlist: /usr/share/wordlists/dirb/common.txt
    vhost_wordlist: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  subzy:
    path: subzy
  nuclei:
    path: nuclei
  katana:
    path: katana
```

Edit this file to match your tool paths if they differ from the defaults.

## Usage

### Basic Usage

```bash
python3 ReconX.py [target] [-o OUTPUT_DIRECTORY]
```

If you don't provide a target at the command line, you'll be prompted to enter one.

### Examples

1. Scan a domain with default settings:

```bash
python3 ReconX.py example.com
```

2. Specify an output directory:

```bash
python3 ReconX.py example.com -o ~/recon-results
```

3. Interactive mode (no command-line arguments):

```bash
python3 ReconX.py
```

### Tool Menu

After launching ReconX, you'll be presented with a menu of available tools. Select the number corresponding to the tool you want to use. You can add additional tool-specific arguments when prompted.

## Output

Results from each tool are saved to text files in the specified output directory (or the current directory if not specified). The files are named according to the tool used, e.g., `amass_output.txt`, `nmap_output.txt`, etc.

## Dependencies Between Tools

Some tools depend on the output of others:
- The Subzy tool (option 7) requires that you first run Subfinder (option 2) to generate a list of subdomains.

## Note for macOS Users

The installation script is primarily designed for Debian-based Linux systems. macOS users may need to modify the installation commands using Homebrew:

```bash
brew install python3 nmap zaproxy go seclists
```

And then follow the manual installation steps for Go-based tools.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

## License

This project is open-source.
