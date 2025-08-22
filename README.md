# xRecon

xRecon is a Bash-based reconnaissance automation tool designed for penetration testers and security researchers. It streamlines the process of gathering information about target domains and IP addresses, integrating multiple open-source utilities for efficient and comprehensive recon workflows.

## Features
- **Automated Workflow (`--all`):** Runs a full, automated reconnaissance process including subdomain enumeration, live host detection, and screenshots.
- **Subdomain Enumeration:**
  - Passive Subdomain discovery (`--subfinder`)
  - Active Subdomain bruteforcing with Gobuster (`--gobuster-sub`)
  - DNS enumeration with Dnsrecon (`--dns`)
- **Host and Web Server Analysis:**
  - Web Server Validation with Httpx (`--httpx`)
  - VHost Scanning with Ffuf (`--vhost`)
  - Subdomain Takeover detection with Subzy (`--subzy`)
  - Web Application Firewall (WAF) detection with Wafw00f (`--waf`)
  - Technology Fingerprinting with Whatweb (`--tech`)
- **Port Scanning:**
  - Comprehensive Port Scanning with Nmap (`--nmap`)
  - Fast Port Scanning with Rustscan (`--rust`)
- **Vulnerability Scanning & Crawling:**
  - Web Crawling with Katana (`--katana`)
  - Directory Bruteforcing with Ffuf (`--dir`)
  - Vulnerability Scanning with Nuclei (`--nuclei`)
  - Deep Web Application Scanning with OWASP ZAP (`--zap`)
- **Visual Reconnaissance:**
  - Screenshots of live web pages with Gowitness (`--screenshots`)
- **Flexible Options:**
  - Support for HTTPS (`--https`)
  - Output to files (`--output`)
  - Custom port specification (`-p` or `--port`)

## Requirements
- Bash (Linux/macOS)
- The following tools must be installed and available in your PATH:
  - `gobuster`
  - `ffuf`
  - `subfinder`
  - `nmap`
  - `rustscan`
  - `httpx`
  - `zaproxy` (OWASP ZAP)
  - `subzy`
  - `nuclei`
  - `katana`
  - `wafw00f`
  - `gowitness`
  - `whatweb`
  - `dnsrecon`
- Wordlists (ensure these paths are correct or update them in the script):
  - `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
  - `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
  - `/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt`

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Thongheng/ReconX.git
   cd ReconX/XRecon
   ```
2. Make the script executable:
   ```bash
   chmod +x xRecon.sh
   ```

## Usage
```bash
./xRecon.sh <target> [scan_flag] [options]
```
  - `<target>`: A domain (e.g., `example.com`) or an IP address (e.g., `10.10.10.10`)

### Scan Flags (choose one):
  - `--all`: Run a full, automated workflow (subdomain enumeration > live host detection > screenshots).
  - `--nmap`: Perform comprehensive port scanning with Nmap.
  - `--rust`: Perform fast port scanning with Rustscan.
  - `--subfinder`: Perform passive subdomain enumeration.
  - `--gobuster-sub`: Perform active subdomain bruteforcing using Gobuster.
  - `--dns`: Perform DNS enumeration with Dnsrecon.
  - `--vhost`: Perform VHost scanning with Ffuf.
  - `--httpx`: Validate live web servers from a list of subdomains or a single target.
  - `--subzy`: Check for subdomain takeovers.
  - `--katana`: Perform web crawling.
  - `--dir`: Perform directory bruteforcing with Ffuf.
  - `--nuclei`: Perform vulnerability scanning.
  - `--zap`: Perform deep web application scanning with OWASP ZAP.
  - `--waf`: Detect Web Application Firewalls with Wafw00f.
  - `--screenshots`: Take screenshots of live web pages.
  - `--tech`: Perform technology fingerprinting with Whatweb.

### Options:
  - `--https`: Use HTTPS for URLs instead of HTTP (default is HTTP).
  - `--output`: Enable output files for commands that support it. Output files will be saved in the current directory.
  - `-p, --port PORT`: Specify a port number for tools that support it (e.g., `-p 8080`).
  - `-h, --help`: Show the help message.

## Examples

1. **Run a full automated workflow:**
   ```bash
   ./xRecon.sh example.com --all --output
   ```

2. **Perform Nmap scan on a specific port:**
   ```bash
   ./xRecon.sh 10.10.10.10 --nmap -p 80,443
   ```

3. **Find subdomains passively and save output:**
   ```bash
   ./xRecon.sh example.com --subfinder --output
   ```

4. **Perform directory bruteforcing over HTTPS:**
   ```bash
   ./xRecon.sh example.com --dir --https --output
   ```

5. **Check for WAF and technologies:**
   ```bash
   ./xRecon.sh example.com --waf
   ./xRecon.sh example.com --tech
   ```

## Output
Results are displayed in the terminal. If `--output` flag is used, results will also be saved to respective output files (e.g., `subfinder_output.txt`, `nmap_output.txt`, `screenshots/`).

## License
See [LICENSE](LICENSE) for details.

## Disclaimer
This tool is intended for authorized security testing and research only. Use responsibly and ensure you have permission to scan any target.
