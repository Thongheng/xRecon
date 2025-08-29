#!/bin/bash

# Color codes
C_HEADER='\033[95m'
C_OKCYAN='\033[96m'
C_OKGREEN='\033[92m'
C_WARNING='\033[93m'
C_FAIL='\033[91m'
C_ENDC='\033[0m'
C_BOLD='\033[1m'

# ==============================================================================
# --- SCRIPT CONFIGURATION ---
# ==============================================================================
TOOL_GOBUSTER="gobuster"
TOOL_FFUF="ffuf"
TOOL_SUBFINDER="subfinder"
TOOL_NMAP="nmap"
TOOL_RUSTSCAN="rustscan"
TOOL_HTTPX="httpx"
TOOL_ZAPROXY="zaproxy"
TOOL_SUBZY="subzy"
TOOL_NUCLEI="nuclei"
TOOL_KATANA="katana"
TOOL_WAFW00F="wafw00f"
TOOL_GOWITNESS="gowitness"
TOOL_WHATWEB="whatweb"
TOOL_DNSRECON="dnsrecon"
WORDLIST_DIR="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
WORDLIST_SUBDOMAIN="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
WORDLIST_VHOST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
# ==============================================================================
# --- End of Configuration ---
# ==============================================================================

# --- Helper function to check if a tool is installed ---
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${C_FAIL}Error: Command '$1' not found. Please ensure it is installed and in your PATH.${C_ENDC}"
        exit 1
    fi
}

# --- Helper function to validate domain or IP address format ---
validate_target() {
    # IPv4 regex pattern
    ipv4_pattern='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    # Domain regex pattern
    domain_pattern='^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if [[ "$1" =~ $ipv4_pattern ]]; then
        # Validate each octet is between 0-255
        IFS='.' read -ra ADDR <<< "$1"
        for i in "${ADDR[@]}"; do
            if [ "$i" -gt 255 ] || [ "$i" -lt 0 ]; then
                echo -e "${C_FAIL}Error: Invalid IP address format: $1${C_ENDC}"
                exit 1
            fi
        done
        return 0
    elif echo "$1" | grep -Pq "$domain_pattern"; then
        return 0
    else
        echo -e "${C_FAIL}Error: Invalid target format. Please provide a valid domain or IP address: $1${C_ENDC}"
        exit 1
    fi
}

# --- Usage/Help Function ---
usage() {
    echo -e "${C_BOLD}All-in-One Recon Tool${C_ENDC}"
    echo ""
    echo -e "${C_BOLD}USAGE:${C_ENDC}"
    echo "  $0 <target> [scan_flag]"
    echo "  where <target> can be a domain (example.com) or an IP address (10.10.10.10)"
    echo ""
    echo -e "${C_BOLD}SCAN FLAGS (use one):${C_ENDC}"
    echo "  --all                Run a full, automated workflow (subdomain enumeration > live host detection)."
    echo "  --nmap               Port Scanning"
    echo "  --rust               Fast Port Scanning with Rustscan"
    echo "  --subfinder          Passive Subdomain"
    echo "  --gobuster-sub       Active Subdomain (gobuster)"
    echo "  --dns                DNS Enum (dnsrecon)"
    echo "  --vhost              VHost Scanning (ffuf)"
    echo "  --httpx              Web Server Validation"
    echo "  --subzy              Subdomain Takeover"
    echo "  --katana             Web Crawling"
    echo "  --dir                Directory Bruteforcing (ffuf)"
    echo "  --nuclei             Vulnerability Scanning"
    echo "  --zap                Deep Web App Scanning (OWASP ZAP)"
    echo "  --waf                WAF Detection (wafw00f)"
    echo "  --screenshots        Screenshots of live web pages (gowitness)"
    echo "  --tech               Technology Fingerprinting (whatweb)"
    echo "  --https              Use HTTPS instead of HTTP for URLs (default is HTTP)"
    echo "  --output             Enable output files for commands that support it"
    echo "  -p, --port PORT      Specify port number for tools that support it"
    echo "  -h, --help           Show this help message"
    exit 1
}

# --- Argument Parsing ---
TARGET=""
SCAN_MODE=""
USE_HTTPS=false  # Default to HTTP unless --https is specified
OUTPUT_ENABLED=false  # Default to no output files unless --output is specified
PORT=""  # Default to no port specification

if [ "$#" -eq 0 ]; then
    echo -e "${C_FAIL}Error: No target or scan flag specified.${C_ENDC}"
    usage
fi

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --all) SCAN_MODE="all" ;;
        --nmap) SCAN_MODE="nmap" ;;
        --rust) SCAN_MODE="rust" ;;
        --subfinder) SCAN_MODE="subfinder" ;;
        --gobuster-sub) SCAN_MODE="gobuster-sub" ;;
        --dns) SCAN_MODE="dns" ;;
        --vhost) SCAN_MODE="vhost" ;;
        --httpx) SCAN_MODE="httpx" ;;
        --subzy) SCAN_MODE="subzy" ;;
        --katana) SCAN_MODE="katana" ;;
        --dir) SCAN_MODE="dir" ;;
        --nuclei) SCAN_MODE="nuclei" ;;
        --zap) SCAN_MODE="zap" ;;
        --waf) SCAN_MODE="waf" ;;
        --screenshots) SCAN_MODE="screenshots" ;;
        --tech) SCAN_MODE="tech" ;;
        --https) USE_HTTPS=true ;;
        --output) OUTPUT_ENABLED=true ;;
        -p|--port)
            shift
            if [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ] && [ "$1" -lt 65536 ]; then
                PORT="$1"
            else
                echo -e "${C_FAIL}Error: Invalid port number: $1. Port must be between 1-65535.${C_ENDC}"
                exit 1
            fi
            ;;
        -h|--help) usage ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            else
                echo -e "${C_FAIL}Error: Unknown argument or multiple targets specified: $1${C_ENDC}"
                usage
            fi
            ;;
    esac
    shift
done

# --- Validation ---
if [ -z "$TARGET" ]; then
    echo -e "${C_FAIL}Error: Target not specified.${C_ENDC}"
    usage
fi

if [ -z "$SCAN_MODE" ]; then
    echo -e "${C_FAIL}Error: No scan flag specified. Please provide a scan flag (e.g., --all, --nmap).${C_ENDC}"
    usage
fi

# Validate target format (domain or IP)
validate_target "$TARGET"

# --- Helper function to get output file parameter ---
get_output_param() {
    local tool="$1"
    local default_output="$2"
    
    if [ "$OUTPUT_ENABLED" = true ]; then
        case "$tool" in
            "subfinder"|"gobuster"|"dnsrecon"|"httpx"|"subzy"|"katana"|"nuclei")
                echo "-o $default_output"
                ;;
            "nmap")
                echo "-oN $default_output"
                ;;
            "ffuf")
                echo "-o $default_output"
                ;;
            *)
                echo ""
                ;;
        esac
    else
        echo ""
    fi
}

# --- Helper function to get URL prefix ---
get_url_prefix() {
    if [ "$USE_HTTPS" = true ]; then
        echo "https://"
    else
        echo "http://"
    fi
}

# --- Helper function to get port parameter ---
get_port_param() {
    local tool="$1"
    
    if [ -n "$PORT" ]; then
        case "$tool" in
            "nmap")
                echo "-p $PORT"
                ;;
            "httpx"|"katana"|"ffuf"|"gowitness"|"whatweb"|"zaproxy"|"nuclei"|"wafw00f")
                echo ":$PORT"
                ;;
            *)
                echo ""
                ;;
        esac
    else
        echo ""
    fi
}

# --- Command Execution Functions ---
execute_interactive() {
    # Auto-copy ONLY the command
    if command -v xclip >/dev/null 2>&1; then
        echo -n "$1" | xclip -selection clipboard
        echo "[+] Initial command copied to clipboard (xclip)"
    elif command -v xsel >/dev/null 2>&1; then
        echo -n "$1" | xsel --clipboard --input
        echo "[+] Initial command copied to clipboard (xsel)"
    elif command -v pbcopy >/dev/null 2>&1; then
        echo -n "$1" | pbcopy
        echo "[+] Initial command copied to clipboard (pbcopy)"
    elif command -v clip.exe >/dev/null 2>&1; then
        echo -n "$1" | clip.exe
        echo "[+] Initial command copied to clipboard (Windows/WSL)"
    else
        echo "[!] Clipboard tool not found — initial command NOT copied."
    fi

    echo -e "${C_HEADER}Edit command below and press Enter to run.${C_ENDC}"
    read -e -p "$(echo -e ${C_OKCYAN}'> '${C_ENDC})" -i "$1" final_command
    eval "$final_command"
    if [ $? -ne 0 ]; then
        echo -e "${C_FAIL}Error: Interactive command failed: $final_command${C_ENDC}"
        exit 1
    fi
}

# --- Automated Workflow ---
run_all_workflow() {
    echo -e "${C_HEADER}--- Starting Automated Workflow for $TARGET ---${C_ENDC}"

    # 1. Subfinder, Gobuster, and Dnsrecon in parallel
    echo -e "\n${C_OKCYAN}[WORKFLOW] Running Subfinder, Gobuster, and Dnsrecon in parallel for subdomain enumeration...${C_ENDC}"
    check_tool "$TOOL_SUBFINDER"
    check_tool "$TOOL_GOBUSTER"
    check_tool "$TOOL_DNSRECON"
    [ ! -f "$WORDLIST_SUBDOMAIN" ] && { echo -e "${C_FAIL}Error: Subdomain wordlist not found at '$WORDLIST_SUBDOMAIN'${C_ENDC}"; exit 1; }
    
    # Save original OUTPUT_ENABLED value to restore later
    local original_output=$OUTPUT_ENABLED
    
    # Force enable output for workflow
    OUTPUT_ENABLED=true
    
    execute_interactive "$TOOL_SUBFINDER -d $TARGET $(get_output_param subfinder subfinder_output.txt)" &
    execute_interactive "$TOOL_GOBUSTER dns -d $TARGET -w $WORDLIST_SUBDOMAIN $(get_output_param gobuster gobuster_subdomain_output.txt)" &
    execute_interactive "$TOOL_DNSRECON -d $TARGET -t brf -w $WORDLIST_SUBDOMAIN -f -n 8.8.8.8 -z $(get_output_param dnsrecon dnsrecon_output.txt)" &
    wait
    echo -e "${C_OKGREEN}Subfinder, Gobuster, and Dnsrecon finished. Results saved to subfinder_output.txt, gobuster_subdomain_output.txt, and dnsrecon_output.txt${C_ENDC}"

    # 2. Combine and Unique
    echo -e "\n${C_OKCYAN}[WORKFLOW] Combining and sorting results...${C_ENDC}"
    cat subfinder_output.txt gobuster_subdomain_output.txt dnsrecon_output.txt 2>/dev/null | sort -u > all_subdomains.txt
    echo -e "${C_OKGREEN}Combined unique subdomains saved to all_subdomains.txt${C_ENDC}"

    # 3. Httpx
    echo -e "\n${C_OKCYAN}[WORKFLOW] Running Httpx to find live web servers...${C_ENDC}"
    check_tool "$TOOL_HTTPX"
    PORT_PARAM=""
    [ -n "$PORT" ] && PORT_PARAM="-p $PORT"
    execute_interactive "$TOOL_HTTPX -l all_subdomains.txt $PORT_PARAM $(get_output_param httpx httpx_live_servers.txt)"
    echo -e "${C_OKGREEN}Httpx finished. Live web servers saved to httpx_live_servers.txt${C_ENDC}"

    # 4. Screenshots
    echo -e "\n${C_OKCYAN}[WORKFLOW] Taking screenshots with Gowitness...${C_ENDC}"
    check_tool "$TOOL_GOWITNESS"
    execute_interactive "$TOOL_GOWITNESS file -f httpx_live_servers.txt -P screenshots"
    echo -e "${C_OKGREEN}Gowitness finished. Screenshots saved to screenshots directory${C_ENDC}"
    
    # Restore original OUTPUT_ENABLED value
    OUTPUT_ENABLED=$original_output

    echo -e "\n${C_HEADER}--- Automated Workflow Finished ---${C_ENDC}"
    echo -e "${C_BOLD}Next steps suggestion:${C_ENDC}"
    echo "  - Review screenshots in screenshots directory."
    if [ "$OUTPUT_ENABLED" = true ]; then
        echo "  - Run --nuclei against 'httpx_live_servers.txt' for vulnerability scanning."
    else
        echo "  - Run --nuclei with --output against 'httpx_live_servers.txt' for vulnerability scanning with output files."
    fi
}

# --- Main Command Logic ---
if [ "$SCAN_MODE" = "all" ]; then
    run_all_workflow
    exit 0
fi

base_command=""

case "$SCAN_MODE" in
    "subfinder")
        check_tool "$TOOL_SUBFINDER"
        base_command="$TOOL_SUBFINDER -d $TARGET $(get_output_param subfinder subfinder_output.txt)"
        execute_interactive "$base_command"
        ;;
    "gobuster-sub")
        check_tool "$TOOL_GOBUSTER"
        [ ! -f "$WORDLIST_SUBDOMAIN" ] && { echo -e "${C_FAIL}Error: Subdomain wordlist not found at '$WORDLIST_SUBDOMAIN'${C_ENDC}"; exit 1; }
        base_command="$TOOL_GOBUSTER dns -d $TARGET -w $WORDLIST_SUBDOMAIN $(get_output_param gobuster gobuster_subdomain_output.txt)"
        execute_interactive "$base_command"
        ;;
    "dns")
        check_tool "$TOOL_DNSRECON"
        base_command="$TOOL_DNSRECON -d $TARGET -t brf -w $WORDLIST_SUBDOMAIN -f -n 8.8.8.8 $(get_output_param dns dnsrecon_output.txt)"
        execute_interactive "$base_command"
        ;;
    "httpx")
        check_tool "$TOOL_HTTPX"
        echo -e "${C_WARNING}Note: Httpx is best used with a list of hosts from another tool's output.${C_ENDC}"
        PORT_PARAM=""
        [ -n "$PORT" ] && PORT_PARAM="-p $PORT"
        base_command="$TOOL_HTTPX -u $(get_url_prefix)$TARGET $PORT_PARAM $(get_output_param httpx httpx_output.txt)"
        execute_interactive "$base_command"
        ;;
    "waf")
        check_tool "$TOOL_WAFW00F"
        TARGET_WITH_PORT="$TARGET"
        [ -n "$PORT" ] && TARGET_WITH_PORT="$TARGET:$PORT"
        base_command="$TOOL_WAFW00F -a $TARGET_WITH_PORT"
        execute_interactive "$base_command"
        ;;
    "tech")
        check_tool "$TOOL_WHATWEB"
        TARGET_WITH_PORT="$TARGET"
        [ -n "$PORT" ] && TARGET_WITH_PORT="$TARGET:$PORT"
        base_command="$TOOL_WHATWEB $TARGET_WITH_PORT"
        execute_interactive "$base_command"
        ;;
    "nmap")
        check_tool "$TOOL_NMAP"
        PORT_PARAM=""
        [ -n "$PORT" ] && PORT_PARAM="-p $PORT"
        base_command="$TOOL_NMAP -sV -sC -Pn -v $PORT_PARAM $TARGET $(get_output_param nmap nmap_output.txt)"
        execute_interactive "$base_command"
        ;;
    "rust")
        check_tool "$TOOL_RUSTSCAN"
        PORT_PARAM=""
        [ -n "$PORT" ] && PORT_PARAM="-p $PORT"
        base_command="$TOOL_RUSTSCAN -a $TARGET $PORT_PARAM --ulimit 5000"
        execute_interactive "$base_command"
        ;;
    "vhost")
        check_tool "$TOOL_FFUF"
        [ ! -f "$WORDLIST_VHOST" ] && { echo -e "${C_FAIL}Error: VHost wordlist not found at '$WORDLIST_VHOST'${C_ENDC}"; exit 1; }
        TARGET_WITH_PORT="$TARGET"
        [ -n "$PORT" ] && TARGET_WITH_PORT="$TARGET:$PORT"
        base_command="$TOOL_FFUF -u $(get_url_prefix)$TARGET_WITH_PORT -H 'Host:FUZZ.$TARGET' -w $WORDLIST_VHOST $(get_output_param ffuf ffuf_vhost_output.txt)"
        execute_interactive "$base_command"
        ;;
    "subzy")
        check_tool "$TOOL_SUBZY"
        if [ "$OUTPUT_ENABLED" = true ]; then
            [ ! -f "subfinder_output.txt" ] && { echo -e "${C_FAIL}Error: Run --subfinder with --output first to generate subfinder_output.txt${C_ENDC}"; exit 1; }
            base_command="$TOOL_SUBZY run --targets subfinder_output.txt $(get_output_param subzy subzy_output.txt)"
        else
            echo -e "${C_WARNING}Note: Without --output flag, you'll need to run subfinder with --output first and redirect output to a file.${C_ENDC}"
            base_command="$TOOL_SUBZY run"
        fi
        execute_interactive "$base_command"
        ;;
    "katana")
        check_tool "$TOOL_KATANA"
        TARGET_WITH_PORT="$TARGET"
        [ -n "$PORT" ] && TARGET_WITH_PORT="$TARGET:$PORT"
        base_command="$TOOL_KATANA -u $(get_url_prefix)$TARGET_WITH_PORT -d 5 $(get_output_param katana katana_output.txt)"
        execute_interactive "$base_command"
        ;;
    "dir")
        check_tool "$TOOL_FFUF"
        [ ! -f "$WORDLIST_DIR" ] && { echo -e "${C_FAIL}Error: Directory wordlist not found at '$WORDLIST_DIR'${C_ENDC}"; exit 1; }
        TARGET_WITH_PORT="$TARGET"
        [ -n "$PORT" ] && TARGET_WITH_PORT="$TARGET:$PORT"
        base_command="$TOOL_FFUF -u $(get_url_prefix)$TARGET_WITH_PORT/FUZZ -w $WORDLIST_DIR $(get_output_param ffuf ffuf_dir_output.txt)"
        execute_interactive "$base_command"
        ;;
    "nuclei")
        check_tool "$TOOL_NUCLEI"
        TARGET_WITH_PORT="$TARGET"
        [ -n "$PORT" ] && TARGET_WITH_PORT="$TARGET:$PORT"
        base_command="$TOOL_NUCLEI -u $TARGET_WITH_PORT $(get_output_param nuclei nuclei_output.txt)"
        execute_interactive "$base_command"
        ;;
    "zap")
        check_tool "$TOOL_ZAPROXY"
        echo -e "${C_WARNING}Note: ZAP output must be configured manually (e.g., add '-quickreport report.html')${C_ENDC}"
        TARGET_WITH_PORT="$TARGET"
        [ -n "$PORT" ] && TARGET_WITH_PORT="$TARGET:$PORT"
        base_command="$TOOL_ZAPROXY -cmd -quickurl $(get_url_prefix)$TARGET_WITH_PORT"
        execute_interactive "$base_command"
        ;;
    "screenshots")
        check_tool "$TOOL_GOWITNESS"
        if [ "$OUTPUT_ENABLED" = true ]; then
            echo -e "${C_WARNING}This tool requires a file with a list of URLs (e.g., from --all or --httpx with --output).${C_ENDC}"
            base_command="$TOOL_GOWITNESS file -f httpx_live_servers.txt -P screenshots"
        else
            echo -e "${C_WARNING}Note: Without --output flag, you'll need to specify a URL or file manually.${C_ENDC}"
            TARGET_WITH_PORT="$TARGET"
            [ -n "$PORT" ] && TARGET_WITH_PORT="$TARGET:$PORT"
            base_command="$TOOL_GOWITNESS single $(get_url_prefix)$TARGET_WITH_PORT -P screenshots"
        fi
        execute_interactive "$base_command"
        ;;
esac