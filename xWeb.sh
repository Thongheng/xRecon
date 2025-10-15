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
    local target_input="$1"
    local host=""
    local port=""

    # Remove http(s):// prefix
    target_input=$(echo "$target_input" | sed -E 's/^(http|https):\/\///i')

    # Separate host and port if a port is present
    if [[ "$target_input" =~ :([0-9]+)$ ]]; then
        port="${BASH_REMATCH[1]}"
        host=$(echo "$target_input" | sed -E 's/:[0-9]+$//')
    else
        host="$target_input"
    fi

    # IPv4 regex pattern
    ipv4_pattern='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    # Domain regex pattern
    domain_pattern='^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if [[ "$host" =~ $ipv4_pattern ]]; then
        # Validate each octet is between 0-255
        IFS='.' read -ra ADDR <<< "$host"
        for i in "${ADDR[@]}"; do
            if [ "$i" -gt 255 ] || [ "$i" -lt 0 ]; then
                echo -e "${C_FAIL}Error: Invalid IP address format in host: $host${C_ENDC}"
                exit 1
            fi
        done
    elif ! echo "$host" | grep -Pq "$domain_pattern"; then
        echo -e "${C_FAIL}Error: Invalid domain format in host: $host${C_ENDC}"
        exit 1
    fi

    # Validate port if present
    if [ -n "$port" ]; then
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            echo -e "${C_FAIL}Error: Invalid port number: $port. Port must be between 1-65535.${C_ENDC}"
            exit 1
        fi
    fi
    
    # Update TARGET and PORT global variables
    TARGET="$host"
    [ -n "$port" ] && PORT="$port"

    return 0
}

# --- Usage/Help Function ---
usage() {
    echo -e "${C_BOLD}All-in-One Recon Tool${C_ENDC}"
    echo ""
    echo -e "${C_BOLD}USAGE:${C_ENDC}"
    echo "  $0 <target> [scan_flag]"
    echo "  where <target> can be:"
    echo "    - IP address (e.g., 10.10.10.10)"
    echo "    - Domain name (e.g., example.com)"
    echo "    - Domain with port (e.g., example.com:8080)"
    echo "    - URL with HTTP/HTTPS (e.g., http://example.com, https://example.com:8443)"
    echo ""
    echo -e "${C_BOLD}SCAN FLAGS (use one):${C_ENDC}"
    echo "  --all                Run a full, automated workflow (subdomain enumeration > live host detection)."
    echo "  -subfinder           Passive Subdomain"
    echo "  -gobuster-dns        Active Subdomain (gobuster)"
    echo "  -dns                 DNS Enum (dnsrecon)"
    echo "  -ffuf-vhost          VHost Scanning (ffuf)"
    echo "  -gobuster-vhost      VHost Scanning (gobuster)"
    echo "  -httpx               Web Server Validation"
    echo "  -subzy               Subdomain Takeover"
    echo "  -katana              Web Crawling"
    echo "  -dir                 Directory Bruteforcing (ffuf)"
    echo "  -nuclei              Vulnerability Scanning"
    echo "  -zap                 Deep Web App Scanning (OWASP ZAP)"
    echo "  -waf                 WAF Detection (wafw00f)"
    echo "  -screenshots         Screenshots of live web pages (gowitness)"
    echo "  -tech                Technology Fingerprinting (whatweb)"
    echo "  -output              Enable output files for commands that support it"
    echo "  -h, --help           Show this help message"
    echo "  -c                   Copy the command to clipboard instead of executing"
    exit 1
}

# --- Argument Parsing ---
TARGET=""
SCAN_MODE=""
OUTPUT_ENABLED=false  # Default to no output files unless --output is specified
COPY_COMMAND=false  # Default to not copying commands

if [ "$#" -eq 0 ]; then
    echo -e "${C_FAIL}Error: No target or scan flag specified.${C_ENDC}"
    usage
fi

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -all|--all) SCAN_MODE="all" ;;
        -nmap|--nmap) SCAN_MODE="nmap" ;;
        -rust|--rust) SCAN_MODE="rust" ;;
        -subfinder|--subfinder) SCAN_MODE="subfinder" ;;
    -gobuster-dns|--gobuster-dns) SCAN_MODE="gobuster-dns" ;;
    -gobuster-vhost|--gobuster-vhost) SCAN_MODE="gobuster-vhost" ;;
        -dns|--dns) SCAN_MODE="dns" ;;
        -ffuf-vhost|--ffuf-vhost) SCAN_MODE="vhost" ;;
        -httpx|--httpx) SCAN_MODE="httpx" ;;
        -subzy|--subzy) SCAN_MODE="subzy" ;;
        -katana|--katana) SCAN_MODE="katana" ;;
        -dir|--dir) SCAN_MODE="dir" ;;
        -nuclei|--nuclei) SCAN_MODE="nuclei" ;;
        -zap|--zap) SCAN_MODE="zap" ;;
        -waf|--waf) SCAN_MODE="waf" ;;
        -screenshots|--screenshots) SCAN_MODE="screenshots" ;;
        -tech|--tech) SCAN_MODE="tech" ;;
        -output|--output) OUTPUT_ENABLED=true ;;
        -c) COPY_COMMAND=true ;;
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
    if [[ "$TARGET" =~ ^https:// ]]; then
        echo "https://"
    else
        echo "http://"
    fi
}

# --- Command Execution Functions ---
execute_interactive() {
    local cmd="$1"
    echo -e "${C_OKCYAN}Running: $cmd${C_ENDC}"
    if [ "$COPY_COMMAND" = true ]; then
        if command -v xclip >/dev/null 2>&1; then
            echo -n "$cmd" | xclip -selection clipboard
            echo "[+] Command copied to clipboard (xclip)"
        elif command -v xsel >/dev/null 2>&1; then
            echo -n "$cmd" | xsel --clipboard --input
            echo "[+] Command copied to clipboard (xsel)"
        elif command -v pbcopy >/dev/null 2>&1; then
            echo -n "$cmd" | pbcopy
            echo "[+] Command copied to clipboard (pbcopy)"
        elif command -v clip.exe >/dev/null 2>&1; then
            echo -n "$cmd" | clip.exe
            echo "[+] Command copied to clipboard (Windows/WSL)"
        else
            echo "[!] Clipboard tool not found — command NOT copied."
        fi
    else
        eval "$cmd"
        if [ $? -ne 0 ]; then
            echo -e "${C_FAIL}Error: Command failed: $cmd${C_ENDC}"
            exit 1
        fi
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
    local PORT_PARAM=""
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
        echo "  - Run -nuclei against 'httpx_live_servers.txt' for vulnerability scanning."
    else
        echo "  - Run -nuclei with -output against 'httpx_live_servers.txt' for vulnerability scanning with output files."
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
    "gobuster-dns")
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
        local PORT_PARAM=""
        [ -n "$PORT" ] && PORT_PARAM="-p $PORT"
        base_command="$TOOL_HTTPX -u $(get_url_prefix)$TARGET $PORT_PARAM $(get_output_param httpx httpx_output.txt)"
        execute_interactive "$base_command"
        ;;
    "waf")
        check_tool "$TOOL_WAFW00F"
        base_command="$TOOL_WAFW00F -a $(get_url_prefix)$TARGET${PORT:+:$PORT}"
        execute_interactive "$base_command"
        ;;
    "tech")
        check_tool "$TOOL_WHATWEB"
        base_command="$TOOL_WHATWEB $(get_url_prefix)$TARGET${PORT:+:$PORT}"
        execute_interactive "$base_command"
        ;;
    "vhost")
        check_tool "$TOOL_FFUF"
        [ ! -f "$WORDLIST_VHOST" ] && { echo -e "${C_FAIL}Error: VHost wordlist not found at '$WORDLIST_VHOST'${C_ENDC}"; exit 1; }
        base_command="$TOOL_FFUF -u $(get_url_prefix)$TARGET${PORT:+:$PORT} -H 'Host:FUZZ.$TARGET' -w $WORDLIST_VHOST -ic $(get_output_param ffuf ffuf_vhost_output.txt)"
        execute_interactive "$base_command"
        ;;
    "gobuster-vhost")
        check_tool "$TOOL_GOBUSTER"
        [ ! -f "$WORDLIST_VHOST" ] && { echo -e "${C_FAIL}Error: VHost wordlist not found at '$WORDLIST_VHOST'${C_ENDC}"; exit 1; }
        # Gobuster vhost mode uses 'vhost' command and a wordlist; output parameter supported
        base_command="$TOOL_GOBUSTER vhost -u $(get_url_prefix)$TARGET${PORT:+:$PORT} -w $WORDLIST_VHOST --append-domain $(get_output_param gobuster gobuster_vhost_output.txt)"
        execute_interactive "$base_command"
        ;;
    "subzy")
        check_tool "$TOOL_SUBZY"
        if [ "$OUTPUT_ENABLED" = true ]; then
            [ ! -f "subfinder_output.txt" ] && { echo -e "${C_FAIL}Error: Run -subfinder with -output first to generate subfinder_output.txt${C_ENDC}"; exit 1; }
            base_command="$TOOL_SUBZY run --targets subfinder_output.txt $(get_output_param subzy subzy_output.txt)"
        else
            echo -e "${C_WARNING}Note: Without -output flag, you'll need to run subfinder with -output first and redirect output to a file.${C_ENDC}"
            base_command="$TOOL_SUBZY run"
        fi
        execute_interactive "$base_command"
        ;;
    "katana")
        check_tool "$TOOL_KATANA"
        base_command="$TOOL_KATANA -u $(get_url_prefix)$TARGET${PORT:+:$PORT} -d 5 $(get_output_param katana katana_output.txt)"
        execute_interactive "$base_command"
        ;;
    "dir")
        check_tool "$TOOL_FFUF"
        [ ! -f "$WORDLIST_DIR" ] && { echo -e "${C_FAIL}Error: Directory wordlist not found at '$WORDLIST_DIR'${C_ENDC}"; exit 1; }
        base_command="$TOOL_FFUF -u $(get_url_prefix)$TARGET${PORT:+:$PORT}/FUZZ -w $WORDLIST_DIR -ic $(get_output_param ffuf ffuf_dir_output.txt)"
        execute_interactive "$base_command"
        ;;
    "nuclei")
        check_tool "$TOOL_NUCLEI"
        base_command="$TOOL_NUCLEI -u $(get_url_prefix)$TARGET${PORT:+:$PORT} $(get_output_param nuclei nuclei_output.txt)"
        execute_interactive "$base_command"
        ;;
    "zap")
        check_tool "$TOOL_ZAPROXY"
        echo -e "${C_WARNING}Note: ZAP output must be configured manually (e.g., add '-quickreport report.html')${C_ENDC}"
        base_command="$TOOL_ZAPROXY -cmd -quickurl $(get_url_prefix)$TARGET${PORT:+:$PORT}"
        execute_interactive "$base_command"
        ;;
    "screenshots")
        check_tool "$TOOL_GOWITNESS"
        if [ "$OUTPUT_ENABLED" = true ]; then
            echo -e "${C_WARNING}This tool requires a file with a list of URLs (e.g., from -all or -httpx with -output).${C_ENDC}"
            base_command="$TOOL_GOWITNESS file -f httpx_live_servers.txt -P screenshots"
        else
            echo -e "${C_WARNING}Note: Without -output flag, you'll need to specify a URL or file manually.${C_ENDC}"
            base_command="$TOOL_GOWITNESS single $(get_url_prefix)$TARGET${PORT:+:$PORT} -P screenshots"
        fi
        execute_interactive "$base_command"
        ;;
esac