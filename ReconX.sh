#!/bin/bash

# Color codes
C_HEADER='\033[95m'
C_OKBLUE='\033[94m'
C_OKCYAN='\033[96m'
C_OKGREEN='\033[92m'
C_WARNING='\033[93m'
C_FAIL='\033[91m'
C_ENDC='\033[0m'
C_BOLD='\033[1m'

# --- Default Tool and Wordlist Paths ---
TOOL_FFUF="ffuf"
TOOL_SUBFINDER="subfinder"
TOOL_NMAP="nmap"
TOOL_HTTPX="httpx"
TOOL_ZAPROXY="zaproxy"
TOOL_SUBZY="subzy"
TOOL_NUCLEI="nuclei"
TOOL_KATANA="katana"
WORDLIST_DIR="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
WORDLIST_SUBDOMAIN="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
WORDLIST_VHOST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"


# --- Function to load config from the script's directory ---
load_config() {
    SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
    CONFIG_FILE="$SCRIPT_DIR/recon.conf"
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        echo -e "${C_OKBLUE}Info: Config file not found at '$CONFIG_FILE'. Using default tool paths.${C_ENDC}"
    fi
}

# --- Helper function to check if a tool is installed ---
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${C_FAIL}Error: Command '$1' not found. Please ensure it is installed and in your PATH.${C_ENDC}"
        exit 1
    fi
}

# --- Menu Functions ---
display_menu() {
    echo -e "\n${C_HEADER}${C_BOLD}All-in-One Recon Tool (Bash Edition)${C_ENDC}"
    echo "1. Network Port Scanning - Nmap"
    echo -e "2. ${C_BOLD}Passive${C_ENDC} Subdomain Enumeration - Subfinder"
    echo -e "3. ${C_BOLD}Active${C_ENDC} Subdomain Enumeration - ffuf"
    echo "4. VHost Scanning - ffuf"
    echo "5. Web Server Validation (HTTP/HTTPS) - Httpx"
    echo "6. Subdomain Takeover Check - Subzy"
    echo "7. Web Crawling - Katana"
    echo "8. Directory Brute-Forcing - ffuf"
    echo "9. Vulnerability Scanning - Nuclei"
    echo "10. Deep Web App Scanning - OWASP ZAP"
    echo -e "${C_HEADER}------------------------------------------${C_ENDC}"
    echo "0. Exit"
    echo -ne "${C_WARNING}Select an option: ${C_ENDC}"
    read choice
}

display_post_scan_menu() {
    echo -e "\n${C_HEADER}${C_BOLD}Scan Finished${C_ENDC}"
    echo "1. Continue (Return to main menu)"
    echo "2. Quit"
    echo -ne "${C_WARNING}Select an option: ${C_ENDC}"
    read choice
}

# --- Load Configuration ---
load_config

# --- Argument Parsing ---
TARGET=""
OUTPUT_DIR="."

if [ -n "$1" ]; then
    TARGET=$1
else
    # ROBUST PROMPT: Use simple echo and read on separate lines.
    echo -e -n "${C_WARNING}Enter target (e.g., example.com or IP): ${C_ENDC}"
    read TARGET
fi

if [ -z "$TARGET" ]; then
    echo -e "${C_FAIL}Error: Target is required.${C_ENDC}"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# --- Main Loop ---
post_scan_mode=0
while true; do
    if [ "$post_scan_mode" -eq 1 ]; then
        display_post_scan_menu
        case "$choice" in
            1) post_scan_mode=0 ;;
            2) echo "Exiting..."; break ;;
            *) echo -e "${C_FAIL}Invalid option. Please try again.${C_ENDC}" ;;
        esac
    else
        display_menu
        base_command=""
        
        case "$choice" in
            0) echo "Exiting..."; break ;;
            1) # Nmap
                check_tool "$TOOL_NMAP"
                base_command="$TOOL_NMAP -sV -T4 $TARGET -oN $OUTPUT_DIR/nmap_output.txt"
                ;;
            2) # Subfinder
                check_tool "$TOOL_SUBFINDER"
                base_command="$TOOL_SUBFINDER -d $TARGET -o $OUTPUT_DIR/subfinder_output.txt"
                ;;
            3) # ffuf Active Subdomain
                check_tool "$TOOL_FFUF"
                [ ! -f "$WORDLIST_SUBDOMAIN" ] && { echo -e "${C_FAIL}Error: Subdomain wordlist not found at '$WORDLIST_SUBDOMAIN'${C_ENDC}"; continue; }
                base_command="$TOOL_FFUF -u http://FUZZ.$TARGET -w $WORDLIST_SUBDOMAIN -o $OUTPUT_DIR/ffuf_subdomain_output.json -of json"
                ;;
            4) # ffuf VHost
                check_tool "$TOOL_FFUF"
                [ ! -f "$WORDLIST_VHOST" ] && { echo -e "${C_FAIL}Error: VHost wordlist not found at '$WORDLIST_VHOST'${C_ENDC}"; continue; }
                base_command="$TOOL_FFUF -u http://$TARGET -H 'Host:FUZZ.$TARGET' -w $WORDLIST_VHOST -o $OUTPUT_DIR/ffuf_vhost_output.json -of json"
                ;;
            5) # Httpx
                check_tool "$TOOL_HTTPX"
                echo -e "${C_WARNING}Note: Httpx is best used with a list of hosts. E.g., subfinder -d $TARGET | httpx ${C_ENDC}"
                base_command="$TOOL_HTTPX -u http://$TARGET -o $OUTPUT_DIR/httpx_output.txt"
                ;;
            6) # Subzy
                check_tool "$TOOL_SUBZY"
                SUBFINDER_OUTPUT="$OUTPUT_DIR/subfinder_output.txt"
                [ ! -f "$SUBFINDER_OUTPUT" ] && { echo -e "${C_FAIL}Error: Run Subfinder (option 2) first to generate $SUBFINDER_OUTPUT${C_ENDC}"; continue; }
                base_command="$TOOL_SUBZY run --targets $SUBFINDER_OUTPUT --output $OUTPUT_DIR/subzy_output.txt"
                ;;
            7) # Katana
                check_tool "$TOOL_KATANA"
                base_command="$TOOL_KATANA -u http://$TARGET -d 5 -o $OUTPUT_DIR/katana_output.txt"
                ;;
            8) # ffuf Directory
                check_tool "$TOOL_FFUF"
                [ ! -f "$WORDLIST_DIR" ] && { echo -e "${C_FAIL}Error: Directory wordlist not found at '$WORDLIST_DIR'${C_ENDC}"; continue; }
                base_command="$TOOL_FFUF -u http://$TARGET/FUZZ -w $WORDLIST_DIR -o $OUTPUT_DIR/ffuf_dir_output.json -of json"
                ;;
            9) # Nuclei
                check_tool "$TOOL_NUCLEI"
                base_command="$TOOL_NUCLEI -u $TARGET -o $OUTPUT_DIR/nuclei_output.txt"
                ;;
            10) # OWASP ZAP
                check_tool "$TOOL_ZAPROXY"
                base_command="$TOOL_ZAPROXY -cmd -quickurl http://$TARGET -quickreport $OUTPUT_DIR/zap_report.html"
                ;;
            *)
                echo -e "${C_FAIL}Invalid option. Please try again.${C_ENDC}"
                continue
                ;;
        esac

        if [ -n "$base_command" ]; then
            echo -e "\n${C_OKBLUE}Edit command below or press Enter to run.${C_ENDC}"
            echo -e "${C_OKBLUE}(Press Ctrl+D at empty prompt to cancel)${C_ENDC}"
            
            read -e -p "$(echo -e ${C_OKCYAN}'> '${C_ENDC})" -i "$base_command" final_command

            if [ -n "$final_command" ]; then
                echo -e "\n${C_OKCYAN}Executing command: $final_command${C_ENDC}\n"
                eval "$final_command"
                post_scan_mode=1
            else
                echo "Operation cancelled."
            fi
        fi
    fi
done