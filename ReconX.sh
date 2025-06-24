#!/bin/bash

# A class to hold ANSI color codes for terminal output
C_HEADER='\033[95m'
C_OKBLUE='\033[94m'
C_OKCYAN='\033[96m'
C_OKGREEN='\033[92m'
C_WARNING='\033[93m'
C_FAIL='\033[91m'
C_ENDC='\033[0m'
C_BOLD='\033[1m'

# ==============================================================================
# --- SCRIPT CONFIGURATION ---
# All tool paths and wordlist paths are defined here.
# Edit these variables directly to change the script's behavior.
# ==============================================================================

# --- Tool Paths (use command name if in PATH, or an absolute path) ---
TOOL_FFUF="ffuf"
TOOL_SUBFINDER="subfinder"
TOOL_NMAP="nmap"
TOOL_HTTPX="httpx"
TOOL_ZAPROXY="zaproxy"
TOOL_SUBZY="subzy"
TOOL_NUCLEI="nuclei"
TOOL_KATANA="katana"

# --- Wordlist Paths ---
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

# --- Argument Parsing ---
TARGET=""
# Use a more descriptive name for the output directory variable
PROJECT_DIR="."

if [ -n "$1" ]; then
    TARGET=$1
else
    echo -ne "${C_WARNING}Enter target (e.g., example.com or IP): ${C_ENDC}"
    read TARGET
fi

if [ -z "$TARGET" ]; then
    echo -e "${C_FAIL}Error: Target is required.${C_ENDC}"
    exit 1
fi

# Create a directory for the target to keep results organized
PROJECT_DIR="$TARGET-recon"
mkdir -p "$PROJECT_DIR"
echo -e "${C_OKBLUE}Results will be saved in: ${PROJECT_DIR}${C_ENDC}"


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
                base_command="$TOOL_NMAP -sV -T4 $TARGET -oN $PROJECT_DIR/nmap_output.txt"
                ;;
            2) # Subfinder
                check_tool "$TOOL_SUBFINDER"
                base_command="$TOOL_SUBFINDER -d $TARGET -o $PROJECT_DIR/subfinder_output.txt"
                ;;
            3) # ffuf Active Subdomain
                check_tool "$TOOL_FFUF"
                [ ! -f "$WORDLIST_SUBDOMAIN" ] && { echo -e "${C_FAIL}Error: Subdomain wordlist not found at '$WORDLIST_SUBDOMAIN'${C_ENDC}"; continue; }
                base_command="$TOOL_FFUF -u http://FUZZ.$TARGET -w $WORDLIST_SUBDOMAIN -o $PROJECT_DIR/ffuf_subdomain_output.json -of json"
                ;;
            4) # ffuf VHost
                check_tool "$TOOL_FFUF"
                [ ! -f "$WORDLIST_VHOST" ] && { echo -e "${C_FAIL}Error: VHost wordlist not found at '$WORDLIST_VHOST'${C_ENDC}"; continue; }
                base_command="$TOOL_FFUF -u http://$TARGET -H 'Host:FUZZ.$TARGET' -w $WORDLIST_VHOST -o $PROJECT_DIR/ffuf_vhost_output.json -of json"
                ;;
            5) # Httpx
                check_tool "$TOOL_HTTPX"
                echo -e "${C_WARNING}Note: Httpx is best used with a list of hosts from another tool's output.${C_ENDC}"
                base_command="$TOOL_HTTPX -u http://$TARGET -o $PROJECT_DIR/httpx_output.txt"
                ;;
            6) # Subzy
                check_tool "$TOOL_SUBZY"
                SUBFINDER_OUTPUT="$PROJECT_DIR/subfinder_output.txt"
                [ ! -f "$SUBFINDER_OUTPUT" ] && { echo -e "${C_FAIL}Error: Run Subfinder (option 2) first to generate $SUBFINDER_OUTPUT${C_ENDC}"; continue; }
                base_command="$TOOL_SUBZY run --targets $SUBFINDER_OUTPUT --output $PROJECT_DIR/subzy_output.txt"
                ;;
            7) # Katana
                check_tool "$TOOL_KATANA"
                base_command="$TOOL_KATANA -u http://$TARGET -d 5 -o $PROJECT_DIR/katana_output.txt"
                ;;
            8) # ffuf Directory
                check_tool "$TOOL_FFUF"
                [ ! -f "$WORDLIST_DIR" ] && { echo -e "${C_FAIL}Error: Directory wordlist not found at '$WORDLIST_DIR'${C_ENDC}"; continue; }
                base_command="$TOOL_FFUF -u http://$TARGET/FUZZ -w $WORDLIST_DIR -o $PROJECT_DIR/ffuf_dir_output.json -of json"
                ;;
            9) # Nuclei
                check_tool "$TOOL_NUCLEI"
                base_command="$TOOL_NUCLEI -u $TARGET -o $PROJECT_DIR/nuclei_output.txt"
                ;;
            10) # OWASP ZAP
                check_tool "$TOOL_ZAPROXY"
                base_command="$TOOL_ZAPROXY -cmd -quickurl http://$TARGET -quickreport $PROJECT_DIR/zap_report.html"
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
                # Use eval to correctly execute the command string with all its arguments and redirections
                eval "$final_command"
                post_scan_mode=1
            else
                echo "Operation cancelled."
            fi
        fi
    fi
done