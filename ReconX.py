import subprocess
import argparse
import sys
import os
from pathlib import Path
import shutil
import yaml
import threading
import select

# A class to hold ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'  # Yellow
    FAIL = '\033[91m'      # Red
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def check_tool(tool_path):
    """Check if a tool is installed at the specified path."""
    if not shutil.which(tool_path):
        print(f"{Colors.FAIL}Error: {tool_path} is not installed. Please install it first.{Colors.ENDC}")
        sys.exit(1)

def run_tool(command, output_file):
    """
    Run a command, display its output in real-time, and only save the output
    to a file if the command completes successfully without being cancelled.
    """
    print(f"\n{Colors.OKCYAN}Running command: {' '.join(command)}{Colors.ENDC}\n")

    stop_event = threading.Event()
    process = None
    output_lines = []

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1,
        )

        def monitor_and_stream_output(lines_buffer):
            for line in process.stdout:
                if stop_event.is_set():
                    break
                sys.stdout.write(line)
                lines_buffer.append(line)
        
        output_thread = threading.Thread(target=monitor_and_stream_output, args=(output_lines,))
        output_thread.start()

        print(f"{Colors.HEADER}---{Colors.ENDC}")
        print(f"{Colors.OKBLUE}>>> Tool is running. Type 'q' and press Enter to cancel (output will not be saved).{Colors.ENDC}")
        print(f"{Colors.HEADER}---\n{Colors.ENDC}")
        
        while output_thread.is_alive():
            try:
                rlist, _, _ = select.select([sys.stdin], [], [], 1.0)
                if rlist:
                    user_input = sys.stdin.readline().strip().lower()
                    if user_input == 'q':
                        print(f"\n{Colors.WARNING}[INFO] 'q' received. Cancelling operation...{Colors.ENDC}")
                        stop_event.set()
                        break
            except (EOFError, KeyboardInterrupt):
                print(f"\n{Colors.WARNING}[INFO] Interruption detected. Cancelling operation...{Colors.ENDC}")
                stop_event.set()
                break

    except FileNotFoundError:
        print(f"{Colors.FAIL}Error: Command '{command[0]}' not found. Please ensure it is installed and in your system's PATH.{Colors.ENDC}")
        return
    except Exception as e:
        print(f"{Colors.FAIL}An unexpected error occurred: {e}{Colors.ENDC}")
        return
    finally:
        if process and stop_event.is_set():
            process.terminate()

        if 'output_thread' in locals() and output_thread.is_alive():
            output_thread.join()
        
        return_code = process.wait() if process else -1

        if not stop_event.is_set() and return_code == 0:
            print(f"\n{Colors.OKGREEN}Command completed successfully. Saving output to {output_file}...{Colors.ENDC}")
            try:
                with open(output_file, "w") as f:
                    f.writelines(output_lines)
                print(f"{Colors.OKGREEN}Results saved to {output_file}{Colors.ENDC}")
            except IOError as e:
                print(f"\n{Colors.FAIL}Error: Could not write to file {output_file}. {e}{Colors.ENDC}")
        elif stop_event.is_set():
            print(f"{Colors.WARNING}\nOperation cancelled by user. Output was NOT saved.{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}\nCommand finished with an error (code: {return_code}). Output was NOT saved.{Colors.ENDC}")


def display_menu():
    """Display the tool selection menu."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}All-in-One Recon Tool{Colors.ENDC}")
    print(f"1. {Colors.BOLD}Active{Colors.ENDC} Subdomain Enumeration - ffuf")
    print(f"2. {Colors.BOLD}Passive{Colors.ENDC} Subdomain Enumeration - Subfinder")
    print("3. Network Scanning - Nmap")
    print("4. Web Server Validation - Httpx")
    print("5. Web App Scanning - OWASP ZAP")
    print("6. Directory Brute-Forcing - ffuf")
    print("7. Subdomain Takeover Check - Subzy")
    print("8. Vulnerability Scanning - Nuclei")
    print("9. VHost Scanning - ffuf")
    print("10. Web Crawling - Katana")
    print("0. Exit")
    return input(f"{Colors.WARNING}Select an option: {Colors.ENDC}")

def display_post_scan_menu():
    """Displays a simplified menu after a scan is complete."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}Scan Finished{Colors.ENDC}")
    print("1. Continue (Return to main menu)")
    print("2. Quit")
    return input(f"{Colors.WARNING}Select an option: {Colors.ENDC}")

def load_config():
    """Load configuration from config.yaml, located in the same directory as the script."""
    try:
        script_dir = Path(__file__).resolve().parent
        config_file_path = script_dir / "config.yaml"
        with open(config_file_path, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"{Colors.OKBLUE}Info: Config file not found at '{config_file_path}'. Using default tool paths.{Colors.ENDC}")
        return {}
    except yaml.YAMLError as e:
        print(f"{Colors.FAIL}Error parsing config file '{config_file_path}': {e}{Colors.ENDC}")
        sys.exit(1)

def get_editable_command(base_command):
    """
    Displays the base command and allows the user to edit it in real-time.
    """
    # readline is a standard library on Linux/macOS that provides editable input fields
    try:
        import readline
        initial_text = ' '.join(base_command)
        
        # This function pre-fills the input buffer for the user
        def startup_hook():
            readline.insert_text(initial_text)

        readline.set_startup_hook(startup_hook)
        
        prompt = (
            f"\n{Colors.OKBLUE}Edit command below or press Enter to run."
            f"\n(Press Ctrl+C to cancel){Colors.ENDC}\n{Colors.OKCYAN}> {Colors.ENDC}"
        )
        final_command_str = input(prompt)
        
        # Must clear the hook so it doesn't affect the next input() call
        readline.set_startup_hook()

        return final_command_str.split()

    except ImportError:
        # Fallback for systems without readline (like default Windows)
        print(f"\n{Colors.OKCYAN}Base command: {' '.join(base_command)}{Colors.ENDC}")
        add_args = input(f"{Colors.WARNING}Add arguments or press Enter: {Colors.ENDC}")
        return base_command + add_args.split()
    except KeyboardInterrupt:
        # User pressed Ctrl+C
        print("\nOperation cancelled.")
        return None


def main():
    parser = argparse.ArgumentParser(description="All-in-One Recon Tool")
    parser.add_argument("target", nargs="?", help="Target domain or IP (e.g., example.com or 192.168.1.1)")
    parser.add_argument("-o", "--output", default=".", help="Output directory (default: current directory)")
    args = parser.parse_args()

    config = load_config()
    default_tools = {
        "ffuf": "ffuf",
        "subfinder": "subfinder",
        "nmap": "nmap",
        "httpx": "httpx",
        "zaproxy": "zaproxy",
        "subzy": "subzy",
        "nuclei": "nuclei",
        "katana": "katana",
        "ffuf_wordlist_dir": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "ffuf_wordlist_subdomain": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "ffuf_wordlist_vhost": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    }
    
    tools_config = config.get("tools", {})
    tools = default_tools.copy()
    for tool_name in ["ffuf", "subfinder", "nmap", "httpx", "zaproxy", "subzy", "nuclei", "katana"]:
        tools[tool_name] = tools_config.get(tool_name, {}).get("path", default_tools[tool_name])
    
    ffuf_config = tools_config.get("ffuf", {})
    tools["ffuf_wordlist_dir"] = ffuf_config.get("wordlist_dir", default_tools["ffuf_wordlist_dir"])
    tools["ffuf_wordlist_subdomain"] = ffuf_config.get("wordlist_subdomain", default_tools["ffuf_wordlist_subdomain"])
    tools["ffuf_wordlist_vhost"] = ffuf_config.get("wordlist_vhost", default_tools["ffuf_wordlist_vhost"])

    target = args.target
    if not target:
        target = input(f"{Colors.WARNING}Enter target (e.g., example.com or IP): {Colors.ENDC}")
        if not target:
            print(f"{Colors.FAIL}Error: Target is required.{Colors.ENDC}")
            sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    post_scan_mode = False
    while True:
        if post_scan_mode:
            choice = display_post_scan_menu()
            if choice == "1":
                post_scan_mode = False
                continue
            elif choice == "2":
                print("Exiting...")
                break
            else:
                print(f"{Colors.FAIL}Invalid option. Please try again.{Colors.ENDC}")
                continue
        
        choice = display_menu()
        if choice == "0":
            print("Exiting...")
            break

        if choice not in {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}:
            print(f"{Colors.FAIL}Invalid option. Please try again.{Colors.ENDC}")
            continue

        base_command = []
        output_file = ""
        
        if choice == "1":
            check_tool(tools["ffuf"])
            wordlist_path = tools["ffuf_wordlist_subdomain"]
            if not Path(wordlist_path).exists():
                print(f"{Colors.FAIL}Error: Subdomain wordlist '{wordlist_path}' not found.{Colors.ENDC}")
                continue
            base_command = [tools["ffuf"], "-u", f"http://{target}", "-H", f"Host: FUZZ.{target}", "-w", wordlist_path]
            output_file = output_dir / "ffuf_subdomain_output.txt"
        elif choice == "2":
            check_tool(tools["subfinder"])
            base_command = [tools["subfinder"], "-d", target]
            output_file = output_dir / "subfinder_output.txt"
        elif choice == "3":
            check_tool(tools["nmap"])
            base_command = [tools["nmap"], "-sV", "-T4", target]
            output_file = output_dir / "nmap_output.txt"
        elif choice == "4":
            check_tool(tools["httpx"])
            base_command = [tools["httpx"], "-u", f"http://{target}"]
            output_file = output_dir / "httpx_output.txt"
        elif choice == "5":
            check_tool(tools["zaproxy"])
            base_command = [tools["zaproxy"], "-cmd", "-quickurl", f"http://{target}", "-quickout", str(output_dir / "zap_output.xml")]
            output_file = output_dir / "zap_report.html"
        elif choice == "6":
            check_tool(tools["ffuf"])
            wordlist_path = tools["ffuf_wordlist_dir"]
            if not Path(wordlist_path).exists():
                print(f"{Colors.FAIL}Error: Directory wordlist '{wordlist_path}' not found.{Colors.ENDC}")
                continue
            base_command = [tools["ffuf"], "-u", f"http://{target}/FUZZ", "-w", wordlist_path]
            output_file = output_dir / "ffuf_dir_output.txt"
        elif choice == "7":
            check_tool(tools["subzy"])
            subdomain_file = output_dir / "subfinder_output.txt"
            if not subdomain_file.exists():
                print(f"{Colors.FAIL}Error: Run Subfinder (option 2) first to generate {subdomain_file}{Colors.ENDC}")
                continue
            base_command = [tools["subzy"], "run", "--targets", str(subdomain_file)]
            output_file = output_dir / "subzy_output.txt"
        elif choice == "8":
            check_tool(tools["nuclei"])
            base_command = [tools["nuclei"], "-u", target]
            output_file = output_dir / "nuclei_output.txt"
        elif choice == "9":
            check_tool(tools["ffuf"])
            wordlist_path = tools["ffuf_wordlist_vhost"]
            if not Path(wordlist_path).exists():
                print(f"{Colors.FAIL}Error: VHost wordlist '{wordlist_path}' not found.{Colors.ENDC}")
                continue
            base_command = [tools["ffuf"], "-u", f"http://{target}", "-H", f"Host: FUZZ.{target}", "-w", wordlist_path]
            output_file = output_dir / "ffuf_vhost_output.txt"
        elif choice == "10":
            check_tool(tools["katana"])
            base_command = [tools["katana"], "-u", f"http://{target}", "-d", "5"]
            output_file = output_dir / "katana_output.txt"

        if not base_command:
            continue

        # Replace get_additional_args with the new editable command prompt
        final_command = get_editable_command(base_command)

        if final_command:
            run_tool(final_command, output_file)
            post_scan_mode = True

if __name__ == "__main__":
    main()