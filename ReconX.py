import subprocess
import argparse
import sys
import os
from pathlib import Path
import shutil
import yaml
import threading

def check_tool(tool_path):
    """Check if a tool is installed at the specified path."""
    if not shutil.which(tool_path):
        print(f"Error: {tool_path} is not installed. Please install it first.")
        sys.exit(1)

def run_tool(command, output_file):
    """
    Run a command, display its output in real-time, and only save the output
    to a file if the command completes successfully without being cancelled.
    """
    print(f"\nRunning command: {' '.join(command)}\n")

    stop_event = threading.Event()
    process = None
    output_lines = []  # Store output in memory instead of writing directly to file

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
            """This function runs in a thread, printing output and storing it in a buffer."""
            for line in process.stdout:
                if stop_event.is_set():
                    break
                sys.stdout.write(line)
                lines_buffer.append(line)
        
        output_thread = threading.Thread(target=monitor_and_stream_output, args=(output_lines,))
        output_thread.start()

        print("---")
        print(">>> Tool is running. Type 'q' and press Enter to cancel (output will not be saved).")
        print("---\n")
        
        while output_thread.is_alive():
            try:
                user_input = input() 
                if user_input.strip().lower() == 'q':
                    print("\n[INFO] 'q' received. Cancelling operation...")
                    stop_event.set()
                    break
            except (EOFError, KeyboardInterrupt):
                print("\n[INFO] Interruption detected. Cancelling operation...")
                stop_event.set()
                break

    except FileNotFoundError:
        print(f"Error: Command '{command[0]}' not found. Please ensure it is installed and in your system's PATH.", file=sys.stderr)
        return
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return
    finally:
        # Cleanup Section
        if process and stop_event.is_set():
            process.terminate()

        if 'output_thread' in locals() and output_thread.is_alive():
            output_thread.join()
        
        return_code = process.wait() if process else -1

        # --- Conditional Saving Logic ---
        if not stop_event.is_set() and return_code == 0:
            print(f"\nCommand completed successfully. Saving output to {output_file}...")
            try:
                with open(output_file, "w") as f:
                    f.writelines(output_lines)
                print(f"Results saved to {output_file}")
            except IOError as e:
                print(f"\nError: Could not write to file {output_file}. {e}", file=sys.stderr)
        elif stop_event.is_set():
            print("\nOperation cancelled by user. Output was NOT saved.")
        else:
            print(f"\nCommand finished with an error (code: {return_code}). Output was NOT saved.", file=sys.stderr)


def display_menu():
    """Display the tool selection menu."""
    print("\nAll-in-One Recon Tool")
    print("1. Passive Subdomain Enumeration - Amass")
    print("2. Active Subdomain Enumeration - Subfinder")
    print("3. Network Scanning - Nmap")
    print("4. Web Server Validation - Httpx")
    print("5. Web App Scanning - OWASP ZAP")
    print("6. Directory Brute-Forcing - ffuf")
    print("7. Subdomain Takeover Check - Subzy")
    print("8. Vulnerability Scanning - Nuclei")
    print("9. VHost Scanning - ffuf")
    print("10. Web Crawling - Katana")
    print("0. Exit")
    return input("Select an option: ")

def load_config():
    """Load configuration from config.yaml."""
    config_file = "config.yaml"
    try:
        with open(config_file, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"Info: {config_file} not found. Using default tool paths.")
        return {}
    except yaml.YAMLError as e:
        print(f"Error parsing {config_file}: {e}")
        sys.exit(1)

def get_additional_args():
    """Prompt for optional additional arguments."""
    args = input("Enter additional arguments (optional, press Enter to skip, 'q' to cancel): ")
    if args.lower() == 'q':
        return None
    return args.split() if args else []

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="All-in-One Recon Tool")
    parser.add_argument("target", nargs="?", help="Target domain or IP (e.g., example.com or 192.168.1.1)")
    parser.add_argument("-o", "--output", default=".", help="Output directory (default: current directory)")
    args = parser.parse_args()

    # Load configuration
    config = load_config()
    
    # Default tool paths and settings
    default_tools = {
        "amass": "amass",
        "subfinder": "subfinder",
        "nmap": "nmap",
        "httpx": "httpx",
        "zaproxy": "zaproxy",
        "ffuf": "ffuf",
        "subzy": "subzy",
        "nuclei": "nuclei",
        "katana": "katana",
        "ffuf_wordlist": "/usr/share/wordlists/dirb/common.txt",
        "vhost_wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    }
    
    # Update with config.yaml values
    tools_config = config.get("tools", {})
    tools = default_tools.copy()
    tools.update({
        "amass": tools_config.get("amass", {}).get("path", default_tools["amass"]),
        "subfinder": tools_config.get("subfinder", {}).get("path", default_tools["subfinder"]),
        "nmap": tools_config.get("nmap", {}).get("path", default_tools["nmap"]),
        "httpx": tools_config.get("httpx", {}).get("path", default_tools["httpx"]),
        "zaproxy": tools_config.get("zaproxy", {}).get("path", default_tools["zaproxy"]),
        "ffuf": tools_config.get("ffuf", {}).get("path", default_tools["ffuf"]),
        "subzy": tools_config.get("subzy", {}).get("path", default_tools["subzy"]),
        "nuclei": tools_config.get("nuclei", {}).get("path", default_tools["nuclei"]),
        "katana": tools_config.get("katana", {}).get("path", default_tools["katana"]),
        "ffuf_wordlist": tools_config.get("ffuf", {}).get("wordlist", default_tools["ffuf_wordlist"]),
        "vhost_wordlist": tools_config.get("ffuf", {}).get("vhost_wordlist", default_tools["vhost_wordlist"])
    })

    # Prompt for target if not provided
    target = args.target
    if not target:
        target = input("Enter target (e.g., example.com or IP): ")
        if not target:
            print("Error: Target is required.")
            sys.exit(1)

    # Validate and create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    while True:
        choice = display_menu()
        if choice == "0":
            print("Exiting...")
            break

        if choice not in {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}:
            print("Invalid option. Please try again.")
            continue

        additional_args = get_additional_args()
        if additional_args is None:
            print("Operation cancelled.")
            continue

        command = []
        output_file = ""
        
        # Map choices to tools and commands
        if choice == "1":
            check_tool(tools["amass"])
            command = [tools["amass"], "enum", "-passive", "-d", target] + additional_args
            output_file = output_dir / "amass_output.txt"
        elif choice == "2":
            check_tool(tools["subfinder"])
            command = [tools["subfinder"], "-d", target] + additional_args
            output_file = output_dir / "subfinder_output.txt"
        elif choice == "3":
            check_tool(tools["nmap"])
            command = [tools["nmap"], "-sV", "-T4", target] + additional_args
            output_file = output_dir / "nmap_output.txt"
        elif choice == "4":
            check_tool(tools["httpx"])
            command = [tools["httpx"], "-u", target] + additional_args
            output_file = output_dir / "httpx_output.txt"
        elif choice == "5":
            check_tool(tools["zaproxy"])
            command = [tools["zaproxy"], "-cmd", "-quickurl", f"http://{target}", "-quickout", str(output_dir / "zap_output.xml")] + additional_args
            output_file = output_dir / "zap_report.html" 
        elif choice == "6":
            check_tool(tools["ffuf"])
            if not Path(tools["ffuf_wordlist"]).exists():
                print(f"Error: Wordlist {tools['ffuf_wordlist']} not found.")
                continue
            command = [tools["ffuf"], "-u", f"http://{target}/FUZZ", "-w", tools["ffuf_wordlist"]] + additional_args
            output_file = output_dir / "ffuf_output.txt"
        elif choice == "7":
            check_tool(tools["subzy"])
            subdomain_file = output_dir / "subfinder_output.txt"
            if not subdomain_file.exists():
                print(f"Error: Run Subfinder (option 2) first to generate {subdomain_file}")
                continue
            command = [tools["subzy"], "run", "--targets", str(subdomain_file)] + additional_args
            output_file = output_dir / "subzy_output.txt"
        elif choice == "8":
            check_tool(tools["nuclei"])
            command = [tools["nuclei"], "-u", target] + additional_args
            output_file = output_dir / "nuclei_output.txt"
        elif choice == "9":
            check_tool(tools["ffuf"])
            if not Path(tools["vhost_wordlist"]).exists():
                print(f"Error: VHost wordlist {tools['vhost_wordlist']} not found.")
                continue
            command = [tools["ffuf"], "-u", f"http://{target}", "-H", f"Host: FUZZ.{target}", "-w", tools["vhost_wordlist"], "-fs", "4242"] + additional_args
            output_file = output_dir / "ffuf_vhost_output.txt"
        elif choice == "10":
            check_tool(tools["katana"])
            command = [tools["katana"], "-u", f"http://{target}", "-d", "3", "-jc"] + additional_args
            output_file = output_dir / "katana_output.txt"

        if command:
            run_tool(command, output_file)

if __name__ == "__main__":
    main()