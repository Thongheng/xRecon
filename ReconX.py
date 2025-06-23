import subprocess
import argparse
import sys
import os
from pathlib import Path
import shutil
import yaml

def check_tool(tool_path):
    """Check if a tool is installed at the specified path."""
    if not shutil.which(tool_path):
        print(f"Error: {tool_path} is not installed. Please install it first.")
        sys.exit(1)

def run_tool(command, output_file):
    """
    Run a command, display its output in real-time, and save it to a file.
    """
    print(f"\nRunning command: {' '.join(command)}\n")
    try:
        # Use Popen to start the process without blocking
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1,  # Line-buffered
        )

        # Open the output file to write to
        with open(output_file, "w") as f:
            # Read the output line by line in real-time
            # The loop will end when the subprocess finishes and closes its stdout
            for line in process.stdout:
                # Print the line to the console in real-time
                sys.stdout.write(line)
                # Write the same line to the output file
                f.write(line)

        # Wait for the process to terminate and get its return code
        process.wait()

        # Check for errors after the process has finished
        if process.returncode != 0:
            print(f"\nError: Command failed with return code {process.returncode}", file=sys.stderr)
            # You might want to handle this more gracefully depending on your needs

        print(f"\n\nResults saved to {output_file}")

    except FileNotFoundError:
        print(f"Error: Command '{command[0]}' not found. Please ensure it is installed and in your system's PATH.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

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
    print("20. Exit")
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
        if choice == "20":
            print("Exiting...")
            break

        if choice not in {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}:
            print("Invalid option. Please try again.")
            continue

        # Get additional arguments
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
            command = [tools["nmap"], "-sV", target] + additional_args
            output_file = output_dir / "nmap_output.txt"
        elif choice == "4":
            # httpx is handled differently as it may need piped input
            # This example assumes you want to run it on the primary target
            check_tool(tools["httpx"])
            print(f"\nRunning command: echo {target} | {tools['httpx']} {' '.join(additional_args)}\n")
            # For simplicity, we'll run httpx on the single target.
            # A more advanced version might read subdomains from a file.
            command = [tools["httpx"], "-u", target] + additional_args
            output_file = output_dir / "httpx_output.txt"
        elif choice == "5":
            check_tool(tools["zaproxy"])
            command = [tools["zaproxy"], "-cmd", "-quickurl", f"http://{target}", "-quickout", str(output_dir / "zap_output.xml")] + additional_args
            output_file = output_dir / "zap_report.html" # ZAP often outputs multiple formats
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

        # Note: The original special handling for choice "4" (httpx) is removed
        # as the generic run_tool can now handle it. If you need to pipe
        # input from other commands, that would require more specific logic.
        if command:
            run_tool(command, output_file)

if __name__ == "__main__":
    main()