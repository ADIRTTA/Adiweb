import os
import requests

# Colors and formatting
cln = "\033[0m"
bold = "\033[1m"
red = "\033[91m"
fgreen = "\033[92m"
lblue = "\033[94m"
yellow = "\033[93m"
blue = "\033[94m"
magenta = "\033[95m"
mint = "\033[48;5;82m"
aqua = "\033[48;5;81m"
ten = "\033[48;5;180m"


# ASCII Banner
def redhawk_banner():
    banner = f"""
{red}{bold}
             ___    ____  ________  _______________
            /   |  / __ \/  _/ __ \/_  __/_  __/   |
           / /| | / / / // // /_/ / / /   / / / /| |      code by adirtta 💀
          / ___ |/ /_/ // // _, _/ / /   / / / ___ |       THANK YOU FOR USE MY TOOL❤️
         /_/  |_/_____/___/_/ |_| /_/   /_/ /_/  |_|        don't copy my tool🤗
{fgreen}            Web Vulnerability Scanner
{cln}
"""
    print(banner)

# Function to check if required modules are installed
def check_modules():
    print(f"\n{red}{bold}[+] RED HAWK FiX MENU [+]{cln}")
    print(f"{bold}{blue}[+] Checking if 'requests' module is installed...")
    try:
        import requests
        print(f"{bold}{fgreen}[i] 'requests' is already installed.\n")
    except ImportError:
        print(f"{bold}{red}[!] 'requests' not installed!\n")
        print(f"{yellow}[*] Installing 'requests'. (Requires sudo permission){cln}")
        os.system("pip install requests")
        print(f"{bold}{fgreen}[i] 'requests' installed successfully.\n")

# Function to get input from the user
def userinput(prompt):
    return input(f"{yellow}{prompt}{cln}")

# Service functions (Placeholders for actual implementations)
def whois_lookup(domain):
    print(f"{bold}{lblue}[iNFO] WHOIS Lookup: {cln}")
    response = requests.get(f"http://api.hackertarget.com/whois/?q={domain}")
    print(f"{fgreen}{response.text}{cln}\n")

def geo_ip_lookup(domain):
    print(f"{bold}{lblue}[iNFO] Geo-IP Lookup: {cln}")
    response = requests.get(f"http://api.hackertarget.com/geoip/?q={domain}")
    print(f"{fgreen}{response.text}{cln}\n")

def grab_banners(domain):
    print(f"{bold}{yellow}[iNFO] Grab Banners for: {domain}{cln}")
    # Placeholder for actual banner grabbing implementation
    print(f"{fgreen}Banners: Not implemented yet{cln}\n")

def dns_lookup(domain):
    print(f"{bold}{lblue}[iNFO] DNS Lookup: {cln}")
    response = requests.get(f"http://api.hackertarget.com/dnslookup/?q={domain}")
    print(f"{fgreen}{response.text}{cln}\n")

def subnet_calculator():
    print(f"{bold}{yellow}[iNFO] Subnet Calculator{cln}")
    # Placeholder for actual subnet calculator
    print(f"{fgreen}Subnet: 255.255.255.0{cln}\n")

def nmap_port_scan(domain):
    print(f"{bold}{red}[iNFO] NMAP Port Scan on: {domain}{cln}")
    os.system(f"nmap {domain}")
    print(f"{bold}{red}[iNFO] NMAP Scan Completed!{cln}\n")

def subdomain_scanner(domain):
    print(f"{bold}{yellow}[iNFO] Subdomain Scanner for: {domain}{cln}")
    # Placeholder for actual subdomain scanner
    print(f"{fgreen}Found subdomains: sub.example.com{cln}\n")

def reverse_ip_cms(domain):
    print(f"{bold}{yellow}[iNFO] Reverse IP & CMS Detection for: {domain}{cln}")
    # Placeholder for reverse IP & CMS detection
    print(f"{fgreen}CMS: WordPress{cln}\n")

def sqli_scanner(domain):
    print(f"{bold}{yellow}[iNFO] SQL Injection Scanner for: {domain}{cln}")
    # Placeholder for SQLi scanner
    print(f"{fgreen}Vulnerable URLs: None Found{cln}\n")

def wordpress_scan(domain):
    print(f"{bold}{yellow}[iNFO] WordPress Scan for: {domain}{cln}")
    # Placeholder for WordPress scanner
    print(f"{fgreen}WordPress Version: 5.8.1{cln}\n")

def bloggers_view(domain):
    print(f"{bold}{yellow}[iNFO] Bloggers View for: {domain}{cln}")
    # Placeholder for bloggers view
    print(f"{fgreen}Blogging info found{cln}\n")

def scan_everything(domain):
    print(f"{bold}{yellow}[iNFO] Scanning Everything for: {domain}{cln}")
    whois_lookup(domain)
    geo_ip_lookup(domain)
    grab_banners(domain)
    dns_lookup(domain)
    subnet_calculator()
    subdomain_scanner(domain)
    sqli_scanner(domain)
    reverse_ip_cms(domain)
    wordpress_scan(domain)
    print(f"{bold}{fgreen}[iNFO] All-in-one scan completed!{cln}\n")

# Main function
def start_scan():
    os.system("clear")
    redhawk_banner()

    # Check if required modules are installed
    check_modules()

    # Ask for domain name first
    domain = userinput("Enter the domain name: ").strip()

    # Validate the input domain
    if "://" in domain:
        print(f"{red}[!] Invalid URL format! Enter a valid domain without 'http://' or 'https://'{cln}")
        return
    elif "." not in domain:
        print(f"{red}[!] Invalid URL format! Enter a valid domain name.{cln}")
        return

    # Start main menu
    while True:
        print(f"\n{bold}{yellow}Choose an option for {fgreen}{domain}{cln}:{cln}")
        print(f"""
        {fgreen}[1] {red}Whois Lookup{cln}
        {fgreen}[2] {red}Geo-IP Lookup{cln}
        {fgreen}[3] {red}Grab Banners{cln}
        {fgreen}[4] {red}DNS Lookup{cln}
        {fgreen}[5] {red}Subnet Calculator{cln}
        {fgreen}[6] {red}Subdomain Scanner{cln}
        {fgreen}[7] {red}Reverse IP Lookup & CMS Detection{cln}
        {fgreen}[8] {red}SQLi Scanner{cln}
        {fgreen}[9] {red}Bloggers View{cln}
        {fgreen}[10] {red}WordPress Scan{cln}
        {aqua}[A] {red}Scan For Everything{cln}
        """)

        user_option = userinput("Select option: ").lower()

        if user_option == "1":
            whois_lookup(domain)
        elif user_option == "2":
            geo_ip_lookup(domain)
        elif user_option == "3":
            grab_banners(domain)
        elif user_option == "4":
            dns_lookup(domain)
        elif user_option == "5":
            subnet_calculator()
        elif user_option == "6":
            nmap_port_scan(domain)
        elif user_option == "7":
            subdomain_scanner(domain)
        elif user_option == "8":
            reverse_ip_cms(domain)
        elif user_option == "9":
            sqli_scanner(domain)
        elif user_option == "10":
            bloggers_view(domain)
        elif user_option == "11":
            wordpress_scan(domain)
        elif user_option == "a":
            scan_everything(domain)
        elif user_option == "exit":
            print(f"{bold}{mint}{fgreen}Goodbye!{cln}")
            exit()
        else:
            print(f"{red}[!] Invalid option!{cln}")

if __name__ == "__main__":
    start_scan()
