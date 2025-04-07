import argparse
import webbrowser
from pyfiglet import Figlet
from termcolor import colored

def generate_links_with_descriptions():
    tools = {
        colored("Geolocation", "cyan"): [
            {"url_format": "https://www.iplocation.net/?query={ip}", "description": "Provides geographical location details, ISP, and more."},
            {"url_format": "https://ipinfo.io/{ip}", "description": "Offers detailed IP information including location, organization, ASN, and more (often in JSON format)."},
            {"url_format": "https://www.maxmind.com/en/geoip2-databases", "description": "A provider of GeoIP databases (manual lookup on their site)."},
            {"url_format": "https://ip2location.com/{ip}", "description": "Shows IP address information, including country, region, city, latitude, and longitude."},
            {"url_format": "https://whatismyipaddress.com/ip/{ip}", "description": "Basic IP information, location, and ability to check for proxies."},
            {"url_format": "https://db-ip.com/{ip}", "description": "IP address lookup with location, ISP, and ASN details."},
            {"url_format": "https://freegeoip.app/{ip}", "description": "Free IP geolocation lookup service."},
        ],
        colored("Host / Port Discovery", "magenta"): [
            {"url_format": "https://viewdns.info/reverseip/?host={ip}", "description": "Finds other domains hosted on the same IP address."},
            {"url_format": "https://securitytrails.com/domain/{ip}", "description": "Comprehensive domain and IP address intelligence (might require an account for full details)."},
            {"url_format": "https://www.shodan.io/search?query={ip}", "description": "Search engine for internet-connected devices, showing open ports and services. **Potential Result:** Open ports, running services, device type."},
            {"url_format": "https://censys.io/ipv4/{ip}", "description": "Provides detailed information about the configuration and services running on an IP address. **Potential Result:** Certificates, services, software versions."},
            {"url_format": "https://zoomeye.org/searchResult?q={ip}", "description": "Cyberspace search engine showing network devices and web services. **Potential Result:** Device types, service banners."},
            {"note": "Consider using online port scanner websites directly to check for open ports. **Potential Result:** List of open TCP/UDP ports."}
        ],
        colored("IPv4 Specific", "yellow"): [
            {"url_format": "https://bgp.he.net/ip/{ip}", "description": "Shows BGP (Border Gateway Protocol) routing information for the IP address. **Potential Result:** ASN, origin AS, routing path."},
            {"url_format": "https://whois.arin.net/ui/query.jsp?searchTxt={ip}", "description": "WHOIS lookup for IP addresses registered in the ARIN region. **Potential Result:** Owner organization, contact information."},
            {"url_format": "https://ipapi.co/{ip}/json/", "description": "Simple API that returns IP information in JSON format (good for programmatic access). **Potential Result:** Geolocation data, ASN, country code (in JSON format)."},
            {"url_format": "https://www.ultratools.com/tools/ipWhoisLookup", "description": "WHOIS lookup tool for IP addresses (requires manual input). **Potential Result:** Owner information, registration details."}
        ],
        colored("Reputation / Blacklists", "red"): [
            {"url_format": "https://www.virustotal.com/gui/ip-address/{ip}/detection", "description": "Checks IP address against multiple antivirus engines and blacklists."},
            {"url_format": "https://www.abuseipdb.com/check/{ip}", "description": "Checks if an IP address is listed in the AbuseIPDB database of reported malicious IPs. **Potential Result:** Number of reports, confidence score, categories of abuse."},
            {"url_format": "https://talosintelligence.com/reputation_center/lookup?search={ip}", "description": "Cisco Talos IP and domain reputation lookup. **Potential Result:** Reputation score (Good, Neutral, Poor), threat categories."},
            {"url_format": "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{ip}", "description": "Checks the IP address against multiple DNS blacklists. **Potential Result:** Listing status on various blacklists."},
            {"url_format": "https://spur.us/context/{ip}", "description": "Provides context and threat intelligence data for the IP address. **Potential Result:** Threat level, associated activities."},
            {"url_format": "https://www.greynoise.io/viz/ip/{ip}", "description": "Analyzes internet background noise to identify potentially malicious IPs. **Potential Result:** Whether the IP is considered 'noise' or potentially malicious."},
        ],
        colored("Neighbor Domains (Reverse IP Lookup)", "green"): [
            {"url_format": "https://viewdns.info/reverseip/?host={ip}", "description": "Lists domains that are hosted on the same IP address. **Potential Result:** List of domain names."},
            {"url_format": "https://completedns.com/dns-history/", "description": "DNS history lookup (requires a domain name, might not work directly with an IP)."},
            {"url_format": "https://securitytrails.com/domain/{ip}", "description": "Domain and IP address history and related information (might require an account). **Potential Result:** Historical DNS records, associated domains/IPs."}
        ]
        # Add more categories and tools as needed
    }
    return tools

def display_banner():
    f = Figlet(font='slant')
    banner = f.renderText("IP-OSINT")
    author = colored("by Rajnayak0", "blue", attrs=['bold'])
    print(colored(banner, "red"))
    print(f"\t\t{author}\n")

def main():
    display_banner()
    ip_address = input(colored("Enter the IP address to investigate: ", "yellow"))
    all_tools = generate_links_with_descriptions()

    while True:
        print("\n" + colored("Available Categories:", "cyan"))
        print(colored("[0] All Categories", "cyan"))
        for i, category in enumerate(all_tools.keys(), start=1):
            print(colored(f"[{i}] {category}", "cyan"))
        print(colored("[b] Go Back", "red"))
        print(colored("[q] Quit", "red"))

        choice = input(colored("Choose a category to explore: ", "yellow")).lower()

        if choice == 'q':
            break
        elif choice == 'b':
            continue
        elif choice == '0':
            selected_categories = all_tools.keys()
        elif choice.isdigit() and 1 <= int(choice) <= len(all_tools):
            selected_category_index = int(choice) - 1
            selected_categories = [list(all_tools.keys())[selected_category_index]]
        else:
            print(colored("Invalid choice. Please try again.", "red"))
            continue

        print(f"\n" + colored(f"--- Results for IP: {ip_address} ---", "green"))
        open_links = input(colored("Do you want to open the links in your browser tabs? (yes/no): ", "yellow")).lower()

        for category in selected_categories:
            print(f"\n--- {category} ---")
            for tool in all_tools[category]:
                if "url_format" in tool:
                    url = tool["url_format"].format(ip=ip_address)
                    description = tool["description"]
                    potential_result = tool.get("potential_result", "N/A")
                    print(url)
                    print(colored(f"\tDescription: {description}", "white", attrs=['dark']))
                    if potential_result != "N/A":
                        print(colored(f"\tPotential Result: {potential_result}", "green", attrs=['dark']))
                    if open_links == 'yes':
                        webbrowser.open_new_tab(url)
                elif "note" in tool:
                    print(colored(f"\tNote: {tool['note']}", "yellow"))

        confirm = input(colored("\nAre you finished exploring these categories? (yes/no/back): ", "yellow")).lower()
        if confirm == 'yes':
            break
        elif confirm == 'back':
            continue

if __name__ == "__main__":
    main()
