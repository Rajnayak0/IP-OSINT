import argparse
import webbrowser
from pyfiglet import Figlet
from termcolor import colored

def generate_links_with_descriptions(ip_address):
    tools = {
        colored("Geolocation", "cyan"): [
            {"url": f"https://www.iplocation.net/?query={ip_address}", "description": "Provides geographical location details, ISP, and more."},
            {"url": f"https://ipinfo.io/{ip_address}", "description": "Offers detailed IP information including location, organization, ASN, and more (often in JSON format)."},
            {"url": "https://www.maxmind.com/en/geoip2-databases", "description": "A provider of GeoIP databases (manual lookup on their site)."},
            {"url": f"https://ip2location.com/{ip_address}", "description": "Shows IP address information, including country, region, city, latitude, and longitude."},
            {"url": f"https://whatismyipaddress.com/ip/{ip_address}", "description": "Basic IP information, location, and ability to check for proxies."},
            {"url": "https://www.ipfingerprints.com/", "description": "IP address, hostname, and network details (often requires manual input)."},
            {"url": f"https://db-ip.com/{ip_address}", "description": "IP address lookup with location, ISP, and ASN details."},
            {"url": "https://www.iplocationfinder.net/", "description": "Provides IP location and related information (often requires manual input)."},
            {"url": "https://www.infobyip.com/ip-lookup", "description": "IP lookup tool with geolocation and ISP information (requires manual input)."},
            {"url": "https://iptrackeronline.com/", "description": "Offers IP tracking and lookup services (requires manual input)."},
            {"url": f"https://myip.ms/{ip_address}", "description": "Detailed IP address information, including reputation and hosting details."}
        ],
        colored("Host / Port Discovery", "magenta"): [
            {"url": f"https://viewdns.info/reverseip/?host={ip_address}", "description": "Finds other domains hosted on the same IP address."},
            {"url": f"https://securitytrails.com/domain/{ip_address}", "description": "Comprehensive domain and IP address intelligence (might require an account for full details)."},
            {"url": f"https://www.shodan.io/search?query={ip_address}", "description": "Search engine for internet-connected devices, showing open ports and services. **Potential Result:** Open ports, running services, device type."},
            {"url": f"https://censys.io/ipv4/{ip_address}", "description": "Provides detailed information about the configuration and services running on an IP address. **Potential Result:** Certificates, services, software versions."},
            {"url": f"https://fofa.info/#/search?qbase64={ip_address}", "description": "Cybersecurity search engine (might require encoding the IP and a free account). **Potential Result:** Exposed assets, vulnerabilities."},
            {"url": f"https://zoomeye.org/searchResult?q={ip_address}", "description": "Cyberspace search engine showing network devices and web services. **Potential Result:** Device types, service banners."},
            {"note": "Consider using online port scanner websites directly to check for open ports. **Potential Result:** List of open TCP/UDP ports."}
        ],
        colored("IPv4 Specific", "yellow"): [
            {"url": f"https://bgp.he.net/ip/{ip_address}", "description": "Shows BGP (Border Gateway Protocol) routing information for the IP address. **Potential Result:** ASN, origin AS, routing path."},
            {"url": f"https://whois.arin.net/ui/query.jsp?searchTxt={ip_address}", "description": "WHOIS lookup for IP addresses registered in the ARIN region. **Potential Result:** Owner organization, contact information."},
            {"url": f"https://ipapi.co/{ip_address}/json/", "description": "Simple API that returns IP information in JSON format (good for programmatic access). **Potential Result:** Geolocation data, ASN, country code (in JSON format)."},
            {"url": "https://www.ultratools.com/tools/ipWhoisLookup", "description": "WHOIS lookup tool for IP addresses (requires manual input). **Potential Result:** Owner information, registration details."}
        ],
        colored("Reputation / Blacklists", "red"): [
            {"url": f"https://www.abuseipdb.com/check/{ip_address}", "description": "Checks if an IP address is listed in the AbuseIPDB database of reported malicious IPs. **Potential Result:** Number of reports, confidence score, categories of abuse."},
            {"url": f"https://talosintelligence.com/reputation_center/lookup?search={ip_address}", "description": "Cisco Talos IP and domain reputation lookup. **Potential Result:** Reputation score (Good, Neutral, Poor), threat categories."},
            {"url": f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{ip_address}", "description": "Checks the IP address against multiple DNS blacklists. **Potential Result:** Listing status on various blacklists."},
            {"url": f"https://spur.us/context/{ip_address}", "description": "Provides context and threat intelligence data for the IP address. **Potential Result:** Threat level, associated activities."},
            {"url": "https://www.ipvoid.com/ip-blacklist-check/", "description": "Checks the IP address against numerous blacklists (requires manual input). **Potential Result:** Listing status on various blacklists."},
            {"url": f"https://www.greynoise.io/viz/ip/{ip_address}", "description": "Analyzes internet background noise to identify potentially malicious IPs. **Potential Result:** Whether the IP is considered 'noise' or potentially malicious."},
            {"url": f"https://live.ipmap.app/#/ip/{ip_address}", "description": "Visual IP address reputation and threat map. **Potential Result:** Visual representation of reputation and threat level."}
        ],
        colored("Neighbor Domains (Reverse IP Lookup)", "green"): [
            {"url": f"https://viewdns.info/reverseip/?host={ip_address}", "description": "Lists domains that are hosted on the same IP address. **Potential Result:** List of domain names."},
            {"url": "https://completedns.com/dns-history/", "description": "DNS history lookup (requires a domain name, might not work directly with an IP)."},
            {"url": f"https://securitytrails.com/domain/{ip_address}", "description": "Domain and IP address history and related information (might require an account). **Potential Result:** Historical DNS records, associated domains/IPs."}
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
    parser = argparse.ArgumentParser(description="Perform OSINT on an IP address by providing links and potential results from various online tools.")
    parser.add_argument("ip_address", help="The IP address to investigate.")
    parser.add_argument("-o", "--open", action="store_true", help="Open the links in your web browser.")
    args = parser.parse_args()
    ip_address = args.ip_address

    display_banner()
    print(f"Performing OSINT for IP Address: {ip_address}\n")
    all_tools = generate_links_with_descriptions(ip_address)

    for category, tool_list in all_tools.items():
        print(f"--- {category} ---")
        for tool in tool_list:
            if isinstance(tool, dict) and "url" in tool and "description" in tool:
                print(tool["url"])
                description = tool["description"]
                potential_result = tool.get("potential_result")
                print(colored(f"\tDescription: {description}", "white", attrs=['dark']))
                if potential_result:
                    print(colored(f"\tPotential Result: {potential_result}", "green", attrs=['dark']))
                if args.open:
                    webbrowser.open_new_tab(tool["url"])
            elif isinstance(tool, dict) and "note" in tool:
                print(colored(f"\tNote: {tool['note']}", "yellow"))
            else:
                print(colored(f"\tError: Unexpected tool format: {tool}", "red"))
        print()

if __name__ == "__main__":
    main()
