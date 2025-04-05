import argparse
import webbrowser
from pyfiglet import Figlet
from termcolor import colored

def generate_links(ip_address):
    links = {
        colored("Geolocation", "cyan"): [
            f"https://www.iplocation.net/?query={ip_address}",
            f"https://ipinfo.io/{ip_address}",
            f"https://www.maxmind.com/en/geoip2-databases", # Link to MaxMind (requires manual lookup)
            f"https://ip2location.com/{ip_address}",
            f"https://whatismyipaddress.com/ip/{ip_address}",
            f"https://www.ipfingerprints.com/", # Often requires manual input
            f"https://db-ip.com/{ip_address}",
            f"https://www.iplocationfinder.net/", # Often requires manual input
            f"https://www.infobyip.com/ip-lookup", # Requires manual input
            f"https://iptrackeronline.com/", # Requires manual input
            f"https://myip.ms/{ip_address}"
        ],
        colored("Host / Port Discovery", "magenta"): [
            f"https://viewdns.info/reverseip/?host={ip_address}",
            f"https://securitytrails.com/domain/{ip_address}", # Might require account
            f"https://www.shodan.io/search?query={ip_address}",
            f"https://censys.io/ipv4/{ip_address}",
            f"https://fofa.info/#/search?qbase64={ip_address}", # Might require encoding
            f"https://zoomeye.org/searchResult?q={ip_address}",
            # Online port scanners often have limitations and might be better used directly
            # Consider mentioning websites that offer them rather than direct links with IP
        ],
        colored("IPv4 Specific", "yellow"): [
            f"https://bgp.he.net/ip/{ip_address}",
            f"https://whois.arin.net/ui/query.jsp?searchTxt={ip_address}",
            f"https://ipapi.co/{ip_address}/json/",
            f"https://www.ultratools.com/tools/ipWhoisLookup" # Requires manual input
        ],
        colored("Reputation / Blacklists", "red"): [
            f"https://www.abuseipdb.com/check/{ip_address}",
            f"https://talosintelligence.com/reputation_center/lookup?search={ip_address}",
            f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{ip_address}",
            f"https://spur.us/context/{ip_address}",
            f"https://www.ipvoid.com/ip-blacklist-check/", # Requires manual input
            f"https://www.greynoise.io/viz/ip/{ip_address}",
            f"https://live.ipmap.app/#/ip/{ip_address}"
        ],
        colored("Neighbor Domains (Reverse IP Lookup)", "green"): [
            f"https://viewdns.info/reverseip/?host={ip_address}",
            f"https://completedns.com/dns-history/", # Requires domain, might not work directly with IP
            f"https://securitytrails.com/domain/{ip_address}" # Might require account
        ]
        # Add more categories and tools from your image as needed
    }
    return links

def display_banner():
    f = Figlet(font='slant')
    banner = f.renderText("IP-OSINT")
    author = colored("by Rajnayak0", "blue", attrs=['bold'])
    print(colored(banner, "red"))
    print(f"\t\t{author}\n")

def main():
    parser = argparse.ArgumentParser(description="Perform OSINT on an IP address by providing links to various online tools.")
    parser.add_argument("ip_address", help="The IP address to investigate.")
    parser.add_argument("-o", "--open", action="store_true", help="Open the links in your web browser.")
    args = parser.parse_args()
    ip_address = args.ip_address

    display_banner()
    print(f"Performing OSINT for IP Address: {ip_address}\n")
    all_links = generate_links(ip_address)

    for category, urls in all_links.items():
        print(f"--- {category} ---")
        for url in urls:
            print(url)
            if args.open:
                webbrowser.open_new_tab(url)
        print()

if __name__ == "__main__":
    main()
