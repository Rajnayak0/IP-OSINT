# IP-OSINT

A simple command-line tool to gather Open Source Intelligence (OSINT) on a given IP address by providing links and descriptions of various online analysis tools.

## Usage

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Rajnayak0/IP-OSINT.git
    cd IP-OSINT
    ```
2.  **Install dependencies:**
    ```bash
    pip install pyfiglet termcolor
    ```
3.  **Run the script:**
    ```bash
    python ip.py <IP_ADDRESS>
    ```
    Replace `<IP_ADDRESS>` with the IP you want to investigate (e.g., `python ip.py 8.8.8.8`). The tool will display a colorful banner and a categorized list of links with descriptions and potential results in your terminal.

4.  **Automatically open links in your browser (optional):**
    ```bash
    python ip.py <IP_ADDRESS> -o
    ```
    This command will open each link in a new tab of your default web browser.

## Supported Operating Systems

This tool is written in Python and should be compatible with any operating system that supports Python 3. This includes, but is not limited to:

* **Windows:** Versions 7, 8, 8.1, 10, 11
* **macOS:** All recent versions (e.g., Catalina, Big Sur, Monterey, Ventura, Sonoma)
* **Linux:** Various distributions such as Ubuntu, Debian, Fedora, CentOS, Arch Linux, etc.

As long as you have Python 3 installed and the required dependencies are met, you should be able to run `IP-OSINT` on your operating system.

## Dependencies

* **Python 3:** Make sure you have Python 3 installed on your system. You can download it from [https://www.python.org/downloads/](https://www.python.org/downloads/).
* **pyfiglet:** For generating the ASCII art banner. Install with `pip install pyfiglet`.
* **termcolor:** For adding color to the terminal output. Install with `pip install termcolor`.

## Tools Included

The tool provides links to resources in the following categories:

* **Geolocation:** Tools for determining the geographical location and other details associated with an IP address.
* **Host / Port Discovery:** Tools for finding information about the hosts associated with an IP and potentially discovering open ports and services.
* **IPv4 Specific:** Tools focused on providing information specific to IPv4 addresses.
* **Reputation / Blacklists:** Services that check if an IP address has a history of malicious activity or is listed on blacklists.
* **Neighbor Domains (Reverse IP Lookup):** Tools that can identify other domain names hosted on the same IP address.

For each tool, a brief description is provided, along with a "Potential Result" hint indicating the type of information you might find on the linked page.

## Contributing

(Optional: Add information about how others can contribute to your project. For example:)

If you'd like to contribute to this project, you can:

* Suggest new tools or categories to include..
* Improve the descriptions of existing tools..
* Report any broken links or issues..
* Contribute code enhancements (e.g., more advanced analysis features - with careful consideration of website terms of service)..

Please feel free to open issues or submit pull requests on the GitHub repository..

## Author

**Rajnayak0**
