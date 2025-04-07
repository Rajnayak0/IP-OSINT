# IP-OSINT

A simple command-line tool to gather Open Source Intelligence (OSINT) on a given IP address by providing links and descriptions of various online analysis tools, with interactive category selection and browser opening options.

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
    python ip.py
    ```
    The script will first display a colorful banner and then prompt you to enter the IP address you want to investigate.

4.  **Interactive Category Selection:**
    After entering the IP address, the script will present you with a numbered list of available categories:
    * `[0] All Categories`
    * `[1] Geolocation`
    * `[2] Host / Port Discovery`
    * `[3] IPv4 Specific`
    * `[4] Reputation / Blacklists`
    * `[5] Neighbor Domains (Reverse IP Lookup)`
    * `[b] Go Back`
    * `[q] Quit`

    Enter the number corresponding to the category you want to explore. You can choose '0' for all categories.

5.  **Open Links in Browser:**
    After selecting a category (or all), the script will ask if you want to open the links for that category in your web browser tabs. Type `yes` to open them or `no` to just see the links in the terminal.

6.  **Confirmation and Navigation:**
    After displaying the links for the selected category, you will be asked if you are finished exploring these categories.
    * Type `yes` to quit the script.
    * Type `no` to return to the category selection menu for further exploration.
    * Type `back` to return to the category selection menu.

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

* **Geolocation:** Tools for determining the geographical location and other details associated with an IP address (includes `freegeoip.app`).
* **Host / Port Discovery:** Tools for finding information about the hosts associated with an IP and potentially discovering open ports and services.
* **IPv4 Specific:** Tools focused on providing information specific to IPv4 addresses.
* **Reputation / Blacklists:** Services that check if an IP address has a history of malicious activity or is listed on blacklists (includes `VirusTotal`).
* **Neighbor Domains (Reverse IP Lookup):** Tools that can identify other domain names hosted on the same IP address.

For each tool, a brief description is provided, along with a "Potential Result" hint indicating the type of information you might find on the linked page.

## Contributing

(Optional: Add information about how others can contribute to your project. For example:)

If you'd like to contribute to this project, you can:

* Suggest new tools or categories to include.
* Improve the descriptions of existing tools.
* Report any broken links or issues.
* Contribute code enhancements (e.g., more advanced analysis features - with careful consideration of website terms of service).

Please feel free to open issues or submit pull requests on the GitHub repository.

## Author

**Rajnayak0**
