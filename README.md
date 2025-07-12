
## Overview
`hunter.sh` is a simple enumeration script designed to automate the initial reconnaissance phase of a penetration test or bug bounty engagement. It streamlines the process of gathering information about a target by integrating several common tools and techniques into a single, easy-to-use script.

## Features
- **Subdomain Enumeration**: Utilizes `subfinder` and `assetfinder` to discover subdomains.
- **HTTP/S Probe**: Uses `httpx` to identify live web servers on discovered subdomains.
- **Port Scanning**: Employs `nmap` to perform a quick port scan on the target.
- **Directory Brute-forcing**: Leverages `gobuster` for directory and file enumeration.
- **Vulnerability Scanning**: Integrates `nuclei` for automated vulnerability scanning.
- **Output Management**: Organizes results into a dedicated directory for easy review.

## Required Tools
Before running `hunter.sh`, ensure you have the following tools installed and configured in your system's PATH:

- **subfinder**: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- **assetfinder**: `go install -v github.com/tomnomnom/assetfinder@latest`
- **httpx**: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
- **nmap**: `sudo apt install nmap` or `brew install nmap`
- **gobuster**: `go install github.com/OJ/gobuster/v3@latest`
- **nuclei**: `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`
- **anew**: `go install -v github.com/tomnomnom/anew@latest`
- **unfurl**: `go install -v github.com/tomnomnom/unfurl@latest`
- **qsreplace**: `go install github.com/tomnomnom/qsreplace@latest`
- **dalfox**: `go install github.com/hahwul/dalfox/v2@latest`
- **gf**: `go install github.com/tomnomnom/gf@latest`
- **waybackurls**: `go install github.com/tom# hunter
Simple enumeration script
