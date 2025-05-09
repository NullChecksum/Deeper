
# Deeper.py

**Deeper** is a lightweight and automated security reconnaissance toolkit written in Python. 
It combines subdomain discovery, URL collection, live endpoint filtering, vulnerability scanning (via Nuclei), and network enumeration (via Nmap), all into one cohesive workflow.

The tool generates an interactive HTML report summarizing the findings.

---

##  Features

- 🔍 Subdomain enumeration using `subfinder` and `assetfinder`
- 🌐 URL discovery with `gau` and `katana`
- ✅ Live HTTP 200 endpoint detection
- 🌳 URL path tree JSON generation
- 🚨 Vulnerability scanning with `nuclei`
- 📡 Port and service scanning with `nmap`
- 📊 Interactive HTML reporting (Nmap + Nuclei + URL Tree)

---

##  Usage

### Basic Scan

```
python3 Deeper.py <target-domain>

(12000 ports scanned + all Nuclei templates, use this for best performance)
```

### Custom Output Directory

```
python3 Deeper.py <target-domain> --output <folder-name>
```

### Custom Port Range for Nmap 

```
python3 Deeper.py <target-domain> --nmap-ports 1-1000
```


---

## 📁 Output Structure

```
output_<target-domain>/
├── subdomains.txt             # All found subdomains
├── resolved_ips.txt           # Subdomains resolved to IPs
├── clean_endpoints.txt        # All unique URLs discovered
├── live_endpoints.txt         # URLs returning HTTP 200
├── <domain>_Nmap.txt          # Nmap output
├── <domain>_Nuclei.txt        # Nuclei output
├── <domain>_URLTree.json      # Hierarchical view of paths
├── <domain>_Report.html       # Full HTML report
```

---

# 🛠 Requirements

The following tools must be installed and available in your `$PATH`:

- [`subfinder`](https://github.com/projectdiscovery/subfinder)
- [`assetfinder`](https://github.com/tomnomnom/assetfinder)
- [`gau`](https://github.com/lc/gau)
- [`katana`](https://github.com/projectdiscovery/katana)
- [`nuclei`](https://github.com/projectdiscovery/nuclei)
- [`nmap`](https://nmap.org)

You can install Python dependencies (optional):

```bash
pip install -r requirements.txt
```

#### `requirements.txt` example:

```
requests
```

---

## 📌 Upcoming Features

- 🧩 CMS Detection (e.g. WordPress, Joomla, Drupal)
- 🐞 SQL Injection and XSS Detection via payload scanning
- 🔄 More Flexible commands, better report and other Surprise!

---

## 📝 Example Output

```
[+] Total unique URLs collected: 146
[✓] Saved to: output_scanme.org/clean_endpoints.txt
[*] Creating URL tree structure...
[✓] URL tree structure created and saved to output_scanme.org/scanme.org_URLTree.json
[*] Checking which URLs return HTTP 200...
[✓] Total live (HTTP 200) endpoints: 27
[✓] Saved to: output_scanme.org/live_endpoints.txt
[*] Launching nuclei scan...
[*] Processing each subdomain with nuclei (this may take time)...
 - Scanning nmap.scanme.org
 - Scanning scanme.org
 - Scanning www.scanme.org
..
..
::

```
![image](https://github.com/user-attachments/assets/b169bb34-47be-47df-ab12-a314b870647a)

![image](https://github.com/user-attachments/assets/772714a9-0721-4a2b-ba6a-0f32deb04a36)

And nmap of course, searchbar included.
---

## 📄 License

This project is provided "as is" for educational and internal testing purposes only. Use responsibly.

---
