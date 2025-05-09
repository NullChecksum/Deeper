#!/usr/bin/env python3

import subprocess
import sys
import os
import requests
import mimetypes
import json
import datetime
import time
import argparse
import re
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict


def print_banner():
    banner = """
███████╗██╗  ██ ███████╗    ██████╗ ███████╗███████╗██████╗ ███████╗██████╗ 
══██╔══╝██║  ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗
  ██║   ███████║█████╗      ██║  ██║█████╗  █████╗  ██████╔╝█████╗  ██████╔╝
  ██║   ██╔══██║██╔══╝      ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██╗
  ██║   ██║  ██║███████╗    ██████╔╝███████╗███████╗██║     ███████╗██║  ██║
  ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝
    Simplified Security Scanner
    """
    print(banner)


def run_command(cmd, timeout=None):
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                               text=True, timeout=timeout)
        if result.returncode != 0 and result.stderr:
            print(f"[!] Warning: Command returned error: {result.stderr.strip()}")
        return result.stdout.strip().splitlines()
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out after {timeout} seconds: {cmd}")
        return []
    except Exception as e:
        print(f"[!] Error while running command: {cmd}")
        print(f"[!] Exception: {str(e)}")
        return []


def resolve_to_ip(domain):
    """Resolve domain to IP using dig command"""
    try:
        result = subprocess.run(f"dig +short {domain}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ips = result.stdout.strip().splitlines()
        # Return the first IP if available
        for ip in ips:
            # Check if it's a valid IPv4 address
            if ip and all(c.isdigit() or c == '.' for c in ip) and len(ip.split('.')) == 4:
                return ip
        return None
    except Exception as e:
        print(f"[!] Error resolving {domain}: {str(e)}")
        return None


def check_url_live(url):
    try:
        response = requests.get(url, timeout=6, allow_redirects=True, verify=False, 
                               headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        return url if response.status_code == 200 else None
    except:
        return None


def organize_urls_into_tree(urls, domain, outdir):
    """Organize URLs into a tree structure for visualization"""
    url_tree_file = f"{outdir}/{domain}_URLTree.json"
    print("[*] Creating URL tree structure...")
    url_tree = {}
    
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if not domain:
                continue
                
            path = parsed.path.strip('/')
            
            if domain not in url_tree:
                url_tree[domain] = {'paths': set(), 'children': {}}
            
            # Add the full path
            if path:
                url_tree[domain]['paths'].add(path)
                
                # Also add parent paths for tree structure
                parts = path.split('/')
                for i in range(1, len(parts)):
                    parent_path = '/'.join(parts[:i])
                    if parent_path:
                        url_tree[domain]['paths'].add(parent_path)
        except Exception:
            continue
    
    # Convert sets to lists for JSON serialization
    for domain in url_tree:
        url_tree[domain]['paths'] = sorted(list(url_tree[domain]['paths']))
        
        # Create hierarchy
        for path in list(url_tree[domain]['paths']):
            parts = path.split('/')
            current = url_tree[domain]['children']
            
            for i, part in enumerate(parts):
                if part not in current:
                    current[part] = {'paths': [], 'children': {}}
                
                if i == len(parts) - 1:  # Leaf node
                    current[part]['paths'].append(path)
                
                current = current[part]['children']
    
    # Save the tree structure
    with open(url_tree_file, "w") as f:
        json.dump(url_tree, f, indent=2)
    
    print(f"[✓] URL tree structure created and saved to {url_tree_file}")
    return url_tree_file


# Funzioni di parsing da gen.py
def parse_nmap(nmap_content):
    hosts = []
    current_host = None
    
    for line in nmap_content.split('\n'):
        if 'Nmap scan report for' in line:
            if current_host:
                hosts.append(current_host)
            
            ip_match = re.search(r'Nmap scan report for\s+([^\s]+)', line)
            if ip_match:
                current_host = {
                    'ip': ip_match.group(1),
                    'ports': []
                }
        elif current_host and re.match(r'^\d+/tcp', line):
            port_match = re.search(r'^(\d+)/tcp\s+(open|closed|filtered)\s+([^\s]+)(?:\s+(.+))?', line)
            if port_match:
                current_host['ports'].append({
                    'port': port_match.group(1),
                    'state': port_match.group(2),
                    'service': port_match.group(3),
                    'version': port_match.group(4) if port_match.group(4) else 'N/A'
                })
        elif current_host and 'Service Info:' in line:
            current_host['serviceInfo'] = line.replace('Service Info: ', '')
    
    if current_host:
        hosts.append(current_host)
    
    return hosts


def parse_nuclei(nuclei_content):
    findings = []
    
    for line in nuclei_content.split('\n'):
        if not line.strip():
            continue
        
        line = re.sub(r'\x1b\[[0-9;]*m', '', line)
        
        pattern = r'\[([\w\-]+(?::[\w\-]+)?)\]\s+\[([\w]+)\]\s+\[([\w]+)\]\s+([^\s][^\[]*?)(?:\s+\["([^"]*)")?\]?$'
        
        match = re.search(pattern, line)
        
        if match:
            finding_type = match.group(1)
            protocol = match.group(2)
            severity = match.group(3).lower()
            target = match.group(4).strip()
            details = match.group(5) if match.group(5) else ''
            
            if details:
                details = details.replace('\\r\\n', '<br>')
                details = details.replace('\\', '')
                details = details.replace('"', '')
            
            findings.append({
                'type': finding_type,
                'protocol': protocol,
                'severity': severity,
                'target': target,
                'details': details
            })
    
    return findings


def parse_url_json(json_content):
    try:
        url_data = json.loads(json_content)
        domains = {}
        
        for domain, data in url_data.items():
            paths = data.get('paths', [])
            domains[domain] = paths
        
        return domains
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        return {"www.example.com": {"paths": ["Error parsing JSON file"]}}


def generate_report_html(nmap_data, nuclei_data, url_data):
    stats = {
        'hosts': len(nmap_data),
        'openPorts': sum(len([p for p in host['ports'] if p['state'] == 'open']) for host in nmap_data),
        'findings': {
            'info': len([f for f in nuclei_data if f['severity'] == 'info']),
            'low': len([f for f in nuclei_data if f['severity'] == 'low']),
            'medium': len([f for f in nuclei_data if f['severity'] == 'medium']),
            'high': len([f for f in nuclei_data if f['severity'] == 'high']),
            'critical': len([f for f in nuclei_data if f['severity'] == 'critical'])
        },
        'domains': len(url_data),
        'urls': sum(len(paths) for paths in url_data.values())
    }
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Security Report - {datetime.datetime.now().strftime('%d/%m/%Y')}</title>
      <style>
        :root {{
          --primary-color: #2c3e50;
          --secondary-color: #3498db;
          --bg-color: #f8f9fa;
          --text-color: #333;
          --border-color: #ddd;
          --info-color: #0088FF;
          --low-color: #FFCC00;
          --medium-color: #FF8800;
          --high-color: #FF0000;
          --critical-color: #880000;
        }}
        
        body {{
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: var(--text-color);
          background-color: var(--bg-color);
          margin: 0;
          padding: 0;
        }}
        
        .container {{
          max-width: 1200px;
          margin: 0 auto;
          padding: 20px;
        }}
        
        header {{
          background-color: var(--primary-color);
          color: white;
          padding: 20px;
          margin-bottom: 30px;
          border-radius: 5px;
          box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        
        h1, h2, h3, h4 {{
          color: var(--primary-color);
          margin-top: 30px;
        }}
        
        header h1 {{
          color: white;
          margin-top: 0;
        }}
        
        .card {{
          background-color: white;
          border-radius: 5px;
          box-shadow: 0 2px 5px rgba(0,0,0,0.1);
          padding: 20px;
          margin-bottom: 20px;
        }}
        
        .stats-container {{
          display: flex;
          flex-wrap: wrap;
          gap: 15px;
          margin-bottom: 30px;
        }}
        
        .stat-card {{
          flex: 1;
          min-width: 200px;
          background-color: white;
          border-radius: 5px;
          box-shadow: 0 2px 5px rgba(0,0,0,0.1);
          padding: 15px;
          text-align: center;
        }}
        
        .stat-value {{
          font-size: 2.5rem;
          font-weight: bold;
          color: var(--secondary-color);
        }}
        
        .stat-label {{
          color: var(--text-color);
          font-size: 0.9rem;
          text-transform: uppercase;
        }}
        
        table {{
          width: 100%;
          border-collapse: collapse;
          margin-bottom: 20px;
          box-shadow: 0 2px 3px rgba(0,0,0,0.1);
        }}
        
        th, td {{
          padding: 12px 15px;
          text-align: left;
          border-bottom: 1px solid var(--border-color);
        }}
        
        th {{
          background-color: var(--primary-color);
          color: white;
          position: sticky;
          top: 0;
        }}
        
        tr:nth-child(even) {{
          background-color: rgba(0,0,0,0.02);
        }}
        
        tr:hover {{
          background-color: rgba(0,0,0,0.05);
        }}
        
        .severity {{
          display: inline-block;
          width: 80px;
          padding: 5px 10px;
          border-radius: 3px;
          color: white;
          font-weight: bold;
          text-align: center;
        }}
        
        .severity-info {{
          background-color: var(--info-color);
        }}
        
        .severity-low {{
          background-color: var(--low-color);
        }}
        
        .severity-medium {{
          background-color: var(--medium-color);
        }}
        
        .severity-high {{
          background-color: var(--high-color);
        }}
        
        .severity-critical {{
          background-color: var(--critical-color);
        }}
        
        .filter-container {{
          margin-bottom: 20px;
        }}
        
        .search-box {{
          width: 100%;
          padding: 12px 15px;
          border: 1px solid var(--border-color);
          border-radius: 5px;
          font-size: 16px;
          margin-bottom: 15px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        .tree-view {{
          margin-top: 20px;
        }}
        
        .tree-item {{
          margin-bottom: 5px;
        }}
        
        .tree-toggle {{
          cursor: pointer;
          padding: 10px 15px;
          background-color: #f1f1f1;
          border-radius: 3px;
          display: block;
          margin-bottom: 5px;
          transition: background-color 0.2s;
          box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }}
        
        .tree-toggle:hover {{
          background-color: #e9e9e9;
        }}
        
        .tree-content {{
          padding-left: 20px;
          display: none;
          max-height: 400px;
          overflow-y: auto;
          border-left: 2px solid #e0e0e0;
          margin-left: 10px;
        }}
        
        .tabs {{
          display: flex;
          border-bottom: 1px solid var(--border-color);
          margin-bottom: 20px;
        }}
        
        .tab {{
          padding: 12px 18px;
          cursor: pointer;
          border: 1px solid transparent;
          border-bottom: none;
          font-weight: 500;
          transition: background-color 0.2s;
        }}
        
        .tab.active {{
          background-color: white;
          border-color: var(--border-color);
          border-radius: 5px 5px 0 0;
          margin-bottom: -1px;
          color: var(--secondary-color);
        }}
        
        .tab:hover:not(.active) {{
          background-color: rgba(0,0,0,0.02);
        }}
        
        .tab-content {{
          display: none;
        }}
        
        .tab-content.active {{
          display: block;
        }}
        
        .port-open {{
          color: #27ae60;
          font-weight: bold;
        }}
        
        .port-closed {{
          color: #e74c3c;
        }}
        
        .port-filtered {{
          color: #f39c12;
        }}
        
        .pill {{
          display: inline-block;
          padding: 2px 8px;
          border-radius: 12px;
          font-size: 0.85em;
          font-weight: 500;
          background-color: #e0e0e0;
          margin-right: 5px;
          margin-bottom: 5px;
        }}
        
        .finding-row {{
          cursor: pointer;
        }}
        
        .finding-details {{
          display: none;
          padding: 15px;
          background-color: #f9f9f9;
          border-left: 3px solid var(--secondary-color);
          margin: 5px 0 15px 0;
          white-space: pre-wrap;
          font-family: monospace;
        }}
        
        .badge {{
          display: inline-flex;
          align-items: center;
          justify-content: center;
          background-color: var(--secondary-color);
          color: white;
          border-radius: 50%;
          width: 24px;
          height: 24px;
          font-size: 12px;
          margin-left: 8px;
        }}
        
        @media print {{
          body {{
            background-color: white;
          }}
          
          .container {{
            max-width: 100%;
            padding: 0;
          }}
          
          .card {{
            box-shadow: none;
            border: 1px solid #ddd;
          }}
          
          table {{
            page-break-inside: auto;
          }}
          
          tr {{
            page-break-inside: avoid;
            page-break-after: auto;
          }}
        }}
        
        .progress-container {{
          margin-top: 10px;
          background-color: #f1f1f1;
          border-radius: 3px;
          height: 10px;
          overflow: hidden;
        }}
        
        .progress-bar {{
          height: 10px;
          border-radius: 3px;
          transition: width 1s ease-in-out;
        }}
        
        @keyframes fadeIn {{
          from {{ opacity: 0; }}
          to {{ opacity: 1; }}
        }}
        
        .animated {{
          animation: fadeIn 0.5s ease-in-out;
        }}
      </style>
    </head>
    <body>
      <div class="container">
        <header>
          <h1>Security Report</h1>
          <p>Generated on {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
        </header>
        
        <div class="card animated">
          <h2>Executive Summary</h2>
          <div class="stats-container">
            <div class="stat-card">
              <div class="stat-value">{stats['hosts']}</div>
              <div class="stat-label">Hosts Scanned</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">{stats['openPorts']}</div>
              <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">{stats['domains']}</div>
              <div class="stat-label">Domains</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">{stats['urls']}</div>
              <div class="stat-label">URLs Scanned</div>
            </div>
          </div>
          
          <h3>Findings by Severity</h3>
          <div class="stats-container">
            <div class="stat-card">
              <div class="stat-value" style="color: var(--info-color)">{stats['findings']['info']}</div>
              <div class="stat-label">Info</div>
              <div class="progress-container">
                <div class="progress-bar" style="width: {stats['findings']['info'] / (len(nuclei_data) or 1) * 100}%; background-color: var(--info-color);"></div>
              </div>
            </div>
            <div class="stat-card">
              <div class="stat-value" style="color: var(--low-color)">{stats['findings']['low']}</div>
              <div class="stat-label">Low</div>
              <div class="progress-container">
                <div class="progress-bar" style="width: {stats['findings']['low'] / (len(nuclei_data) or 1) * 100}%; background-color: var(--low-color);"></div>
              </div>
            </div>
            <div class="stat-card">
              <div class="stat-value" style="color: var(--medium-color)">{stats['findings']['medium']}</div>
              <div class="stat-label">Medium</div>
              <div class="progress-container">
                <div class="progress-bar" style="width: {stats['findings']['medium'] / (len(nuclei_data) or 1) * 100}%; background-color: var(--medium-color);"></div>
              </div>
            </div>
            <div class="stat-card">
              <div class="stat-value" style="color: var(--high-color)">{stats['findings']['high']}</div>
              <div class="stat-label">High</div>
              <div class="progress-container">
                <div class="progress-bar" style="width: {stats['findings']['high'] / (len(nuclei_data) or 1) * 100}%; background-color: var(--high-color);"></div>
              </div>
            </div>
            <div class="stat-card">
              <div class="stat-value" style="color: var(--critical-color)">{stats['findings']['critical']}</div>
              <div class="stat-label">Critical</div>
              <div class="progress-container">
                <div class="progress-bar" style="width: {stats['findings']['critical'] / (len(nuclei_data) or 1) * 100}%; background-color: var(--critical-color);"></div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="card animated">
          <div class="tabs">
            <div class="tab active" data-target="hosts-tab">Hosts & Ports</div>
            <div class="tab" data-target="vulnerabilities-tab">Findings</div>
            <div class="tab" data-target="urls-tab">URLs</div>
          </div>
          
          <div id="hosts-tab" class="tab-content active">
            <h2>Detected Hosts and Ports</h2>
            <input type="text" id="host-search" class="search-box" placeholder="Search by IP, port or service...">
            
            <div id="hosts-container">
              {''.join([f"""
                <div class="tree-item host-item">
                  <div class="tree-toggle">{host['ip']} <span class="badge">{len([p for p in host['ports'] if p['state'] == 'open'])}</span></div>
                  <div class="tree-content">
                    <table>
                      <thead>
                        <tr>
                          <th>Port</th>
                          <th>State</th>
                          <th>Service</th>
                          <th>Version</th>
                        </tr>
                      </thead>
                      <tbody>
                        {''.join([f"""
                          <tr>
                            <td>{port['port']}</td>
                            <td class="port-{port['state']}">{port['state']}</td>
                            <td>{port['service']}</td>
                            <td>{port['version']}</td>
                          </tr>
                        """ for port in host['ports']])}
                      </tbody>
                    </table>
                    {f'<p><strong>Service Info:</strong> {host["serviceInfo"]}</p>' if 'serviceInfo' in host else ''}
                  </div>
                </div>
              """ for host in nmap_data])}
            </div>
          </div>
          
          <div id="vulnerabilities-tab" class="tab-content">
            <h2>Identified Findings</h2>
            <input type="text" id="vuln-search" class="search-box" placeholder="Search by type, protocol or severity...">
            
            <table id="vuln-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Protocol</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {''.join([f"""
                  <tr class="finding-row" data-id="finding-{i}">
                    <td>{finding['type']}</td>
                    <td>{finding['protocol']}</td>
                    <td><span class="severity severity-{finding['severity']}">{finding['severity'].upper()}</span></td>
                  </tr>
                  <tr>
                    <td colspan="3" class="finding-details" id="finding-{i}">
                      <strong>Target:</strong> {finding['target']}
                      {f'<br><br><strong>Details:</strong><br>{finding["details"]}' if finding['details'] else ''}
                    </td>
                  </tr>
                """ for i, finding in enumerate(nuclei_data)])}
              </tbody>
            </table>
          </div>
          
          <div id="urls-tab" class="tab-content">
            <h2>Scanned URLs</h2>
            <input type="text" id="url-search" class="search-box" placeholder="Search URLs...">
            
            <div id="urls-container" class="tree-view">
              {''.join([f"""
                <div class="tree-item url-item">
                  <div class="tree-toggle">{domain} <span class="badge">{len(paths)}</span></div>
                  <div class="tree-content">
                    <ul>
                      {''.join([f"""
                        <li>{path}</li>
                      """ for path in paths])}
                    </ul>
                  </div>
                </div>
              """ for domain, paths in url_data.items()])}
            </div>
          </div>
        </div>
      </div>
      
      <script>
        document.addEventListener('DOMContentLoaded', function() {{
          setTimeout(function() {{
            document.querySelectorAll('.progress-bar').forEach(function(bar) {{
              bar.style.width = bar.style.width || '0%';
            }});
          }}, 100);
          
          document.querySelectorAll('.tree-toggle').forEach(toggle => {{
            toggle.addEventListener('click', function() {{
              const content = this.nextElementSibling;
              if (content.style.display === 'block') {{
                content.style.display = 'none';
              }} else {{
                content.style.display = 'block';
              }}
            }});
          }});
          
          document.querySelectorAll('.tab').forEach(tab => {{
            tab.addEventListener('click', function() {{
              document.querySelectorAll('.tab').forEach(t => {{
                t.classList.remove('active');
              }});
              
              this.classList.add('active');
              
              document.querySelectorAll('.tab-content').forEach(content => {{
                content.classList.remove('active');
              }});
              
              const targetId = this.getAttribute('data-target');
              document.getElementById(targetId).classList.add('active');
            }});
          }});
          
          document.querySelectorAll('.finding-row').forEach(row => {{
            row.addEventListener('click', function() {{
              const detailsId = this.getAttribute('data-id');
              const detailsElement = document.getElementById(detailsId);
              
              if (detailsElement.style.display === 'table-cell') {{
                detailsElement.style.display = 'none';
              }} else {{
                document.querySelectorAll('.finding-details').forEach(details => {{
                  details.style.display = 'none';
                }});
                detailsElement.style.display = 'table-cell';
              }}
            }});
          }});
          
          document.getElementById('host-search').addEventListener('input', function() {{
            const query = this.value.toLowerCase();
            document.querySelectorAll('.host-item').forEach(item => {{
              const hostText = item.textContent.toLowerCase();
              if (hostText.includes(query)) {{
                item.style.display = 'block';
              }} else {{
                item.style.display = 'none';
              }}
            }});
          }});
          
          document.getElementById('vuln-search').addEventListener('input', function() {{
            const query = this.value.toLowerCase();
            const rows = document.querySelectorAll('#vuln-table .finding-row');
            
            rows.forEach(row => {{
              const rowText = row.textContent.toLowerCase();
              const detailsId = row.getAttribute('data-id');
              const detailsRow = document.getElementById(detailsId).parentNode;
              
              if (rowText.includes(query)) {{
                row.style.display = '';
                detailsRow.style.display = '';
              }} else {{
                row.style.display = 'none';
                detailsRow.style.display = 'none';
              }}
            }});
          }});
          
          document.getElementById('url-search').addEventListener('input', function() {{
            const query = this.value.toLowerCase();
            document.querySelectorAll('.url-item').forEach(item => {{
              const domainText = item.querySelector('.tree-toggle').textContent.toLowerCase();
              const domainMatch = domainText.includes(query);
              
              let pathsMatch = false;
              item.querySelectorAll('li').forEach(li => {{
                if (li.textContent.toLowerCase().includes(query)) {{
                  pathsMatch = true;
                  li.style.display = '';
                }} else {{
                  li.style.display = 'none';
                }}
              }});
              
              if (domainMatch || pathsMatch) {{
                item.style.display = 'block';
                if (pathsMatch && !domainMatch) {{
                  item.querySelector('.tree-content').style.display = 'block';
                }}
              }} else {{
                item.style.display = 'none';
              }}
            }});
          }});
        }});
      </script>
    </body>
    </html>
    """
    
    return html


def create_html_report_enhanced(domain, outdir, nmap_file, nuclei_file, url_tree_file):
    """Generate HTML report using the enhanced format from gen.py"""
    try:
        # Read and parse the input files
        with open(nmap_file, 'r', encoding='utf-8') as f:
            nmap_content = f.read()
        
        with open(nuclei_file, 'r', encoding='utf-8') as f:
            nuclei_content = f.read()
        
        with open(url_tree_file, 'r', encoding='utf-8') as f:
            url_json_content = f.read()
        
        nmap_data = parse_nmap(nmap_content)
        nuclei_data = parse_nuclei(nuclei_content)
        url_data = parse_url_json(url_json_content)
        
        # Generate the HTML report
        html_report = generate_report_html(nmap_data, nuclei_data, url_data)
        
        # Write the report to file
        report_file = f"{outdir}/{domain}_Report.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        print(f"[✓] Enhanced HTML report generated: {report_file}")
        return report_file
    
    except Exception as e:
        print(f"[!] Error generating enhanced report: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


def main():
    parser = argparse.ArgumentParser(description="Simplified Security Scanner")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("--output", help="Custom output directory name")
    parser.add_argument("--nmap-ports", default="1-12000", help="Port range for Nmap scan (default: 1-12000)")
    args = parser.parse_args()

    domain = args.domain
    outdir = args.output if args.output else f"output_{domain}"
    os.makedirs(outdir, exist_ok=True)
    
    print_banner()
    print(f"[+] Starting simplified security scan for: {domain}")
    print(f"[+] Output directory: {outdir}")
    
    start_time = time.time()

    # Find subdomains with subfinder and assetfinder
    print("[*] Running subfinder...")
    subfinder_subs = run_command(f"subfinder -d {domain} -silent")

    print("[*] Running assetfinder...")
    assetfinder_subs = run_command(f"assetfinder {domain}")

    # Create set of all subdomains and add root domain to ensure it's included
    all_subs = set(subfinder_subs + assetfinder_subs)
    all_subs.add(domain)  # Ensure root domain is included
    
    sub_file = f"{outdir}/subdomains.txt"
    with open(sub_file, "w") as f:
        for sub in sorted(all_subs):
            f.write(sub + "\n")

    print(f"[+] Total unique subdomains found: {len(all_subs)}")

    # Resolve domains to IPs
    print("[*] Resolving domains to IPs...")
    ip_mapping = {}
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = list(executor.map(resolve_to_ip, all_subs))
        
        for domain, ip in zip(all_subs, results):
            if ip:
                ip_mapping[domain] = ip
    
    ip_file = f"{outdir}/resolved_ips.txt"
    with open(ip_file, "w") as f:
        for ip in sorted(set(ip_mapping.values())):
            f.write(ip + "\n")
    
    print(f"[+] Total unique IPs resolved: {len(set(ip_mapping.values()))}")
    print(f"[✓] Saved to: {ip_file}")

    # Crawling with gau and katana
    all_urls = set()
    
    for sub in all_subs:
        print(f"\n[*] Processing subdomain: {sub}")

        print(" - Running gau")
        urls = run_command(f"gau {sub}")
        all_urls.update(urls)

        print(" - Running katana")
        urls = run_command(f"katana -u https://{sub} -d 3 -silent")
        all_urls.update(urls)

    clean_file = f"{outdir}/clean_endpoints.txt"
    with open(clean_file, "w") as f:
        for url in sorted(all_urls):
            f.write(url + "\n")

    print(f"\n[+] Total unique URLs collected: {len(all_urls)}")
    print(f"[✓] Saved to: {clean_file}")

    # Create URL tree structure for the report
    url_tree_file = organize_urls_into_tree(all_urls, domain, outdir)

    print("[*] Checking which URLs return HTTP 200...")
    requests.packages.urllib3.disable_warnings()
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        live_results = list(executor.map(check_url_live, sorted(all_urls)))

    live_urls = list(filter(None, live_results))

    live_file = f"{outdir}/live_endpoints.txt"
    with open(live_file, "w") as f:
        for url in sorted(live_urls):
            f.write(url + "\n")

    print(f"[✓] Total live (HTTP 200) endpoints: {len(live_urls)}")
    print(f"[✓] Saved to: {live_file}")

    # Launch nuclei scan with simplified approach
    print("[*] Launching nuclei scan...")
    nuclei_results_file = f"{outdir}/{domain}_Nuclei.txt"
    
    # Create an empty file to start with or clear existing file
    with open(nuclei_results_file, 'w') as f:
        pass
    
    # Process each subdomain separately to ensure all results are captured
    print("[*] Processing each subdomain with nuclei (this may take time)...")
    for subdomain in sorted(all_subs):
        print(f" - Scanning {subdomain}")
        # Run nuclei on a single subdomain and append results
        nuclei_cmd = f"nuclei -u {subdomain} -headless >> {nuclei_results_file}"
        run_command(nuclei_cmd)
    
    print(f"[✓] Nuclei scan completed. Results saved to {nuclei_results_file}")

    # Run nmap on resolved IPs
    print("[*] Launching nmap scan on resolved IPs...")
    nmap_results_file = f"{outdir}/{domain}_Nmap.txt"
    
    port_range = args.nmap_ports
    nmap_cmd = f"sudo nmap -sS -sV -sC -p {port_range} -n -Pn -iL {ip_file} -oN {nmap_results_file}"
    run_command(nmap_cmd)
    print(f"[✓] Nmap scan completed. Results saved to {nmap_results_file}")

    # Generate HTML report using the enhanced version
    print("[*] Generating enhanced HTML report...")
    report_path = create_html_report_enhanced(
        domain, 
        outdir, 
        nmap_results_file, 
        nuclei_results_file,
        url_tree_file
    )
    
    if report_path:
        print(f"[✓] Enhanced HTML report generated: {report_path}")
    
    end_time = time.time()
    duration = end_time - start_time
    print(f"\n[+] Scan completed for {domain}")
    print(f"[+] Total scan duration: {duration:.2f} seconds ({duration/60:.2f} minutes)")

if __name__ == "__main__":
    main()
