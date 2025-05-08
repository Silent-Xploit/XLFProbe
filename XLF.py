#!/usr/bin/python3

import sys
import os
import urllib.parse
import urllib.request
import urllib.error
from time import sleep
import socket
from typing import List, Optional, Tuple
from colorama import init, Fore, Style
from datetime import datetime
import json

# Initialize colorama for Windows support
init()

# Tool Information
__version__ = "1.0.0"
__author__ = "det0x"
__github_repo__ = "Silent-Xploit/XLFProbe"

def clear_screen():
    """Clear the terminal screen based on OS."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner(banner_type: str = "main"):
    """Display ASCII art banner based on the type."""
    clear_screen()
    
    banners = {
        "main": {
            "color": Fore.CYAN,
            "text": f"""
    ═══════════════════════════════════════
           __  ___    ____   ____ 
           \ \/ / |  / __/  / __/ 
            \  /| | / /_   / /_   
            /  \| |/ __/  / __/   
           /_/\_\_/_/    /_/      
                                  
         [ Local File & XSS Probe ]
    ═══════════════════════════════════════
            Author: {__author__}
            Version: {__version__}
    ═══════════════════════════════════════
        """
        },
        "lfi": {
            "color": Fore.RED,
            "text": """
    ═══════════════════════════════════════
             __    ______ ____ 
            / /   / ____//  _/
           / /   / /_    / /  
          / /___/ __/  _/ /   
         /_____/_/    /___/   
                             
        [ Local File Inclusion Scanner ]
    ═══════════════════════════════════════
        """
        },
        "xss": {
            "color": Fore.YELLOW,
            "text": """
    ═══════════════════════════════════════
           _  __  _____ _____ 
          | |/ / / ___// ___/
          |   /  \__ \ \__ \ 
         /   |  ___/ /___/ / 
        /_/|_| /____//____/  
                            
        [ Cross-Site Scripting Scanner ]
    ═══════════════════════════════════════
        """
        },
        "update": {
            "color": Fore.GREEN,
            "text": """
    ═══════════════════════════════════════
         __  ______  ____   ___   ______ ____
        / / / / __ \/ __ \ /   | /_  __// __/
       / / / / /_/ / / / // /| |  / /  / /_  
      / /_/ / ____/ /_/ // ___ | / /  / __/  
      \____/_/    \____//_/  |_|/_/  /_/     
                                           
            [ XLF Update Manager ]
    ═══════════════════════════════════════
        """
        }
    }
    
    banner = banners.get(banner_type, banners["main"])
    print(f"{banner['color']}{banner['text']}{Style.RESET_ALL}")

def validate_url(url: str) -> bool:
    """Validate if the given URL is properly formatted."""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def load_payloads(payload_type: str, payload_path: Optional[str] = None) -> List[str]:
    """Load attack payloads from a custom file."""
    if not payload_path:
        print_status(f"No payload file specified for {payload_type.upper()} scan", "error")
        print_status("Please provide a payload file to continue", "warning")
        return []
    
    try:
        with open(payload_path, 'r') as f:
            custom_payloads = [line.strip() for line in f if line.strip()]
        if not custom_payloads:
            print_status(f"No payloads found in file: {payload_path}", "error")
            return []
        print_status(f"Successfully loaded {len(custom_payloads)} payloads from {payload_path}", "success")
        return custom_payloads
    except FileNotFoundError:
        print_status(f"Payload file not found: {payload_path}", "error")
        return []
    except Exception as e:
        print_status(f"Error reading payload file: {str(e)}", "error")
        return []

def generate_html_report(url: str, scan_type: str, successful_payloads: List[Tuple[str, str]]) -> str:
    """Generate an HTML report for successful scan results."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XLF Scan Report - {scan_type.upper()}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
            background-color: #f0f0f0;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1, h2 {{
            color: #2c3e50;
        }}
        .header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        .vulnerability {{
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }}
        .success {{
            color: #155724;
            background-color: #d4edda;
            border-color: #c3e6cb;
            padding: 10px;
            margin: 5px 0;
            border-radius: 3px;
        }}
        .details {{
            margin-left: 20px;
            padding: 10px;
            background-color: #f8f9fa;
            border-left: 3px solid #2c3e50;
        }}
        .timestamp {{
            color: #6c757d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XLF Scanner Report</h1>
            <p>Scan Type: {scan_type.upper()}</p>
            <p>Target URL: {url}</p>
            <p class="timestamp">Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <h2>Successful Payloads</h2>
        <div class="vulnerability">
            <p>Number of successful payloads: {len(successful_payloads)}</p>
            
            {generate_payload_sections(successful_payloads)}
        </div>
    </div>
</body>
</html>
"""
    
    # Create reports directory if it doesn't exist
    os.makedirs("reports", exist_ok=True)
    
    # Save the report
    filename = f"reports/xlf_report_{scan_type}_{timestamp}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return filename

def generate_payload_sections(successful_payloads: List[Tuple[str, str]]) -> str:
    """Generate HTML sections for each successful payload."""
    sections = []
    for test_url, payload in successful_payloads:
        sections.append(f"""
            <div class="success">
                <strong>Payload:</strong>
                <div class="details">
                    <code>{html_escape(payload)}</code>
                </div>
                <strong>URL:</strong>
                <div class="details">
                    <code>{html_escape(test_url)}</code>
                </div>
            </div>
        """)
    return "\n".join(sections)

def html_escape(text: str) -> str:
    """Escape HTML special characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

def validate_lfi_response(content: str, payload: str) -> bool:
    """
    Validate LFI vulnerability with multiple checks to avoid false positives.
    Returns True if the content indicates a successful LFI, False otherwise.
    """
    # Common patterns that indicate successful LFI
    unix_patterns = [
        # /etc/passwd patterns
        r"root:.*:0:0:",
        r"nobody:.*:65534:65534:",
        r"daemon:.*:1:1:",
        # Common system file patterns
        r"sbin:/bin/sh",
        r"/bin/bash$",
        # Apache config patterns
        r"<Directory /",
        r"DocumentRoot",
    ]
    
    windows_patterns = [
        # Windows system file patterns
        r"\[boot loader\]",
        r"^\[fonts\]",
        r"WINDOWS\\system32",
        r"\\Device\\Harddisk",
        r"\\SystemRoot",
        # Windows ini patterns
        r"^\[extensions\]",
        r"^\[mci extensions\]"
    ]
    
    # Additional validation for specific payloads
    payload_specific = {
        "passwd": ["root:", "bin:", "daemon:", "sys:"],
        "shadow": ["root:$", "daemon:*", "*:*:"],
        "win.ini": ["extensions", "fonts", "mci extensions"],
        "boot.ini": ["boot loader", "operating systems"],
    }
    
    import re
    
    # Check if content is empty or too short
    if not content or len(content) < 10:
        return False
    
    # Check for common error messages that might be false positives
    error_patterns = [
        "warning",
        "fatal error",
        "not found",
        "404",
        "403",
        "permission denied",
        "<html",  # Usually indicates normal webpage
        "<!DOCTYPE"
    ]
    
    # If content contains common error patterns, likely not a successful LFI
    if any(err.lower() in content.lower() for err in error_patterns):
        return False
    
    # Check for payload-specific patterns
    payload_lower = payload.lower()
    for key, patterns in payload_specific.items():
        if key in payload_lower:
            if any(pattern.lower() in content.lower() for pattern in patterns):
                # Additional validation: must match multiple patterns for higher confidence
                matches = sum(1 for pattern in patterns if pattern.lower() in content.lower())
                if matches >= 2:  # Require at least 2 matches for confirmation
                    return True
    
    # Check Unix patterns
    unix_matches = sum(1 for pattern in unix_patterns if re.search(pattern, content, re.MULTILINE))
    if unix_matches >= 2:  # Require multiple matches for higher confidence
        return True
    
    # Check Windows patterns
    windows_matches = sum(1 for pattern in windows_patterns if re.search(pattern, content, re.MULTILINE))
    if windows_matches >= 2:
        return True
    
    return False

def validate_xss_response(content: str, payload: str) -> bool:
    """
    Validate XSS vulnerability with multiple checks to avoid false positives.
    Returns True if the content indicates a successful XSS, False otherwise.
    """
    import re
    
    # Remove whitespace and convert to lowercase for comparison
    content_normalized = re.sub(r'\s+', '', content.lower())
    payload_normalized = re.sub(r'\s+', '', payload.lower())
    
    # For simple script payloads like <script>alert(1)</script>, do a direct check first
    if re.match(r'^\s*<script>\s*alert\(\d+\)\s*</script>\s*$', payload, re.IGNORECASE):
        # Check the content for unencoded payload
        if payload.lower() in content.lower():
            # Additional check: ensure it's not encoded
            if not any(encoded in content.lower() for encoded in ['&lt;script', '%3cscript', '\\u003cscript']):
                # Verify script tags are properly placed
                if '<script' in content.lower() and '</script>' in content.lower():
                    return True
        
        # Also check for the alert content specifically
        alert_content = re.search(r'alert\(\d+\)', payload, re.IGNORECASE)
        if alert_content and alert_content.group() in content:
            # Verify it's within script tags and not encoded
            script_tags = re.findall(r'<script[^>]*>(.*?)</script>', content, re.IGNORECASE | re.DOTALL)
            return any(alert_content.group() in script for script in script_tags)
    
    # Handle iframe payloads more accurately
    if '<iframe' in payload_normalized:
        # First check if the iframe tag is properly reflected
        if payload_normalized not in content_normalized:
            return False
            
        # Check if the iframe is encoded or escaped
        encoded_forms = [
            '&lt;iframe',
            '%3ciframe',
            '\\u003ciframe',
            '&#x3c;iframe',
            '&#60;iframe'
        ]
        if any(encoded in content_normalized for encoded in encoded_forms):
            return False
            
        # Check if the javascript: protocol is properly included and not sanitized
        if 'javascript:' in payload_normalized:
            # Common sanitization patterns
            sanitized_forms = [
                'about:blank',
                'javascript:void(0)',
                'javascript:;',
                'javascript&colon;',
                'javascript&#58;',
                'javascript&#x3a;'
            ]
            if any(sanitized in content_normalized for sanitized in sanitized_forms):
                return False
                
            # Check if javascript: protocol is encoded or removed
            if 'javascript:' not in content_normalized:
                return False
            
            # Check if it's part of a string literal
            js_protocol_context = re.findall(r'["\'].*?javascript:.*?["\']', content_normalized)
            if js_protocol_context:
                return False
    
    # Handle img tag with onerror
    if '<img' in payload_normalized and 'onerror' in payload_normalized:
        if not re.search(r'<img[^>]*onerror\s*=\s*["\']?[^>]*>', content, re.IGNORECASE):
            return False
        # Check if the onerror attribute is properly set
        onerror_value = re.search(r'onerror\s*=\s*["\']?(.*?)["\']?[\s>]', payload, re.IGNORECASE)
        if onerror_value and onerror_value.group(1) not in content:
            return False
    
    # Handle SVG payloads
    if '<svg' in payload_normalized:
        if 'onload' in payload_normalized:
            # Check if onload event is properly reflected
            if not re.search(r'<svg[^>]*onload\s*=\s*["\']?[^>]*>', content, re.IGNORECASE):
                return False
        if '<script' in payload_normalized:
            # Check for script content within SVG
            svg_script = re.search(r'<svg[^>]*>.*?<script[^>]*>(.*?)</script>.*?</svg>', 
                                 payload, re.IGNORECASE | re.DOTALL)
            if svg_script and svg_script.group(1) not in content:
                return False
    
    # Handle data: URIs
    if 'data:' in payload_normalized:
        # Extract and check data URI content
        data_uri = re.search(r'data:.*?base64,(.*?)[\'")\s>]', payload)
        if data_uri and data_uri.group(1) not in content:
            return False
    
    # If we've made it this far with a script alert payload, do one final check
    if '<script' in payload_normalized and 'alert' in payload_normalized:
        # Check if the script tag and alert are in the correct sequence
        script_pos = content_normalized.find('<script')
        alert_pos = content_normalized.find('alert')
        if script_pos != -1 and alert_pos != -1:
            # Alert should come after script tag
            if alert_pos > script_pos:
                # Check that they're in the same script block
                script_block = re.search(r'<script[^>]*>.*?alert.*?</script>', 
                                       content, re.IGNORECASE | re.DOTALL)
                if script_block:
                    return True
    
    return False

def scan_url(url: str, payload_type: str, payload_path: Optional[str] = None):
    """Scan a single URL for vulnerabilities."""
    payloads = load_payloads(payload_type, payload_path)
    if not payloads:
        print_status("No payloads available. Aborting scan.", "error")
        return
        
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    
    print_status(f"Testing URL: {url}", "info")
    print_status(f"Number of parameters detected: {len(params)}", "info")
    print_status(f"Number of payloads loaded: {len(payloads)}", "info")
    
    # Track successful payloads
    successful_payloads = []
    failed_payloads = []
    
    for param in params:
        print_status(f"\nTesting parameter: {param}", "info")
        print("\n" + "="*60)  # Separator line
        
        original_response = None
        try:
            # Get original response for comparison
            original_response = urllib.request.urlopen(url, timeout=5).read().decode('utf-8', errors='ignore')
        except:
            print_status("Could not get original response for comparison", "warning")
        
        for payload in payloads:
            test_url = construct_test_url(url, param, payload)
            try:
                response = urllib.request.urlopen(test_url, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                # Skip if response is identical to original (likely no injection)
                if original_response and content == original_response:
                    print(f"{Fore.YELLOW}[?] No change in response - Payload: {payload}{Style.RESET_ALL}")
                    continue
                
                if payload_type == "lfi":
                    if validate_lfi_response(content, payload):
                        successful_payloads.append((test_url, payload))
                        print(f"{Fore.GREEN}[✓] Success - LFI Payload: {payload}{Style.RESET_ALL}")
                    else:
                        failed_payloads.append((test_url, payload))
                        print(f"{Fore.RED}[×] Failed - LFI Payload: {payload}{Style.RESET_ALL}")
                else:  # XSS
                    if validate_xss_response(content, payload):
                        successful_payloads.append((test_url, payload))
                        print(f"{Fore.GREEN}[✓] Success - XSS Payload: {payload}{Style.RESET_ALL}")
                    else:
                        failed_payloads.append((test_url, payload))
                        print(f"{Fore.RED}[×] Failed - XSS Payload: {payload}{Style.RESET_ALL}")
                        
            except urllib.error.URLError as e:
                failed_payloads.append((test_url, payload))
                print(f"{Fore.RED}[×] Error - Payload: {payload} - {str(e)}{Style.RESET_ALL}")
            except socket.timeout:
                failed_payloads.append((test_url, payload))
                print(f"{Fore.RED}[×] Timeout - Payload: {payload}{Style.RESET_ALL}")
            except Exception as e:
                failed_payloads.append((test_url, payload))
                print(f"{Fore.RED}[×] Error - Payload: {payload} - {str(e)}{Style.RESET_ALL}")
            
            sleep(0.5)  # Small delay to avoid overwhelming the server
        
        print("="*60)  # Separator line
        
        # Print summary for this parameter
        if successful_payloads:
            print("\n" + "="*60)
            print(f"{Fore.YELLOW}[!] VULNERABILITY DETECTED{Style.RESET_ALL}")
            print(f"\n{Fore.GREEN}Successfully working payloads:{Style.RESET_ALL}")
            for test_url, payload in successful_payloads:
                print(f"\n{Fore.GREEN}✓ Payload: {payload}")
                print(f"✓ URL: {test_url}{Style.RESET_ALL}")
            
            # Generate and save HTML report
            report_file = generate_html_report(url, payload_type, successful_payloads)
            print_status(f"HTML report generated: {report_file}", "success")
        
        print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✓ Working Payloads: {len(successful_payloads)}{Style.RESET_ALL}")
        print(f"{Fore.RED}× Failed Payloads: {len(failed_payloads)}{Style.RESET_ALL}")
        print("="*60 + "\n")  # Separator line

def construct_test_url(url: str, param: str, payload: str) -> str:
    """Construct a URL with the test payload."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

def bulk_scan(file_path: str, scan_type: str, payload_path: Optional[str] = None):
    """Scan multiple URLs from a file."""
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print_status(f"Loaded {len(urls)} URLs from {file_path}", "info")
        for url in urls:
            if validate_url(url):
                scan_url(url, scan_type, payload_path)
            else:
                print_status(f"Invalid URL format: {url}", "error")
    except FileNotFoundError:
        print_status(f"File not found: {file_path}", "error")
    except Exception as e:
        print_status(f"Error reading file: {str(e)}", "error")

def print_menu_option(number: str, text: str):
    """Print a colored menu option."""
    print(f"{Fore.CYAN}{number}.{Style.RESET_ALL} {text}")

def print_status(message: str, status_type: str = "info"):
    """Print a colored status message."""
    colors = {
        "success": Fore.GREEN,
        "error": Fore.RED,
        "info": Fore.CYAN,
        "warning": Fore.YELLOW
    }
    prefix = {
        "success": "[+]",
        "error": "[-]",
        "info": "[*]",
        "warning": "[!]"
    }
    color = colors.get(status_type, Fore.WHITE)
    prefix_symbol = prefix.get(status_type, "[*]")
    print(f"{color}{prefix_symbol} {message}{Style.RESET_ALL}")

def lfi_scanner():
    """LFI Scanner main function."""
    print_banner("lfi")
    print("\nSelect an option:")
    print_menu_option("1", "Single URL")
    print_menu_option("2", "Bulk Scan")
    
    choice = input(f"\n{Fore.CYAN}Select an option (1-2): {Style.RESET_ALL}")
    payload_path = input(f"\n{Fore.CYAN}Enter path to LFI payloads file: {Style.RESET_ALL}").strip()
    
    if not payload_path:
        print_status("Payload file is required!", "error")
        return
        
    if choice == "1":
        url = input(f"\n{Fore.CYAN}Enter the URL to scan: {Style.RESET_ALL}")
        if validate_url(url):
            scan_url(url, "lfi", payload_path)
        else:
            print_status("Invalid URL format!", "error")
    elif choice == "2":
        file_path = input(f"\n{Fore.CYAN}Enter the path to your URLs file: {Style.RESET_ALL}")
        bulk_scan(file_path, "lfi", payload_path)
    else:
        print_status("Invalid choice!", "error")

def xss_scanner():
    """XSS Scanner main function."""
    print_banner("xss")
    print("\nSelect an option:")
    print_menu_option("1", "Single URL")
    print_menu_option("2", "Bulk Scan")
    
    choice = input(f"\n{Fore.CYAN}Select an option (1-2): {Style.RESET_ALL}")
    payload_path = input(f"\n{Fore.CYAN}Enter path to XSS payloads file: {Style.RESET_ALL}").strip()
    
    if not payload_path:
        print_status("Payload file is required!", "error")
        return
        
    if choice == "1":
        url = input(f"\n{Fore.CYAN}Enter the URL to scan: {Style.RESET_ALL}")
        if validate_url(url):
            scan_url(url, "xss", payload_path)
        else:
            print_status("Invalid URL format!", "error")
    elif choice == "2":
        file_path = input(f"\n{Fore.CYAN}Enter the path to your URLs file: {Style.RESET_ALL}")
        bulk_scan(file_path, "xss", payload_path)
    else:
        print_status("Invalid choice!", "error")

def check_github_version() -> tuple:
    """Check the latest version from GitHub repository."""
    try:
        api_url = f"https://api.github.com/repos/{__github_repo__}/releases/latest"
        response = urllib.request.urlopen(api_url, timeout=10)
        data = json.loads(response.read().decode('utf-8'))
        latest_version = data['tag_name'].lstrip('v')  # Remove 'v' prefix if present
        download_url = data['zipball_url']
        return True, latest_version, download_url
    except Exception as e:
        return False, str(e), None

def download_and_update(download_url: str) -> bool:
    """Download and update the tool from GitHub."""
    try:
        # Create temp directory
        temp_dir = "temp_update"
        os.makedirs(temp_dir, exist_ok=True)
        
        # Download the update
        zip_path = os.path.join(temp_dir, "update.zip")
        print_status("Downloading update...", "info")
        urllib.request.urlretrieve(download_url, zip_path)
        
        # Extract the update
        import zipfile
        print_status("Extracting files...", "info")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # Get the extracted directory name (it will be the repo name + commit hash)
        extracted_dir = next(d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d)))
        
        # Copy new files
        import shutil
        current_dir = os.path.dirname(os.path.abspath(__file__))
        source_dir = os.path.join(temp_dir, extracted_dir)
        
        print_status("Installing update...", "info")
        # Copy all files except the ones in use
        for item in os.listdir(source_dir):
            source = os.path.join(source_dir, item)
            destination = os.path.join(current_dir, item)
            if os.path.isfile(source):
                shutil.copy2(source, destination)
            elif os.path.isdir(source):
                shutil.copytree(source, destination, dirs_exist_ok=True)
        
        # Clean up
        shutil.rmtree(temp_dir)
        print_status("Update completed successfully!", "success")
        return True
    except Exception as e:
        print_status(f"Update failed: {str(e)}", "error")
        return False

def update_tool():
    """Update Tool function."""
    print_banner("update")
    print_status("Checking for updates...", "info")
    
    success, latest_version, download_url = check_github_version()
    
    if not success:
        print_status(f"Failed to check for updates: {latest_version}", "error")
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        return
    
    # Compare versions
    from pkg_resources import parse_version
    current_ver = parse_version(__version__)
    latest_ver = parse_version(latest_version)
    
    if latest_ver <= current_ver:
        print_status(f"You are running the latest version! (v{__version__})", "success")
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        return
    
    print_status(f"New version available: v{latest_version} (Current: v{__version__})", "info")
    choice = input(f"\n{Fore.CYAN}Do you want to update? (y/N): {Style.RESET_ALL}").lower()
    
    if choice == 'y':
        if download_and_update(download_url):
            print_status("Please restart the tool to use the new version.", "warning")
            sys.exit(0)
    else:
        print_status("Update cancelled.", "info")
    
    input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

def main():
    """Main program loop."""
    while True:
        print_banner()
        print("\nSelect an option:")
        print_menu_option("1", "LFI Scanner")
        print_menu_option("2", "XSS Scanner")
        print_menu_option("3", "Update Tool")
        print_menu_option("4", "Exit")
        
        choice = input(f"\n{Fore.CYAN}Enter your choice (1-4): {Style.RESET_ALL}")
        
        if choice == "1":
            lfi_scanner()
        elif choice == "2":
            xss_scanner()
        elif choice == "3":
            update_tool()
        elif choice == "4":
            print_status("Thanks for using XLF. Goodbye!", "info")
            sys.exit(0)
        else:
            print_status("Invalid choice! Please try again.", "error")
        
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_status("Program terminated by user.", "warning")
        sys.exit(0)