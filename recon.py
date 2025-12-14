import socket
import argparse
import concurrent.futures
import json
import csv
import time
import sys
import base64
from datetime import datetime
from typing import List, Tuple, Dict, Any
import requests
import ssl
from urllib.parse import urlparse, urljoin
import re
import hashlib


# TCP Port Scanner

def probe_tcp(host: str, port: int, timeout: float = 2.0) -> Tuple[int, bool, str]:
    """
    TCP port probe - returns (port, open_status, reason)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return (port, True, "open")
    except socket.timeout:
        return (port, False, "timeout")
    except ConnectionRefusedError:
        return (port, False, "refused")
    except socket.gaierror:
        return (port, False, "name_error")
    except Exception as e:
        return (port, False, str(e))


def grab_banner_tcp(host: str, port: int, timeout: float = 2.0, 
                   send_bytes: bytes = None, read_size: int = 1024) -> Tuple[bool, str]:
    """
    Banner grabbing function
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = ""
    try:
        s.connect((host, port))
        if send_bytes:
            s.sendall(send_bytes)
        try:
            data = s.recv(read_size)
            # Try to decode, fallback to base64 for binary
            try:
                banner += data.decode(errors='replace')
            except:
                banner = base64.b64encode(data).decode('ascii')
        except socket.timeout:
            pass
        s.close()
        return True, banner.strip()[:1000]
    except Exception as e:
        return False, str(e)


def parse_port_spec(spec: str) -> List[int]:
    """
    Parse port specification like '80,443,8000-8100'
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)



# HTTP Probing Functions


def probe_http_service(host: str, port: int, use_https: bool = False, 
                      timeout: float = 10.0) -> Dict[str, Any]:
    """
    Probe HTTP service and extract information
    """
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"
    
    result = {
        "url": url,
        "final_url": url,
        "status_code": 0,
        "title": "",
        "meta_description": "",
        "server_header": "",
        "cookies": [],
        "error": "",
        "scanned_at": datetime.now().isoformat()
    }
    
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,  # Allow self-signed certs
            allow_redirects=True,
            headers={"User-Agent": "Recon-Tool/1.0"}
        )
        
        result["status_code"] = response.status_code
        result["final_url"] = str(response.url)
        
        # Extract Server header
        if "Server" in response.headers:
            result["server_header"] = response.headers["Server"]
        
        # Extract Cookies
        if "Set-Cookie" in response.headers:
            cookies = response.headers.get_list("Set-Cookie")
            result["cookies"] = [cookie.split(";")[0] for cookie in cookies[:5]]
        
        # Extract HTML content
        if "text/html" in response.headers.get("Content-Type", "").lower():
            html = response.text[:8192]  # First 8KB
            
            # Extract title
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if title_match:
                result["title"] = title_match.group(1).strip()[:200]
            
            # Extract meta description
            meta_match = re.search(
                r'<meta\s+[^>]*name\s*=\s*["\']description["\'][^>]*content\s*=\s*["\']([^"\']*)["\'][^>]*>',
                html, re.IGNORECASE
            )
            if meta_match:
                result["meta_description"] = meta_match.group(1).strip()[:500]
            
            # Try to get favicon hash
            try:
                favicon_url = urljoin(str(response.url), "/favicon.ico")
                favicon_response = requests.get(favicon_url, timeout=2, verify=False)
                if favicon_response.status_code == 200:
                    result["favicon_sha256"] = hashlib.sha256(favicon_response.content).hexdigest()
            except:
                pass
    
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    
    return result



# TLS Certificate Analysis


def analyze_tls_certificate(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Analyze TLS certificate
    """
    result = {
        "subject_cn": "",
        "issuer_cn": "",
        "not_before": "",
        "not_after": "",
        "expired": False,
        "weak_params": [],
        "error": ""
    }
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.create_connection((host, port), timeout=timeout)
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            
            if cert:
                # Get subject CN
                subject = dict(x[0] for x in cert.get("subject", []))
                result["subject_cn"] = subject.get("commonName", "") if isinstance(subject, dict) else ""
                
                # Get issuer CN
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer_cn"] = issuer.get("commonName", "") if isinstance(issuer, dict) else ""
                
                # Get validity dates
                if "notBefore" in cert:
                    result["not_before"] = cert["notBefore"]
                if "notAfter" in cert:
                    result["not_after"] = cert["notAfter"]
                    
                    # Check if expired
                    try:
                        not_after_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        result["expired"] = not_after_date < datetime.now()
                    except:
                        pass
        
        sock.close()
        
    except Exception as e:
        result["error"] = str(e)
    
    return result

# Main Reconnaissance Class

class ReconTool:
    def __init__(self, args):
        self.args = args
        self.results = {
            "meta": {
                "run_started": datetime.now().isoformat(),
                "args": vars(args),
                "resumed": False
            },
            "targets": {}
        }
        
    def parse_targets(self) -> List[Tuple[str, List[int]]]:
        """
        Parse targets from file
        """
        targets = []
        try:
            with open(self.args.targets, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle host:port format
                        if ':' in line:
                            host, port_str = line.split(':', 1)
                            try:
                                port = int(port_str)
                                targets.append((host.strip(), [port]))
                            except ValueError:
                                print(f"Warning: Invalid port in target: {line}")
                        else:
                            targets.append((line.strip(), parse_port_spec(self.args.ports)))
        except FileNotFoundError:
            print(f"Error: Targets file not found: {self.args.targets}")
            sys.exit(1)
            
        return targets
    
    def scan_target(self, host: str, ports: List[int]) -> Dict[str, Any]:
        """
        Scan a single target with multiple ports
        """
        target_results = {"ports": {}}
        
        print(f"Scanning {host}...")
        
        # Scan ports concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.workers) as executor:
            future_to_port = {
                executor.submit(probe_tcp, host, port, self.args.timeout): port
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port_num, is_open, reason = future.result()
                    
                    port_result = {
                        "status": "open" if is_open else reason,
                        "scanned_at": datetime.now().isoformat()
                    }
                    
                    # If port is open, get banner and do additional probing
                    if is_open:
                        # Get banner
                        success, banner = grab_banner_tcp(host, port, timeout=2.0)
                        if success and banner:
                            port_result["banner"] = banner
                        
                        # HTTP probing if requested or common HTTP port
                        if self.args.http or port in [80, 443, 8080, 8443]:
                            use_https = port in [443, 8443]
                            http_info = probe_http_service(host, port, use_https, self.args.timeout)
                            port_result["http"] = http_info
                        
                        # TLS analysis if requested
                        if self.args.tls and port in [443, 8443, 993, 995]:
                            tls_info = analyze_tls_certificate(host, port, self.args.timeout)
                            port_result["tls"] = tls_info
                    
                    target_results["ports"][str(port)] = port_result
                    
                except Exception as e:
                    print(f"Error scanning {host}:{port}: {e}")
                    target_results["ports"][str(port)] = {
                        "status": "error",
                        "error": str(e),
                        "scanned_at": datetime.now().isoformat()
                    }
        
        return target_results
    
    def run_scan(self):
        """
        Main scanning function
        """
        targets = self.parse_targets()
        print(f"Loaded {len(targets)} targets")
        
        total_scans = sum(len(ports) for _, ports in targets)
        print(f"Total port scans to perform: {total_scans}")
        
        # Process each target
        for host, ports in targets:
            print(f"\nProcessing target: {host} ({len(ports)} ports)")
            self.results["targets"][host] = self.scan_target(host, ports)
            
            # Count open ports for this target
            open_ports = [
                port for port, data in self.results["targets"][host]["ports"].items()
                if data.get("status") == "open"
            ]
            print(f"  Found {len(open_ports)} open ports")
    
    def save_results(self):
        """
        Save results to JSON and CSV files
        """
        prefix = self.args.output if self.args.output else "recon"
        json_file = f"{prefix}.results.json"
        csv_file = f"{prefix}.results.csv"
        
        # Save JSON
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\nJSON results saved to {json_file}")
        
        # Save CSV
        self.save_csv(csv_file)
        print(f"CSV results saved to {csv_file}")
    
    def save_csv(self, filename: str):
        """
        Save results as CSV
        """
        rows = []
        
        for host, host_data in self.results["targets"].items():
            for port_str, port_data in host_data.get("ports", {}).items():
                if port_data.get("status") == "open":
                    row = {
                        "host": host,
                        "port": port_str,
                        "open": True,
                        "status_code": "",
                        "title": "",
                        "server_header": "",
                        "cert_subject_cn": "",
                        "cert_notAfter": "",
                        "banner_snippet": "",
                        "fingerprint_tags": ""
                    }
                    
                    # Add HTTP info
                    if "http" in port_data:
                        http_info = port_data["http"]
                        row["status_code"] = http_info.get("status_code", "")
                        row["title"] = http_info.get("title", "")[:100]
                        row["server_header"] = http_info.get("server_header", "")[:50]
                    
                    # Add TLS info
                    if "tls" in port_data:
                        tls_info = port_data["tls"]
                        row["cert_subject_cn"] = tls_info.get("subject_cn", "")[:50]
                        row["cert_notAfter"] = tls_info.get("not_after", "")
                    
                    # Add banner snippet
                    if "banner" in port_data:
                        banner = port_data["banner"]
                        row["banner_snippet"] = str(banner)[:100]
                    
                    rows.append(row)
        
        if rows:
            with open(filename, 'w', newline='') as f:
                fieldnames = [
                    "host", "port", "open", "status_code", "title",
                    "server_header", "cert_subject_cn", "cert_notAfter",
                    "banner_snippet", "fingerprint_tags"
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

# Main Function


def main():
    parser = argparse.ArgumentParser(
        description="Professional Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:              python recon.py --targets targets.txt --ports 80,443
  Full scan:               python recon.py --targets targets.txt --ports 1-1024 --http --tls --workers 50
  Common ports scan:       python recon.py --targets targets.txt --ports 21,22,23,25,80,443 --http
  Custom output:           python recon.py --targets targets.txt --ports 80,443 --output myscan
        """
    )
    
    parser.add_argument(
        "--targets",
        required=True,
        help="Path to file with targets (one per line, host or host:port)"
    )
    
    parser.add_argument(
        "--ports",
        required=True,
        help="Ports to scan (e.g., '80,443,8000-8100')"
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Number of concurrent workers (default: 20)"
    )
    
    parser.add_argument(
        "--http",
        action="store_true",
        help="Probe HTTP services for title, meta description, server headers"
    )
    
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Analyze TLS certificates"
    )
    
    parser.add_argument(
        "--output",
        help="Output file prefix (default: recon)"
    )
    
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5.0)"
    )
    
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from previous scan"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Create and run tool
    tool = ReconTool(args)
    
    try:
        print("=" * 60)
        print("PROFESSIONAL RECONNAISSANCE TOOL")
        print("=" * 60)
        print(f"Targets file: {args.targets}")
        print(f"Ports: {args.ports}")
        print(f"Workers: {args.workers}")
        print(f"Timeout: {args.timeout}s")
        print(f"HTTP probing: {'Yes' if args.http else 'No'}")
        print(f"TLS analysis: {'Yes' if args.tls else 'No'}")
        print("=" * 60)
        
        start_time = time.time()
        tool.run_scan()
        tool.save_results()
        
        elapsed = time.time() - start_time
        print(f"\nScan completed in {elapsed:.2f} seconds")
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()