# Professional Reconnaissance Tool

A production-style command-line Python reconnaissance tool that probes targets, enumerates services and HTTP apps, inspects TLS, fingerprints web stacks, and emits machine-readable reports.

## Project Overview

This tool is designed for security professionals and network administrators to perform comprehensive reconnaissance of target systems. It combines port scanning, service enumeration, HTTP analysis, and TLS inspection in a single, easy-to-use command-line tool. The tool emphasizes concurrency, testability, robust error handling, reproducible outputs, and ethical compliance.

## Features

### Core Functionality 

-  TCP Port Scanning : Concurrent TCP connect scans with accurate open/closed/filtered detection
-  HTTP Extraction : Extraction of titles, meta descriptions, and server headers from HTTP services
- TLS Certificate Analysis : Certificate inspection including subject, issuer, validity periods, and expiry detection
-  Structured Output : JSON and CSV reports with consistent schema and proper formatting
- Concurrency Control : Respects --workers and --timeout flags for controlled scanning

## Requirements

### Python Version

- Python 3.8 or higher

### Dependencies

```bash
# Install from requirements.txt
pip install -r requirements.txt
```

The main dependency is:

- requests>=2.28.0 for HTTP probing functionality

All other functionality uses Python's standard library.

## Installation

3. Install dependencies:

```bash
pip install cryptography
```

4. Create necessary files:

```bash
# Create targets file
echo "scanme.nmap.org" > targets.txt
echo "example.com" >> targets.txt

```

## Usage

### Basic Examples

Scan common web ports:

```bash
python recon.py --targets targets.txt --ports 80,443 --http --output scan1
```

Full port scan with TLS analysis:

```bash
python recon.py --targets targets.txt --ports 1-1024 --workers 50 --http --tls --output fullscan
```

Scan specific service ports:

```bash
python recon.py --targets targets.txt --ports 21,22,23,25,80,110,143,443,445,993,995 --tls
```

Scan with custom timeout:

```bash
python recon.py --targets targets.txt --ports 80,443 --timeout 10.0 --http --verbose
```

### Command Line Arguments

| Argument | Description | Required | Default |
|----------|-------------|----------|---------|
| --targets PATH | Path to targets file (one host per line; allow host:port) | Yes | - |
| --ports PORTS | Comma list or ranges (e.g., 80,443,8000-8100) | Yes | - |
| --workers N | Concurrent TCP workers | No | 20 |
| --http | Probe HTTP(S) services and extract title, meta description, Server header | No | False |
| --tls | Attempt TLS retrieval for ports that speak TLS | No | False |
| --output PREFIX | Path prefix for results (creates .json and .csv files) | No | "recon" |
| --timeout S | Per-connection timeout in seconds (float OK) | No | 5.0 |
| --resume | Resume from previous results | No | False |
| -v, --verbose | Verbose output | No | False |

### Targets File Format

Create a text file with one target per line. Supports two formats:

- Hostname or IP address only (will scan all specified ports):

```
scanme.nmap.org
example.com
192.168.1.1
```

- Hostname:port combination (will only scan specified port):

```
localhost:8080
example.com:443
192.168.1.1:22
```

Example targets.txt:

```
# Public testing targets
scanme.nmap.org
example.com

# Local testing
localhost
localhost:8080
localhost:3000

# Specific service testing
google.com:443
github.com:80
```

### Port Specification Examples

- Single ports: 80,443,8080
- Ranges: 1-1000
- Mixed: 21,22,80-100,443,8000-8100
- Common web ports: 80,443,8080,8443,8000,3000
- Common service ports: 21,22,23,25,53,80,110,143,443,445,993,995

## Output Formats

### JSON Output (prefix.results.json)

Complete structured data with the following schema:

```json
{
  "meta": {
    "run_started": "2024-01-15T10:30:00.000000",
    "args": {
      "targets": "targets.txt",
      "ports": "80,443",
      "workers": 20,
      "http": true,
      "tls": false,
      "output": "scan1",
      "timeout": 5.0,
      "resume": false,
      "verbose": false
    },
    "resumed": false,
    "version": "1.0"
  },
  "targets": {
    "scanme.nmap.org": {
      "ports": {
        "80": {
          "status": "open",
          "scanned_at": "2024-01-15T10:30:05.123456",
          "banner": "HTTP/1.1 200 OK...",
          "service_hint": "http",
          "http": {
            "url": "http://scanme.nmap.org:80/",
            "final_url": "http://scanme.nmap.org:80/",
            "status_code": 200,
            "title": "Test Page",
            "meta_description": "Test page description",
            "server_header": "nginx/1.18",
            "cookies": [],
            "error": ""
          }
        },
        "443": {
          "status": "open",
          "scanned_at": "2024-01-15T10:30:06.234567",
          "banner": "",
          "tls": {
            "subject_cn": "scanme.nmap.org",
            "issuer_cn": "Let's Encrypt",
            "not_before": "Jan 01 00:00:00 2024 GMT",
            "not_after": "Apr 01 00:00:00 2024 GMT",
            "expired": false,
            "error": ""
          }
        }
      }
    }
  }
}
```

### CSV Output (prefix.results.csv)

Flattened summary with one row per discovered service:

| Column | Description | Example |
|--------|-------------|---------|
| host | Target hostname or IP | scanme.nmap.org |
| port | Port number | 80 |
| open | Whether port is open | TRUE |
| status | Port status | open |
| status_code | HTTP status code | 200 |
| title | HTML page title | Test Page |
| server_header | Server header value | nginx/1.18 |
| cert_subject_cn | TLS certificate subject CN | scanme.nmap.org |
| cert_notAfter | TLS certificate expiry date | Apr 01 00:00:00 2024 GMT |
| banner_snippet | First 100 chars of banner | HTTP/1.1 200 OK... |
| fingerprint_tags | Service fingerprint tags | (Reserved for future) |

## Implementation Details

### TCP Port Scanning

- **Method**: TCP connect scanning (not raw SYN)
- **Concurrency**: ThreadPoolExecutor with configurable worker count
- **Timeout Handling**: Respects --timeout parameter for all connections
- **Status Detection**:
  - open: Successful connection
  - closed: Connection refused
  - filtered: Connection timeout
  - error: Other connection errors

### HTTP Probing

- **Protocol Support**: HTTP and HTTPS (autodetected based on port)
- **Redirect Handling**: Follows up to 5 redirects
- **Content Extraction**:
  - HTML title (first 200 characters)
  - Meta description (first 500 characters)
  - Server header
  - Cookies (first 5)
  - Favicon SHA256 hash
- **Error Handling**: Graceful degradation on connection failures

### TLS Certificate Analysis

- **Certificate Parsing**: Uses Python's ssl library
- **Information Extracted**:
  - Subject Common Name
  - Issuer Common Name
  - Validity period (notBefore, notAfter)
  - Expiry status
- **Weak Parameter Detection**: Basic checking for expired certificates

### Output Generation

- **JSON Schema**: Consistent structure for machine processing
- **CSV Format**: Flattened view for human analysis
- **File Naming**: {prefix}.results.json and {prefix}.results.csv
- **Error Preservation**: All errors captured and included in output


### Acceptable Targets

- Systems you own or administrate
- Public testing services (e.g., scanme.nmap.org)
- Systems with written permission from the owner
- Educational lab environments

### Unacceptable Use

- Scanning systems without permission
- Disrupting production services
- Violating terms of service
- Illegal surveillance

### Safety Guidelines

- Always obtain written permission before scanning
- Start with light scans (few ports, high timeouts)
- Monitor resource usage on both scanner and target
- Respect rate limits to avoid service disruption
- Document all activities for audit purposes
- Use appropriate timeouts for the network environment
- Test locally first before scanning remote targets

## Testing

### Test Commands

Basic functionality test:

```bash
python recon.py --targets targets.txt --ports 80,443 --http --output test_basic
```

Concurrency test:

```bash
python recon.py --targets targets.txt --ports 1-100 --workers 50 --output test_concurrent
```

TLS analysis test:

```bash
python recon.py --targets targets.txt --ports 443 --tls --output test_tls
```

Verbose output test:

```bash
python recon.py --targets targets.txt --ports 22,80,443 -v --output test_verbose
```

### Expected Output

Successful execution produces:

- Progress output to console
- {prefix}.results.json file with detailed results
- {prefix}.results.csv file with summary data
- Exit code 0 on success, 1 on error

## Troubleshooting

### Common Issues

**"Connection refused" for all ports:**

- Target may be offline or blocking connections
- Check network connectivity with ping or traceroute

**Timeout errors:**

- Increase --timeout value (e.g., --timeout 10.0)
- Check firewall rules on both ends
- Verify target is reachable

**"Name resolution failed":**

- Check DNS configuration
- Use IP addresses instead of hostnames
- Verify internet connectivity

**Slow scanning:**

- Reduce --workers count
- Increase --timeout value
- Scan fewer ports at once

**No output files created:**

- Check write permissions in current directory
- Verify --output prefix doesn't conflict with existing files
- Check disk space

### Debug Mode

Use verbose flag for detailed output:

```bash
python recon.py --targets targets.txt --ports 80,443 -v
```

Verbose mode shows:

- Connection attempts and results
- Banner grabbing attempts
- HTTP probe details
- Error stack traces

## Project Structure

```
recon-tool/
├── recon.py              # Main executable script
├── README.md             # Project documentation (this file)
├── AUTHORISATION.txt     # Authorization statement (REQUIRED)
├── targets.txt           # Example targets for testing
├── requirements.txt      # Python dependencies
├── results.json          # Example JSON output (generated)
├── results.csv           # Example CSV output (generated)
└── lab4-2_activity.log   # Activity log (if used for lab)
```

### File Descriptions

- **recon.py**: Main Python script with all functionality
- **README.md**: Complete project documentation
- **AUTHORISATION.txt**: REQUIRED - certifies permission to scan
- **targets.txt**: Example targets for testing
- **requirements.txt**: Python package dependencies
- **results.json**: Example output in JSON format
- **results.csv**: Example output in CSV format

## Limitations

### Current Limitations

- No UDP scanning - TCP only
- Basic fingerprinting - Limited service identification
- No vulnerability assessment - Reconnaissance only
- Single-threaded HTTP/TLS - After port discovery
- Basic rate limiting - Simple sleep-based approach

### Design Decisions

- TCP connect scanning chosen over raw SYN for simplicity and compatibility
- ThreadPoolExecutor used for concurrency for ease of use
- JSON primary output for machine readability
- Modular design for easy extension

## Future Enhancements

### Priority Features

- UDP port scanning support
- Advanced fingerprinting with database lookup
- Vulnerability pattern matching
- Distributed scanning capabilities
- Web interface for results visualization

### Extended Functionality

- DNS enumeration and subdomain discovery
- WHOIS lookup integration
- SSL/TLS cipher suite analysis
- HTTP method testing (OPTIONS, PUT, DELETE)
- WAF detection and bypass techniques

## Development

### Code Organization

- Functions grouped by functionality: TCP, HTTP, TLS, Output
- Clear separation of concerns: Scanning, probing, analysis, reporting
- Error handling: Comprehensive try/except blocks
- Type hints: Python type annotations for clarity


