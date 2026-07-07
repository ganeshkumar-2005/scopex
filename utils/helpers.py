import re
from datetime import datetime
import urllib.parse
import httpx

# Suppress certificate verification warnings for cleaner progress/CLI output
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

def validate_target(target: str) -> str:
    """
    Validates the target input and normalizes it.
    Supports:
      - Hostnames (e.g. example.com, test.example.com)
      - IP Addresses (IPv4 and IPv6 format)
      - URLs (extracts host, or retains full URL if protocol is required)
    """
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    
    # Check for shell metacharacters anywhere in the target string
    shell_metachars = ('&', '|', ';', '`', '$', '>', '<', '\n', '\r')
    if any(char in target for char in shell_metachars):
        raise ValueError("Target contains illegal shell characters.")

    # Simple Host/IP regex
    host_regex = re.compile(
        r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    )
    ip_regex = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )

    # Check if target is a full URL
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme in ('http', 'https'):
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"Invalid URL host: '{target}'")
        if not (host_regex.match(hostname) or ip_regex.match(hostname)):
            raise ValueError(f"Invalid URL host format: '{hostname}'")
        return target
        
    # Strip any port if provided (e.g., host:port)
    host_only = target.split(':')[0]
    
    if host_regex.match(host_only) or ip_regex.match(host_only):
        return target
    
    raise ValueError(f"Invalid host or IP address format: '{target}'")

def get_timestamp() -> str:
    """Generates formatted ISO-like filename-safe timestamp."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def get_readable_timestamp() -> str:
    """Generates human-readable timestamp for reports."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def severity_color(severity: str) -> str:
    """Maps finding severity to rich styling color strings."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return "bold red"
    elif sev == "HIGH":
        return "red"
    elif sev == "MEDIUM":
        return "yellow"
    elif sev == "LOW":
        return "blue"
    elif sev == "INFO":
        return "green"
    return "white"

def severity_icon(severity: str) -> str:
    """Maps severity to icons/emojis."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return "[CRITICAL]"
    elif sev == "HIGH":
        return "[HIGH]"
    elif sev == "MEDIUM":
        return "[WARN]"
    elif sev == "LOW":
        return "[LOW]"
    return "[INFO]"

def make_web_request(url: str, method: str = "GET", headers: dict = None, 
                     params: dict = None, data=None, json_data=None, timeout: float = 5.0, 
                     allow_redirects: bool = True) -> httpx.Response:
    """Helper wrapper to execute web requests safely with standard user agent.
    
    Args:
        json_data: If provided, sends as JSON body (Content-Type: application/json).
                   Mutually exclusive with data - json_data takes priority if both given.
    """
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    if headers:
        default_headers.update(headers)
        
    try:
        with httpx.Client(verify=False, follow_redirects=allow_redirects) as client:
            response = client.request(
                method=method,
                url=url,
                headers=default_headers,
                params=params,
                data=data if json_data is None else None,
                json=json_data,
                timeout=timeout,
            )
            return response
    except httpx.RequestError as e:
        # Re-raise or return None to let scanner handle network issues
        raise e
