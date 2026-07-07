import socket
from .base_plugin import BasePlugin
from utils.helpers import make_web_request

class SubdomainTakeoverPlugin(BasePlugin):
    PLUGIN_ID = "10006"
    PLUGIN_NAME = "Subdomain Takeover Scanner"
    PLUGIN_FAMILY = "DNS Security"
    PLUGIN_VERSION = "1.0"
    PLUGIN_SHORT_KEY = "takeover"
    DESCRIPTION = "Dangling CNAME, cloud provider takeover detection"

    def __init__(self, target: str, timeout: float = 5.0, discovered_subdomains: list = None):
        super().__init__(target, timeout)
        self.discovered_subdomains = discovered_subdomains or []

    def run(self, progress_callback=None) -> dict:
        """Scan discovered subdomains for takeover vulnerabilities."""
        if not self.discovered_subdomains:
            # Fallback to main host if no subdomains provided
            self.discovered_subdomains = [{"subdomain": self.host, "ip": ""}]

        for sub in self.discovered_subdomains:
            subdomain = sub.get("subdomain")
            if subdomain:
                self.check_takeover(subdomain)
        return self.get_results()

    def check_takeover(self, subdomain: str):
        """Checks target subdomain for dangling CNAME pointing to claimable cloud service."""
        try:
            # Simple check for CNAME resolution
            # Note: socket.getaddrinfo returns IP, but we want CNAME target.
            # Python's built-in socket module has gethostbyaddr which sometimes returns CNAMEs
            # under some OS environments. For standard robustness, we request DNS info or probe HTTP response.
            # Common cloud takeovers can be detected by unique HTTP body signatures.
            url = f"https://{subdomain}"
            res = make_web_request(url, timeout=self.timeout)
            if res:
                self.fingerprint_response(subdomain, res.text)
        except Exception:
            # If HTTPS fails, try HTTP
            try:
                url = f"http://{subdomain}"
                res = make_web_request(url, timeout=self.timeout)
                if res:
                    self.fingerprint_response(subdomain, res.text)
            except Exception:
                pass

    def fingerprint_response(self, subdomain: str, body: str):
        """Matches response bodies to known cloud service error signatures."""
        takeover_signatures = {
            "AWS S3": {
                "sigs": ["NoSuchBucket", "The specified bucket does not exist"],
                "provider": "Amazon AWS S3"
            },
            "GitHub Pages": {
                "sigs": ["There isn't a GitHub Pages site here", "github.io"],
                "provider": "GitHub Pages"
            },
            "Heroku": {
                "sigs": ["No such app", "herokucdn.com"],
                "provider": "Heroku"
            },
            "Azure": {
                "sigs": ["The resource you are looking for has been removed", "azurewebsites.net"],
                "provider": "Microsoft Azure"
            },
            "Shopify": {
                "sigs": ["Sorry, this shop is currently unavailable", "myshopify.com"],
                "provider": "Shopify"
            }
        }

        for name, data in takeover_signatures.items():
            if any(sig in body for sig in data["sigs"]):
                self.add_finding(
                    title=f"Subdomain Takeover Vulnerability ({name})",
                    severity="HIGH",
                    description=f"The subdomain '{subdomain}' points to an inactive {data['provider']} service, allowing takeover.",
                    evidence=f"HTTP signature match found for provider: {name}",
                    remediation=f"Remove the DNS CNAME record for '{subdomain}' or claim the bucket/app in {data['provider']}.",
                    cvss=8.0
                )
                break
