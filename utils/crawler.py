import urllib.parse
from bs4 import BeautifulSoup
from utils.helpers import make_web_request

class Crawler:
    def __init__(self, root_url: str, max_depth: int = 2, max_links: int = 50, timeout: float = 5.0):
        self.root_url = root_url
        self.max_depth = max_depth
        self.max_links = max_links
        self.timeout = timeout
        self.visited = set()
        self.discovered_urls = set()
        self.parameterized_urls = set()

    def crawl(self) -> list:
        """Starts crawling from the root URL and returns a list of unique URLs with query parameters."""
        self._crawl_recursive(self.root_url, depth=0)
        return list(self.parameterized_urls)

    def _crawl_recursive(self, url: str, depth: int):
        if depth > self.max_depth or len(self.discovered_urls) >= self.max_links:
            return

        if url in self.visited:
            return

        self.visited.add(url)
        self.discovered_urls.add(url)

        try:
            response = make_web_request(url, timeout=self.timeout)
            if not response or response.status_code != 200:
                return

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract links from <a> tags
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                self._process_link(url, href)

            # Extract actions from <form> tags
            for form_tag in soup.find_all('form', action=True):
                action = form_tag['action']
                self._process_link(url, action)

        except Exception as e:
            from loguru import logger
            logger.debug(f"[Utils Crawler _crawl_recursive] failed: {e}")

    def _process_link(self, base_url: str, link: str):
        full_url = urllib.parse.urljoin(base_url, link)
        parsed_url = urllib.parse.urlparse(full_url)
        
        # Check if the domain matches the root URL domain
        root_parsed = urllib.parse.urlparse(self.root_url)
        if parsed_url.netloc != root_parsed.netloc:
            return

        # Strip fragment
        clean_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, ''))
        
        if parsed_url.query:
             self.parameterized_urls.add(clean_url)
             
        # Continue crawling if within limits
        if len(self.discovered_urls) < self.max_links:
            self._crawl_recursive(clean_url, depth=1)
