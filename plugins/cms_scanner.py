import re
import httpx
from bs4 import BeautifulSoup
from .base_plugin import BasePlugin
from utils.helpers import make_web_request


class CMSPlugin(BasePlugin):
    PLUGIN_ID = "10003"
    PLUGIN_NAME = "CMS Vulnerability Scanner"
    PLUGIN_FAMILY = "Web CMS"
    PLUGIN_VERSION = "1.1"
    PLUGIN_SHORT_KEY = "cms"
    DESCRIPTION = "WordPress, Joomla, Drupal specific vulnerability detection"

    # Commonly-vulnerable WordPress plugins to probe for during enumeration.
    # Each tuple is (slug, human-readable name).
    WP_PLUGIN_TARGETS = [
        ("contact-form-7", "Contact Form 7"),
        ("woocommerce", "WooCommerce"),
        ("wordpress-seo", "Yoast SEO"),
        ("elementor", "Elementor"),
        ("wpforms-lite", "WPForms Lite"),
        ("classic-editor", "Classic Editor"),
        ("akismet", "Akismet"),
        ("jetpack", "Jetpack"),
    ]

    def run(self, progress_callback=None) -> dict:
        """Scan target for CMS fingerprints and versions."""
        self.check_wordpress()
        self.check_joomla()
        self.check_drupal()
        return self.get_results()

    # ------------------------------------------------------------------
    # WordPress checks
    # ------------------------------------------------------------------

    def check_wordpress(self):
        """WordPress vulnerability scanner checks."""
        # WordPress indicators
        wp_paths = ["/wp-content/", "/wp-includes/", "/wp-links-opml.php"]
        is_wp = False

        # Probe index first
        try:
            index_res = make_web_request(self.url, timeout=self.timeout)
        except httpx.RequestError as e:
            self.add_error("WordPress Index Probe HTTP Request", e)
            index_res = None
        except Exception as e:
            self.add_error("WordPress Index Probe Generic Exception", e)
            index_res = None

        if index_res and index_res.status_code == 200:
            if any(path in index_res.text for path in wp_paths):
                is_wp = True

        if not is_wp:
            return

        version = "Unknown"
        # Try to find generator meta tag
        try:
            soup = BeautifulSoup(index_res.text, "html.parser")
            gen_meta = soup.find("meta", attrs={"name": "generator"})
            if gen_meta and "WordPress" in gen_meta.get("content", ""):
                version_match = re.search(r"WordPress\s+([0-9\.]+)", gen_meta["content"])
                if version_match:
                    version = version_match.group(1)
        except Exception as e:
            # BeautifulSoup and regex parsing can raise miscellaneous parser/attribute errors
            self.add_error("WordPress Version Extraction", e)

        self.add_finding(
            title="WordPress CMS Detected",
            severity="INFO",
            description=f"WordPress CMS was identified on the target host. Version: {version}.",
            evidence=f"WordPress patterns found in page source. Version: {version}",
            remediation="Ensure WordPress core, plugins, and themes are updated regularly.",
            cvss=0.0
        )

        # WP XMLRPC Abuse check
        # NOTE: CVE-2018-7600 is Drupalgeddon 2 (Drupal-only) and does NOT
        # apply to WordPress XML-RPC. The finding here is about brute-force
        # amplification and DDoS via system.multicall — no specific CVE.
        xmlrpc_url = f"{self.url}/xmlrpc.php"
        try:
            xmlrpc_res = make_web_request(xmlrpc_url, timeout=self.timeout)
        except httpx.RequestError as e:
            self.add_error("WordPress XML-RPC Probe HTTP Request", e)
            xmlrpc_res = None
        except Exception as e:
            self.add_error("WordPress XML-RPC Probe Generic Exception", e)
            xmlrpc_res = None

        if xmlrpc_res and xmlrpc_res.status_code == 200 and "XML-RPC server accepts POST requests" in xmlrpc_res.text:
            self.add_finding(
                title="WordPress XML-RPC Enabled",
                severity="MEDIUM",
                description="WordPress XML-RPC interface is enabled on the server, permitting external APIs to communicate. This can be exploited for brute-force attacks and DDoS amplification.",
                evidence=f"XML-RPC endpoint active at: {xmlrpc_url}",
                remediation="Disable XML-RPC by using a plugin or blocking xmlrpc.php via .htaccess / Nginx config.",
                # No CVE — XML-RPC DDoS amplification is a design risk, not a specific CVE
                cvss=5.3
            )

        # WP User Enumeration — REST API endpoint
        user_url = f"{self.url}/wp-json/wp/v2/users"
        try:
            user_res = make_web_request(user_url, timeout=self.timeout)
        except httpx.RequestError as e:
            self.add_error("WordPress User Enumeration REST API HTTP Request", e)
            user_res = None
        except Exception as e:
            self.add_error("WordPress User Enumeration REST API Generic Exception", e)
            user_res = None

        if user_res and user_res.status_code == 200 and "slug" in user_res.text:
            try:
                users = user_res.json()
                usernames = [u.get("slug") for u in users if "slug" in u]
                if usernames:
                    self.add_finding(
                        title="WordPress Username Enumeration",
                        severity="MEDIUM",
                        description="WordPress REST API exposes user profile details, letting attackers discover valid system login accounts.",
                        evidence=f"Discovered usernames: {', '.join(usernames)} via {user_url}",
                        remediation="Restrict public access to wp-json/wp/v2/users REST API endpoint.",
                        cvss=5.3
                    )
            except Exception as e:
                # json() parsing or list comprehension can raise ValueError/AttributeError
                self.add_error("WordPress Username Enumeration Parse", e)

        # WP User Enumeration — Author archive redirect method
        # Requesting ?author=N causes WordPress to 301-redirect to /author/<slug>/
        # when the user ID exists. This works even when the REST API is locked down.
        self._enumerate_wp_authors()

        # WP Plugin Enumeration — probe readme.txt for common plugins
        self._enumerate_wp_plugins()

    def _enumerate_wp_authors(self):
        """Enumerate WordPress usernames via ?author=N archive redirects.

        WordPress redirects /?author=<id> → /author/<username>/ with a 301
        when that user ID exists.  We probe author IDs 1–10 and extract the
        slug from the Location header.
        """
        discovered_users = []

        for author_id in range(1, 11):
            author_url = f"{self.url}/?author={author_id}"
            try:
                # Disable follow-redirects so we can inspect the Location header
                author_res = make_web_request(
                    author_url, timeout=self.timeout, allow_redirects=False
                )
            except httpx.RequestError as e:
                self.add_error(f"WordPress Author Probe HTTP Request {author_id}", e)
                continue
            except Exception as e:
                self.add_error(f"WordPress Author Probe Generic Exception {author_id}", e)
                continue

            if author_res is None:
                continue

            # WordPress returns 301/302 redirect to /author/<slug>/
            if author_res.status_code in (301, 302):
                location = author_res.headers.get("Location", "")
                # Extract username from /author/<username>/ path
                match = re.search(r"/author/([^/]+)/?", location)
                if match:
                    discovered_users.append(match.group(1))

        if discovered_users:
            self.add_finding(
                title="WordPress Author Archive User Enumeration",
                severity="MEDIUM",
                description=(
                    "WordPress author archive redirects expose valid usernames. "
                    "An attacker can iterate ?author=N to discover login accounts "
                    "for brute-force attacks."
                ),
                evidence=(
                    f"Discovered usernames via author redirect: "
                    f"{', '.join(discovered_users)}"
                ),
                remediation=(
                    "Disable author archives or install a plugin that blocks "
                    "?author=N enumeration. Consider using the "
                    "'discourage_author_enumeration' approach in .htaccess/Nginx."
                ),
                cvss=5.3
            )

    def _enumerate_wp_plugins(self):
        """Probe for commonly-vulnerable WordPress plugins by requesting
        their readme.txt file and extracting the 'Stable tag:' version.

        Detection methodology: WordPress plugins publish a readme.txt in
        their directory root.  If the file is publicly accessible (HTTP 200),
        the plugin is installed.  The 'Stable tag:' header inside the readme
        tells us the installed version, which can be cross-referenced against
        known CVE databases.
        """
        detected_plugins = []

        for slug, friendly_name in self.WP_PLUGIN_TARGETS:
            readme_url = f"{self.url}/wp-content/plugins/{slug}/readme.txt"
            try:
                readme_res = make_web_request(readme_url, timeout=self.timeout)
            except httpx.RequestError as e:
                self.add_error(f"WordPress Plugin Readme Probe HTTP Request {slug}", e)
                continue
            except Exception as e:
                self.add_error(f"WordPress Plugin Readme Probe Generic Exception {slug}", e)
                continue

            if readme_res is None or readme_res.status_code != 200:
                continue

            # Extract version from "Stable tag:" line (standard WP readme header)
            version = "Unknown"
            stable_match = re.search(
                r"Stable\s+tag:\s*([^\s\r\n]+)", readme_res.text, re.IGNORECASE
            )
            if stable_match:
                version = stable_match.group(1)

            detected_plugins.append(f"{friendly_name} ({slug}) v{version}")

        if detected_plugins:
            self.add_finding(
                title="WordPress Installed Plugins Detected",
                severity="LOW",
                description=(
                    "One or more WordPress plugins were identified by probing "
                    "their public readme.txt files. Exposed version information "
                    "helps attackers locate known CVEs for each plugin."
                ),
                evidence=f"Detected plugins: {'; '.join(detected_plugins)}",
                remediation=(
                    "Block direct access to plugin readme.txt files via server "
                    "configuration. Keep all plugins updated to the latest "
                    "security releases."
                ),
                cvss=3.7
            )

    # ------------------------------------------------------------------
    # Joomla checks
    # ------------------------------------------------------------------

    def check_joomla(self):
        """Joomla vulnerability scanner checks."""
        joomla_detected = False

        # Test Administrator panel and media assets
        try:
            res = make_web_request(f"{self.url}/administrator/", timeout=self.timeout)
        except httpx.RequestError as e:
            self.add_error("Joomla Admin Panel Probe HTTP Request", e)
            res = None
        except Exception as e:
            self.add_error("Joomla Admin Panel Probe Generic Exception", e)
            res = None

        if res and (res.status_code == 200 or "joomla" in res.text.lower()):
            joomla_detected = True

        if not joomla_detected:
            return

        # Check configuration backups
        config_files = ["/configuration.php.bak", "/configuration.php~", "/configuration.php.old"]
        for cfile in config_files:
            try:
                cres = make_web_request(f"{self.url}{cfile}", timeout=self.timeout)
            except httpx.RequestError as e:
                self.add_error(f"Joomla Config Exposure HTTP Request {cfile}", e)
                cres = None
            except Exception as e:
                self.add_error(f"Joomla Config Exposure Generic Exception {cfile}", e)
                cres = None

            if cres and cres.status_code == 200 and ("$host" in cres.text or "$password" in cres.text):
                self.add_finding(
                    title="Joomla configuration.php Backup Exposed",
                    severity="HIGH",
                    description=f"An exposed Joomla configuration file backup was found at {cfile}. This contains plain-text database credentials.",
                    evidence=f"Found database connection strings in: {self.url}{cfile}",
                    remediation="Delete backup configuration files from the public root folder immediately.",
                    cvss=7.5
                )

    # ------------------------------------------------------------------
    # Drupal checks
    # ------------------------------------------------------------------

    def check_drupal(self):
        """Drupal vulnerability scanner checks."""
        drupal_detected = False

        try:
            res = make_web_request(f"{self.url}/core/misc/drupal.js", timeout=self.timeout)
        except httpx.RequestError as e:
            self.add_error("Drupal JS Probe HTTP Request", e)
            res = None
        except Exception as e:
            self.add_error("Drupal JS Probe Generic Exception", e)
            res = None

        if res and res.status_code == 200:
            drupal_detected = True
        else:
            # Check headers/meta generator
            try:
                idx_res = make_web_request(self.url, timeout=self.timeout)
            except httpx.RequestError as e:
                self.add_error("Drupal Index Generator Probe HTTP Request", e)
                idx_res = None
            except Exception as e:
                self.add_error("Drupal Index Generator Probe Generic Exception", e)
                idx_res = None

            if idx_res and "Drupal" in idx_res.text:
                drupal_detected = True

        if not drupal_detected:
            return

        # Try to find version from CHANGELOG.txt
        version = "Unknown"
        try:
            changelog_res = make_web_request(f"{self.url}/CHANGELOG.txt", timeout=self.timeout)
        except httpx.RequestError as e:
            self.add_error("Drupal Changelog Probe HTTP Request", e)
            changelog_res = None
        except Exception as e:
            self.add_error("Drupal Changelog Probe Generic Exception", e)
            changelog_res = None

        if changelog_res and changelog_res.status_code == 200:
            match = re.search(r"Drupal\s+([0-9\.]+)", changelog_res.text)
            if match:
                version = match.group(1)

        self.add_finding(
            title="Drupal CMS Detected",
            severity="INFO",
            description=f"Drupal CMS was identified. Version: {version}.",
            evidence=f"Drupal JavaScript or metadata observed. Changelog Version: {version}",
            remediation="Keep Drupal core security releases updated.",
            cvss=0.0
        )

        # Check for Drupalgeddon 2 vulnerability (CVE-2018-7600)
        if version != "Unknown":
            try:
                parts = [int(p) for p in version.split(".")]
                is_vulnerable = False
                if len(parts) >= 2:
                    if parts[0] == 7 and parts[1] < 58:
                        is_vulnerable = True
                    elif parts[0] == 8 and parts[1] == 5 and len(parts) >= 3 and parts[2] < 1:
                        is_vulnerable = True
                    elif parts[0] == 8 and parts[1] < 5:
                        is_vulnerable = True

                if is_vulnerable:
                    self.add_finding(
                        title="Outdated Drupal Version (Drupalgeddon RCE Vulnerability)",
                        severity="CRITICAL",
                        description=f"The Drupal site version {version} is vulnerable to Drupalgeddon 2 Remote Code Execution.",
                        evidence=f"Version {version} is less than patched core releases (7.58 / 8.5.1).",
                        remediation="Apply latest Drupal core security updates immediately.",
                        cve_ids=["CVE-2018-7600"],
                        cvss=9.8
                    )
            except Exception as e:
                # String conversion or range checking can raise miscellaneous errors
                self.add_error("Drupalgeddon Version Vulnerability Logic", e)
