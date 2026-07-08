import socket
from .base_plugin import BasePlugin
from utils.helpers import make_web_request

class ServiceVulnPlugin(BasePlugin):
    PLUGIN_ID = "10002"
    PLUGIN_NAME = "Service Vulnerability Scanner"
    PLUGIN_FAMILY = "Services"
    PLUGIN_VERSION = "1.0"
    PLUGIN_SHORT_KEY = "services"
    DESCRIPTION = "FTP anon, SSH weak algos, SMTP relay, DB no-auth checks"

    def run(self, progress_callback=None) -> dict:
        """Runs service vulnerability audits."""
        self.check_ftp_anon()
        self.check_ssh_weak_algos()
        self.check_smtp_open_relay()
        self.check_mysql_no_auth()
        self.check_redis_no_auth()
        self.check_default_credentials()
        return self.get_results()

    def check_ftp_anon(self):
        """Checks for anonymous FTP login."""
        try:
            with socket.create_connection((self.host, 21), timeout=self.timeout) as sock:
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                if "220" in banner:
                    sock.sendall(b"USER anonymous\r\n")
                    resp = sock.recv(1024).decode("utf-8", errors="ignore")
                    if "331" in resp:
                        sock.sendall(b"PASS anonymous@example.com\r\n")
                        resp2 = sock.recv(1024).decode("utf-8", errors="ignore")
                        if "230" in resp2:
                            self.add_finding(
                                title="Anonymous FTP Login Allowed",
                                severity="MEDIUM",
                                description="The FTP service permits anonymous users to log in, which could leak sensitive information or host malicious files if write permissions are enabled.",
                                evidence=f"FTP server response: {resp2.strip()}",
                                remediation="Disable anonymous authentication in FTP daemon settings.",
                                cvss=5.3
                            )
        except socket.error as e:
            self.add_error("Anonymous FTP Check socket.error", e)
        except Exception as e:
            self.add_error("Anonymous FTP Check Generic Exception", e)

    def check_ssh_weak_algos(self):
        """Heuristic check on SSH service on standard port 22.
        
        Detection methodology:
        - Connect to port 22 and read the SSH banner
        - Check for deprecated SSHv1 protocol support
        - Parse OpenSSH version and check against known vulnerable versions
        """
        try:
            with socket.create_connection((self.host, 22), timeout=self.timeout) as sock:
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                if "SSH-" in banner:
                    # Check for SSHv1 support
                    if "SSH-1.99" in banner or "SSH-1.5" in banner:
                        self.add_finding(
                            title="SSH Protocol Version 1 Supported",
                            severity="HIGH",
                            description="The SSH server supports SSHv1, which is obsolete and contains cryptographic vulnerabilities.",
                            evidence=f"SSH Banner: {banner.strip()}",
                            remediation="Disable SSHv1 protocol in SSH configuration.",
                            cvss=7.5
                        )
                    
                    # Check for known vulnerable OpenSSH versions
                    import re
                    version_match = re.search(r'OpenSSH[_\s](\d+\.\d+(?:p\d+)?)', banner, re.IGNORECASE)
                    if version_match:
                        version_str = version_match.group(1)
                        # Known vulnerable versions (major CVEs)
                        # CVE-2024-6387 (regreSSHion): OpenSSH 8.5p1 - 9.7p1
                        # CVE-2023-38408: OpenSSH before 9.3p2
                        try:
                            version_num = float(version_str.split('p')[0])
                            if version_num < 8.0:
                                self.add_finding(
                                    title="Outdated OpenSSH Version",
                                    severity="MEDIUM",
                                    description=f"The SSH server runs OpenSSH {version_str}, which is significantly outdated and may contain multiple known vulnerabilities.",
                                    evidence=f"SSH Banner: {banner.strip()}",
                                    remediation="Update OpenSSH to the latest stable version.",
                                    cvss=6.5
                                )
                        except ValueError:
                            pass
        except socket.error as e:
            self.add_error("SSH Protocol Version 1 Check socket.error", e)
        except Exception as e:
            self.add_error("SSH Protocol Version 1 Check Generic Exception", e)

    def check_smtp_open_relay(self):
        """Basic SMTP open relay test."""
        try:
            with socket.create_connection((self.host, 25), timeout=self.timeout) as sock:
                sock.recv(1024)
                sock.sendall(b"EHLO test-client.com\r\n")
                sock.recv(1024)
                sock.sendall(b"MAIL FROM:<test@example.com>\r\n")
                resp1 = sock.recv(1024).decode("utf-8", errors="ignore")
                if "250" in resp1:
                    sock.sendall(b"RCPT TO:<external-recipient@gmail.com>\r\n")
                    resp2 = sock.recv(1024).decode("utf-8", errors="ignore")
                    if "250" in resp2:
                        self.add_finding(
                            title="SMTP Open Relay Detected",
                            severity="HIGH",
                            description="The SMTP mail server allows relaying of messages to external domains without authentication, which is abused by spammers.",
                            evidence=f"SMTP server accepted external recipient: {resp2.strip()}",
                            remediation="Configure the SMTP server to require authentication for relaying external mail.",
                            cvss=7.5
                        )
        except socket.error as e:
            self.add_error("SMTP Open Relay Check socket.error", e)
        except Exception as e:
            self.add_error("SMTP Open Relay Check Generic Exception", e)

    def check_mysql_no_auth(self):
        """Checks if MySQL database allows passwordless access.
        
        Detection methodology:
        - Connect to port 3306 and read the MySQL server greeting packet
        - Parse the protocol version and server version string from the greeting
        - Attempt authentication with 'root' user and empty password using
          MySQL native authentication protocol (4.1+ handshake)
        - A successful auth (OK packet, first byte 0x00) indicates no password set
        """
        import struct
        try:
            with socket.create_connection((self.host, 3306), timeout=self.timeout) as sock:
                # Read MySQL handshake packet
                data = sock.recv(1024)
                if len(data) < 10:
                    return
                
                # Parse MySQL greeting packet:
                # Bytes 0-2: payload length, Byte 3: sequence id
                # Byte 4: protocol version
                # Byte 5+: null-terminated version string
                protocol_version = data[4]
                
                # Extract server version string (null-terminated starting at byte 5)
                try:
                    null_pos = data.index(b'\x00', 5)
                    server_version = data[5:null_pos].decode('utf-8', errors='ignore')
                except (ValueError, UnicodeDecodeError):
                    return
                
                # Build a minimal MySQL authentication packet
                # Client capabilities flags for basic auth
                capabilities = 0x0000a685  # CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
                max_packet_size = 0x01000000
                charset = 0x21  # utf8
                
                auth_payload = struct.pack('<I', capabilities)
                auth_payload += struct.pack('<I', max_packet_size)
                auth_payload += struct.pack('B', charset)
                auth_payload += b'\x00' * 23  # reserved bytes
                auth_payload += b'root\x00'   # username null-terminated
                auth_payload += b'\x00'       # empty auth response (no password)
                
                # Wrap in MySQL packet header: length(3 bytes LE) + sequence(1 byte)
                packet_len = len(auth_payload)
                header = struct.pack('<I', packet_len)[:3] + b'\x01'
                
                sock.sendall(header + auth_payload)
                
                # Read response
                response = sock.recv(1024)
                if len(response) > 4:
                    response_type = response[4]
                    if response_type == 0x00:  # OK packet — auth succeeded without password
                        self.add_finding(
                            title="MySQL Root Passwordless Access",
                            severity="CRITICAL",
                            description=f"The MySQL database (version {server_version}) allows root login without a password. "
                                        f"This provides full control over all databases and server configuration.",
                            evidence=f"MySQL server version: {server_version}, root user authenticated with empty password",
                            remediation="Set a strong password for the MySQL root account: ALTER USER 'root'@'%%' IDENTIFIED BY 'secure_password'; "
                                        "Remove remote root access and bind MySQL to localhost.",
                            cve_id="CVE-1999-0508",
                            cvss=9.8
                        )
        except socket.error as e:
            self.add_error("MySQL Passwordless Root Check socket.error", e)
        except struct.error as e:
            self.add_error("MySQL Passwordless Root Response struct.error", e)
        except Exception as e:
            self.add_error("MySQL Passwordless Root Check Generic Exception", e)

    def check_redis_no_auth(self):
        """Checks if Redis database allows unauthenticated commands."""
        try:
            with socket.create_connection((self.host, 6379), timeout=self.timeout) as sock:
                sock.sendall(b"PING\r\n")
                resp = sock.recv(1024).decode("utf-8", errors="ignore")
                if "PONG" in resp:
                    self.add_finding(
                        title="Redis Database Unauthenticated Access",
                        severity="CRITICAL",
                        description="The Redis database is exposed to the public internet and does not require authentication, allowing full control over database contents and execution of arbitrary code.",
                        evidence=f"Redis command 'PING' returned: '{resp.strip()}'",
                        remediation="Enable authentication in redis.conf (requirepass) and bind Redis to local interfaces.",
                        cvss=9.8
                    )
        except socket.error as e:
            self.add_error("Redis Unauthenticated Access Check socket.error", e)
        except Exception as e:
            self.add_error("Redis Unauthenticated Access Check Generic Exception", e)

    def check_default_credentials(self):
        """Probes typical login/admin panels for default logins."""
        test_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("root", "root"),
            ("root", "admin")
        ]
        
        login_endpoints = [
            "/login", "/admin", "/wp-login.php", "/user/login", "/administrator"
        ]
        
        for endpoint in login_endpoints:
            url = f"{self.url}{endpoint}"
            try:
                # Find input fields first or make sample post requests
                res = make_web_request(url, timeout=self.timeout)
                if res and res.status_code == 200:
                    for username, password in test_credentials:
                        # Attempt generic POST login request payloads
                        payloads = [
                            {"username": username, "password": password},
                            {"user": username, "pass": password},
                            {"log": username, "pwd": password}
                        ]
                        for p in payloads:
                            post_res = make_web_request(url, method="POST", data=p, timeout=self.timeout)
                            if post_res and post_res.status_code == 200:
                                # Look for successful admin indicators or redirects
                                if any(ind in post_res.text.lower() for ind in ["dashboard", "logout", "admin panel", "welcome"]):
                                    self.add_finding(
                                        title="Default Credentials Vulnerability",
                                        severity="CRITICAL",
                                        description=f"The login page at {url} accepts default credentials ({username}:{password}).",
                                        evidence=f"Successful authentication using payload: {p}",
                                        remediation="Change the credentials for administrative accounts immediately.",
                                        cvss=9.8
                                    )
                                    return
            except httpx.RequestError as e:
                self.add_error(f"Default Credentials Probe HTTP Request {endpoint}", e)
            except Exception as e:
                self.add_error(f"Default Credentials Probe Generic Exception {endpoint}", e)
