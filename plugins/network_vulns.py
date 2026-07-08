import socket
import struct
from .base_plugin import BasePlugin


class NetworkVulnPlugin(BasePlugin):
    PLUGIN_ID = "10004"
    PLUGIN_NAME = "Network Vulnerability Scanner"
    PLUGIN_FAMILY = "Network"
    PLUGIN_VERSION = "1.1"
    PLUGIN_SHORT_KEY = "network"
    DESCRIPTION = "DNS zone transfer, SNMP community, SMB signing checks"

    def run(self, progress_callback=None) -> dict:
        """Runs network-level vulnerability checks."""
        self.check_dns_zone_transfer()
        self.check_snmp_default_community()
        self.check_smb_signing()
        self.check_ntp_amplification()
        self.check_ldap_anonymous_bind()
        self.check_exposed_databases()
        return self.get_results()

    # ------------------------------------------------------------------
    # DNS helpers
    # ------------------------------------------------------------------

    def _build_dns_name(self, domain: str) -> bytes:
        """Encode a domain name into DNS wire format (length-prefixed labels).

        Example: 'example.com' -> b'\\x07example\\x03com\\x00'
        """
        parts = domain.split(".")
        name = b""
        for part in parts:
            name += struct.pack("B", len(part)) + part.encode("ascii")
        name += b"\x00"
        return name

    def _resolve_ns_records(self, domain: str) -> list:
        """Resolve authoritative NS hostnames for *domain* using a raw
        UDP DNS query (type NS = 2) sent to the target host itself.

        Returns a list of nameserver hostnames extracted from the response.
        If the query fails, falls back to returning [self.host] so that
        AXFR is still attempted against the original target.
        """
        nameservers = []
        try:
            # Build a standard DNS query for NS records
            dns_header = struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
            query_name = self._build_dns_name(domain)
            # Type NS (2), Class IN (1)
            dns_question = query_name + struct.pack(">HH", 2, 1)
            packet = dns_header + dns_question

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(packet, (self.host, 53))
                resp, _ = sock.recvfrom(4096)

            # Parse answer count from header
            if len(resp) < 12:
                return [self.host]
            _, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", resp[:12])

            # Skip question section
            offset = 12
            for _ in range(qdcount):
                while offset < len(resp) and resp[offset] != 0:
                    if (resp[offset] & 0xC0) == 0xC0:
                        offset += 2
                        break
                    offset += resp[offset] + 1
                else:
                    offset += 1  # null terminator
                offset += 4  # QTYPE + QCLASS

            # Parse answer RRs to extract NS hostnames
            for _ in range(ancount):
                if offset >= len(resp):
                    break
                # Skip RR name (may be pointer)
                if (resp[offset] & 0xC0) == 0xC0:
                    offset += 2
                else:
                    while offset < len(resp) and resp[offset] != 0:
                        offset += resp[offset] + 1
                    offset += 1

                if offset + 10 > len(resp):
                    break

                rr_type, rr_class, rr_ttl, rr_rdlength = struct.unpack(
                    ">HHIH", resp[offset:offset + 10]
                )
                offset += 10

                if rr_type == 2:  # NS record
                    # Read the NS hostname from RDATA (domain name, possibly compressed)
                    ns_name = self._read_dns_name(resp, offset)
                    if ns_name:
                        nameservers.append(ns_name)

                offset += rr_rdlength

        except (struct.error, IndexError) as e:
            self.add_error("DNS Response Parse Struct/Index Error", e)
        except Exception as e:
            self.add_error("DNS Response Parse Generic Exception", e)

        return nameservers if nameservers else [self.host]

    @staticmethod
    def _read_dns_name(data: bytes, offset: int) -> str:
        """Read a DNS domain name from *data* starting at *offset*,
        handling compression pointers (RFC 1035 §4.1.4).

        Returns the decoded domain string or an empty string on failure.
        """
        labels = []
        visited_offsets = set()  # guard against pointer loops
        try:
            while offset < len(data):
                if offset in visited_offsets:
                    break
                visited_offsets.add(offset)

                length = data[offset]
                if length == 0:
                    break
                if (length & 0xC0) == 0xC0:
                    # Compression pointer — follow it
                    if offset + 1 >= len(data):
                        break
                    pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
                    offset = pointer
                    continue
                else:
                    offset += 1
                    label = data[offset:offset + length].decode("ascii", errors="replace")
                    labels.append(label)
                    offset += length
        except (struct.error, IndexError) as e:
            self.add_error("DNS Name Read Struct/Index Error", e)
        except Exception as e:
            self.add_error("DNS Name Read Generic Exception", e)
        return ".".join(labels)

    # ------------------------------------------------------------------
    # DNS Zone Transfer (AXFR)
    # ------------------------------------------------------------------

    def check_dns_zone_transfer(self):
        """Attempts a DNS zone transfer (AXFR) query against the domain's
        authoritative nameservers.

        Detection methodology:
        1. Resolve NS records for the target domain.
        2. For each nameserver, open a TCP connection on port 53 and send
           an AXFR query.
        3. If the nameserver responds with RCODE 0 (No Error), the zone
           transfer succeeded — all DNS records are exposed.
        """
        # Step 1: Resolve NS records for the target domain
        nameservers = self._resolve_ns_records(self.host)

        # Step 2: Attempt AXFR against each nameserver
        for ns in nameservers:
            # Resolve the NS hostname to an IP so we can connect
            try:
                ns_ip = socket.gethostbyname(ns)
            except socket.gaierror as e:
                self.add_error(f"DNS AXFR Hostname Resolution socket.gaierror {ns}", e)
                continue
            except Exception as e:
                self.add_error(f"DNS AXFR Hostname Resolution Generic Exception {ns}", e)
                continue

            try:
                # Build manual DNS query AXFR header
                # Transaction ID: 0x1234, Flags: 0x0000 (Standard Query)
                # Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
                dns_header = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)

                # Format target domain for query (e.g. example.com -> \x07example\x03com\x00)
                query_name = self._build_dns_name(self.host)

                # AXFR Type (252), Class IN (1)
                dns_question = query_name + struct.pack(">HH", 252, 1)
                packet = dns_header + dns_question
                # DNS TCP packets are prefixed with a 2-byte length
                tcp_packet = struct.pack(">H", len(packet)) + packet

                with socket.create_connection((ns_ip, 53), timeout=self.timeout) as sock:
                    sock.sendall(tcp_packet)
                    resp_len_data = sock.recv(2)
                    if len(resp_len_data) == 2:
                        resp_len = struct.unpack(">H", resp_len_data)[0]
                        resp = sock.recv(resp_len)
                        # If server returns zone answers (AXFR response usually contains SOA records)
                        # We check if it is not REFUSED (DNS RCODE 5)
                        if len(resp) > 4:
                            flags = struct.unpack(">H", resp[2:4])[0]
                            rcode = flags & 0x000F
                            if rcode == 0:  # No Error - Zone Transfer accepted!
                                self.add_finding(
                                    title="DNS Zone Transfer (AXFR) Enabled",
                                    severity="MEDIUM",
                                    description=(
                                        f"The nameserver {ns} ({ns_ip}) allows "
                                        f"full AXFR zone transfers to unauthorized "
                                        f"IPs. Attackers can enumerate all DNS records."
                                    ),
                                    evidence=(
                                        f"AXFR query to {ns} ({ns_ip}:53) returned "
                                        f"RCODE 0 (Success)."
                                    ),
                                    remediation="Configure the DNS server to allow zone transfers only to trusted secondary DNS servers (e.g., allow-transfer configuration).",
                                    cvss=5.3
                                )
                                # One successful transfer is enough to report
                                return
            except socket.error as e:
                self.add_error(f"DNS AXFR Query socket.error {ns}", e)
                continue
            except (struct.error, IndexError) as e:
                self.add_error(f"DNS AXFR Response Struct/Index Error {ns}", e)
                continue
            except Exception as e:
                self.add_error(f"DNS AXFR Query Generic Exception {ns}", e)
                continue

    # ------------------------------------------------------------------
    # SNMP
    # ------------------------------------------------------------------

    def check_snmp_default_community(self):
        """Probes UDP port 161 with default 'public' and 'private' community strings.

        Detection methodology: send a minimal SNMPv1 GetRequest for sysDescr
        (OID 1.3.6.1.2.1.1.1.0) using each community string.  Any response
        indicates the community string is accepted.
        """
        # Community strings to test — 'public' gives read access, 'private'
        # often grants read-write access and is more severe.
        community_probes = {
            "public": {
                # Simple SNMPv1 GetRequest packet for sysDescr (1.3.6.1.2.1.1.1.0)
                # using community string 'public'
                "packet": (
                    b"\x30\x29\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63"
                    b"\xa0\x1c\x02\x04\x05\x00\x00\x01\x02\x01\x00\x02\x01"
                    b"\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01"
                    b"\x01\x00\x05\x00"
                ),
                "severity": "HIGH",
                "title": "SNMP Default Community String 'public' Exposed",
                "description": (
                    "The SNMP service is running with the default community "
                    "string 'public', allowing read access to system properties."
                ),
                "cvss": 7.5,
            },
            "private": {
                # Same SNMPv1 GetRequest but with community string 'private'
                # Hex encoding: \x07 length + 'private' (70 72 69 76 61 74 65)
                # Full packet rebuilt with correct lengths:
                #   SEQUENCE (total), version(0), community('private'), PDU
                "packet": (
                    b"\x30\x2a\x02\x01\x00\x04\x07\x70\x72\x69\x76\x61\x74"
                    b"\x65\xa0\x1c\x02\x04\x05\x00\x00\x01\x02\x01\x00\x02"
                    b"\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01"
                    b"\x01\x01\x00\x05\x00"
                ),
                "severity": "CRITICAL",
                "title": "SNMP Default Community String 'private' Exposed",
                "description": (
                    "The SNMP service is running with the default community "
                    "string 'private', which typically grants read-write "
                    "access. An attacker could modify device configuration."
                ),
                "cvss": 9.1,
            },
        }

        for community, info in community_probes.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2.0)
                    sock.sendto(info["packet"], (self.host, 161))
                    resp, _ = sock.recvfrom(1024)
                    if len(resp) > 0:
                        self.add_finding(
                            title=info["title"],
                            severity=info["severity"],
                            description=info["description"],
                            evidence=f"SNMP service replied to '{community}' community query.",
                            remediation="Disable SNMP if not needed, or change default community string to a strong, secret value.",
                            cvss=info["cvss"]
                        )
            except socket.error as e:
                self.add_error(f"SNMP Probe socket.error {community}", e)
            except Exception as e:
                self.add_error(f"SNMP Probe Generic Exception {community}", e)

    # ------------------------------------------------------------------
    # SMB
    # ------------------------------------------------------------------

    def check_smb_signing(self):
        """Checks if SMB signing is not required on port 445."""
        # Minimal NetBIOS Session Request & SMB Negotiate Protocol
        smb_negotiate = (
            b"\x00\x00\x00\x85"  # NetBIOS length
            b"\xff\x53\x4d\x42"  # SMB Header magic
            b"\x72"              # Negotiate Command
            b"\x00\x00\x00\x00"  # Status
            b"\x18"              # Flags
            b"\x53\xc8"          # Flags2
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\xff\xff"
            b"\x00\x00"
            b"\x00\x00"          # Mid
            b"\x00\x62"          # Byte count
            b"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00" # NT LM 0.12 dialect
        )
        try:
            with socket.create_connection((self.host, 445), timeout=self.timeout) as sock:
                sock.sendall(smb_negotiate)
                resp = sock.recv(1024)
                if len(resp) > 37:
                    # Security Mode is at offset 37 of negotiate response
                    security_mode = resp[37]
                    # Bit 2 (0x04) in Security Mode: Signing Required
                    signing_required = (security_mode & 0x04) != 0
                    if not signing_required:
                        self.add_finding(
                            title="SMB Signing Not Required",
                            severity="MEDIUM",
                            description="SMB signing is not enforced on this server. This permits attackers on the same network layer to perform SMB relay attacks.",
                            evidence="SMB security mode flag check: signing is supported but not required.",
                            remediation="Enable SMB signing policy: 'Microsoft network server: Digitally sign communications (always)'.",
                            cvss=5.3
                        )
        except socket.error as e:
            self.add_error("SMB Signing Probe socket.error", e)
        except (struct.error, IndexError) as e:
            self.add_error("SMB Signing Response Struct/Index Error", e)
        except Exception as e:
            self.add_error("SMB Signing Probe Generic Exception", e)

    # ------------------------------------------------------------------
    # NTP
    # ------------------------------------------------------------------

    def check_ntp_amplification(self):
        """Checks if NTP monlist command is enabled on UDP port 123."""
        # NTP v2 Mode 7 (Private) Request - Command: MON_GETLIST (42)
        ntp_monlist_payload = struct.pack("!BBBBHHH", 0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.0)
                sock.sendto(ntp_monlist_payload, (self.host, 123))
                resp, _ = sock.recvfrom(1024)
                if len(resp) > 4:
                    self.add_finding(
                        title="NTP monlist Command Enabled (DDoS Amplification)",
                        severity="MEDIUM",
                        description="The NTP server responds to 'monlist' queries, allowing remote attackers to retrieve active client lists and amplify traffic in DDoS attacks.",
                        evidence="NTP server returned monlist response to UDP request.",
                        remediation="Disable monlist support by updating NTP daemon config or restricting access via firewall.",
                        cvss=5.3
                    )
        except socket.error as e:
            self.add_error("NTP Amplification Probe socket.error", e)
        except struct.error as e:
            self.add_error("NTP Amplification Response struct.error", e)
        except Exception as e:
            self.add_error("NTP Amplification Probe Generic Exception", e)

    # ------------------------------------------------------------------
    # LDAP Anonymous Bind
    # ------------------------------------------------------------------

    def check_ldap_anonymous_bind(self):
        """Tests port 389 for LDAP anonymous bind.

        Detection methodology: send a minimal LDAP Simple BindRequest
        (RFC 4511) with an empty DN and empty password. If the server
        responds with resultCode 0 (success), anonymous access is granted.

        The raw BindRequest ASN.1 structure:
            SEQUENCE {
              messageID  INTEGER (1),
              BindRequest APPLICATION[0] {
                version   INTEGER (3),  -- LDAPv3
                name      OCTET STRING (""),  -- empty DN
                authentication CHOICE { simple [0] "" }  -- empty password
              }
            }
        """
        # Pre-built LDAP BindRequest packet (anonymous, LDAPv3)
        # 30 0c          -- SEQUENCE, length 12
        #   02 01 01     -- INTEGER messageID = 1
        #   60 07        -- APPLICATION[0] BindRequest, length 7
        #     02 01 03   -- INTEGER version = 3 (LDAPv3)
        #     04 00      -- OCTET STRING name = "" (empty DN)
        #     80 00      -- CONTEXT[0] simple authentication = "" (empty password)
        ldap_bind_request = (
            b"\x30\x0c"
            b"\x02\x01\x01"
            b"\x60\x07"
            b"\x02\x01\x03"
            b"\x04\x00"
            b"\x80\x00"
        )

        try:
            with socket.create_connection((self.host, 389), timeout=self.timeout) as sock:
                sock.sendall(ldap_bind_request)
                resp = sock.recv(1024)

                if len(resp) < 2:
                    return

                # Parse the BindResponse to extract resultCode.
                # Response structure (simplified):
                #   SEQUENCE { messageID INTEGER, BindResponse APPLICATION[1] {
                #       resultCode ENUMERATED, matchedDN OCTET STRING, diagnosticMessage OCTET STRING }}
                #
                # We walk the ASN.1 TLV to find the resultCode value.
                result_code = self._parse_ldap_bind_result(resp)

                if result_code == 0:
                    self.add_finding(
                        title="LDAP Anonymous Bind Permitted",
                        severity="HIGH",
                        description=(
                            "The LDAP service on port 389 accepts anonymous "
                            "bind requests. An attacker can query the directory "
                            "without authentication, potentially enumerating "
                            "users, groups, and organizational structure."
                        ),
                        evidence="LDAP BindResponse returned resultCode 0 (success) for anonymous bind.",
                        remediation=(
                            "Disable anonymous LDAP binds in the directory server "
                            "configuration. Require authenticated binds for all queries."
                        ),
                        cvss=7.5
                    )
        except socket.error as e:
            self.add_error("LDAP Anonymous Bind Probe socket.error", e)
        except Exception as e:
            self.add_error("LDAP Anonymous Bind Probe Generic Exception", e)

    @staticmethod
    def _parse_ldap_bind_result(data: bytes) -> int:
        """Parse an LDAP BindResponse and return the resultCode integer.

        Returns -1 if parsing fails.
        """
        try:
            offset = 0

            # Outer SEQUENCE tag (0x30)
            if data[offset] != 0x30:
                return -1
            offset += 1
            # Skip length (handle single-byte or multi-byte BER length)
            offset, _ = NetworkVulnPlugin._read_ber_length(data, offset)

            # messageID — INTEGER (0x02)
            if data[offset] != 0x02:
                return -1
            offset += 1
            offset, msg_id_len = NetworkVulnPlugin._read_ber_length(data, offset)
            offset += msg_id_len  # skip messageID value

            # BindResponse — APPLICATION[1] tag is 0x61
            if data[offset] != 0x61:
                return -1
            offset += 1
            offset, _ = NetworkVulnPlugin._read_ber_length(data, offset)

            # resultCode — ENUMERATED (0x0A)
            if data[offset] != 0x0A:
                return -1
            offset += 1
            offset, rc_len = NetworkVulnPlugin._read_ber_length(data, offset)
            # Read resultCode value (usually 1 byte)
            result_code = int.from_bytes(data[offset:offset + rc_len], byteorder="big")
            return result_code
        except (IndexError, ValueError) as e:
            self.add_error("LDAP Bind Result Parser Index/Value Error", e)
            return -1
        except Exception as e:
            self.add_error("LDAP Bind Result Parser Generic Exception", e)
            return -1

    @staticmethod
    def _read_ber_length(data: bytes, offset: int) -> tuple:
        """Read a BER-encoded length starting at *offset*.

        Returns (new_offset, length_value).
        """
        if data[offset] & 0x80 == 0:
            # Short form: single byte
            return offset + 1, data[offset]
        else:
            # Long form: lower 7 bits = number of length bytes
            num_bytes = data[offset] & 0x7F
            offset += 1
            length_val = int.from_bytes(data[offset:offset + num_bytes], byteorder="big")
            return offset + num_bytes, length_val

    # ------------------------------------------------------------------
    # Exposed Database Services
    # ------------------------------------------------------------------

    def check_exposed_databases(self):
        """Scans for database ports exposed directly to the internet.

        Enhanced checks:
        - MySQL (3306): Read the server greeting packet to extract the
          MySQL/MariaDB version string from the handshake.
        - Redis (6379): Send PING and verify +PONG response.
        - Other ports: basic TCP connectivity check.
        """
        db_ports = {
            3306: "MySQL Database",
            5432: "PostgreSQL Database",
            27017: "MongoDB Database",
            1521: "Oracle Database",
            1433: "Microsoft SQL Server",
        }
        for port, name in db_ports.items():
            try:
                with socket.create_connection((self.host, port), timeout=2.0) as sock:
                    extra_evidence = ""

                    if port == 3306:
                        # MySQL greeting packet: the server sends an initial
                        # handshake packet immediately after TCP connect.
                        # Packet format (simplified):
                        #   4 bytes: packet header (3-byte length + 1-byte seq)
                        #   1 byte:  protocol version (0x0A for MySQL 5.x+)
                        #   NUL-terminated string: server version
                        extra_evidence = self._parse_mysql_greeting(sock)

                    self.add_finding(
                        title=f"Exposed Database Service ({name})",
                        severity="HIGH",
                        description=f"The database port ({port}) is open and listening publicly, leaving it prone to brute force attacks.",
                        evidence=f"Exposed listening socket on port {port}. {extra_evidence}".strip(),
                        remediation="Filter the database port to localhost or restrict connection access using network firewall rules.",
                        cvss=7.5
                    )
            except socket.error as e:
                self.add_error(f"Exposed Database Probe socket.error {port}", e)
            except Exception as e:
                self.add_error(f"Exposed Database Probe Generic Exception {port}", e)

        # Redis — dedicated check with PING/PONG verification
        self._check_redis()

    def _parse_mysql_greeting(self, sock: socket.socket) -> str:
        """Read and parse the MySQL server greeting packet to extract the
        version string.

        Returns a human-readable evidence fragment, or an empty string
        if parsing fails.
        """
        try:
            # Read the 4-byte packet header
            header = sock.recv(4)
            if len(header) < 4:
                return ""

            # Packet length is first 3 bytes (little-endian)
            pkt_len = header[0] | (header[1] << 8) | (header[2] << 16)
            if pkt_len <= 0 or pkt_len > 65535:
                return ""

            payload = sock.recv(pkt_len)
            if len(payload) < 2:
                return ""

            # First byte is protocol version (usually 0x0A = 10)
            proto_version = payload[0]

            # Server version is a NUL-terminated string starting at byte 1
            nul_pos = payload.find(b"\x00", 1)
            if nul_pos == -1:
                return ""

            version_str = payload[1:nul_pos].decode("ascii", errors="replace")
            return f"MySQL version: {version_str} (protocol v{proto_version})"
        except (struct.error, IndexError, ValueError) as e:
            self.add_error("MySQL Greeting Parser Struct/Index/Value Error", e)
            return ""
        except Exception as e:
            self.add_error("MySQL Greeting Parser Generic Exception", e)
            return ""

    def _check_redis(self):
        """Check for unauthenticated Redis on port 6379 using PING command.

        Detection methodology: send the Redis PING command in RESP protocol
        format. If the server responds with '+PONG', it accepts commands
        without authentication.
        """
        try:
            with socket.create_connection((self.host, 6379), timeout=2.0) as sock:
                # Send Redis PING command (inline protocol)
                sock.sendall(b"PING\r\n")
                resp = sock.recv(256)
                if resp and b"+PONG" in resp:
                    self.add_finding(
                        title="Redis Server Unauthenticated Access",
                        severity="CRITICAL",
                        description=(
                            "A Redis server on port 6379 responds to PING "
                            "without requiring authentication. An attacker can "
                            "read/write all keys, execute Lua scripts, or write "
                            "to arbitrary files via CONFIG SET."
                        ),
                        evidence="Redis responded with +PONG to unauthenticated PING.",
                        remediation=(
                            "Require authentication with 'requirepass' in redis.conf. "
                            "Bind Redis to localhost and block port 6379 in the firewall."
                        ),
                        cvss=9.8
                    )
                elif resp:
                    # Port open but requires auth or returned error — still exposed
                    self.add_finding(
                        title="Exposed Database Service (Redis)",
                        severity="HIGH",
                        description="The Redis port (6379) is open and listening publicly, leaving it prone to brute force attacks.",
                        evidence=f"Exposed listening socket on port 6379.",
                        remediation="Filter the database port to localhost or restrict connection access using network firewall rules.",
                        cvss=7.5
                    )
        except socket.error as e:
            self.add_error("Redis Probe socket.error", e)
        except Exception as e:
            self.add_error("Redis Probe Generic Exception", e)
