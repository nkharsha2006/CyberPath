import socket


class SSHConfigurationCheck:
    """Perform safe, read-only SSH configuration checks."""

    def __init__(self, timeout=10):
        self.timeout = timeout

    def check(self, host, port):
        """
        Perform safe checks against an SSH service.

        This check does not authenticate or modify the server.
        """

        target = f"{host}:{port}"

        try:
            banner = self.get_banner(
                host,
                port,
            )

        except (socket.timeout, OSError) as error:
            return {
                "rule": "SSH_CONFIGURATION",
                "status": "INCONCLUSIVE",
                "target": target,
                "error": str(error),
                "findings": [],
            }

        findings = []

        if not banner:

            return {
                "rule": "SSH_CONFIGURATION",
                "status": "INCONCLUSIVE",
                "target": target,
                "error": (
                    "SSH identification banner "
                    "was not received."
                ),
                "findings": [],
            }

        # Check whether the server is using the
        # modern SSH protocol identification format.
        if banner.startswith("SSH-2.0-"):

            findings.append({
                "check": "SSH_PROTOCOL_VERSION",
                "status": "PASS",
                "severity": "INFO",
                "value": "SSH-2.0",
                "description": (
                    "The SSH service identified itself "
                    "using the SSH-2.0 protocol."
                ),
            })

        elif banner.startswith("SSH-1."):

            findings.append({
                "check": "SSH_PROTOCOL_VERSION",
                "status": "WEAK",
                "severity": "HIGH",
                "value": banner.split("-", 2)[1],
                "description": (
                    "The SSH service exposed an obsolete "
                    "SSH protocol version."
                ),
            })

        else:

            findings.append({
                "check": "SSH_PROTOCOL_VERSION",
                "status": "INCONCLUSIVE",
                "severity": "INFO",
                "value": banner,
                "description": (
                    "The SSH protocol version could "
                    "not be determined from the banner."
                ),
            })

        # Record the server identification as evidence.
        findings.append({
            "check": "SSH_SERVER_IDENTIFICATION",
            "status": "OBSERVED",
            "severity": "INFO",
            "value": banner,
            "description": (
                "The SSH server identification string "
                "was observed during the connection."
            ),
        })

        return {
            "rule": "SSH_CONFIGURATION",
            "status": "COMPLETED",
            "target": target,
            "banner": banner,
            "findings": findings,
        }

    def get_banner(self, host, port):
        """Retrieve the SSH identification banner."""

        with socket.create_connection(
            (host, int(port)),
            timeout=self.timeout,
        ) as sock:

            sock.settimeout(self.timeout)

            data = b""

            while len(data) < 4096:

                chunk = sock.recv(1024)

                if not chunk:
                    break

                data += chunk

                if b"\n" in data:
                    break

            banner = data.decode(
                "utf-8",
                errors="replace",
            )

            return banner.strip()

