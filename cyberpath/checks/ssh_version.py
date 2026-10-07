import socket


class SSHVersionCheck:
    """Safely inspect the SSH server identification banner."""

    def __init__(self, timeout=10):
        self.timeout = timeout

    def check(self, host, port):
        """
        Connect to an SSH service and read its identification
        banner without attempting authentication.
        """

        try:
            banner = self.get_banner(
                host,
                port,
            )

        except (socket.timeout, OSError) as error:
            return {
                "rule": "SSH_VERSION",
                "status": "INCONCLUSIVE",
                "target": f"{host}:{port}",
                "error": str(error),
                "findings": [],
            }

        if not banner:
            return {
                "rule": "SSH_VERSION",
                "status": "INCONCLUSIVE",
                "target": f"{host}:{port}",
                "error": "SSH identification banner not received.",
                "findings": [],
            }

        return {
            "rule": "SSH_VERSION",
            "status": "COMPLETED",
            "target": f"{host}:{port}",
            "banner": banner,
            "findings": [
                {
                    "type": "SSH_BANNER",
                    "status": "OBSERVED",
                    "severity": "INFO",
                    "value": banner,
                    "description": (
                        "SSH server identification banner "
                        "was observed."
                    ),
                }
            ],
        }

    def get_banner(self, host, port):
        """Connect to SSH and retrieve the identification banner."""

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