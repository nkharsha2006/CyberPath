class TargetNormalizer:
    """Convert scanner output into a standard CyberPath format."""

    def normalize(self, scan_data):
        """
        Convert Nmap parser output into the
        standard CyberPath target structure.
        """

        normalized_target = {
            "scanner": scan_data.get("scanner"),
            "hosts": [],
        }

        for host in scan_data.get("hosts", []):

            normalized_host = {
                "status": host.get("status"),
                "addresses": [],
                "hostnames": [],
                "services": [],
            }

            # Normalize addresses
            for address in host.get("addresses", []):

                normalized_host["addresses"].append({
                    "type": address.get("type"),
                    "address": address.get("address"),
                })

            # Normalize hostnames
            for hostname in host.get("hostnames", []):

                normalized_host["hostnames"].append(
                    hostname
                )

            # Normalize services
            for port in host.get("ports", []):

                normalized_service = {
                    "port": port.get("port"),
                    "protocol": port.get("protocol"),
                    "state": port.get("state"),
                    "service": port.get("service"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                }

                normalized_host["services"].append(
                    normalized_service
                )

            normalized_target["hosts"].append(
                normalized_host
            )

        return normalized_target