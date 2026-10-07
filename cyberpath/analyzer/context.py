class TargetContext:
    """Build security-relevant context from normalized target data."""

    def __init__(self, normalized_target):
        self.target = normalized_target

    def get_services(self):
        """Return all discovered services."""

        services = []

        for host in self.target.get("hosts", []):

            for service in host.get("services", []):

                services.append({
                    "host": self._get_host_address(host),
                    "port": service.get("port"),
                    "protocol": service.get("protocol"),
                    "state": service.get("state"),
                    "service": service.get("service"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                })

        return services

    def get_open_services(self):
        """Return only services with an open port."""

        return [
            service
            for service in self.get_services()
            if service.get("state") == "open"
        ]

    def get_service_types(self):
        """Identify unique service types."""

        service_types = set()

        for service in self.get_open_services():

            service_name = service.get("service")

            if service_name:
                service_types.add(
                    service_name.lower()
                )

        return sorted(service_types)

    def get_applicable_checks(self):
        """
        Determine which security-check categories
        are relevant to the discovered services.
        """

        checks = set()

        service_types = self.get_service_types()

        if "http" in service_types:
            checks.add("HTTP")

        if "https" in service_types:
            checks.add("HTTPS")

        if "ssh" in service_types:
            checks.add("SSH")

        return sorted(checks)

    def _get_host_address(self, host):
        """Return the first available host address."""

        addresses = host.get("addresses", [])

        if addresses:
            return addresses[0].get("address")

        return None

    def build_context(self):
        """Build the complete target context."""

        return {
            "hosts": len(
                self.target.get("hosts", [])
            ),
            "open_services": self.get_open_services(),
            "service_types": self.get_service_types(),
            "applicable_checks": self.get_applicable_checks(),
        }