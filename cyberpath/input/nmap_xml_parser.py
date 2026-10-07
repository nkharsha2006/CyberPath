from pathlib import Path
from lxml import etree


class NmapXMLParser:
    """Parse Nmap XML scan results."""

    def __init__(self, xml_file):
        self.xml_file = Path(xml_file)

    def load_xml(self):
        """Load and parse the Nmap XML file."""

        if not self.xml_file.exists():
            raise FileNotFoundError(
                f"Nmap XML file not found: {self.xml_file}"
            )

        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
        )

        return etree.parse(
            str(self.xml_file),
            parser,
        )

    def parse(self):
        """Parse hosts, ports, services and versions."""

        tree = self.load_xml()
        root = tree.getroot()

        scan_data = {
            "scanner": "nmap",
            "hosts": [],
        }

        for host in root.findall("host"):

            host_data = {
                "status": None,
                "addresses": [],
                "hostnames": [],
                "ports": [],
            }

            status = host.find("status")

            if status is not None:
                host_data["status"] = status.get("state")

            for address in host.findall("address"):

                host_data["addresses"].append({
                    "type": address.get("addrtype"),
                    "address": address.get("addr"),
                })

            hostnames = host.find("hostnames")

            if hostnames is not None:
                for hostname in hostnames.findall("hostname"):
                    host_data["hostnames"].append(
                        hostname.get("name")
                    )

            ports = host.find("ports")

            if ports is not None:

                for port in ports.findall("port"):

                    port_data = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": None,
                        "service": None,
                        "product": None,
                        "version": None,
                    }

                    state = port.find("state")

                    if state is not None:
                        port_data["state"] = state.get("state")

                    service = port.find("service")

                    if service is not None:
                        port_data["service"] = service.get("name")
                        port_data["product"] = service.get("product")
                        port_data["version"] = service.get("version")

                    host_data["ports"].append(port_data)

            scan_data["hosts"].append(host_data)

        return scan_data