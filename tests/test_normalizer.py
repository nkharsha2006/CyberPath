from cyberpath.input.nmap_xml_parser import NmapXMLParser
from cyberpath.analyzer.normalizer import TargetNormalizer


xml_file = "samples/sample_nmap.xml"


# Parse Nmap XML
parser = NmapXMLParser(xml_file)
scan_data = parser.parse()


# Normalize scanner data
normalizer = TargetNormalizer()
normalized_data = normalizer.normalize(scan_data)


print("\n" + "=" * 60)
print("CYBERPATH NORMALIZER TEST")
print("=" * 60)

print(f"\nScanner: {normalized_data['scanner']}")

for host in normalized_data["hosts"]:

    print("\nHost")
    print("-" * 40)

    print(f"Status: {host['status']}")

    print("\nAddresses:")

    for address in host["addresses"]:
        print(
            f"  {address['type']}: "
            f"{address['address']}"
        )

    print("\nHostnames:")

    for hostname in host["hostnames"]:
        print(f"  {hostname}")

    print("\nServices:")

    for service in host["services"]:
        print(
            f"  {service['port']}/"
            f"{service['protocol']} "
            f"{service['state']} "
            f"{service['service']} "
            f"{service['product']} "
            f"{service['version']}"
        )

print("\n" + "=" * 60)
print("NORMALIZER TEST COMPLETE")
print("=" * 60)