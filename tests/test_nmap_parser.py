from cyberpath.input.nmap_xml_parser import NmapXMLParser


xml_file = "samples/sample_nmap.xml"

parser = NmapXMLParser(xml_file)

result = parser.parse()

print("\n" + "=" * 60)
print("NMAP XML PARSER TEST")
print("=" * 60)

print(f"\nScanner: {result['scanner']}")

for host in result["hosts"]:

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

    print("\nPorts:")

    for port in host["ports"]:

        print(
            f"  {port['port']}/"
            f"{port['protocol']} "
            f"{port['state']} "
            f"{port['service']} "
            f"{port['product']} "
            f"{port['version']}"
        )

print("\n" + "=" * 60)
print("PARSER TEST COMPLETE")
print("=" * 60)