from cyberpath.input.nmap_xml_parser import NmapXMLParser
from cyberpath.analyzer.normalizer import TargetNormalizer
from cyberpath.analyzer.context import TargetContext


xml_file = "samples/sample_nmap.xml"


# Parse Nmap XML
parser = NmapXMLParser(xml_file)

scan_data = parser.parse()


# Normalize data
normalizer = TargetNormalizer()

normalized_data = normalizer.normalize(
    scan_data
)


# Build context
context_engine = TargetContext(
    normalized_data
)

context = context_engine.build_context()


print("\n" + "=" * 60)
print("CYBERPATH CONTEXT ENGINE TEST")
print("=" * 60)

print(
    f"\nHosts discovered: "
    f"{context['hosts']}"
)

print("\nOpen Services")
print("-" * 40)

for service in context["open_services"]:

    print(
        f"{service['host']} "
        f"{service['port']}/"
        f"{service['protocol']} "
        f"{service['service']} "
        f"{service['product']} "
        f"{service['version']}"
    )

print("\nService Types")
print("-" * 40)

for service_type in context["service_types"]:
    print(f"  {service_type}")

print("\nApplicable Security Checks")
print("-" * 40)

for check in context["applicable_checks"]:
    print(f"  {check}")

print("\n" + "=" * 60)
print("CONTEXT ENGINE TEST COMPLETE")
print("=" * 60)