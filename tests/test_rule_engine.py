from cyberpath.input.nmap_xml_parser import NmapXMLParser
from cyberpath.analyzer.normalizer import TargetNormalizer
from cyberpath.analyzer.context import TargetContext
from cyberpath.analyzer.rule_engine import RuleEngine


xml_file = "samples/sample_nmap.xml"


# Parse Nmap XML
parser = NmapXMLParser(xml_file)

scan_data = parser.parse()


# Normalize data
normalizer = TargetNormalizer()

normalized_data = normalizer.normalize(
    scan_data
)


# Build target context
context_engine = TargetContext(
    normalized_data
)

context = context_engine.build_context()


# Build rule execution plan
rule_engine = RuleEngine(context)

execution_plan = rule_engine.build_execution_plan()


print("\n" + "=" * 60)
print("CYBERPATH RULE ENGINE TEST")
print("=" * 60)

print("\nApplicable Security Checks")
print("-" * 40)

for check in context["applicable_checks"]:
    print(f"  {check}")

print("\nSelected Security Rules")
print("-" * 40)

for rule in execution_plan["rules"]:
    print(f"  {rule}")

print("\nTotal Rules:")
print(f"  {execution_plan['total_rules']}")

print("\n" + "=" * 60)
print("RULE ENGINE TEST COMPLETE")
print("=" * 60)