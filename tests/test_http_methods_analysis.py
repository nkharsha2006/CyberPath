from cyberpath.checks.http_methods import HTTPMethodsCheck
from cyberpath.analyzer.finding_analyzer import FindingAnalyzer


url = "http://127.0.0.1:8000"

checker = HTTPMethodsCheck()

check_result = checker.check(url)

analyzer = FindingAnalyzer(check_result)

analysis = analyzer.analyze()


print("\n" + "=" * 60)
print("CYBERPATH HTTP METHODS ANALYSIS TEST")
print("=" * 60)

print(f"\nTarget     : {analysis['target']}")
print(f"Rule       : {analysis['rule']}")
print(f"Status     : {analysis['status']}")
print(f"Confidence : {analysis['confidence']}")

print("\nFindings")
print("-" * 40)

for number, finding in enumerate(
    analysis["findings"],
    start=1,
):

    print(f"\nFinding #{number}")

    print(f"Title      : {finding['title']}")
    print(f"Status     : {finding['status']}")
    print(f"Severity   : {finding['severity']}")
    print(f"Confidence : {finding['confidence']}")
    print(f"Evidence   : {finding['evidence']}")
    print(f"OWASP      : {finding['owasp']}")
    print(f"CWE        : {finding['cwe']}")
    print(f"Remediation: {finding['remediation']}")

print("\n" + "=" * 60)
print("HTTP METHODS ANALYSIS COMPLETE")
print("=" * 60)