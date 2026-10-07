from cyberpath.checks.http_headers import HTTPSecurityHeadersCheck
from cyberpath.analyzer.finding_analyzer import FindingAnalyzer


url = "http://127.0.0.1:3000"

checker = HTTPSecurityHeadersCheck()

check_result = checker.check(url)

analyzer = FindingAnalyzer(check_result)

analysis = analyzer.analyze()

print("\n" + "=" * 60)
print("CYBERPATH FINDING ANALYZER TEST")
print("=" * 60)

print(f"\nTarget     : {analysis['target']}")
print(f"Rule       : {analysis['rule']}")
print(f"Status     : {analysis['status']}")
print(f"Confidence : {analysis['confidence']}")

if analysis.get("error"):

    print("\nError")
    print("-" * 40)
    print(analysis["error"])

print("\nFindings")
print("-" * 40)

for number, finding in enumerate(
    analysis["findings"],
    start=1
):

    print(f"\nFinding #{number}")

    print(f"Title      : {finding['title']}")
    print(f"Status     : {finding['status']}")
    print(f"Severity   : {finding['severity']}")
    print(f"Confidence : {finding['confidence']}")

    print(
        f"Evidence   : "
        f"{finding['evidence']['header']} = "
        f"{finding['evidence']['observed']}"
    )

    print(
        f"Description: "
        f"{finding['description']}"
    )

    if finding["remediation"]:
        print(
            f"Remediation: "
            f"{finding['remediation']}"
        )

print("\n" + "=" * 60)
print("FINDING ANALYZER TEST COMPLETE")
print("=" * 60)