from cyberpath.checks.http_headers import HTTPSecurityHeadersCheck


url = "http://127.0.0.1:3000"

checker = HTTPSecurityHeadersCheck()

result = checker.check(url)

print("\n" + "=" * 60)
print("HTTP SECURITY HEADERS CHECK")
print("=" * 60)

print(f"\nTarget       : {result['target']}")
print(f"Rule         : {result['rule']}")
print(f"Status       : {result['status']}")

if "http_status" in result:
    print(f"HTTP Status  : {result['http_status']}")

if "final_url" in result:
    print(f"Final URL    : {result['final_url']}")

if result["findings"]:

    print("\nHeaders")
    print("-" * 40)

    for finding in result["findings"]:

        print(
            f"{finding['header']:<30} "
            f"{finding['status']:<10} "
            f"{finding['severity']}"
        )

if "error" in result:

    print("\nError")
    print("-" * 40)
    print(result["error"])

print("\n" + "=" * 60)
print("HTTP HEADER CHECK COMPLETE")
print("=" * 60)