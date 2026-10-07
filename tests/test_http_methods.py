from cyberpath.checks.http_methods import HTTPMethodsCheck


url = "http://127.0.0.1:8000"

checker = HTTPMethodsCheck()

result = checker.check(url)

print("\n" + "=" * 60)
print("CYBERPATH HTTP METHODS CHECK")
print("=" * 60)

print(f"\nTarget      : {result['target']}")
print(f"Rule        : {result['rule']}")
print(f"Status      : {result['status']}")

if "http_status" in result:
    print(f"HTTP Status : {result['http_status']}")

if "final_url" in result:
    print(f"Final URL   : {result['final_url']}")

print("\nAllowed Methods")
print("-" * 40)

if result.get("methods"):
    for method in result["methods"]:
        print(f"  {method}")
else:
    print("  No Allow header observed.")

if result.get("allow_header"):
    print(f"\nAllow Header:")
    print(f"  {result['allow_header']}")

if result.get("error"):
    print("\nError")
    print("-" * 40)
    print(result["error"])

print("\n" + "=" * 60)
print("HTTP METHODS CHECK COMPLETE")
print("=" * 60)