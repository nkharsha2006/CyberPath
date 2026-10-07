from cyberpath.core.check_executor import CheckExecutor


target = "http://127.0.0.1:8000"

rules = [
    "HTTP_SECURITY_HEADERS",
    "HTTP_METHODS",
]


executor = CheckExecutor()

results = executor.execute_rules(
    rules,
    target,
)


print("\n" + "=" * 60)
print("CYBERPATH CHECK EXECUTOR TEST")
print("=" * 60)

print(f"\nTarget: {target}")

print("\nExecuted Rules")
print("-" * 40)

for result in results:

    print(
        f"\nRule   : {result['rule']}"
    )

    print(
        f"Status : {result['status']}"
    )

    if result.get("http_status"):
        print(
            f"HTTP Status: "
            f"{result['http_status']}"
        )

    if result.get("error"):
        print(
            f"Error  : "
            f"{result['error']}"
        )

print("\n" + "=" * 60)
print("CHECK EXECUTOR TEST COMPLETE")
print("=" * 60)