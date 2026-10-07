from cyberpath.core.assessment_pipeline import (
    AssessmentPipeline,
)


xml_file = "samples/ssh_pipeline_test.xml"


pipeline = AssessmentPipeline(
    xml_file
)

result = pipeline.run()


print("\n" + "=" * 60)
print("CYBERPATH ASSESSMENT PIPELINE TEST")
print("=" * 60)

print("\nScanner")
print("-" * 40)

print(
    f"Scanner: "
    f"{result['scanner']}"
)


print("\nTarget Context")
print("-" * 40)

context = result["context"]

print(
    f"Hosts: "
    f"{context['hosts']}"
)

print(
    f"Service Types: "
    f"{context['service_types']}"
)

print(
    f"Applicable Checks: "
    f"{context['applicable_checks']}"
)


print("\nExecution Plan")
print("-" * 40)

plan = result["execution_plan"]

print(
    f"Total Rules: "
    f"{plan['total_rules']}"
)

for rule in plan["rules"]:
    print(
        f"  {rule}"
    )


print("\nExecuted Checks")
print("-" * 40)

for check in result["check_results"]:

    print(
        f"{check['rule']:<30} "
        f"{check['status']}"
    )


print("\nRisk Results")
print("-" * 40)

for risk_result in result[
    "risk_results"
]:

    print(
        f"\nRule: "
        f"{risk_result['rule']}"
    )

    for finding in risk_result[
        "findings"
    ]:

        print(
            f"  {finding['title']}"
        )

        print(
            f"    Status: "
            f"{finding['status']}"
        )

        print(
            f"    Severity: "
            f"{finding['severity']}"
        )

        print(
            f"    Confidence: "
            f"{finding['confidence']}"
        )

        print(
            f"    Risk Score: "
            f"{finding['risk_score']}"
        )

        print(
            f"    Priority: "
            f"{finding['priority']}"
        )


print("\n" + "=" * 60)
print("ASSESSMENT PIPELINE TEST COMPLETE")
print("=" * 60)
