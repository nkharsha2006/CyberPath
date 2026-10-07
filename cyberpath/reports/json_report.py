import json
from datetime import datetime
from pathlib import Path


class JSONReportGenerator:
    """Generate JSON reports for CyberPath assessments."""

    def __init__(self, output_directory="reports"):
        self.output_directory = Path(output_directory)

    def generate(self, assessment_data, filename="cyberpath_report.json"):
        """Generate and save a JSON assessment report."""

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        report = {
            "cyberpath_version": "2.0",
            "report_type": "security_assessment",
            "generated_at": datetime.now().astimezone().isoformat(),
            "assessment": assessment_data,
        }

        output_file = self.output_directory / filename

        with output_file.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
            )

        return output_file