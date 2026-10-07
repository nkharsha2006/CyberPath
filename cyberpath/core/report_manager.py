from pathlib import Path

from cyberpath.reports.json_report import JSONReportGenerator
from cyberpath.reports.html_report import HTMLReportGenerator


class ReportManager:
    """Manage CyberPath JSON and HTML report generation."""

    def __init__(self, output_directory="reports"):
        self.output_directory = Path(
            output_directory
        )

        self.json_generator = JSONReportGenerator(
            output_directory=self.output_directory
        )

        self.html_generator = HTMLReportGenerator(
            output_directory=self.output_directory
        )

    def generate_json(
        self,
        assessment_data,
        filename="cyberpath_report.json",
    ):
        """Generate a JSON report."""

        return self.json_generator.generate(
            assessment_data,
            filename=filename,
        )

    def generate_html(
        self,
        assessment_data,
        filename="cyberpath_report.html",
    ):
        """Generate an HTML report."""

        return self.html_generator.generate(
            assessment_data,
            filename=filename,
        )

    def generate_all(
        self,
        assessment_data,
        json_filename="cyberpath_report.json",
        html_filename="cyberpath_report.html",
    ):
        """Generate both JSON and HTML reports."""

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        json_file = self.generate_json(
            assessment_data,
            filename=json_filename,
        )

        html_file = self.generate_html(
            assessment_data,
            filename=html_filename,
        )

        return {
            "json": str(json_file),
            "html": str(html_file),
        }
