import argparse
import sys
from pathlib import Path

from cyberpath.core.assessment_pipeline import AssessmentPipeline
from cyberpath.core.nmap_manager import NmapManager
from cyberpath.core.config import ensure_directories, REPORTS_DIR
from cyberpath.scanner.nmap_runner import NmapRunner
from cyberpath.core.report_manager import ReportManager


class CyberPathCLI:
    """Command-line interface for CyberPath 2.0."""

    def __init__(self):
        self.nmap_manager = NmapManager()
        self.report_manager = ReportManager(
            output_directory=REPORTS_DIR
        )

    def print_banner(self):
        """Display the CyberPath banner."""

        print()
        print("=" * 70)
        print("                     CYBERPATH 2.0")
        print("        Context-Aware Security Assessment Platform")
        print("=" * 70)
        print()

    def check_environment(self):
        """Verify that CyberPath is ready for assessment."""

        print("[+] Checking assessment environment...")

        if not self.nmap_manager.is_kali():
            print("[-] CyberPath assessment mode requires Kali Linux.")
            return False

        if not self.nmap_manager.is_installed():
            print("[-] Nmap is not installed.")
            print("[!] Install Nmap with:")
            print("    sudo apt install nmap")
            return False

        print("[+] Kali Linux detected.")
        print(f"[+] Nmap: {self.nmap_manager.nmap_path}")

        return True

    def run_scan(self, target, xml_file):
        """Run the Nmap reconnaissance scan."""

        runner = NmapRunner(
            nmap_path=self.nmap_manager.nmap_path
        )

        return runner.run_scan(
            target,
            xml_file,
        )

    def run_assessment(self, xml_file):
        """Run the CyberPath assessment pipeline."""

        print()
        print("[+] Starting CyberPath assessment...")
        print()

        pipeline = AssessmentPipeline(
            xml_file
        )

        return pipeline.run()

    def generate_reports(self, assessment_data):
        """Generate JSON and HTML reports."""

        print()
        print("[+] Generating reports...")

        reports = self.report_manager.generate_all(
            assessment_data
        )

        print()
        print("[+] Reports generated:")
        print(f"    JSON : {reports['json']}")
        print(f"    HTML : {reports['html']}")

        return reports

    def print_summary(self, assessment_data):
        """Display a concise assessment summary."""

        context = assessment_data.get(
            "context",
            {}
        )

        risk_results = assessment_data.get(
            "risk_results",
            []
        )

        total_findings = 0
        priorities = {}

        for result in risk_results:

            for finding in result.get(
                "findings",
                []
            ):

                total_findings += 1

                priority = finding.get(
                    "priority",
                    "INFO"
                )

                priorities[priority] = (
                    priorities.get(priority, 0) + 1
                )

        print()
        print("=" * 70)
        print("                    ASSESSMENT SUMMARY")
        print("=" * 70)

        print(
            f"Hosts discovered : "
            f"{context.get('hosts', 0)}"
        )

        print(
            f"Open services   : "
            f"{len(context.get('open_services', []))}"
        )

        print(
            f"Service types   : "
            f"{', '.join(context.get('service_types', [])) or 'None'}"
        )

        print(
            f"Rules executed  : "
            f"{assessment_data.get('execution_plan', {}).get('total_rules', 0)}"
        )

        print(
            f"Total findings  : "
            f"{total_findings}"
        )

        print()
        print("Risk Priorities")
        print("-" * 40)

        for priority in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        ]:

            count = priorities.get(
                priority,
                0
            )

            print(
                f"{priority:<10} : {count}"
            )

        print("=" * 70)

    def execute(self, target):
        """Execute a complete CyberPath assessment."""

        ensure_directories()

        self.print_banner()

        if not self.check_environment():
            return 1

        target_name = target.replace(
            "/",
            "_"
        ).replace(
            ":",
            "_"
        )

        xml_file = (
            Path("samples")
            / f"{target_name}_nmap.xml"
        )

        print()
        print("[+] Assessment target:")
        print(f"    {target}")

        print()
        print("[!] IMPORTANT")
        print(
            "[!] Only scan systems that you own "
            "or are explicitly authorized to assess."
        )

        confirmation = input(
            "\nContinue with this authorized target? [y/N]: "
        ).strip().lower()

        if confirmation != "y":
            print("[-] Assessment cancelled.")
            return 0

        if not self.run_scan(
            target,
            xml_file,
        ):
            print("[-] Nmap reconnaissance failed.")
            return 1

        try:

            assessment_data = self.run_assessment(
                xml_file
            )

        except Exception as error:

            print()
            print("[-] Assessment failed.")
            print(f"[-] Error: {error}")

            return 1

        self.print_summary(
            assessment_data
        )

        try:

            self.generate_reports(
                assessment_data
            )

        except Exception as error:

            print()
            print("[-] Report generation failed.")
            print(f"[-] Error: {error}")

            return 1

        print()
        print("[+] CyberPath assessment completed successfully.")

        return 0


def build_parser():
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            "CyberPath 2.0 - "
            "Context-Aware Security Assessment Platform"
        )
    )

    parser.add_argument(
        "target",
        help=(
            "Authorized target hostname or IP address"
        ),
    )

    return parser


def main():
    """CLI entry point."""

    parser = build_parser()

    args = parser.parse_args()

    cli = CyberPathCLI()

    return_code = cli.execute(
        args.target
    )

    sys.exit(return_code)


if __name__ == "__main__":
    main()
