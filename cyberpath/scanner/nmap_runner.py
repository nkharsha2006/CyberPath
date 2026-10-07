import subprocess
from pathlib import Path


class NmapRunner:
    """Run controlled Nmap reconnaissance scans."""

    def __init__(self, nmap_path="nmap"):
        self.nmap_path = nmap_path

    def run_scan(self, target, output_file):
        """
        Run a basic service/version detection scan
        and save the result as Nmap XML.
        """

        output_path = Path(output_file)

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        command = [
            self.nmap_path,
            "-sV",
            "-oX",
            str(output_path),
            target,
        ]

        print("\n[+] Starting Nmap scan...")
        print(f"[+] Target : {target}")
        print(f"[+] Output : {output_path}")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

        except subprocess.TimeoutExpired:
            print("[-] Nmap scan timed out.")
            return False

        except (subprocess.SubprocessError, OSError) as error:
            print(f"[-] Failed to start Nmap: {error}")
            return False

        if result.stdout:
            print(result.stdout)

        if result.stderr:
            print(result.stderr)

        if result.returncode != 0:
            print(
                f"[-] Nmap exited with code "
                f"{result.returncode}."
            )
            return False

        if not output_path.exists():
            print("[-] Nmap XML output was not created.")
            return False

        print("[+] Nmap scan completed successfully.")
        print(f"[+] XML report: {output_path}")

        return True