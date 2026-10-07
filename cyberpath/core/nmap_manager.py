import platform
import shutil
import subprocess


class NmapManager:
    """Manage Nmap on the Kali assessment environment."""

    def __init__(self):
        self.nmap_path = None

    def is_kali(self):
        """Check whether the current system is Kali Linux."""

        if platform.system() != "Linux":
            return False

        try:
            with open("/etc/os-release", "r", encoding="utf-8") as file:
                data = file.read().lower()

            return "id=kali" in data or "id_like=kali" in data

        except (FileNotFoundError, OSError):
            return False

    def detect_nmap(self):
        """Find Nmap in the system PATH."""

        self.nmap_path = shutil.which("nmap")

        return self.nmap_path

    def is_installed(self):
        """Check whether Nmap is installed."""

        return self.detect_nmap() is not None

    def get_version(self):
        """Get the installed Nmap version."""

        if not self.nmap_path:
            self.detect_nmap()

        if not self.nmap_path:
            return None

        try:
            result = subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                return result.stdout.strip()

        except (subprocess.SubprocessError, OSError):
            return None

        return None

    def check_apt(self):
        """Check whether apt-get is available."""

        return shutil.which("apt-get") is not None

    def install_nmap(self):
        """
        Ask the user for permission and install Nmap
        using Kali's package manager.
        """

        if not self.is_kali():
            print("[-] Nmap installation is only supported on Kali Linux.")
            return False

        if self.is_installed():
            print("[+] Nmap is already installed.")
            return True

        if not self.check_apt():
            print("[-] apt-get was not found.")
            return False

        print("\n[!] Nmap is not installed.")
        print("[+] CyberPath can install Nmap using Kali's package manager.")
        print()
        print("The following commands will be executed:")
        print("    sudo apt-get update")
        print("    sudo apt-get install -y nmap")
        print()

        choice = input("Install Nmap now? [y/N]: ").strip().lower()

        if choice != "y":
            print("[-] Nmap installation cancelled.")
            return False

        print("\n[+] Updating package information...")

        try:
            update_result = subprocess.run(
                ["sudo", "apt-get", "update"],
                check=False,
            )

            if update_result.returncode != 0:
                print("[-] apt-get update failed.")
                return False

            print("\n[+] Installing Nmap...")

            install_result = subprocess.run(
                ["sudo", "apt-get", "install", "-y", "nmap"],
                check=False,
            )

            if install_result.returncode != 0:
                print("[-] Nmap installation failed.")
                return False

        except (subprocess.SubprocessError, OSError) as error:
            print(f"[-] Installation error: {error}")
            return False

        self.nmap_path = None

        if self.is_installed():
            print("\n[+] Nmap installed successfully.")
            print(f"[+] Nmap path: {self.nmap_path}")

            return True

        print("[-] Nmap installation could not be verified.")

        return False

    def get_status(self):
        """Return the current Nmap status."""

        kali = self.is_kali()
        installed = self.is_installed()

        return {
            "kali": kali,
            "installed": installed,
            "path": self.nmap_path,
            "version": self.get_version() if installed else None,
        }