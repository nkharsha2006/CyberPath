import platform
import sys
from pathlib import Path


def get_operating_system():
    """Return the current operating system."""
    return platform.system()


def get_python_version():
    """Return the current Python version."""
    return platform.python_version()


def get_python_executable():
    """Return the Python executable being used."""
    return sys.executable


def get_linux_distribution():
    """Detect the Linux distribution."""
    os_release = Path("/etc/os-release")

    if not os_release.exists():
        return None

    data = {}

    for line in os_release.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key] = value.strip('"')

    return data.get("ID")


def detect_environment():
    """
    Detect whether CyberPath is running on
    Windows, Kali Linux, or another system.
    """

    operating_system = get_operating_system()

    if operating_system == "Windows":
        return "WINDOWS"

    if operating_system == "Linux":
        distro = get_linux_distribution()

        if distro == "kali":
            return "KALI"

        return "OTHER_LINUX"

    return "OTHER"


def get_environment_info():
    """Return complete environment information."""
    return {
        "operating_system": get_operating_system(),
        "linux_distribution": get_linux_distribution(),
        "environment": detect_environment(),
        "python_version": get_python_version(),
        "python_executable": get_python_executable(),
    }