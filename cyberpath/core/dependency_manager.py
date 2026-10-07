import importlib.util
import sys


PYTHON_PACKAGES = {
    "requests": "requests",
    "lxml": "lxml",
    "bs4": "beautifulsoup4",
    "rich": "rich",
}


def check_python():
    """Check whether the Python version is supported."""
    return sys.version_info >= (3, 10)


def check_python_package(module_name):
    """Check whether a Python module is installed."""
    return importlib.util.find_spec(module_name) is not None


def check_python_packages():
    """Check all required Python packages."""

    results = {}

    for module_name in PYTHON_PACKAGES:
        results[module_name] = check_python_package(module_name)

    return results


def check_python_environment():
    """Check Python and required Python packages."""

    return {
        "python": check_python(),
        "python_packages": check_python_packages(),
    }