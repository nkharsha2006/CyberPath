from cyberpath.core.config import ensure_directories
from cyberpath.core.environment import (
    get_environment_info,
)
from cyberpath.core.dependency_manager import (
    check_python_environment,
)
from cyberpath.core.nmap_manager import NmapManager


def print_status(status):
    if status:
        print("[+] OK")
    else:
        print("[-] NOT FOUND")


def main():

    print("=" * 60)
    print("              CYBERPATH 2.0")
    print("   Context-Aware Security Assessment Platform")
    print("=" * 60)

    ensure_directories()

    print("\n[+] Detecting environment...\n")

    environment = get_environment_info()

    python_environment = check_python_environment()

    print("System")
    print("-" * 40)

    print(
        f"Operating system : "
        f"{environment['operating_system']}"
    )

    if environment["linux_distribution"]:
        print(
            f"Distribution     : "
            f"{environment['linux_distribution']}"
        )

    print(
        f"Python version   : "
        f"{environment['python_version']}"
    )

    print("\nPython packages")
    print("-" * 40)

    for package, status in python_environment[
        "python_packages"
    ].items():

        print(f"{package:<15} : ", end="")
        print_status(status)

    print("\nEnvironment")
    print("-" * 40)

    current_environment = environment["environment"]

    if current_environment == "WINDOWS":

        print("Mode             : WINDOWS / DEVELOPMENT")

        print("\nSecurity Tools")
        print("-" * 40)

        print("Nmap             : [--] Kali Only")

        python_ok = all(
            python_environment["python_packages"].values()
        )

        environment_ready = python_ok

    elif current_environment == "KALI":

        print("Mode             : KALI / ASSESSMENT")

        print("\nSecurity Tools")
        print("-" * 40)

        nmap_manager = NmapManager()
        nmap_status = nmap_manager.get_status()

        print("Nmap             : ", end="")
        print_status(nmap_status["installed"])

        if nmap_status["installed"]:

            print(
                f"Nmap path        : "
                f"{nmap_status['path']}"
            )

            if nmap_status["version"]:

                first_line = (
                    nmap_status["version"]
                    .splitlines()[0]
                )

                print(
                    f"Nmap version     : "
                    f"{first_line}"
                )

        else:
            print("Nmap path        : NOT FOUND")

        python_ok = all(
            python_environment["python_packages"].values()
        )

        environment_ready = (
            python_ok
            and nmap_status["installed"]
        )

    else:

        print(
            "Mode             : "
            "UNSUPPORTED / OTHER ENVIRONMENT"
        )

        print("\nSecurity Tools")
        print("-" * 40)

        print("Nmap             : [--] Environment not supported")

        environment_ready = False

    print("\n" + "=" * 60)

    if environment_ready:
        print("ENVIRONMENT STATUS: READY")
    else:
        print("ENVIRONMENT STATUS: INCOMPLETE")

    print("=" * 60)


if __name__ == "__main__":
    main()