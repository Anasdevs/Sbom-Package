import json
import subprocess
import platform

def get_installed_packages():
    system = platform.system()
    if system == "Linux":
        distribution = platform.linux_distribution()[0].lower()
        if distribution in ["debian", "ubuntu"]:
            # Debian-based systems
            command = "dpkg-query --show"
        elif distribution in ["centos", "redhat", "fedora"]:
            # Red Hat-based systems
            command = "rpm -qa"
        else:
            print("Unsupported distribution:", distribution)
            return None
        try:
            output = subprocess.check_output(command.split()).decode("utf-8")
            return output.splitlines()
        except subprocess.CalledProcessError:
            print("Error: Failed to retrieve package information.")
            return None
    else:
        print("Unsupported platform:", system)
        return None

def generate_sbom():
    packages = get_installed_packages()
    if packages:
        sbom = [{"name": pkg.split()[0], "version": pkg.split()[1]} for pkg in packages]
        with open("sbom.json", "w") as f:
            json.dump(sbom, f, indent=4)
        print("SBOM generated successfully.")
    else:
        print("Failed to generate SBOM.")

if __name__ == "__main__":
    generate_sbom()
