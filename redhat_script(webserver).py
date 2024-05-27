import subprocess
import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def normalize_version(version):
    if ':' in version:
        version = version.split(':')[1]
    version = re.split(r'[-+]', version)[0]
    version = re.sub(r'[^0-9.]', '', version)
    return version

def query_ubuntu_security_tracker(package_name, session):
    url = f"https://ubuntu.com/security/cves.json?package={package_name}&limit=1&order=descending&sort_by=published"
    print(f"Querying Ubuntu Security Tracker for {package_name}...")
    try:
        response = session.get(url)
        response.raise_for_status()
        try:
            cves = response.json().get('cves', [])
            print(f"Found {len(cves)} CVEs for {package_name}")
            return [cve['id'] for cve in cves]
        except json.JSONDecodeError:
            print(f"Invalid JSON response for {package_name}: {response.text}")
            return []
    except requests.RequestException as e:
        print(f"Request failed for {package_name}: {e}")
        return []

def clean_description(description):
    return description.replace("\n", "")

def query_cve_details(cve_id, session):
    try:
        response = session.get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
        response.raise_for_status()
        cve_data = response.json()

        cve_details = {
            "cveId": cve_id,
            "description": clean_description(cve_data['containers']['cna']['descriptions'][0]['value']),
            "cvssScore": cve_data['containers']['cna']['metrics'][0]['cvssV3_1']['baseScore'],
            "cvssVector": cve_data['containers']['cna']['metrics'][0]['cvssV3_1']['vectorString'],
            "severity": cve_data['containers']['cna']['metrics'][0]['cvssV3_1']['baseSeverity'],
            "affectedVersions": [
                v['version'] for a in cve_data['containers']['cna']['affected'] for v in a['versions']
            ],
            "affectedVersionsRange": [
                (v.get('lessThan'), v.get('version'), v.get('versionType')) for a in cve_data['containers']['cna']['affected'] for v in a['versions']
            ]
        }
        return cve_details
    except requests.exceptions.RequestException as e:
        print(f"Error querying CVE details for {cve_id}: {e}")
        return None

def version_to_tuple(version):
    return tuple(map(int, re.findall(r'\d+', version)))

def is_version_affected(current_version, affected_version, less_than_version, version_type):
    current_version_tuple = version_to_tuple(current_version)
    if version_type == 'custom':
        less_than_version_tuple = version_to_tuple(less_than_version)
        return current_version_tuple < less_than_version_tuple
    elif version_type == 'semver':
        affected_version_tuple = version_to_tuple(affected_version)
        less_than_version_tuple = version_to_tuple(less_than_version)
        return affected_version_tuple <= current_version_tuple < less_than_version_tuple
    return False

def process_package(package, session):
    print(f"Processing package: {package['name']}")
    package['version'] = normalize_version(package['version'])
    package['cve'] = []

    cve_ids = query_ubuntu_security_tracker(package['name'], session)
    if cve_ids:
        for cve_id in cve_ids:
            cve_details = query_cve_details(cve_id, session)
            if cve_details:
                for affected_version, less_than_version, version_type in cve_details['affectedVersionsRange']:
                    if is_version_affected(package['version'], affected_version, less_than_version, version_type):
                        package['cve'].append(cve_details)
                        break
    return package

def list_installed_packages():
    try:
        # Use dnf for Red Hat-based systems
        dnf_output = subprocess.check_output(['dnf', 'list', 'installed'], stderr=subprocess.DEVNULL)
        return dnf_output.decode('utf-8')
    except subprocess.CalledProcessError:
        # Fallback to yum for older systems
        yum_output = subprocess.check_output(['yum', 'list', 'installed'], stderr=subprocess.DEVNULL)
        return yum_output.decode('utf-8')

def parse_installed_packages(output):
    packages = []
    for line in output.splitlines():
        if line and not line.startswith('Installed Packages') and not line.startswith(' '):
            parts = re.split(r'\s+', line)
            if len(parts) >= 3:
                name_arch = parts[0].rsplit('.', 1)
                if len(name_arch) == 2:
                    name, arch = name_arch
                    # Filter out unwanted prefixes (e.g., amazon-)
                    if name.startswith('amazon-'):
                        name = name.replace('amazon-', '')
                    version = normalize_version(parts[1].split(':', 1)[-1])
                    package = {
                        "name": name,
                        "version": version,
                        "architecture": arch,
                        "repository": parts[2]
                    }
                    packages.append(package)
    return packages

def generate_packages_json():
    print("Listing installed packages...")
    package_list_output = list_installed_packages()
    parsed_packages = parse_installed_packages(package_list_output)

    print("Starting to process packages concurrently...")
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_package = {executor.submit(process_package, package, session): package for package in parsed_packages}
            for future in as_completed(future_to_package):
                package = future_to_package[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"Package {package['name']} generated an exception: {exc}")

    sbom = {
        "sbomVersion": "1.0",
        "generatedDate": datetime.now().strftime("%Y-%m-%d"),
        "components": parsed_packages
    }

    print("Writing packages data to installed_packages.json...")
    with open('installed_packages.json', 'w') as json_file:
        json.dump(sbom, json_file, indent=4)

if __name__ == "__main__":
    generate_packages_json()
