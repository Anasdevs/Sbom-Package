import subprocess
import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from time import sleep
import uuid

def normalize_version(version_str):
    return re.sub(r'[^0-9.]', '', version_str.split(':')[-1].split('-')[0])

def version_to_tuple(version):
    return tuple(map(int, re.findall(r'\d+', version)))

def is_version_affected(current_version, affected_product):
    current_v = version_to_tuple(current_version)
    affected_v = version_to_tuple(affected_product['version']) if affected_product['version'] else None
    less_than_v = version_to_tuple(affected_product['lessThan']) if affected_product['lessThan'] else None
    less_than_or_equal_v = version_to_tuple(affected_product['lessThanOrEqual']) if affected_product['lessThanOrEqual'] else None

    if affected_product['versionType'] == 'custom':
        return (less_than_v is None or current_v < less_than_v) and \
               (less_than_or_equal_v is None or current_v <= less_than_or_equal_v)
    elif affected_product['versionType'] == 'semver':
        return (affected_v is None or current_v >= affected_v) and \
               (less_than_v is None or current_v < less_than_v) and \
               (less_than_or_equal_v is None or current_v <= less_than_or_equal_v)
    return False

def query_ubuntu_security_tracker(package_name, session):
    url = f"https://ubuntu.com/security/cves.json?package={package_name}&limit=2&order=descending&sort_by=published"
    print(f"Querying Ubuntu Security Tracker for {package_name}...")
    for attempt in range(3):
        try:
            response = session.get(url)
            response.raise_for_status()
            cves = response.json().get('cves', [])
            print(f"Found {len(cves)} CVEs for {package_name}")
            return [cve['id'] for cve in cves]
        except (requests.RequestException, json.JSONDecodeError):
            print(f"Retrying ({attempt + 1}/3) for {package_name}...")
            sleep(2)
    return []

def query_cve_details(cve_id, session):
    try:
        response = session.get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
        response.raise_for_status()
        cve_data = response.json()

        affected_products = []
        for affected in cve_data['containers']['cna'].get('affected', []):
            product = affected.get('product', '')
            vendor = affected.get('vendor', '')
            for v in affected.get('versions', []):
                affected_products.append({
                    'product': product,
                    'vendor': vendor,
                    'version': v.get('version', ''),
                    'lessThan': v.get('lessThan', ''),
                    'lessThanOrEqual': v.get('lessThanOrEqual', ''),
                    'versionType': v.get('versionType', '')
                })

        cve_details = {
            "cveId": cve_id,
            "description": cve_data['containers']['cna']['descriptions'][0]['value'].replace("\n", " ").strip(),
            "affectedProducts": affected_products
        }

        metrics = cve_data['containers']['cna'].get('metrics', [])
        if metrics:
            cvss = metrics[0].get('cvssV3_1', {})
            cve_details.update({
                "cvssScore": cvss.get('baseScore', None),
                "cvssVector": cvss.get('vectorString', ''),
                "severity": cvss.get('baseSeverity', '')
            })
        return cve_details
    except requests.exceptions.RequestException:
        return None

def process_package(package, session):
    print(f"Processing package: {package['name']}")
    package['version'] = normalize_version(package['version'])
    package['cve'] = []
    cve_ids = query_ubuntu_security_tracker(package['name'], session)
    if cve_ids:
        for cve_id in cve_ids:
            cve_details = query_cve_details(cve_id, session)
            if cve_details:
                for affected_product in cve_details['affectedProducts']:
                    if is_version_affected(package['version'], affected_product):
                        package['cve'].append(cve_details)
                        break
    return package

def get_installed_web_servers():
    web_servers = [
        'apache2',
        'nginx',
        'lighttpd',
        'caddy',
        'h2o',
        'varnish',
        'traefik',
        'haproxy',
        'squid',
        'tomcat',
        'jetty'
    ]
    installed_web_servers = []
    for server in web_servers:
        try:
            subprocess.check_output(["dpkg", "-s", server], stderr=subprocess.DEVNULL)
            installed_web_servers.append(server)
            print(f"Web server found: {server}")
        except subprocess.CalledProcessError:
            pass
    return installed_web_servers

def get_running_web_servers(installed_servers):
    running_servers = []
    try:
        output = subprocess.check_output(["systemctl", "list-units", "--type=service", "--state=running"])
        running_services = output.decode('utf-8').lower()
        for web_server in installed_servers:
            if web_server in running_services:
                running_servers.append(web_server)
                print(f"Running web server detected: {web_server}")
    except subprocess.CalledProcessError:
        pass
    return running_servers

def get_package_dependencies(package_name):
    try:
        output = subprocess.check_output(["apt-cache", "depends", package_name])
        dependencies = re.findall(r'^\s*Depends:\s*(\S+)', output.decode('utf-8'), re.MULTILINE)
        return [dep for dep in dependencies if not dep.startswith('<')]
    except subprocess.CalledProcessError:
        return []

def get_package_info(package_name):
    try:
        output = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}|${Version}|${Architecture}", package_name])
        name, version, architecture = output.decode('utf-8').strip().split('|')
        return {
            "name": name,
            "version": normalize_version(version),
            "architecture": architecture,
            "cve": []
        }
    except subprocess.CalledProcessError:
        return None

def generate_packages_json():
    installed_web_servers = get_installed_web_servers()
    
    if not installed_web_servers:
        print("No web servers found.")
        return

    running_web_servers = get_running_web_servers(installed_web_servers)
    packages = []

    for server in installed_web_servers:
        dependencies = get_package_dependencies(server)
        server_package = get_package_info(server)
        
        if server_package:
            server_package['running'] = (server in running_web_servers)
            server_package['dependencies'] = []
            
            for dep in dependencies:
                dep_info = get_package_info(dep)
                if dep_info:
                    server_package['dependencies'].append(dep_info)
            
            packages.append(server_package)

    print("Starting to process packages concurrently...")
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=10) as executor:
            all_packages = [pkg for package_group in packages for pkg in [package_group] + package_group['dependencies']]
            future_to_package = {executor.submit(process_package, package, session): package for package in all_packages}
            for future in as_completed(future_to_package):
                package = future_to_package[future]
                try:
                    processed_package = future.result()
                    for pkg_group in packages:
                        if pkg_group['name'] == processed_package['name']:
                            pkg_group.update(processed_package)
                        else:
                            for dep in pkg_group['dependencies']:
                                if dep['name'] == processed_package['name']:
                                    dep.update(processed_package)
                except Exception as exc:
                    pass

    sbom = {
        "sbomVersion": "1.0",
        "generatedDate": datetime.now().strftime("%Y-%m-%d"),
        "components": packages
    }

    upload_choice = input("Do you want to upload the SBOM to your dashboard? (Y/N): ").strip().upper()

    if upload_choice == 'Y':
        email = input("Enter your email: ").strip()
        api_key = input("Enter your API key: ").strip()

        sbom_name = f"WebserverSbom_{datetime.now().strftime('%Y-%m-%d')}"
        sbom['name'] = sbom_name

        payload = {
            "email": email,
            "apiKey": api_key,
            "sbom": sbom
        }

        url = "http://host.docker.internal:8000/api/auth/apiverify"
        print(f"Uploading SBOM '{sbom_name}' to the dashboard...")

        try:
            response = requests.post(url, json=payload)

            if response.status_code == 200:
                print("----->> API key verified successfully.")
                print("----->> SBOM uploaded successfully.")
                print(f"Response: {response.json()}")
            else:
                print(f"Failed to upload SBOM. Status Code: {response.status_code}")
                print(f"Response: {response.json()}")

        except requests.exceptions.RequestException as e:
            print(f"An error occurred while uploading the SBOM: {e}")

    else:
        # Save the SBOM locally with a unique filename
        filename = f"sbom_{uuid.uuid4()}.json"
        with open(filename, 'w') as json_file:
            json.dump(sbom, json_file, indent=4)
        print(f"SBOM saved locally as {filename} in the current directory.")

def main():
    generate_packages_json()

if __name__ == "__main__":
    main()
