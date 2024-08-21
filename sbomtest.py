import requests
import json

def main():
    email = input("Enter your email: ")
    api_key = input("Enter your API key: ")

    sbom = {
        "name": "Sample SBOM",
        "format": "cyclonedx",
        "language": "python",
        "details": "This is a sample SBOM for testing."
    }
    url = "http://localhost:8000/api/auth/apiverify"

    payload = {
        "email": email,
        "apiKey": api_key,
        "sbom": sbom
    }

    response = requests.post(url, json=payload)

    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {response.json()}")

if __name__ == "__main__":
    main()
