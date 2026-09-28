import sys
import requests

def lookup_cve(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    try:
        response = requests.get(url, timeout=15)

        if response.status_code != 200:
            print(f"Error: HTTP {response.status_code}")
            return

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            print(f"No information found for {cve_id}")
            return

        cve = vulnerabilities[0]["cve"]

        print("=" * 60)
        print(f"CVE LOOKUP: {cve_id}")
        print("=" * 60)

        descriptions = cve.get("descriptions", [])

        for description in descriptions:
            if description.get("lang") == "en":
                print("\nDescription:")
                print(description.get("value"))
                break

        metrics = cve.get("metrics", {})

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            print("\nCVSS Version: 3.1")
            print(f"Base Score: {cvss.get('baseScore')}")
            print(f"Severity: {cvss.get('baseSeverity')}")

        print("\nSource: NIST National Vulnerability Database")
        print("=" * 60)

    except requests.RequestException as error:
        print(f"Network error: {error}")
    except Exception as error:
        print(f"Error: {error}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 cve_lookup.py CVE-YYYY-NNNN")
        return

    cve_id = sys.argv[1].upper()
    lookup_cve(cve_id)


if __name__ == "__main__":
    main()
