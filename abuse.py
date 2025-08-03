import time
import re
import sys
import numpy as np
from tabulate import tabulate
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
from bs4 import BeautifulSoup
from seleniumbase import Driver
from pymongo import MongoClient
import certifi
from datetime import datetime, timedelta
import folium
import os

####################################
# MongoDB Atlas Integration Functions
####################################

def show_ip_on_map(ip_address, latitude, longitude, folder='templates'):
    # Create a map centered on the IP's location
    my_map = folium.Map(location=[latitude, longitude], zoom_start=10)
    folium.Marker([latitude, longitude], tooltip=f"IP: {ip_address}").add_to(my_map)

    # Save to HTML file inside the templates folder (so Flask can render it)
    map_filename = f"{ip_address.replace('.', '_')}_map.html"
    map_filepath = os.path.join(folder, map_filename)
    my_map.save(map_filepath)

    # Return the path to the HTML file (relative to templates folder)
    return map_filename

def init_mongo():
    connection_string = (
    "add string"
    "ip_reputation_db?retryWrites=true&w=majority&authSource=admin&connectTimeoutMS=120000&socketTimeoutMS=120000"
)
   
    # Removed ssl_version because PyMongo 4 does not support it.
    client = MongoClient(
    connection_string,
    tls=True,
    tlsAllowInvalidCertificates=True
)

    db = client['ip_reputation_db']
    collection = db['ip_reputation']
    return collection

if __name__ == "__main__":
    try:
        collection = init_mongo()
        server_info = collection.database.client.server_info()
        print("Connected to MongoDB Atlas. Server Info:")
        print(server_info)
    except Exception as e:
        print("Error connecting to MongoDB Atlas:", e)
def create_ttl_index(collection):
    """
    Creates a TTL index on the 'created_at' field.
    Documents older than 7 days (604800 seconds) will be automatically deleted.
    """
    index_name = collection.create_index("created_at", expireAfterSeconds=604800)
    print("TTL index created:", index_name)


####################################
# User Input
####################################

def get_user_input():
    """
    Returns the IP address from command-line arguments if provided,
    else prompts the user for input.
    """
    if len(sys.argv) > 1:
        ip = sys.argv[1].strip()
        print(f"Using IP from command line: {ip}")
    else:
        try:
            ip = input("Enter the IP address to check: ").strip()
            if not ip:
                raise ValueError("Empty input provided!")
        except (EOFError, ValueError):
            print("No valid input provided. Using default IP '8.8.8.8'")
            ip = "8.8.8.8"
    return ip


####################################
# Scraping Functions
####################################

def extract_extended_fields(soup):
    """
    Attempt to extract the extended fields either from a table or fallback to regex on the text.
    Returns a dictionary with default values for missing fields.
    """
    fields = {
        "ISP": "Not Available",
        "Usage Type": "Not Available",
        "ASN": "Not Available",
        "Domain Name": "Not Available",
        "Country": "Not Available",
        "City": "Not Available",
        "Hostnames": "Not Available"
    }
    
    # Try table extraction if the table exists.
    table = soup.find("table", class_="table table-bordered")
    if table:
        rows = table.find_all("tr")
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 2:
                label = cols[0].get_text(strip=True)
                value = cols[1].get_text(strip=True)
                if label in fields:
                    fields[label] = value
    else:
        # Fallback: use regex on the full text content.
        text = soup.get_text(separator="\n")
        # These regex patterns look for the label followed by a newline and capture the next line.
        patterns = {
            "ISP": r"ISP\s*\n\s*(.+?)\s*\n",
            "Usage Type": r"Usage Type\s*\n\s*(.+?)\s*\n",
            "ASN": r"ASN\s*\n\s*(.+?)\s*\n",
            "Domain Name": r"Domain Name\s*\n\s*(.+?)\s*\n",
            "Country": r"Country\s*\n\s*(.+?)\s*\n",
            "City": r"City\s*\n\s*(.+?)\s*\n"
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
            if match:
                value = match.group(1).strip()
                if value:
                    fields[key] = value
    return fields


def scrape_abuseipdb_data(ip):
    """
    Scrapes AbuseIPDB for details about the given IP address.
    Extracts general report information (reported times and confidence) 
    as well as extended details like ISP, Usage Type, ASN, Domain Name, Country, and City.
    """
    # Initialize the driver (using undetected-chromedriver in visible mode)
    driver = Driver(uc=True, headless=False)
    abuse_url = f"https://www.abuseipdb.com/check/{ip}"
    print(f"\n[AbuseIPDB] Checking details for IP: {ip}")
    print(f"[AbuseIPDB] URL: {abuse_url}\n")
    
    driver.uc_open_with_reconnect(abuse_url, 4)
    try:
        driver.uc_gui_click_captcha()
        print("[AbuseIPDB] CAPTCHA clicked successfully (if present).")
    except Exception as e:
        print("[AbuseIPDB] CAPTCHA handling error (if not triggered, this is usually fine):", e)
    
    # Wait for the main report element to load
    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, "#report-wrapper > div:nth-child(1) > div:nth-child(1) > div")
            )
        )
    except Exception as e:
        print("[AbuseIPDB] Error waiting for report element:", e)
    
    # Get page source and parse it
    page_source = driver.get_page_source()
    soup = BeautifulSoup(page_source, 'html.parser')
    
    # --- Extract General Report Information ---
    report_element = soup.select_one("#report-wrapper > div:nth-child(1) > div:nth-child(1) > div")
    if report_element:
        report_text = report_element.get_text(separator="\n").strip()
        print("\n[AbuseIPDB] Report Details:")
        print(report_text)
        
        # Extract reported times (e.g., "2,630")
        match_reports = re.search(r"This IP was reported\s+([\d,]+)\s+times", report_text)
        malicious_activity = int(match_reports.group(1).replace(',', '')) if match_reports else 0
        
        # Extract Confidence of Abuse (e.g., "100")
        match_confidence = re.search(
            r"Confidence of Abuse\s*is\s*([\d]+)%", report_text, re.IGNORECASE | re.DOTALL
        )
        source1_score = int(match_confidence.group(1)) if match_confidence else 0
    else:
        print("[AbuseIPDB] Could not find the report element.")
        malicious_activity = 0
        source1_score = 0
    
    # --- Extract Extended Fields (ISP, Usage Type, ASN, Domain Name, Country, City, etc.) ---
    extended_fields = extract_extended_fields(soup)
    country = extended_fields.get("Country", "Not Available")
    city = extended_fields.get("City", "Not Available")
    isp = extended_fields.get("ISP", "Not Available")
    asn = extended_fields.get("ASN", "Not Available")
    usage_type = extended_fields.get("Usage Type", "Not Available")
    domain = extended_fields.get("Domain Name", "Not Available")
    hostnames = extended_fields.get("Hostnames", "Not Available")
    
    # Display the final result in the terminal
    print("\n✅ Final Result Should Look Like:\n--------------------------------")
    print("IP Address:", ip)
    print("Country:", country)
    print("City:", city)
    print("ISP:", isp)
    print("ASN:", asn)
    print("Usage Type:", usage_type)
    print("Domain:", domain)
    print("Hostnames:", hostnames)
    print("Confidence of Abuse (%):", source1_score)
    print("Reported Times:", malicious_activity)
    
    # Prepare the data dictionary for further processing or storage
    data = {
        'IP Address': ip,
        'Confidence of Abuse (%)': source1_score,
        'Reported Times': malicious_activity,
        'Country': country,
        'City': city,
        'ISP': isp,
        'ASN': asn,
        'Usage Type': usage_type,
        'Domain': domain,
        'Hostnames': hostnames
    }
    
    # Quit the driver to close the browser session
    driver.quit()
    return data
import requests

def scrape_virustotal_data(ip):
    api_key = "3711aee80ce1893c54bc188766af21e61ba843d5e0cf884ac3547f596cf15e2f"
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    print(f"\n[VirusTotal] Checking details for IP: {ip}")
    print(f"[VirusTotal] URL: {vt_url}\n")

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(vt_url, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses (e.g., 404 or 401)
        vt_data = response.json()  # Parse JSON response
        
        # Extract relevant data (e.g., "Security Vendors Flagged")
        flagged_vendors = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        
        print("\n[VirusTotal] Raw Report Details:")
        print(vt_data)  # Optionally print the raw JSON response

        data = {
            'Security Vendors Flagged': flagged_vendors
        }
    except requests.exceptions.RequestException as e:
        print("[VirusTotal] Error fetching data:", e)
        data = {
            'Security Vendors Flagged': 0
        }

    return data

def scrape_shodan_data(ip):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    import re

    driver = Driver(uc=True, headless=True)
    shodan_url = f"https://www.shodan.io/host/{ip}"
    print(f"\n[Shodan] Checking details for IP: {ip}")
    print(f"[Shodan] URL: {shodan_url}\n")

    driver.uc_open_with_reconnect(shodan_url, 4)

    # -------------------- Extract Port Info Only --------------------
    try:
        WebDriverWait(driver, 12).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "#host"))
        )
        shodan_text = driver.execute_script("""
            let el = document.querySelector('#host > div:nth-child(2) > div:nth-child(2)');
            return el ? el.textContent : "";
        """)
        print("\n[Shodan] Raw Port Info Text:")
        print(shodan_text)
    except Exception as e:
        print("[Shodan] Error scraping port data:", e)
        shodan_text = ""

    port_tuples = re.findall(r'(\d+)\s*/\s*(tcp|udp)', shodan_text, flags=re.IGNORECASE)
    open_ports = sorted(set(port for port, proto in port_tuples))
    open_ports_count = len(open_ports)

    print("\n[Shodan] Open Ports:", open_ports)
    print("[Shodan] Open Ports Count:", open_ports_count)

    driver.quit()

    return {
        "Open Ports": open_ports,
        "Open Ports Count": open_ports_count
    }
####################################
# Calculation & Database Storage Functions
####################################

def normalize_confidence(val):
    return val

def normalize_reported_times(rt, threshold=1000):
    normalized = (rt / threshold) * 100
    return min(normalized, 100)

def normalize_security_vendors(sv, total_vendors=94):
    normalized = (sv / total_vendors) * 100
    return min(normalized, 100)

def normalize_open_ports(open_ports, threshold=10):
    """
    Normalize the number of open ports to a 0–100 scale.
    The more open ports, the more risky it is (up to the threshold).
    """
    if not isinstance(open_ports, list):
        open_ports = []
    count = len(open_ports)
    normalized = min((count / threshold) * 100, 100)
    return normalized

def calculate_weighted_score(ip_data, weights):
    normalized_metrics = {
        'Confidence of Abuse (%)': normalize_confidence(ip_data.get('Confidence of Abuse (%)', 0)),
        'Reported Times': normalize_reported_times(ip_data.get('Reported Times', 0)),
        'Security Vendors Flagged': normalize_security_vendors(ip_data.get('Security Vendors Flagged', 0)),
        'Open Ports': normalize_open_ports(ip_data.get('Open Ports', []))
    }
    total_score = sum(weights[k] * normalized_metrics[k] for k in weights)
    return total_score / sum(weights.values())

def final_reputation_score_without_ml(ip_data, weights):
    return calculate_weighted_score(ip_data, weights)

from datetime import datetime, timedelta

def fetch_or_scrape_ip_data(ip, collection):
    """
    Checks if data for the given IP exists in the database (and is less than 7 days old).
    If found, returns the cached document.
    Otherwise, scrapes new data, calculates the final reputation score and verdict,
    stores both the raw metrics and final results in the database, and returns the new document.
    """
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    record = collection.find_one({"IP Address": ip, "created_at": {"$gte": seven_days_ago}})
    
    if record:
        print("Using cached data for IP:", ip)
        return record
    else:
        print("No fresh data available. Scraping new data...")

        # Scrape data from all sources
        abuse_data = scrape_abuseipdb_data(ip)
        vt_data = scrape_virustotal_data(ip)
        shodan_data = scrape_shodan_data(ip)

        # Combine the data
        combined_data = {**abuse_data, **vt_data, **shodan_data}

        # Compute final reputation score
        weights = {
            'Confidence of Abuse (%)': 0.40,
            'Reported Times': 0.30,
            'Security Vendors Flagged': 0.20,
            'Open Ports': 0.10,
        }
        final_score = final_reputation_score_without_ml(combined_data, weights)

        # Determine verdict
        if final_score >= 61:
            verdict = "Malicious"
        elif 31 <= final_score < 61:
            verdict = "Moderate"
        else:
            verdict = "Clean"

        # Add final results
        combined_data["Final Reputation Score"] = round(final_score, 1)
        combined_data["Reputation Verdict"] = verdict
        combined_data["IP Address"] = ip  # Ensure IP is also stored
        combined_data["created_at"] = datetime.utcnow()

        # ✅ DEBUG: Print full data before storing
        print("\n✅ Final Combined Data Before Mongo Insert:\n")
        for k, v in combined_data.items():
            print(f"{k}: {v}")

        # Store in DB
        result = collection.insert_one(combined_data)
        print("Inserted new data for IP", ip, "with ID:", result.inserted_id)
        
        return combined_data
####################################
# Display Functions for Terminal Output
####################################

def display_data_table(title, data_dict):
    table_data = [[key, value] for key, value in data_dict.items()]
    print(f"\n{title}:")
    print(tabulate(table_data, headers=["Metric", "Value"], tablefmt="grid"))


####################################
# Main Function
####################################
def main():
    ip = get_user_input()

    print("\n[✔] Fetching data from AbuseIPDB...")
    abuse_data = scrape_abuseipdb_data(ip)

    print("\n[✔] Fetching data from VirusTotal...")
    vt_data = scrape_virustotal_data(ip)

    print("\n[✔] Fetching data from Shodan...")
    shodan_data = scrape_shodan_data(ip)

    # Merge all the dictionaries
    full_data = {
        "IP Address": ip,
        "Country": shodan_data.get("Country", "Not Available"),
        "City": shodan_data.get("City", "Not Available"),
        "ISP": shodan_data.get("ISP", "Not Available"),
        "ASN": shodan_data.get("ASN", "Not Available"),
        "Usage Type": shodan_data.get("Usage Type", "Not Available"),
        "Domain": shodan_data.get("Domain", "Not Available"),
        "Hostnames": shodan_data.get("Hostnames", "Not Available"),
        "Confidence of Abuse (%)": abuse_data.get("Confidence of Abuse (%)", "Not Available"),
        "Reported Times": abuse_data.get("Reported Times", "Not Available"),
    }

    print("\n✅ Final Result Should Look Like:")
    print("-" * 32)
    for k, v in full_data.items():
        print(f"{k}: {v}")

    # Optionally store in MongoDB
    full_data['created_at'] = datetime.utcnow()
    collection = init_mongo()
    collection.insert_one(full_data)
    print("\n✅ Data stored in MongoDB Atlas successfully.")
    
if __name__ == "__main__":
    main()



