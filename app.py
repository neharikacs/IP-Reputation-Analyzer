from flask import Flask, render_template, request
from abuse import init_mongo, fetch_or_scrape_ip_data
import requests
import folium
from bson.regex import Regex
from pymongo import DESCENDING

app = Flask(__name__)
collection = init_mongo()

def get_geolocation(ip):
    """
    Gets geolocation data from ip-api.com and includes additional fields like org and timezone.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            return {
                "ip": ip,
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "city": data.get("city"),
                "region": data.get("regionName"),
                "country": data.get("country"),
                "org": data.get("org", "Not Available"),
                "timezone": data.get("timezone", "Not Available"),
                "isp": data.get("isp", "Not Available")
            }
        else:
            return {
                "ip": ip,
                "lat": None,
                "lon": None,
                "city": "Unknown",
                "region": "",
                "country": "",
                "org": "Not Available",
                "timezone": "Not Available",
                "isp": "Not Available"
            }
    except Exception as e:
        print("Geo Error:", e)
        return {
            "ip": ip,
            "lat": None,
            "lon": None,
            "city": "Unknown",
            "region": "",
            "country": "",
            "org": "Not Available",
            "timezone": "Not Available",
            "isp": "Not Available"
        }

def show_ip_on_map(geo_data):
    """
    Creates and saves a folium map based on the given geo_data.
    """
    lat = geo_data['lat']
    lon = geo_data['lon']
    city = geo_data['city']
    country = geo_data['country']
    ip = geo_data['ip']

    if lat is None or lon is None:
        print("Invalid coordinates for map")
        return

    map_ = folium.Map(location=[lat, lon], zoom_start=10)
    popup_text = f"{ip}<br>{city}, {country}"
    folium.Marker([lat, lon], popup=popup_text).add_to(map_)

    map_.save("static/ip_location_map.html")
    print("Map saved as static/ip_location_map.html")

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        ip = request.form['ip'].strip()

        # Step 1: Get IP data from MongoDB (or scrape it if not recent)
        data = fetch_or_scrape_ip_data(ip, collection)
        print("Step 1 - Data from Mongo/Scrape:", data)

        # Step 2: Get geolocation using ip-api (with extended fields)
        geo_data = get_geolocation(ip)
        print("Step 2 - Geolocation Data:", geo_data)

        # Step 3: Show map with geo data
        show_ip_on_map(geo_data)

        # Step 4: Combine both data sources. Use consistent key names.
        result = {
            "IP Address": ip,
            "Country": data.get("Country") or geo_data.get("country") or "Not Available",
            "City": data.get("City") or geo_data.get("city") or "Not Available",
            "ISP": data.get("ISP") or geo_data.get("isp") or "Not Available",
            "Hostnames": data.get("Hostnames") or "Not Available",
            "ASN": data.get("ASN") or "Not Available",
            "Organization": data.get("Organization") or geo_data.get("org") or "Not Available",
            "Timezone": data.get("Timezone") or geo_data.get("timezone") or "Not Available",
            "Operating System": data.get("Operating System") or "Not Available",
            "Confidence of Abuse (%)": data.get("Confidence of Abuse (%)") or "N/A",
            "Reported Times": data.get("Reported Times") or "N/A",
            "Security Vendors Flagged": data.get("Security Vendors Flagged") or "N/A",
            "Open Ports": data.get("Open Ports") or [],
            "Final Reputation Score": data.get("Final Reputation Score") or "N/A",
            "Reputation Verdict": data.get("Reputation Verdict") or "N/A",
        }
        print("Step 4 - Final Combined Result:", result)

        return render_template('result.html', result=result, map_path='static/ip_location_map.html')

    # GET request – show the input form.
    return render_template('index.html')

@app.route('/history')
def history():
    # Use the correct key for IP Address and created_at for sorting.
    ip_query = request.args.get('ip', '').strip()
    verdict_query = request.args.get('verdict', '').strip()

    query_filter = {}
    if ip_query:
        # Match the "IP Address" field (case-insensitive)
        query_filter["IP Address"] = Regex(ip_query, 'i')
    if verdict_query:
        query_filter["Reputation Verdict"] = verdict_query  # exact match

    # Assuming the data is stored with a "created_at" field.
    results = list(collection.find(query_filter).sort('created_at', DESCENDING))
    return render_template('history.html', results=results, ip_query=ip_query, verdict_query=verdict_query)

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True)