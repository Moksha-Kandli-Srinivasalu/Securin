from flask import Flask, jsonify, render_template, request
import requests
import mysql.connector
from threading import Thread
import json
import time
from datetime import datetime
import schedule

app = Flask(__name__)

# MySQL Configuration
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = ""
DB_NAME = "cve_db"

# MySQL connection
def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )

# To create the database and table
def setup_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create the database when it does not exist
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    cursor.execute(f"USE {DB_NAME}")

    # FOR FIRST TIME
    # If the table already exists, you want to drop it to avoid errors/mismatch in columns
    #cursor.execute("DROP TABLE IF EXISTS cves")

    # Create Table if it does not exists
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id INT AUTO_INCREMENT PRIMARY KEY,
        cve_id VARCHAR(50) NOT NULL UNIQUE,
        source_identifier VARCHAR(255) NOT NULL,
        published_date DATETIME,
        last_modified_date DATETIME,
        status VARCHAR(50)
    )
    """)

    # Commit the changes to the DB
    conn.commit()
    cursor.close()
    conn.close()

# Function to fetch and store CVE data using the API
def fetch_and_store_cves():
    # API URL endpoint to fetch the cve list
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page = 2000
    start_index = 0
    headers = {"User-Agent": "MyCVEFetcher/1.0 (mokshakandli08@gmail.com)"}

    conn = get_db_connection()
    cursor = conn.cursor()

    while True:
        params = {"startIndex": start_index, "resultsPerPage": results_per_page}

        try:
            response = requests.get(url, params=params, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVE data: {e}")
            break
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON response: {e}")
            print(f"Response content: {response.content[:500]}")
            break
        
        # If data is present in vulnerabilities, loop through it to check for duplicates and insert/update the records
        if "vulnerabilities" in data:
            for item in data["vulnerabilities"]:
                cve = item["cve"]
                cve_id = cve["id"]
                source_identifier = cve["sourceIdentifier"]
                published_date = cve["published"]
                last_modified_date = cve["lastModified"]
                status = cve["vulnStatus"]

                conn.ping(reconnect=True)  # Ensuring if the connection is still alive
                
                # Check if the cve_id already exists
                cursor.execute("""
                    SELECT id, last_modified_date
                    FROM cves 
                    WHERE cve_id = %s 
                """, (cve_id,))

                existing_record = cursor.fetchone()

                # If an existing record is present with same cve_id, the record is updated with the latest data
                if existing_record:
                    existing_last_modified_date = existing_record[1]

                    # Remove 'Z' from the end of the timestamp (if present)
                    last_modified_date = last_modified_date.rstrip('Z')

                    # Converting both the dates to datetime objects for comparison
                    # Existing_last_modified_date will already be stored as datetime in the DB, so convert only the new record that is fetched
                    last_modified_date_dt = datetime.strptime(last_modified_date, "%Y-%m-%dT%H:%M:%S.%f")
                    
                    # Check if the last_modified_date is greater
                    if last_modified_date_dt > existing_last_modified_date:
                        cursor.execute("""
                            UPDATE cves
                            SET last_modified_date = %s, status = %s
                            WHERE cve_id = %s
                        """, (last_modified_date_dt, status, cve_id))
                        
                        time.sleep(1)
                        print(f"Updated CVE {cve_id} with new data.")
                    else:
                        # If the record that already exists is more recent, the record will not be updated as it already has the latest information
                        print(f"CVE {cve_id} exists, no update needed.")
                else:
                    # If the cve_id does not exists, a new record is inserted
                    cursor.execute("""
                        INSERT INTO cves (cve_id, source_identifier, published_date, last_modified_date, status)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (cve_id, source_identifier, published_date, last_modified_date, status))
                    #print(f"Inserted new CVE {cve_id}.")
        
        # Commit all the changes to the DB
        conn.commit()
        start_index += results_per_page
        
        total_results = data.get("totalResults", 0)
        if start_index >= total_results:
            break

        time.sleep(6)  # To prevent API rate limit errors

    print("Done updating all records.")
    cursor.close()
    conn.close()

# Function to run fetching data in a background thread
def run_fetch_task():
    fetch_and_store_cves()

# Function to schedule the fetch task every hour
def schedule_fetch_task():
    schedule.every(1).hours.do(fetch_and_store_cves)  # Schedule task every hour

    while True:
        schedule.run_pending()  # Run any pending tasks
        time.sleep(60)  # Sleep for a minute before checking again

# Flask Route to Fetch CVE Data and list them
@app.route('/cves/list', methods=['GET'])
def get_cves():
    # Get filter parameters from the request
    cve_id = request.args.get('cve_id', type=str)
    year = request.args.get('year', type=int)
    days = request.args.get('days', type=int)

    results_per_page = request.args.get('results_per_page', default=10, type=int)
    page = request.args.get('page', default=1, type=int)
    offset = (page - 1) * results_per_page

    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get all the records
    query = "SELECT * FROM cves"
    # Get the total records count
    count_query = "SELECT COUNT(*) as count FROM cves"
    params = []
    count_params = []

    # If cve_id filter is present
    if cve_id:
        query += " WHERE cve_id LIKE %s"
        count_query += " WHERE cve_id LIKE %s"
        params.append(f"%{cve_id}%")
        count_params.append(f"%{cve_id}%")

    # If year filter is present
    if year:
        query += " WHERE YEAR(published_date) = %s"
        count_query += " WHERE YEAR(published_date) = %s"
        params.append(year)
        count_params.append(year)

    # If days filter is present
    if days:
        query += " WHERE published_date >= NOW() - INTERVAL %s DAY"
        count_query += " WHERE published_date >= NOW() - INTERVAL %s DAY"
        params.append(days)
        count_params.append(days)

    # Pagination
    query += " LIMIT %s OFFSET %s"
    params.extend([results_per_page, offset])

    # Execute the queries
    cursor.execute(query, params)
    cves = cursor.fetchall()

    cursor.execute(count_query, count_params)
    total_records = cursor.fetchone()['count']

    total_pages = (total_records // results_per_page) + (1 if total_records % results_per_page else 0)
    start_record = (page - 1) * results_per_page + 1
    end_record = min(start_record + results_per_page - 1, total_records)

    cursor.close()
    conn.close()

    return render_template(
        'cves.html',
        cves=cves,
        results_per_page=results_per_page,
        page=page,
        total_pages=total_pages,
        total_records=total_records,
        start_record=start_record,
        end_record=end_record,
        current_page=page 
    )

# Flask route to fetch specific cve_id details
@app.route("/cves/<cve_id>")
def get_cve_details(cve_id):
    # API URL endpoint to fetch the specific cve_id details
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(api_url)
    
    if response.status_code != 200:
        return jsonify({"error": "CVE not found"}), 404
    
    data = response.json()
    if "vulnerabilities" not in data or len(data["vulnerabilities"]) == 0:
        return jsonify({"error": "No CVE details available"}), 404

    cve_data = data["vulnerabilities"][0]["cve"]

    # Get all the required data
    details = {
        "id": cve_data["id"],
        "description": next((d["value"] for d in cve_data["descriptions"] if d["lang"] == "en"), "No description available"),
        "severity": cve_data.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseSeverity", "Unknown"),
        "score": cve_data.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore", "Unknown"),
        "vectorString": cve_data.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("vectorString", "N/A"),
        "impact": cve_data.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}),
        "exploitabilityScore": cve_data.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("exploitabilityScore", "N/A"),
        "impactScore": cve_data.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("impactScore", "N/A"),
        "cpe": [
            {
                "criteria": cpe["criteria"],
                "matchCriteriaId": cpe["matchCriteriaId"],
                "vulnerable": cpe["vulnerable"]
            }
            for conf in cve_data.get("configurations", []) for node in conf["nodes"] for cpe in node["cpeMatch"]
        ]
    }
    
    return render_template("cve_details.html", details=details)

# Flask route to index page
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == "__main__":
    setup_database()
    # Start the fetch task in the background using thread
    thread = Thread(target=run_fetch_task, daemon=True)
    thread.start()
    
    # Schedule the periodic task to run every hour
    schedule_thread = Thread(target=schedule_fetch_task, daemon=True)
    schedule_thread.start()

    app.run(debug=True, use_reloader=False)