Features
 - View CVE List: See a list of CVEs with their IDs, source identifiers, published dates, last modified dates and statuses.
 - View CVE Details: Fetch detailed information about specific CVEs by their CVE ID.
 - Filter CVEs: Filter CVEs by cve_id, published year, and last N days.

Techstack:
 - Python
 - MySQL
 - Flask
 - HTML
 - CSS
 - JavaScript


Setup:

1. Clone repository:
   git clone https://github.com/Moksha-Kandli-Srinivasalu/Securin.git
   cd Securin
   
2. Install required Python dependencies:
   pip3 install -r requirements.txt
   
3. Set up your MySQL database:
   . Update your MySQL database credentials in the configuration
   . Run the script to create the necessary tables and insert data
   
4. Start the Flask app:
   python3 app.py
   
5. Visit http://127.0.0.1:5000/cves/list in your browser to view the app.


API Endpoints:
1. GET /cves/list
   Fetches a list of all the CVEs from the database

2. GET /cves/{cve_id}
   Fetches detailed data for a specific CVE using its cve_id

Output Screenshots:

/cves/list
<img width="1440" alt=":cves:list" src="https://github.com/user-attachments/assets/5ca1a613-2bd6-4cb7-a10e-b74de6cb93d2" />

/cves/CVE-2016-2515

<img width="1440" alt=":cves:CVE-2016-2515" src="https://github.com/user-attachments/assets/1420ba49-5e26-43c9-8208-d4ef625ac881" />

/cves/list
Filtered by Published Year
<img width="1440" alt="Published Year Filter" src="https://github.com/user-attachments/assets/5f46a03a-463f-4761-b8ec-2679d80dbfcb" />

/cves/list
Filtered by cve_id and published year

<img width="1440" alt="cve_id and Published Year Filer" src="https://github.com/user-attachments/assets/6462875d-4cc8-48d8-b9a1-3976a218aaaa" />




