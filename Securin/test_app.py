import pytest
from app import app, get_db_connection, setup_database
import mysql.connector

@pytest.fixture(scope='module')
def test_client():
    # Setup for Flask test client
    app.config['TESTING'] = True
    app.config['DATABASE'] = 'test_db'
    with app.test_client() as client:
        yield client

@pytest.fixture(scope='module')
def setup_test_db():
    # Setup test database with mock data
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create the test_db and table cves
    cursor.execute("CREATE DATABASE IF NOT EXISTS test_db")
    cursor.execute("USE test_db")

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

    # Insert the mock data for testing
    cursor.execute("""
    INSERT INTO cves (cve_id, source_identifier, published_date, last_modified_date, status)
    VALUES 
    ("CVE-1999-0113", "source1", "2021-01-01 12:00:00", "2021-01-02 12:00:00", "Resolved"),
    ("CVE-2022-67890", "source2", "2022-05-15 08:30:00", "2022-05-16 08:30:00", "Open"),
    ("CVE-2023-98765", "source3", "2023-09-10 15:45:00", "2023-09-11 15:45:00", "In Progress")
    """)

    conn.commit()
    cursor.close()
    conn.close()

    yield

    # Drop the test database after tests
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DROP DATABASE IF EXISTS test_db")
    conn.commit()
    cursor.close()
    conn.close()

def test_index(test_client):
    # Test if the index page is working
    response = test_client.get('/')
    assert response.status_code == 200
    assert b"CVE Vulnerabilities" in response.data 

def test_cve_list(test_client, setup_test_db):
    # Test if the list cves page works
    response = test_client.get('/cves/list')
    assert response.status_code == 200
    assert b"CVE ID" in response.data  
    assert b"Published Date" in response.data  
    assert b"CVE-" in response.data

def test_get_cve_details(test_client, setup_test_db):
    # Test fetching specific cve details
    cve_id = "CVE-1999-0113"
    response = test_client.get(f"/cves/{cve_id}")
    assert response.status_code == 200 
    assert b"CVE-1999-0113" in response.data

    # Test with a cve that does not exist
    cve_id_non_existent = "CVE-9999-00000"
    response = test_client.get(f"/cves/{cve_id_non_existent}")
    assert response.status_code == 404

def test_database_connection():
    # Test if the database connects
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()
    assert ('cves',) in tables
    cursor.close()
    conn.close()

@pytest.mark.parametrize('params, expected_status', [
    ({"cve_id": "CVE-1999-0113"}, 200),  # Valid CVE ID
    ({"cve_id": "CVE-9999-00000"}, 200),  # CVE ID that does not exist
    ({"year": 2021}, 200),  # Filter by year
    ({"days": 7}, 200),  # Filter by last modified within 7 days
])
def test_cve_filters(test_client, setup_test_db, params, expected_status):
    # Test filter parameters
    response = test_client.get('/cves/list', query_string=params)
    assert response.status_code == expected_status

def test_invalid_filter(test_client, setup_test_db):
    # Test invalid filter
    response = test_client.get('/cves/list', query_string={"invalid_param": "test"})
    
    assert response.status_code == 200
    if 'application/json' in response.content_type:
        data = response.get_json()
        assert data.get("total_records") == None