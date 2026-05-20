import requests
import pandas as pd
from datetime import datetime, timedelta
import time
import numpy as np

def fetch_cve_chunk(start_date, end_date):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate":   end_date.strftime("%Y-%m-%dT23:59:59.000"),
        "resultsPerPage": 100
    }
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(
            url, params=params,
            headers=headers, timeout=30
        )
        if response.status_code != 200:
            print(f"Status: {response.status_code}")
            return []
        if not response.text.strip():
            print("Empty response")
            return []
        data = response.json()
    except requests.exceptions.Timeout:
        print("Timeout — skipping chunk")
        return []
    except Exception as e:
        print(f"Error: {e}")
        return []

    records = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        score    = None
        severity = "UNKNOWN"
        try:
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                score    = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV2" in metrics:
                score    = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                severity = metrics["cvssMetricV2"][0]["baseSeverity"]
        except:
            pass
        desc = ""
        for d in cve.get("descriptions", []):
            if d["lang"] == "en":
                desc = d["value"]
                break
        records.append({
            "CVE_ID":      cve["id"],
            "Published":   cve["published"][:10],
            "Description": desc,
            "Score":       score,
            "Severity":    severity,
            "Source":      "NVD"
        })
    return records


def fetch_cve_data(days_back=30):
    end_date    = datetime.now()
    start_date  = end_date - timedelta(days=days_back)
    all_records = []
    chunk_size  = 30
    current_end = end_date

    while current_end > start_date:
        current_start = max(
            current_end - timedelta(days=chunk_size),
            start_date
        )
        print(f"Fetching: {current_start.date()} to {current_end.date()}")
        for attempt in range(3):
            chunk = fetch_cve_chunk(current_start, current_end)
            if chunk:
                all_records.extend(chunk)
                break
            else:
                print(f"Attempt {attempt+1} failed — retrying in 10s")
                time.sleep(10)
        current_end = current_start - timedelta(days=1)
        time.sleep(8)

    if not all_records:
        print("API unavailable — loading sample data")
        return get_sample_data(days_back)

    df = pd.DataFrame(all_records)
    df['Published'] = pd.to_datetime(df['Published'])
    df = df.drop_duplicates(subset='CVE_ID')
    df = df.sort_values('Published', ascending=False)
    print(f"Total CVEs fetched: {len(df)}")
    return df


def get_sample_data(days_back=30):
    np.random.seed(42)
    n = 200

    severities = np.random.choice(
        ['CRITICAL','HIGH','MEDIUM','LOW'],
        size=n,
        p=[0.15, 0.35, 0.35, 0.15]
    )

    score_map = {
        'CRITICAL': (9.0, 10.0),
        'HIGH':     (7.0, 8.9),
        'MEDIUM':   (4.0, 6.9),
        'LOW':      (0.1, 3.9)
    }

    scores = [
        round(np.random.uniform(*score_map[s]), 1)
        for s in severities
    ]

    descriptions = [
        "Buffer overflow in OpenSSL allows remote code execution",
        "SQL injection vulnerability in login form",
        "Cross-site scripting in web application",
        "Privilege escalation via misconfigured sudo",
        "IoT firmware exposes default credentials",
        "Ransomware exploits unpatched SMB vulnerability",
        "Cloud misconfiguration exposes S3 bucket",
        "Phishing campaign targets corporate credentials",
        "Memory corruption in kernel driver",
        "Denial of service in DNS resolver"
    ]

    # Spread dates properly across selected date range
    today     = datetime.now()
    date_list = [
        today - timedelta(days=int(x))
        for x in np.random.randint(0, days_back, size=n)
    ]

    df = pd.DataFrame({
        'CVE_ID':      [f'CVE-2024-{str(i).zfill(5)}' for i in range(n)],
        'Published':   date_list,
        'Description': np.random.choice(descriptions, size=n),
        'Score':       scores,
        'Severity':    severities,
        'Source':      'Sample Data'
    })

    df['Published'] = pd.to_datetime(df['Published'])
    df = df.sort_values('Published', ascending=False)
    print(f"Sample data loaded: {len(df)} records")
    return df