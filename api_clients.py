import requests
import os
import sys

from dotenv import load_dotenv
load_dotenv()



# this function is used to print info. regarding the given specific ip address
def info_ipaddress(ip_address, all_info):

    try:

        api = "http://ip-api.com/json/"
        response = requests.get(api + str(ip_address), timeout=10)
        response.raise_for_status()

    except requests.RequestException:
        all_info.append(f"Error: Can't connect to the api for {ip_address}")
        return

    else:
        data = response.json()

    if data["status"] == "success":
        all_info.append(f"""IP: {ip_address}
Location: {data['city']},{data['regionName']},{data['country']},{data['zip']}
Internet service Provider: {data['isp']}
Autonomous System Number: {(data['as'].split())[0]} """)

    else:
        all_info.append(f"Error: {ip_address}: {data['message']}")




# this function tells the abuse score of an ip address and whether it's safe, malicious
# or suspicious, and also gives its total number of reports and date of last report.
# `days` is sys.argv[2] for single-IP mode or sys.argv[3] for CSV mode.
def score_and_reports(ip_address, all_info, days):

    try:
        days_int = int(days)
    except ValueError:
        sys.exit('days should be an int')

    if not (0 < days_int < 366):
        sys.exit('number of days must lie in between 0 and 365')


    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": os.getenv("my_abuseipdb_key"), "Accept": "application/JSON"}
    param = {"ipAddress": ip_address, "maxAgeInDays": days}

    try:
        response = requests.get(url, headers=headers, params=param, timeout=10)
        response.raise_for_status()
        data = response.json()
        abuse_score = data["data"]["abuseConfidenceScore"]
        total_reports = data["data"]["totalReports"]

        if abuse_score <= 30:
            all_info.append(f"Abuse Score = {abuse_score}/100     (Safe)")
        elif abuse_score < 70:
            all_info.append(f"Abuse Score = {abuse_score}/100     (Suspicious)")
        else:
            all_info.append(f"Abuse Score = {abuse_score}/100     (malicious)")

        if abuse_score != 0:
            last_date = data["data"]["lastReportedAt"].split("T")[0]
            all_info.append(f"""Total number of reports = {total_reports}
last reported date = {last_date}""")

    except requests.RequestException:
        all_info.append(f"Error: can't connect to abuseipdb for {ip_address}")

