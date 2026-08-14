import requests
import os
import sys

from dotenv import load_dotenv

load_dotenv()




# this function is used to print info. regarding the given specific ip address
def info_ipaddress(ip_address, all_info, info):

    try:

        api = "http://ip-api.com/json/"
        response = requests.get(api + str(ip_address), timeout=10)
        response.raise_for_status()

    except requests.RequestException:
        all_info.append(f"Error: Can't connect to the api for {ip_address}")
        info['Error'] = f"Can't connect to ip-api for {ip_address}"
        return info

    else:
        data = response.json()

    if data["status"] == "success":
        
        fields = ['query' , 'city' , 'regionName' , 'country' , 'zip' , 'isp' , 'as']

        all_info.append(f"""IP: {ip_address}    
Location: {data['city']},{data['regionName']},{data['country']},{data['zip']}
Internet service Provider: {data['isp']}
Autonomous System: {data['as']} """)

        info['Input'] = ip_address
        info['city'] = data['city']
        info['region'] = data['regionName']
        info['country'] = data['country']
        info['zip'] = data['zip']
        info['Internet Service Provider'] = data['isp']
        info['Autonomous System'] = data['as']

        return info
    
    else:
        all_info.append(f"Error: {ip_address}: {data['message']}")
        info['Status'] = data['message']

        return info




'''this function tells the abuse score of an ip address and whether it's safe, malicious
or suspicious, and also gives its total number of reports and date of last report.'''
def score_and_reports(ip_address, all_info, info, days = 30):

    try:
        days_int = int(days)
    except ValueError:
        sys.exit("days should be an int")

    if not (0 < days_int < 366):
        sys.exit("number of days must lie in between 0 and 365")

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": os.getenv("my_abuseipdb_key"), "Accept": "application/JSON"}
    param = {"ipAddress": ip_address, "maxAgeInDays": days}

    try:
        response = requests.get(url, headers=headers, params=param, timeout=10)
        response.raise_for_status()
        data = response.json()
        abuse_score = data["data"]["abuseConfidenceScore"]
        total_reports = data["data"]["totalReports"]

        info['Abuse Score'] = abuse_score
        info['Total Reports'] = total_reports

        all_info.append(f"Abuse Score = {abuse_score}/100")

        if abuse_score != 0:
            last_date = data["data"]["lastReportedAt"].split("T")[0]
            all_info.append(f"""Total number of reports = {total_reports}
last reported date = {last_date}""")
            info['Last Reported'] = last_date

        else:
            info['Last Reported'] = ''
        return info


    except requests.RequestException:
        all_info.append(f"Error: can't connect to abuseipdb for {ip_address}")
        info['Error'] = "Can't connect to AbuseIPBD"
        return info 




def virustotal_report(ip, all_info, info):

    api_key = os.getenv('vt_api_key')
    url = 'https://www.virustotal.com/api/v3/ip_addresses/'

    response = requests.get(f'{url}{ip}', headers={'x-apikey' : api_key})
    data = response.json()

    malicious_reports = data['data']['attributes']['last_analysis_stats']['malicious']

    all_info.append(f'Total malicious reports = {malicious_reports}')
    info['Malicious Reports'] = malicious_reports

    return info