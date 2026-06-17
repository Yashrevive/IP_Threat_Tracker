import requests
import sys
import ipaddress
import os
from dotenv import load_dotenv
load_dotenv()



def main():
    argument = check_argument()
    ip_address = check_ipaddress(argument)
    info_ipaddress(str(ip_address))
    score_and_reports(ip_address)



def check_argument():
    if len(sys.argv) == 3:
        return sys.argv[1]
    else:
        sys.exit("Error: insufficient arguments")



def check_ipaddress(argument):
    try:
        return ipaddress.ip_address(argument)
    except ValueError:
        sys.exit(f"Error: {argument} is not a valid IP address")



# this function is used to print info. regarding the given specific ip address
def info_ipaddress(ip_address):

    try:
        api = "http://ip-api.com/json/"
        response = requests.get(api + ip_address, timeout=10)
        response.raise_for_status()

    except requests.RequestException:
        sys.exit("Can't connect to the api")

    else:
        data = response.json()

    if data["status"] == "success":
        print(f"""        IP: {ip_address}
        Location: {data['city']},{data['regionName']},{data['country']},{data['zip']}
        Internet service Provider: {data['isp']}
        Autonomous System Number: {(data['as'].split())[0]} """)


    else:
        sys.exit(f"Error: {data['message']}")



#this function tell the abuse score of an ip addresss and tell weather it safe , maliciious or suspicious, and it also tell its total nummber
#of report and date of last report 
def score_and_reports(ip_address):

    if sys.argv[2].isdigit() and 0 < int(sys.argv[2]) < 366:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": os.getenv("my_abuseipdb_key"), "Accept": "application/JSON"}
        param = {"ipAddress": ip_address, "maxAgeInDays": sys.argv[2]}

        try:
            response = requests.get(url, headers=headers, params=param, timeout=10)
            response.raise_for_status()
            data = response.json()
            abuse_score = (data["data"])["abuseConfidenceScore"]
            total_reports = (data["data"])["totalReports"]
            if abuse_score <= 30:
                print(f"        Abuse Score = {abuse_score}/100     (Safe)")
            elif 30 < abuse_score < 70:
                print(f"        Abuse Score = {abuse_score}/100     (Suspicious)")
            else:
                print(f"        Abuse Score = {abuse_score}/100     (malicious)")
            if abuse_score != 0:
                last_date = ((data["data"])["lastReportedAt"].split("T"))[0]
                print(f"""        Total number of reports = {total_reports}
        last reported date = {last_date}""")

        except requests.RequestException:
            sys.exit("can't connect to abuseipdb")

    else:
        sys.exit('second argument must lie in between 0 and 365')



if __name__ == "__main__":
    main()