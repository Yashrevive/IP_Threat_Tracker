import requests
import sys
import ipaddress
import os
import csv
import re
import socket
from dotenv import load_dotenv

load_dotenv()


def main():
    all_info = []
    argument = check_argument()
    ip_address = check_argument_type(argument, all_info)

    if type(ip_address) == list:
        csv_handling(ip_address)
    else:
        info_1 = info_ipaddress(str(ip_address), all_info)

        if info_1 == None:
            info_2 = score_and_reports(ip_address, all_info, sys.argv[2])
            if info_2 == None:
                for _ in all_info:
                    print(_)
            else:
                print(info_2)
        else:
            print(info_1)


# This function checks the number of arguments
def check_argument():

    if len(sys.argv) != 3 and len(sys.argv) != 4:
        sys.exit("Error: insufficient arguments")

    else:
        return sys.argv[1]


# This function check the type of argument
def check_argument_type(argument, all_info):

    if ".csv" in argument and ".csv" in sys.argv[2]:
        lst = []
        lst.append(argument)
        lst.append(sys.argv[2])
        return lst

    elif re.search(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", argument):
        ip_address = check_ipaddress(argument)
        return ip_address

    elif ":" in argument:
        ip_address = check_ipaddress(argument)
        return ip_address

    else:
        ip_address = convert_to_ip(argument)
        if "invalid" not in ip_address:
            ip_address = check_ipaddress(ip_address)
        return ip_address

# This function is used to read and write from csv file
def csv_handling(lst):

    with open(lst[0]) as inputs, open(lst[1], "w") as outputs:

        reader = csv.DictReader(inputs)
        writer = csv.DictWriter(outputs, fieldnames=["info"])
        writer.writeheader()

        for line in reader:

            all_info = []
            argument = line["target"]

            if argument != "" and argument != None:

                ip_address = check_argument_type(argument, all_info)

                if type(ip_address) != str:

                    info_1 = info_ipaddress(str(ip_address), all_info)

                    if info_1 == None:
                        info_2 = score_and_reports(ip_address, all_info, sys.argv[3])

                        if info_2 == None:

                            for i in all_info:
                                writer.writerow({"info": i})
                            outputs.write("\n")          

                        else:
                            writer.writerow({"info": info_2})
                            outputs.write("\n")          

                    else:
                        writer.writerow({"info": info_1})
                        outputs.write("\n")          

                else:
                    writer.writerow({"info": ip_address})
                    outputs.write("\n")          


# This function converts Domain to ip address
def convert_to_ip(argument):

    try:
        return socket.gethostbyname(argument)

    except:
        return f"{argument} is invalid domain name"


# This function check wether an i address is valid or not
def check_ipaddress(argument):

    try:
        return ipaddress.ip_address(argument)

    except ValueError:
        return f"Error: {argument} is not a valid IP address"


# this function is used to print info. regarding the given specific ip address
def info_ipaddress(ip_address, all_info):

    try:

        api = "http://ip-api.com/json/"
        response = requests.get(api + ip_address, timeout=10)
        response.raise_for_status()

    except requests.RequestException:
        return f"Can't connect to the api for {ip_address}"

    else:
        data = response.json()

    if data["status"] == "success":
        all_info.append(f"""IP: {ip_address}
Location: {data['city']},{data['regionName']},{data['country']},{data['zip']}
Internet service Provider: {data['isp']}
Autonomous System Number: {(data['as'].split())[0]} """)

    else:
        return f"Error for {ip_address}: {data['message']}"


# this function tells the abuse score of an ip address and whether it's safe, malicious
# or suspicious, and also gives its total number of reports and date of last report.
# `days` is sys.argv[2] for single-IP mode or sys.argv[3] for CSV mode.
def score_and_reports(ip_address, all_info, days):

    if not days.isdigit() or not (0 < int(days) < 366):
        return "number of days must lie in between 0 and 365"

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
        return f"can't connect to abuseipdb for {ip_address}"


if __name__ == "__main__":
    main()