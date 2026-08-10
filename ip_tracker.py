import sys
import csv
import argparse

from validators import check_ipaddress
from validators import convert_to_ip
from validators import verdict
from validators import is_domain
from validators import raise_for_Status
from api_clients import info_ipaddress
from api_clients import score_and_reports
from api_clients import virustotal_report

from colorama import just_fix_windows_console
just_fix_windows_console()  
from termcolor import colored



def main():

    parser = argparse.ArgumentParser(description="Used to retrive all info of an ip address or a domain")

    parser.add_argument("-ip", type=str, help="Enter ip address")
    parser.add_argument("-domain", type=str, help="Enter domain name")
    parser.add_argument("-ifile", type=str, help="Enter name of input file")
    parser.add_argument("-ofile", type=str, help="Enter name of output file")
    parser.add_argument("-days", default=30, type=int, help="Enter total number of days")

    args = parser.parse_args()

    ip = args.ip
    domain = args.domain
    inp = args.ifile
    out = args.ofile
    days = args.days

    info = {}

    if ip:
        all_info = []
        output(ip, all_info, days, info)

    if domain:
        all_info = []
        ip = convert_to_ip(domain)
        output(ip, all_info, days, info)

    if inp and out:
        all_info = []
        csv_handling(inp, out, all_info, info, days)



def output(ip, all_info, days, info):

    ip = check_ipaddress(ip)
    if "Error" in str(ip):
        sys.exit(ip)
    info_ipaddress(ip, all_info, info)
    virustotal_report(ip, all_info, info)
    score_and_reports(ip, all_info, info, days)
    verdict(all_info, info)
    for i in all_info:
        if "Error" in i:
            sys.exit(i)
    for j in all_info:
        if info['Safety Status'] == 'Safe':
            print(colored(j,'green'))
        if info['Safety Status'] == 'Suspicious':
            print(colored(j,'yellow'))
        if info['Safety Status'] == 'Malicious':
            print(colored(j,'red'))




# This function is used to read and write from csv file
def csv_handling(inp, out, all_info, info, days):

    try:
        with open(inp) as inputs, open(out, "w") as outputs:
            reader = csv.DictReader(inputs)

            fieldnames = [
                "Serial No.",
                "Input",
                "Status",
                "city",
                "region",
                "country",
                "zip",
                "Internet Service Provider",
                "Autonomous System",
                "Malicious Reports",
                "Abuse Score",
                "Safety Status",
                "Total Reports",
                "Last Reported",
                "Error",
            ]

            writer = csv.DictWriter(outputs, fieldnames)
            writer.writeheader()

            c = 1

            for line in reader:

                target = line["Input"].strip()
                info = {}
                field_list = list(fieldnames)

                check = is_domain(target)

                if target != None and target != '':

                    ip = check_ipaddress(target)

                    if "Error" in str(ip):

                        if check == True :

                            ip_domain = convert_to_ip(target)

                            if "Error" in str(ip_domain):
                                # neither a valid IP nor a resolvable domain
                                info["Error"] = ip_domain[6::]
                                field_list.remove("Error")
                                info["Input"] = target
                                field_list.remove("Input")
                                info['Status'] = 'Invalid'
                                field_list.remove("Status")                 
                                info["Serial No."] = c
                                c += 1
                                field_list.remove("Serial No.")

                                for i in field_list:
                                    info[i] = ""
                                writer.writerow(info)
                                continue

                            else:
                                ip = check_ipaddress(ip_domain)
                                info["Input"] = target
                                info["Serial No."] = c
                                c += 1
                                raise_for_Status(target, info)
                                if info['Status'] == 'Public':
                                    info = info_ipaddress(ip, all_info, info)
                                    info = virustotal_report(ip, all_info, info)
                                    info = score_and_reports(ip, all_info, info, days)
                                    info = verdict(all_info, info)
                                for i in info.keys():
                                    field_list.remove(i)
                                for j in field_list:
                                    info[j] = ""
                                writer.writerow(info)
                                continue

                        else:
                            info["Error"] = f'{target} is invalid'
                            field_list.remove("Error")
                            info["Input"] = target
                            field_list.remove("Input")
                            info['Status'] = 'Invalid'
                            field_list.remove("Status")                 
                            info["Serial No."] = c
                            c += 1
                            field_list.remove("Serial No.")

                            for i in field_list:
                                info[i] = ""
                            writer.writerow(info)
                            continue


                    else:
                        # target was already a literal IP
                        info["Input"] = ip
                        info["Serial No."] = c
                        c += 1
                        info = raise_for_Status(target, info)
                        if info['Status'] == 'Public' :
                            info = info_ipaddress(ip, all_info, info)
                            info = virustotal_report(ip, all_info, info)
                            info = score_and_reports(ip, all_info, info, days)
                            info = verdict(all_info, info)
                        for i in info.keys():
                            field_list.remove(i)
                        for j in field_list:
                            info[j] = ""
                        writer.writerow(info)
                        continue


    except FileNotFoundError:
        sys.exit(f"{inp} not exists")




if __name__ == "__main__":
    main()
