import sys
import csv
import re
import argparse

from validators import check_ipaddress
from validators import convert_to_ip
from api_clients import info_ipaddress
from api_clients import score_and_reports


def main():

    parser = argparse.ArgumentParser(
        description="Used to retrive all info of an ip address or a domain"
    )

    parser.add_argument("-ip", type=str, help="Enter ip address")
    parser.add_argument("-domain", type=str, help="Enter domain name")
    parser.add_argument("-ifile", type=str, help="Enter name of input file")
    parser.add_argument("-ofile", type=str, help="Enter name of output file")
    parser.add_argument(
        "-days", default=30, type=int, help="Enter total number of days"
    )

    args = parser.parse_args()

    ip = args.ip
    domain = args.domain
    inp = args.ifile
    out = args.ofile
    days = args.days

    if ip:
        all_info = []
        ip = check_ipaddress(ip)
        if "Error" in str(ip):
            sys.exit(ip)
        info_ipaddress(ip, all_info)
        score_and_reports(ip, all_info, days)
        for i in all_info:
            if "Error" in i:
                sys.exit(i)
        for _ in all_info:
            print(_)

    if domain:
        all_info = []
        ip = convert_to_ip(domain)
        ip = check_ipaddress(ip)
        if "Error" in str(ip):
            sys.exit(ip)
        info_ipaddress(ip, all_info)
        score_and_reports(ip, all_info, days)
        for i in all_info:
            if "Error" in i:
                sys.exit(i)
        for _ in all_info:
            print(_)

    if inp and out:
        all_info = []
        csv_handling(inp, out, all_info, days)


# This function is used to read and write from csv file
def csv_handling(inp, out, all_info, days):

    with open(inp) as inputs, open(out, "w") as outputs:

        reader = csv.DictReader(inputs)
        writer = csv.DictWriter(outputs, fieldnames=["info"])
        writer.writeheader()
        outputs.write("\n")

        for line in reader:

            all_info = []
            argument = line["target"].strip()

            if argument != "" and argument != None:

                ip = check_ipaddress(argument)
                if "Error" in str(ip):
                    ip = convert_to_ip(argument)
                    if "Error" in str(ip):
                        writer.writerow({"info": ip})
                        outputs.write("\n")
                        continue

                info_ipaddress(ip, all_info)
                score_and_reports(ip, all_info, days)
                c = 0
                for i in all_info:
                    if "Error" in i:
                        writer.writerow({"info": i})
                        outputs.write("\n")
                        c += 1
                        break
                if c == 1:
                    continue
                for _ in all_info:
                    writer.writerow({"info": _})
                outputs.write("\n")


if __name__ == "__main__":
    main()
