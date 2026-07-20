import sys
import csv
import re

from validators import check_ipaddress
from validators import convert_to_ip
from api_clients import info_ipaddress
from api_clients import score_and_reports



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




if __name__ == "__main__":
    main()