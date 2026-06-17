import requests
import sys
import ipaddress


def main():
    argument = check_argument()
    ip_address = check_ipaddress(argument)



def check_argument():
    if len(sys.argv) == 2:
        return(sys.argv[1])
    else:
        sys.exit('Error: insufficient arguments')


def check_ipaddress(argument):
    try:
        return(ipaddress.ip_address(argument))
    except ValueError:
        return(f'Error: {argument} is not a valid IP address')



if __name__ == '__main__':
    main()


