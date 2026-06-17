import requests
import sys
import ipaddress


def main():
    argument = check_argument()
    ip_address = check_ipaddress(argument)
    info_ipaddress(str(ip_address))


def check_argument():
    if len(sys.argv) == 2:
        return(sys.argv[1])
    else:
        sys.exit('Error: insufficient arguments')


def check_ipaddress(argument):
    try:
        return(ipaddress.ip_address(argument))
    except ValueError:
        sys.exit(f'Error: {argument} is not a valid IP address')


def info_ipaddress(ip_address):
    try:
        api = 'http://ip-api.com/json/'
        response = requests.get(api+ip_address) 
        response.raise_for_status()
    except requests.RequestException:
        sys.exit('Can\'t connect to the api')
    else:
        data = response.json()


    if data['status'] == 'success':
        print(f'''        IP: {ip_address}
        Location: {data['city']},{data['regionName']},{data['country']},{data['zip']}
        Internet service Provider: {data['isp']}
        Autonomous System Number: {(data['as'].split())[0]} ''')
    
    else:
        sys.exit(f'Error: {data['message']}')



if __name__ == '__main__':
    main()


