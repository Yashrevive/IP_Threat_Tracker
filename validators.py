import socket
import ipaddress


# This function check wether an i address is valid or not
def check_ipaddress(argument):

    try:
        return ipaddress.ip_address(argument)

    except ValueError:
        return f"Error: {argument} is not a valid IP address"



# This function converts Domain to ip address
def convert_to_ip(argument):

    try:
        return socket.gethostbyname(argument)

    except:
        return f"{argument} is invalid domain name"
