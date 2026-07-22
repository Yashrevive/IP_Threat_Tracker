import socket
import ipaddress


# This function check wether an i address is valid or not
def check_ipaddress(argument):

    try:
        return ipaddress.ip_address(argument)

    except ValueError:
        return f"Error: {argument} is invalid"


# This function converts Domain to ip address
def convert_to_ip(argument):

    try:
        return socket.gethostbyname(argument)

    except socket.gaierror:
        return f"Error: {argument} is invalid"
