import socket
import ipaddress

from threshold import abuse_score_constraints
from threshold import vt_constraints



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



def verdict(all_info, info):

    constraints_abuse = abuse_score_constraints()
    abuse_safe = constraints_abuse['safe_upper']
    abuse_suspicious = constraints_abuse['suspicious_upper']

    constraints_vt = vt_constraints()
    vt_safe = constraints_vt['safe_upper']
    vt_suspicious = constraints_vt['suspicious_upper']

    if (info['Abuse Score'] <= abuse_safe) and (info['Malicious Reports'] <= vt_safe):
        all_info.append(f'Safety Status: Safe')
        info['Safety Status'] = 'Safe'
    elif (info['Abuse Score'] >= abuse_suspicious) or (vt_safe >= info['Malicious Reports'] <= vt_suspicious):
        all_info.append(f'Safety Status: Malicious')   
        info['Safety Status'] = 'Malicious'
    elif (info['Abuse Score'] >= abuse_suspicious) and (vt_safe >= info['Malicious Reports'] <= vt_suspicious):
        all_info.append(f'Safety Status: Malicious')   
        info['Safety Status'] = 'Malicious'
    else:
        all_info.append(f'Safety Status: Suspicious')   
        info['Safety Status'] = 'Suspicious'

    return info



def is_domain(target):

    lst = target.split('.')

    for i in lst:
        if i.isalpha():
            return True
    return False



def raise_for_Status(target, info):

    target = ipaddress.ip_address(target)

    if target.is_loopback:
        info['Status'] = 'Loopback'
    elif target.is_link_local:
        info['Status'] = 'Link-local'
    elif target.is_multicast:
        info['Status'] = 'Multicast'
    elif target.is_private:
        info['Status'] = 'Private'
    elif target.is_reserved:
        info['Status'] = 'Reserved'
    elif target.is_global:
        info['Status'] = 'Public'
    else:
        info['Status'] = 'Reserved'  # catches shared/CGNAT space (100.64.0.0/10) and anything else unclassified

    return info