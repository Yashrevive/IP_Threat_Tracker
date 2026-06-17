import requests
import sys
import ipaddress


def main():
    argument = check_argument() 
    print(argument) 


def check_argument():
    if len(sys.argv) == 2:
        return(sys.argv[1])
    else:
        sys.exit('Error: insufficient arguments')



if __name__ == '__main__':
    main()


