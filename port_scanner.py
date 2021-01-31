import socket
from IPy import IP

def check_ip(target):
    try:
        IP(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)

def get_banner(sock):

    try:
        banner = sock.recv(1024).decode().strip('\n')
    except:
        banner = ''

    return banner
    
def parse_ports(ports):
    ports = ports.split(',')
    port_list = []
    for port in ports:
        if '-' in port:            
            port_list.extend(range( int(port.split('-')[0].strip(' ')), int(port.split('-')[1].strip(' ')) + 1 ))
        else:
            port_list.append(int(port.strip(' ')))
    
    return port_list



def scan_port(ip_addr, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((ip_addr, port))
        print(f'[+] Port {port} is open : {get_banner(sock)}')
    except:
        pass

def scan(target, port_list):
    ip_addr = check_ip(target)
    print(f'[ - 0 Scanning {target}]')
    for port in port_list:
        scan_port(ip_addr, port)

def main():
    targets = input('[+] Enter target(s) to scan (comma seperated): ')
    ports = input('[+] Enter ports to scan (eg. 21-23,80,443): ')
    port_list = parse_ports(ports)

    for ip_addr in targets.split(','):
        scan(ip_addr.strip(' '), port_list)

    


main()

