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
        return True, get_banner(sock)
    except:
        return False, ''

def scan(target, port_list):
    ip_addr = check_ip(target)
    open_ports = {}
    for port in port_list:
        port_is_open, banner = scan_port(ip_addr, port)
        if port_is_open:
            open_ports[port] = banner
    
    return open_ports


def main():
    targets = input('[+] Enter target(s) to scan (comma seperated): ')
    ports = input('[+] Enter ports to scan (eg. 21-23,80,443): ')
    port_list = parse_ports(ports)

    for ip_addr in targets.split(','):
        print(f'[ - 0 Scanning {ip_addr}]')
        open_ports = scan(ip_addr.strip(' '), port_list)
        for port in open_ports:
            print(f'[+] Port {port} is open : {open_ports[port]}')

    

if __name__ == "__main__":
    main()

