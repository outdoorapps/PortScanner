import socket
import argparse
import traceback
import ipaddress
import datetime

parser = argparse.ArgumentParser(prog='PortScanner')
parser.add_argument('ip', help="IPv4 host, e.g. 192.168.185.0/24 or 192.168.185.1-16")
parser.add_argument('port', help="Ports to scan e.g. 1-1000")
parser.add_argument('-t', '--timeout', help="Connection timeout (in second)")
parser.add_argument('-o', '--outFile', help="Output to a file, e.g. scan.txt")

timeout = 1   # in second

log = ["Scan Report","======================================"]

def tcp_scan(ip, port, timeout):
    try:
        s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_tcp.settimeout(0.5)
        s_tcp.connect((ip, port))
        print('TCP Port', port, 'is open')
        log.append('TCP Port %s is open' % port)
        
    except:
        print('TCP Port', port, 'is closed')
#         traceback.print_exc()

def scan_host(ip, port, timeout):
    print('Scanning host (', ip, ')...')
    log.append('\nHost %s was scanned' % ip)
    
    # Support scanning multiple ports
    port_range = port.split('-')
    if len(port_range) == 2:
        start_port = int(port_range[0])
        end_port = int(port_range[1])
        for x in range(start_port, end_port+1):
            tcp_scan(ip, x, timeout)
    else:
        tcp_scan(ip, int(port), timeout)

def main():
    args = parser.parse_args()
    ip = args.ip
    port = args.port
    timeout = args.timeout
    outFile = args.outFile
    
    start_time = datetime.datetime.now()
    print('Scan begins at %s' % start_time)
    log.append('Scan begins at %s' % start_time)
    
    # Support scanning multiple IPs
    ip_range = ip.split('-')    # By range
    ip_mask = ip.split('/')     # By mask
    if len(ip_range) == 2:
        start_ip = ipaddress.ip_address(ip_range[0])
        
        ip_components = ip_range[0].split('.')
        subnet_start_number = ip_components[len(ip_components)-1]
        end_ip = start_ip - int(subnet_start_number) + int(ip_range[1])
        
        for x in range(int(end_ip) - int(start_ip) + 1):
            host_ip = str(start_ip + x)
            scan_host(host_ip, port, timeout)
            
    elif len(ip_mask) == 2:
        subnet = ipaddress.ip_network(ip)
        hosts = list(subnet.hosts())
        for host_ip in hosts:
            scan_host(str(host_ip), port, timeout)
            
    else:
        scan_host(ip, port, timeout)
        
    end_time = datetime.datetime.now()
    print('Scan finished at %s' % end_time)
    log.append('Scan finished at %s' % end_time)
        
    if outFile:
        text_file = open(outFile,"w")
        for line in log:
            text_file.write('%s\n' % line)
        text_file.close()

if __name__ == "__main__":
    main()