import argparse
import platform
from scapy.all import ARP, Ether, srp, sr1, ICMP, IP, conf
import ipaddress
import logging
import socket
import json

os_name = platform.system()

#for banner scan
server=""
version=""

#parser instance
parser = argparse.ArgumentParser("Scanning Tool")

#SCAN
def scaning(target,output):
    print('this is the ip provided by user',target)
    arp = ARP(pdst=target)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet=broadcast/arp
    result = srp(packet, timeout=3)[0]
    print('the result',result)
    clients = []

    for sent, received in result:
        print('rec',received.psrc,'mac',received.hwsrc)
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # print clients
    print("Available devices in the network:")

    
    print("IP" + " "*15+"MAC")
    file1 = open(output+'.txt', "w")
    file1.writelines('---IP Scan---'+"\n")
    for client in clients:
        print((client['ip'], client['mac']))
        filedate='mac:'+" "+client['mac']+"   "+'Ip:'+" "+client['ip']+"\n"
        
        file1.writelines(filedate)

    file1.close()
    
#ICMP
def ICMP_fun(ip,output):
    val="192.168.1.0/24"
    network = ipaddress.ip_network(ip,strict=False)

    file2 = open(output+'.txt', "w")

    file2.writelines('---ICMP Ping---'+"\n")
    for ip in network.hosts():
        #print('ip=>',ip)
        packet = IP(dst=str(ip))/ICMP()
        #print('packet',packet)
        try:
            res=sr1(packet,timeout=1)
            #print('res',res)
            if res is None:
                        print(f"{ip} is unreachable.")

                        file2.writelines(f"{ip} is unreachable."+"\n")
                      
                        logging.info(f"Unreachable: {ip}")
            else:
                    print(f"{ip} is active.")
                    file2.writelines(f"{ip} is active."+"\n")
                    logging.info(f"Active: {ip}")
        except Exception as e:
            # Handle any exceptions that may occur during sending/receiving
            print(f"Error while pinging {ip}: {str(e)}")
    file2.close()


#PORT SCAN
def port_scan(target,start,end,output):

    file3 = open(output+'.txt', "w")

    file3.writelines('---Port Scanning---'+"\n")
   
    try:
        target=socket.gethostbyname(target)
    except socket.gaierror:
        print('Name not resolved err')
    start=int(start)
    end=int(end)
    for port in range(start,end):
        soc=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

      
        soc.settimeout(2)
        connection=soc.connect_ex((target,port))

        #soc.send(b'GET HTTP/1.1 \r\n')

        #request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        #soc.send(request)
         
    
        if connection==0:
            print(f"Port {port} is open.")
            
            if(port==80):
                soc.send(b'GET HTTP/1.1 \r\n')

          
            #print(f"Received banner from port {port}: {banner}")
            file3.writelines(f"Port {port} is open \n")
            try:
               
                banner = soc.recv(1024).decode("utf-8", errors="ignore")
                banner_lines = banner.split("\n")

                # variable to hold server information
                server_info = 'unknown'

                # Iterate over each line in the banner to find the 'Server' header
                for l in banner_lines:
                    if l.lower().startswith('server:'):
                        # Extract the server information
                        server_info = l.split(':', 1)[1].strip()
                        break
                print('Server Info',server_info)
                server=server_info.split('/')[0]
                version=server_info.split('/')[1]
                print("Server Info",server_info.split('/'))
                #banner.split("\n")[0]
                print("port {} is open with banner {}".format(port, banner)) 
                file3.write(f"Banner from port {port} {banner}\n")
            except socket.timeout:
                print(f"No banner received on port {port}")
        else:
            print(f"Port {port} is closed.")
    file3.close()
    soc.close()


'''def search_vulnerabilities():
    results = []
    
    with open('nvdcve-1.1-recent.json', 'r') as file:
        nvd_file_data = json.load(file)
    # Iterate through the vulnerabilities
    for cve_item in nvd_file_data['CVE_Items']:
        # Extract product info from the configurations (CPEs)
        for node in cve_item['configurations']['nodes']:
            if 'cpe_match' in node:
                for cpe in node['cpe_match']:
                    cpe_uri = cpe['cpe23Uri']
                    if server in cpe_uri and version in cpe_uri:
                        # Extract CVE ID and description
                        cve_id = cve_item['cve']['CVE_data_meta']['ID']
                        description = cve_item['cve']['description']['description_data'][0]['value']
                        results.append({'CVE ID': cve_id, 'Description': description})
    
        if results:
            for vuln in results:
                print(f"CVE ID: {vuln['CVE ID']}")
                print(f"Description: {vuln['Description']}\n")
        else:
            print(f"No vulnerabilities found for {server} version {version}.")

'''

subparser=parser.add_subparsers(dest='scantype',help="Select the feature/scan type")

#add command line argument

parser_ip_scan=subparser.add_parser('IpScan',help="Perform IP Scan")
parser_ip_scan.add_argument("target",help="target Ip")
parser_ip_scan.add_argument("output",help="Enter the filename you want the output to be stored")


parser_icmp_scan=subparser.add_parser('ICMPScan',help="Perform ICMP Scan")
parser_icmp_scan.add_argument("target1",help="target Ip")
parser_icmp_scan.add_argument("output1",help="Enter the filename you want the output to be stored")


parser_port_scan=subparser.add_parser('PortScan',help="Perform Port Scanning")
parser_port_scan.add_argument("Target",help="Provide the target")
parser_port_scan.add_argument("StartPort",help="Provide the start port")
parser_port_scan.add_argument("EndPort",help="Provide the end port")
parser_port_scan.add_argument("Output",help="Enter the filename you want the output of port scanning to be stored")

#parser_banner_scan=subparser.add_parser('BannerScan',help="Perform Port Scanning")

args=parser.parse_args()


if args.scantype=='IpScan':
    scaning(args.target,args.output)
elif args.scantype=='ICMPScan':
    ICMP_fun(args.target1,args.output1)
elif args.scantype=='PortScan':
    port_scan(args.Target,args.StartPort,args.EndPort,args.Output)
#elif args.scantype=='BannerScan':
#   search_vulnerabilities()
else:
    print("Please specify a valid scan type (arp,icmp and port scanning).")
