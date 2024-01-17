import os 
import sys 
from scapy.all import DNS, DNSQR, DNSRR, IP, sniff, UDP, rdpcap 

def process_packet(packet):
    # 检查数据包是否包含 IP 层
    if packet.haslayer(IP):
        # 检查数据包是否包含 UDP 层
        if packet.haslayer(UDP):
            # 检查数据包是否包含 DNS 层
            if packet.haslayer(DNS):
                dns = packet[DNS]

                print("\n[+] DNS Packet")
                print("Transaction ID:", dns.id)
                #print("Flags:", dns.flags)
                print("Questions:", dns.qdcount)
                print("Answer RRs:", dns.ancount)
                print("Authority RRs:", dns.nscount)
                print("Additional RRs:", dns.arcount)

                # 解析 DNS 查询记录
                if dns.qr == 0 and dns.qdcount > 0:
                    for i in range(dns.qdcount):
                        query = dns.qd[i]
                        print(f"\n[+] DNS Query Record {i+1}")
                        print("Name:", query.qname)
                        print("Type:", query.qtype)
                        print("Class:", query.qclass)

                # 解析 DNS 应答记录
                if dns.qr == 1 and dns.ancount > 0:
                    for i in range(dns.ancount):
                        answer = dns.an[i]
                        print(f"\n[+] DNS Answer Record {i+1}")
                        print("Name:", answer.rrname)
                        print("Type:", answer.type)
                        print("Class:", answer.rclass)
                        print("TTL:", answer.ttl)
                        print("Data Length:", answer.rdlen)
                        print("Data:", answer.rdata)

# 开始嗅探 DNS 流量
#sniff(filter="udp port 53", prn=process_packet, store=0)

if __name__ == "__main__":
    PROJECT_DIR = os.path.dirname(os.path.dirname(__file__))
    if len(sys.argv) > 1:
        abs_path = sys.argv[1]
    else:
        abs_path =  "dns_isp_hijack.pcapng"
    FILE = os.path.join(PROJECT_DIR, "pkts", abs_path)

    pkts = rdpcap(FILE)
    #for x in enumerate(pkts):
    for x in pkts:
        process_packet(x)


