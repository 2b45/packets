#coding:UTF-8
__author__ = 'xx-zhang'

import os 

#from scapy.arch import get_if_addr
#from scapy.config import conf
#from scapy.consts import WINDOWS
#from scapy.data import ETH_P_ALL, MTU
#from scapy.error import Scapy_Exception, warning
#from scapy.fields import BitField, ByteEnumField, ByteField, ConditionalField, FieldLenField, \
#        FlagsField, IntField, PacketListField, ShortEnumField, ShortField, StrFixedLenField, StrLenField, X3BytesField, XByteField, XIntField, XShortField
#from scapy.interfaces import NetworkInterface
from scapy.packet import bind_layers, NoPayload, Packet
#from scapy.plist import PacketList
#from scapy.sendrecv import send, sendp, sniff
#from scapy.supersocket import SuperSocket
from scapy.utils import atol, itom, mac2str, pretty_list, rdpcap, str2mac, strxor, corrupt_bytes
#from scapy.utils6 import in6_isaddr6to4
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from datetime import datetime, time   


PROGRAM_DIR = os.path.dirname(os.path.dirname(__file__))
PROTO_DATA_FILE = os.path.join(PROGRAM_DIR, "proto_data")


def get_timestr_from_packet(p: Packet):
    return datetime.strftime(datetime.fromtimestamp(int(p.time)), 
                             '%Y-%m-%d %H:%M:%S')


class PcapDecode:
    def __init__(self):
        #ETHER:读取以太网层协议配置文件
        with open(os.path.join(PROTO_DATA_FILE, 'ETHER'), 'r', encoding='UTF-8') as f:
            ethers = f.readlines()
        self.ETHER_DICT = dict()
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]

        #IP:读取IP层协议配置文件
        with open(os.path.join(PROTO_DATA_FILE, 'IP'), 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = dict()
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]

        #PORT:读取应用层协议端口配置文件
        with open(os.path.join(PROTO_DATA_FILE, 'PORT'), 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = dict()
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]

        #TCP:读取TCP层协议配置文件
        with open(os.path.join(PROTO_DATA_FILE, 'TCP'), 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]

        #UDP:读取UDP层协议配置文件
        with open(os.path.join(PROTO_DATA_FILE, 'UDP'), 'r', encoding='UTF-8') as f:
            udps = f.readlines()
        self.UDP_DICT = dict()
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]

    #解析以太网层协议
    def ether_decode(self, p):
        data = dict()
        data['time'] = get_timestr_from_packet(p)

        if p.haslayer(Ether):
            data = self.ip_decode(p)
            return data
        else:
            # data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
            data['Source'] = 'Unknow'
            data['Destination'] = 'Unknow'
            data['Procotol'] = 'Unknow'
            data['len'] = len(corrupt_bytes(p))
            data['info'] = p.summary()
            return data

    #解析IP层协议
    def ip_decode(self, p):
        data = dict()
        if p.haslayer(IP):  #2048:Internet IP (IPv4)
            ip = p.getlayer(IP)
            if p.haslayer(TCP):  #6:TCP
                data = self.tcp_decode(p, ip)
                return data
            elif p.haslayer(UDP): #17:UDP
                data = self.udp_decode(p, ip)
                return data
            else:
                data['Source'] = ip.src
                data['Destination'] = ip.dst
                data['time'] = get_timestr_from_packet(p)
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                if ip.proto in self.IP_DICT:
                    # data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['Procotol'] = self.IP_DICT[ip.proto]
                else:
                    data['Procotol'] = 'IPv4'
                return data 
        elif p.haslayer(IPv6):  #34525:IPv6
            ipv6 = p.getlayer(IPv6)
            if p.haslayer(TCP):  #6:TCP
                data = self.tcp_decode(p, ipv6)
                return data
            elif p.haslayer(UDP): #17:UDP
                data = self.udp_decode(p, ipv6)
                return data
            else:
                if ipv6.nh in self.IP_DICT:
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Procotol'] = self.IP_DICT[ipv6.nh]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Procotol'] = 'IPv6'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        else:
            if p.type in self.ETHER_DICT:
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Procotol'] = self.ETHER_DICT[p.type]
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data
            else:
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Procotol'] = hex(p.type)
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data

    #解析TCP层协议
    def tcp_decode(self, p, ip):
        data = dict()
        tcp = p.getlayer(TCP)
        #data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
        data['time'] = get_timestr_from_packet(p)
        data['Source'] = ip.src + ":" + str(ip.sport)
        data['Destination'] = ip.dst + ":" + str(ip.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if tcp.dport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[tcp.dport]
        elif tcp.sport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[tcp.sport]
        elif tcp.dport in self.TCP_DICT:
            data['Procotol'] = self.TCP_DICT[tcp.dport]
        elif tcp.sport in self.TCP_DICT:
            data['Procotol'] = self.TCP_DICT[tcp.sport]
        else:
            data['Procotol'] = "TCP"
        return data

    #解析UDP层协议
    def udp_decode(self, p, ip):
        data = dict()
        udp = p.getlayer(UDP)
        print(f"Error with pcap pcacket time {p.time}")
        # data['time'] = datetime.strftime(datetime.fromtimestamp(int(p.time)), '%Y-%m-%d %H:%M:%S')
        data['time'] = get_timestr_from_packet(p)
        data['Source'] = ip.src + ":" + str(ip.sport)
        data['Destination'] = ip.dst + ":" + str(ip.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if udp.dport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[udp.dport]
        elif udp.sport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[udp.sport]
        elif udp.dport in self.UDP_DICT:
            data['Procotol'] = self.UDP_DICT[udp.dport]
        elif udp.sport in self.UDP_DICT:
            data['Procotol'] = self.UDP_DICT[udp.sport]
        else:
            data['Procotol'] = "UDP"
        return data


def test():
    PCAP_DATA_DIR = os.path.join(PROGRAM_DIR, 'pkts') 
    __cur_file = os.path.join(PCAP_DATA_DIR, "http_dvwa_sqlinjection.pcapng")
    pcaps = rdpcap(__cur_file)
    res = [PcapDecode().ip_decode(x) for x in pcaps]
    for x in res:
        print(x)

if __name__ == "__main__":
    test() 
