from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.data import ETH_P_ALL, MTU
from scapy.error import Scapy_Exception, warning
from scapy.fields import BitField, ByteEnumField, ByteField, ConditionalField, FieldLenField, \
        FlagsField, IntField, PacketListField, ShortEnumField, ShortField, StrFixedLenField, StrLenField, X3BytesField, XByteField, XIntField, XShortField
from scapy.interfaces import NetworkInterface
from scapy.packet import bind_layers, NoPayload, Packet
from scapy.plist import PacketList
from scapy.sendrecv import send, sendp, sniff
from scapy.supersocket import SuperSocket
from scapy.utils import atol, itom, mac2str, pretty_list, str2mac, strxor
from scapy.utils6 import in6_isaddr6to4 
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether


if __name__ == "__main__":
    a = Ether() / IP() / TCP() / "fffffffffffffffffffffffffffff"
    print(a)



