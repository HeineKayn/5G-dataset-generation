from scapy.all import *
from scapy.contrib.gtp import *
from scapy.layers.inet import IP, ICMP
import sys
from utils.logger import Log
from scapy.all import arping, get_if_list





logger = Log("[GTP-U]")

teid = int(sys.argv[1], 0)
src_ip = "8.8.8.8"
ue_ip = sys.argv[2]
upf_ip = "10.100.200.2"
dport = 2152

logger.info(f"Interfaces: {get_if_list()}")

arping(upf_ip)


ip_payload = IP(src=src_ip, dst=ue_ip) / ICMP(type=8, id=0x1234, seq=1) / b"ABCDEFGHIJKLMNOPQRSTUVWX"

gtpu_header = GTP_U_Header(teid=teid) / ip_payload

packet = IP(dst=upf_ip) / UDP(dport=dport, sport=RandShort()) / gtpu_header

logger.info(f"Sending GTP-U packet with TEID {hex(teid)} to {ue_ip} through the upf ({upf_ip})")


send(packet)

logger.success("Packet sent successfully")
