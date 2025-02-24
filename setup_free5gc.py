import subprocess
import time 
from src import *

PORT     = 2204
PASSWORD = "free5gc\n" 

def ssh_terminal(control:bool=False):

    user  = "root" 
    stdin = subprocess.PIPE
    
    if control :
        user  = "ubuntu"  
        stdin = None

    address = f"{user}@localhost"

    return subprocess.Popen(
        ["cmd", "/K", f"ssh -tt -p {PORT} {address}"],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
        stdin=stdin,
        text=True
    )

def local_command(command):
    subprocess.run(["start", "cmd", "/K", command], shell=True)

def flush_all(clients):
    for pipe in clients.values(): pipe.stdin.flush()

# RUN LOCAL COMMANDS
local_command("ncat -l 9999 | wireshark -k -i -")  # Ecouter sur wireshark

# SETUP REMOTE SSH
clients = {f"nf_{nf}" : ssh_terminal(control=False) for nf in PORTS.keys()} # 1 client par NF
clients["tcpdump"] = ssh_terminal(control=False) # Envoyer le trafic local sur host
   
# RUN REMOTE COMMANDS
time.sleep(3)
clients["tcpdump"].stdin.write("tcpdump -i lo -v -w - | nc 10.0.2.2 9999\n") # Envoyer le trafic à notre local
for nf, port in PORTS.items() :  # Envoyer des curl depuis host
    address_suffixe = port - 8000
    clients[f"nf_{nf}"].stdin.write(f"socat TCP4-LISTEN:{port},fork,reuseaddr TCP4:127.0.0.{address_suffixe}:8000\n") 
flush_all(clients)

# ---------------------------------------------------

TEST = False
if TEST : 

    # J'ai compté environ 45 secondes pour TestRegistration
    # En faisant tourner chaque test 30 minutes on tombe sur 40 itérations
    # En tout 14 test donc 7h de génération
    REPETITIONS = 1 # 40   
    TESTS   = [
        "TestRegistration",
        "TestGUTIRegistration",
        "TestServiceRequest",
        "TestXnHandover",
        "TestN2Handover",
        "TestPDUSessionReleaseRequest",
        "TestPaging",
        "TestNon3GPP",
        "TestReSynchronization",
        "TestDuplicateRegistration",
        "TestEAPAKAPrimeAuthentication",
        "TestMultiAmfRegistration",
        "TestNasReroute",
        "TestDeregistration"
    ]

    ## Lancement auto du code de la plateforme
    free5gc_client = ssh_terminal(control=False) # Lancer le code de free5gc
    tail_client    = ssh_terminal(control=False) # Voir la progression
    export_file    = "/home/ubuntu/dataset_splits/$(date '+%Y-%m-%d %H:%M').csv"
    
    time.sleep(3)
    free5gc_client.stdin.write("cd /home/ubuntu/free5gc\n")
    tail_client.stdin.write(f"touch {export_file}; tail -f {export_file}\n")
    free5gc_client.stdin.flush()
    tail_client.stdin.flush()

    time.sleep(1)
    free5gc_client.stdin.write(f'echo -------\n >> {export_file}; for test in {" ".join(TESTS)}; do for i in {{1..{REPETITIONS}}}; do ./test.sh $test oauth; echo $test,$i,$(date "+%Y-%m-%d %H:%M:%S.%N%z") >> {export_file}; done; done\n')
    free5gc_client.stdin.flush()

else : 
    ssh_terminal(control=True)  # Terminal distant interactif pour lancer le core network 