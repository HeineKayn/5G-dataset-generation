import subprocess
from src import *

SSH_PORT      = 22
NCAT_PORT     = 9998

def ssh_terminal(address,user="root",control:bool=False):
    
    if control : stdin = None
    else :       stdin = subprocess.PIPE

    return subprocess.Popen(
        ["cmd", "/K", f"ssh -tt -p {SSH_PORT} {user}@{address}"],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
        stdin=stdin,
        text=True
    )

def local_command(command):
    subprocess.run(["start", "cmd", "/K", command], shell=True)

def listen_oai(remote_address, local_address):

    # Listen on local and redirect to wireshark
    local_command(f"ncat -l {NCAT_PORT} | wireshark -k -i -")  

    # Send trafic on remote and filter only the CN / UE trafic
    tcpdump = ssh_terminal(remote_address,control=False) 
    tcpdump.stdin.write(f"tcpdump -i any 'src net 192.168.70.128/26 or dst net 192.168.70.128/26 or src net 10.0.0.0/32 or dst net 10.0.0.0/32' -v -w - | nc {local_address} {NCAT_PORT}\n") # Envoyer le trafic à notre local
    tcpdump.stdin.flush()

    # local_command(f"ssh -D {const_content['forward_port']} -N root@{addresses['server2']}")  # Redirect trafic
    # ssh_terminal(SSH_ADDRESSES['server2'], control=True)  # Terminal distant interactif pour lancer le core network 