import subprocess
from src import *
import yaml

SSH_PORT      = 22
NCAT_PORT     = 9998
CONST_FILE    = "plateforme" 

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

with open(f"const/{CONST_FILE}.yaml") as stream:
    try:
        const_content = yaml.safe_load(stream)
        addresses     = const_content["addresses"]  
    except yaml.YAMLError as exc:
        print(exc)
        exit()

# RUN LOCAL COMMANDS
local_command(f"ncat -l {NCAT_PORT} | wireshark -k -i -")  # Ecouter sur wireshark
local_command(f"ssh -D {const_content['forward_port']} -N root@{addresses['server2']}")  # Redirect trafic

tcpdump = ssh_terminal(addresses['server2'],control=False) # Envoyer le trafic local sur host
tcpdump.stdin.write(f"tcpdump -i any 'src net 192.168.70.128/26 or dst net 192.168.70.128/26 or src net 10.0.0.0/32 or dst net 10.0.0.0/32' -v -w - | nc {addresses['local']} {NCAT_PORT}\n") # Envoyer le trafic à notre local
tcpdump.stdin.flush()

# ssh_terminal(SSH_ADDRESSES['server2'], control=True)  # Terminal distant interactif pour lancer le core network 