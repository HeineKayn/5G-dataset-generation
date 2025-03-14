import subprocess
import os
from src import *

SSH_PORT      = 22
NCAT_PORT     = 9998
FORWARD_PORT  = 1090 

'''
    This code is used because free5gc is deployed on a remote server and allow to interact with it.
    If you use free5gc on your machine, use setup_plateform instead.
''' 

def ssh_terminal(address,user="root",control:bool=False):
    
    if control : stdin = None
    else :       stdin = subprocess.PIPE

    return subprocess.Popen(
        ["cmd", "/K", f"ssh -tt -p {SSH_PORT} {user}@{address}"],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
        stdin=stdin,
        text=True
    )

def local_command(command, shell=True):
    subprocess.run(["start", "cmd", "/K", command], shell=shell)

def listen_trafic(remote_address, local_address, plateform):
    
    # Local host listen to trafic from remote and redirect to wireshark
    local_command(f"ncat -l {NCAT_PORT} | wireshark -k -i -")  

    # We use iface any + filter because if we listen 
    # Before creating the docker the interface won't exist yet
    if plateform == "oai" : 
        filter = "src net 192.168.70.128/26 or dst net 192.168.70.128/26 or src net 10.0.0.0/32 or dst net 10.0.0.0/32"
    elif plateform == "free5gc" :   
        filter = "src net 10.100.200.0/24 or dst net 10.100.200.0/24 or src net 10.60.0.0/15 or dst net 10.60.0.0/15"
    else : 
        filter = "" 
        
    # Send trafic from remote to local and filter only the CN / UE trafic
    tcpdump = ssh_terminal(remote_address,control=False) 
    tcpdump.stdin.write(f"tcpdump -i any '{filter}' -v -w - | nc {local_address} {NCAT_PORT}\n") # Envoyer le trafic à notre local
    tcpdump.stdin.flush()

def forward_request(remote_address):
    # Allow to make curl calls from host to dockers
    local_command(f"ssh -D 1090 -N {remote_address}")  
    
def port_forward(remote_address, port=5000):
    # Give access to the webui in the remote docker 
    local_command(f"ssh -N -L {port}:localhost:{port} {remote_address}")  

def docker_log(remote_address, nf):
    tcpdump = ssh_terminal(remote_address,control=False) 
    tcpdump.stdin.write(f"sudo docker log -f {nf}") # follow log of any docker
    tcpdump.stdin.flush()

