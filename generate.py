from src import * 
import time

FREE5GC_PATH  = "~/Deployments/free5gc/2025/thoger"
POPULATE_PATH = "~/Deployments/free5gc/2025/free5gc-populate"

GNB_CONFIG_PATH = "config/gnbcfg.yaml"
UE_CONFIG_PATH  = "config/uecfg.yaml"

def start_free5gc():
    os.popen(f'cd {FREE5GC_PATH} && docker-compose -f docker-compose.yaml up -d')
    os.popen(f'cd {POPULATE_PATH} && ./populate --config config.yaml')
    
def stop_free5gc():
    os.popen(f'cd {FREE5GC_PATH} && docker-compose -f docker-compose.yaml down')

def docker_exec(container, command, read=False):
    execution = os.popen(f'sudo docker exec {container} {command}')
    if read : return execution.read()
    else    : return execution

def ueransim_exec(command, read=False):
    return docker_exec("ueransim",command,read)
    
def get_gnb(): 
    components = ueransim_exec("./nr-cli --dump", read=True).split("\n")
    first_gnb  = components[0]
    return first_gnb
    
def get_all_imsi():
    components     = ueransim_exec("./nr-cli --dump", read=True).split("\n")
    only_imsi_list = [component for component in components if "imsi" in component]
    return only_imsi_list
    
def get_new_imsi():
    # Pioche parmi une liste de disponible
    # peut être read dans free5gc la liste des imsi déclaré
    pass

def register_ue(imsi):
    print(f"Registering new ue : {imsi}")
    ueransim_exec(f"./nr-ue -c {UE_CONFIG_PATH} -i {imsi} &")

def deregister_ue(imsi, permanent=False):
    print(f"Deregistering ue : {imsi}")
    ueransim_exec(f"./nr-cli {imsi} -e 'deregister normal'")
    if permanent : # If the process isn't killed, it will try to register again automatically
        pid = os.popen("ps aux | grep {imsi} | grep -v grep | awk '{print $2}'".format(imsi)).read()
        os.popen(f"sudo kill -9 {pid}")

def set_ue_idle():
    pass

def ue_wake():
    # changer le nom
    # ping depuis l'ue
    pass

def paging():
    # ping vers l'ue
    pass

def pdu_session_stop():
    # restart automatique
    pass

def terminate_all_ue():
    ue_process = os.popen("ps aux | grep '/nr-ue -c' | grep -v grep | awk '{print $2}'").read()
    print("Terminating every UE")
    for pid in ue_process.split("\n"):
        if pid : 
            print("Killing process",pid)
            os.popen(f"sudo kill -9 {pid}")

def isCommandFinished():
    pass
    
def randomCommands():
    pass

    
print('Initial state', get_all_imsi())
# imsi = get_new_imsi()
# register_ue(imsi)

# time.sleep(2)
# print('New added', get_all_imsi())
terminate_all_ue()
time.sleep(2)
print('All removed', get_all_imsi())