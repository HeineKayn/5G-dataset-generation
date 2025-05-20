import os, random


def send_docker_cmd(container_name, cmd, verbose=True):
    final_command = f"sudo docker exec -it {container_name} {cmd}"
    if verbose:
        print(f'[$] Executing "{final_command}" on {container_name}')
    # return os.system(final_command)
    # * Used for local debugging
    return 0


def get_random_container():
    containers_list = ["amf", "smf", "ausf", "gnb"]
    return random.choice(containers_list)


def get_attack_scripts(path):
    try:
        files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
        return files
    except FileNotFoundError:
        print(f"[!] Path not found: {path}")
        return []
    except Exception as e:
        print(f"[!] Error: {e}")
        return []


def get_random_attack_script(path):
    attack_scripts_list = get_attack_scripts(path)

    return random.choice(attack_scripts_list)


def exec_random_attack(scripts_path):
    random_attack_script = get_random_attack_script(scripts_path)
    local_command = f"python {scripts_path}/{random_attack_script}"

    random_container = get_random_container()
    print(f"[i] Running {random_attack_script} on {random_container}...")
    if send_docker_cmd(random_container, local_command) == 0:
        print(f"[+] Attack {random_attack_script} on {random_container} succeed")
    else:
        print(f"[-] Attack {random_attack_script} on {random_container} failed")
    print()


for x in range(20):
    exec_random_attack("./src/attacks/scripts")
