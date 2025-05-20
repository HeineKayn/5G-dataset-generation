import random
import threading
import time

from attacks_customized import *


# Pour chaque attaque ici on fait une fonction on aura plus qu'a appeler la vraie fonction et custom les paramètres
def attack1():
    print("Attack 1 executed")


def attack2():
    print("Attack 2 executed")


def attack3():
    print("Attack 3 executed")


def attack4():
    print("Attack 4 executed")


def benin1():
    print("Benin 1 executed")


def benin2():
    print("Benin 2 executed")


def benin3():
    print("Benin 3 executed")


def random_benin():
    benin_functions = [benin1, benin2, benin3]
    random.choice(benin_functions)()


def random_attack():
    attack_functions = [
        pfcp_session_establishment_flood_customized,
        pfcp_session_deletion_flood_customized,
        pfcp_session_deletion_targeted_customized,
        pfcp_session_modification_far_drop_bruteforce_customized,
        pfcp_session_modification_far_dupl_bruteforce_customized,
        pfcp_seid_fuzzing_customized,
        pfcp_far_fuzzing_customized,
        pfcp_hijack_far_manipulation_customized,
    ]
    random.choice(attack_functions)(ip_list["EVIL"])


def execute_full_benin(duration, sleep_range=(0.5, 0.5)):
    end_time = time.time() + duration
    while time.time() < end_time:
        random_benin(),
        time.sleep(random.uniform(*sleep_range))


def execute_full_attack(duration, sleep_range=(0.5, 0.5)):
    end_time = time.time() + duration
    while time.time() < end_time:
        random_attack()
        time.sleep(random.uniform(*sleep_range))


def main():
    choice = input("Choose mode (1: Full Benin, 2: Benin + Attack): ")
    duration = int(input("Enter duration in seconds: "))
    sleep_min = float(input("Enter minimum sleep time: "))
    sleep_max = float(input("Enter maximum sleep time: "))
    sleep_range = (sleep_min, sleep_max)

    if choice == "1":
        thread = threading.Thread(
            target=execute_full_benin, args=(duration, sleep_range)
        )
        thread.start()
        thread.join()
    elif choice == "2":
        thread1 = threading.Thread(
            target=execute_full_benin, args=(duration, sleep_range)
        )
        thread2 = threading.Thread(
            target=execute_full_attack, args=(duration, sleep_range)
        )
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
