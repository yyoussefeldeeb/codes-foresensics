
import os
from Registry import Registry


HIVE_DIR = r"D:\forensics hives"


def load_hive(filename):
    """Loads a registry hive if it exists."""
    path = os.path.join(HIVE_DIR, filename)
    if not os.path.exists(path):
        print(f"Missing hive: {filename}")
        return None
    return Registry.Registry(path)


def get_windows_version(software):
    try:
        key = software.open("Microsoft\\Windows NT\\CurrentVersion")
        return key.value("ProductName").value()
    except:
        return "Unknown"


def get_computer_name(system):
    try:
        key = system.open("ControlSet001\\Control\\ComputerName\\ComputerName")
        return key.value("ComputerName").value()
    except:
        return "Unknown"


def get_user_accounts(sam):
    users = []
    try:
        root = sam.open("SAM\\Domains\\Account\\Users\\Names")
        for sub in root.subkeys():
            users.append(sub.name())
    except:
        pass
    return users


def get_runmru(ntuser):
    try:
        key = ntuser.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
        return {v.name(): v.value() for v in key.values()}
    except:
        return {}


def get_typed_urls(ntuser):
    try:
        key = ntuser.open("Software\\Microsoft\\Internet Explorer\\TypedURLs")
        return [v.value() for v in key.values()]
    except:
        return []


def main():
    # Load main hives
    software = load_hive("SOFTWARE")
    system = load_hive("SYSTEM")
    sam = load_hive("SAM")

    print("=== Registry Report ===")
    print("Windows Version:", get_windows_version(software))
    print("Computer Name:", get_computer_name(system))
    print("User Accounts:", get_user_accounts(sam))

    print()

   
    for filename in os.listdir(HIVE_DIR):
        if filename.lower().endswith(".dat"):   
            print(f"--- NTUSER Hive: {filename} ---")
            nt = load_hive(filename)
            if nt:
                print("RunMRU:", get_runmru(nt))
                print("Typed URLs:", get_typed_urls(nt))
                print()


if __name__ == "__main__":
    main()
