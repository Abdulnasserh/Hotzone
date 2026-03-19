import hashlib
import subprocess
import platform

def get_machine_id():
    try:
        if platform.system() == "Windows":
            return subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
        elif platform.system() == "Darwin":
            return subprocess.check_output("ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID", shell=True).decode().split('"')[-2]
        else:
            with open("/etc/machine-id", "r") as f:
                return f.read().strip()
    except Exception:
        return "UNKNOWN-MACHINE-ID-FALLBACK-123"

def generate_key(machine_id):
    salt = "HOTZONE_WIFI_PRO_EDITION_2026"
    return hashlib.sha256((machine_id + salt).encode()).hexdigest()[:16].upper()

def verify_key(key):
    expected = generate_key(get_machine_id())
    return key.upper().strip() == expected

if __name__ == "__main__":
    import sys
    # For the seller to generate keys
    if len(sys.argv) > 1:
        machine_id = sys.argv[1]
        print(f"Generated License Code for {machine_id}:")
        print(f"--> {generate_key(machine_id)} <--")
    else:
        print(f"Your Machine ID: {get_machine_id()}")
